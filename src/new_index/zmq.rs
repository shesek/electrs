use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::{Arc, RwLock};
use std::{thread, time};

use bitcoin::hashes::Hash;

use crate::chain::{BlockHash, Txid};
use crate::daemon::Daemon;
use crate::errors::*;
use crate::new_index::{Indexer, Mempool};

pub struct ZmqSyncer {
    daemon: Arc<Daemon>,
    indexer: Indexer,
    mempool: Arc<RwLock<Mempool>>,
    expected_sequence: u64,
}

impl ZmqSyncer {
    pub fn new(daemon: Arc<Daemon>, indexer: Indexer, mempool: Arc<RwLock<Mempool>>) -> Self {
        ZmqSyncer {
            daemon,
            indexer,
            mempool,
            expected_sequence: 0,
        }
    }

    pub fn start(mut self, zmq_addr: &str) -> Result<()> {
        info!("starting ZMQ syncer on {}", zmq_addr);

        // Setup ZMQ connection, subscribe to 'hashblock' & 'sequence'
        let ctx = zmq::Context::new();
        let subscriber = ctx
            .socket(zmq::SUB)
            .chain_err(|| "failed initiating zmq socket")?;
        subscriber
            .connect(zmq_addr)
            .chain_err(|| "failed connecting subscriber")?;
        subscriber
            .set_subscribe(b"hashblock")
            .chain_err(|| "failed subscribing")?;
        subscriber
            .set_subscribe(b"sequence")
            .chain_err(|| "failed subscribing")?;

        // Run an initial sync of our mempool view and record the initial sequence number.
        // The first ZMQ sequence notification will arrive with this sequence number (not the next one)
        self.expected_sequence = self.force_mempool_refresh()?;
        trace!(
            "mempool init sync up to sequence number {}",
            self.expected_sequence
        );

        // Process ZMQ notifications
        loop {
            let msg = match subscriber.recv_multipart(0) {
                Err(e) if e == zmq::Error::EINTR => {
                    // Interrupted due to a system termination signal, exit gracefully without an error.
                    break Ok(());
                }
                Err(e) => {
                    break Err(Error::with_chain(e, "failed receiving zmq message"));
                }
                Ok(msg) => msg,
            };

            self.handle_msg(msg)?;
        }
    }

    fn handle_msg(&mut self, mut msg: Vec<Vec<u8>>) -> Result<()> {
        let (topic, body) = (msg.remove(0), msg.remove(0));
        // the main zmq message sequence number (third msg part) is ignored, checking the mempool sequence is sufficient

        match String::from_utf8_lossy(&topic).as_ref() {
            "sequence" => self.handle_sequence(body),
            "hashblock" => self.handle_hashblock(body),
            t => bail!("unknown zmq topic {}", t),
        }
    }

    fn handle_sequence(&mut self, body: Vec<u8>) -> Result<()> {
        // body format (https://github.com/bitcoin/bitcoin/blob/master/doc/zmq.md)
        // <32-byte hash>C :                 Blockhash connected
        // <32-byte hash>D :                 Blockhash disconnected
        // <32-byte hash>R<8-byte LE uint> : Transactionhash removed from mempool for non-block inclusion reason
        // <32-byte hash>A<8-byte LE uint> : Transactionhash added mempool
        ensure!(
            body.len() == 33 || body.len() == 41,
            "invalid sequence message length"
        );

        let label = body[32] as char;

        // Blockhash connected/disconnected
        if matches!(label, 'C' | 'D') {
            // These messages are ignored. New blocks are handled via the 'hashblock' topic instead, whose functionality
            // is better suited here. See paragraph 3 in https://github.com/bitcoin/bitcoin/blob/9c47eb4503/doc/zmq.md#remarks
            return Ok(());
        }
        ensure!(body.len() == 41, "invalid sequence message length");

        let txid = body[0..32].iter().copied().rev().collect::<Vec<_>>(); // ZMQ hashes are LE, rev() to convert them to the usual BE
        let txid = Txid::from_slice(&txid).unwrap();
        let mempool_sequence = u64::from_le_bytes(body[33..].try_into().unwrap());

        trace!(
            "received ZMQ sequence message '{}' #{} with txid {}",
            label,
            mempool_sequence,
            txid,
        );

        // Check if any mempool sequence messages were lost, and trigger a complete
        // refresh of our mempool view if any were.
        if mempool_sequence > self.expected_sequence {
            warn!(
                "zmq sequence message lost (received {}, expected {}), refreshing mempool",
                mempool_sequence, self.expected_sequence
            );

            self.expected_sequence = self.force_mempool_refresh()?;

            trace!("refreshed up to sequence {}", self.expected_sequence);
            return Ok(());
        }
        // We may occasionally receive outdated notifications, ignore them.
        else if mempool_sequence < self.expected_sequence {
            debug!(
                "ignoring zmq sequence {}, mempool view is more current at {}",
                mempool_sequence, self.expected_sequence
            );
            return Ok(());
        }

        let mut mempool = self.mempool.write().unwrap();

        match label {
            // Transaction added to memppool
            'A' => {
                mempool.add_by_txid(&self.daemon, &txid);
            }

            // Transaction removed from mempool
            'R' => {
                mempool.remove(HashSet::from([txid]), true);
            }

            l => bail!("unknown zmq sequence label '{}'", l),
        }

        self.expected_sequence = mempool_sequence + 1;

        Ok(())
    }

    fn handle_hashblock(&mut self, mut body: Vec<u8>) -> Result<()> {
        body.reverse(); // ZMQ hashes are LE, convert them to the usual BE
        let new_tip = BlockHash::from_slice(&body).unwrap();

        trace!("received ZMQ hashblock message: {}", new_tip);

        // Index new block(s)
        let (_, confirmed_txids) = self.indexer.update(&self.daemon, Some(new_tip), true)?;

        // Drop confirmed transactions from our mempool view
        let num_removed = self.mempool.write().unwrap().remove(confirmed_txids, true);

        // Transactions removed from the mempool due to block inclusion count towards the mempool
        // sequence number, but don't trigger ZMQ notifications with the new sequence numbers.
        // This adjusts the expected sequence number to account for this.
        // See https://github.com/bitcoin/bitcoin/blob/9c47eb450346937b/test/functional/interface_zmq.py#L347-L349
        self.expected_sequence += num_removed as u64;

        trace!(
            "indexed new block, {} txs removed from mempool, sequence at {}",
            num_removed,
            self.expected_sequence
        );

        Ok(())
    }

    // Continuously try to refresh the mempool (with a full re-sync) until it succeeds. This may fail due
    // to a race condition (if the mempool changes between fetching the mempool txids and the txs themselves),
    // and may take several attempts to complete successfully. This is OK because its only done once on startup,
    // and to recover from lost ZMQ sequence messages which should be uncommon.
    fn force_mempool_refresh(&mut self) -> Result<u64> {
        Ok(loop {
            // release lock in between attempts, to give others threads a chance to read the mempool.
            match self.mempool.write().unwrap().update(&self.daemon)? {
                Some(mempool_sequence) => break mempool_sequence,
                None => thread::sleep(time::Duration::from_secs_f32(0.3)),
            }
        })
    }
}
