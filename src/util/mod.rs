mod block;
mod script;
mod transaction;

pub mod electrum_merkle;
pub mod fees;

pub use self::block::{BlockHeaderMeta, BlockId, BlockMeta, BlockStatus, HeaderEntry, HeaderList};
pub use self::fees::get_tx_fee;
pub use self::script::{get_innerscripts, ScriptToAddr, ScriptToAsm};
pub use self::transaction::{
    extract_tx_prevouts, has_prevout, is_coinbase, is_spendable, serialize_outpoint,
    TransactionStatus, TxInput,
};

use std::collections::HashMap;
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::{sync, thread};

use crate::chain::BlockHeader;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

pub type Bytes = Vec<u8>;
pub type HeaderMap = HashMap<Sha256dHash, BlockHeader>;

// TODO: consolidate serialization/deserialize code for bincode/bitcoin.
const HASH_LEN: usize = 32;

pub type FullHash = [u8; HASH_LEN];

pub fn full_hash(hash: &[u8]) -> FullHash {
    *array_ref![hash, 0, HASH_LEN]
}

pub struct SyncChannel<T> {
    tx: SyncSender<T>,
    rx: Receiver<T>,
}

impl<T> SyncChannel<T> {
    pub fn new(size: usize) -> SyncChannel<T> {
        let (tx, rx) = sync_channel(size);
        SyncChannel { tx, rx }
    }

    pub fn sender(&self) -> SyncSender<T> {
        self.tx.clone()
    }

    pub fn receiver(&self) -> &Receiver<T> {
        &self.rx
    }

    pub fn into_receiver(self) -> Receiver<T> {
        self.rx
    }
}

pub struct Channel<T> {
    tx: Sender<T>,
    rx: Receiver<T>,
}

impl<T> Channel<T> {
    pub fn unbounded() -> Self {
        let (tx, rx) = channel();
        Channel { tx, rx }
    }

    pub fn sender(&self) -> Sender<T> {
        self.tx.clone()
    }

    pub fn receiver(&self) -> &Receiver<T> {
        &self.rx
    }

    pub fn into_receiver(self) -> Receiver<T> {
        self.rx
    }
}

pub fn spawn_thread<F, T>(name: &str, f: F) -> thread::JoinHandle<T>
where
    F: FnOnce() -> T,
    F: Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(f)
        .unwrap()
}

/// A trait to represent either an RwLock or an already-acquired read lock guard.
/// This makes it easier to reuse the lock in recursive calls and to avoid deadlocks.
/// See https://github.com/Blockstream/electrs/pull/57
pub trait ReusableReadLock<'a, T> {
    /// Get an RwLockReadGuard, either by acquiring a new lock or reusing a previous one
    /// The return value implements ReusableReadLock itself too.
    fn read(self) -> sync::LockResult<sync::RwLockReadGuard<'a, T>>;
}

impl<'a, T> ReusableReadLock<'a, T> for &'a sync::Arc<sync::RwLock<T>> {
    // Acquire a new read lock on the RwLock
    fn read(self) -> sync::LockResult<sync::RwLockReadGuard<'a, T>> {
        sync::RwLock::read(self)
    }
}

impl<'a, T> ReusableReadLock<'a, T> for sync::RwLockReadGuard<'a, T> {
    // Reuse the existing read lock
    fn read(self) -> sync::LockResult<sync::RwLockReadGuard<'a, T>> {
        Ok(self)
    }
}

/// Utility for specifying a typed None for functions that accept an Option<ReusableReadLock>
pub type GuardOpt<T> = Option<sync::RwLockReadGuard<'static, T>>;

// Similar to https://doc.rust-lang.org/std/primitive.bool.html#method.then (nightly only),
// but with a function that returns an `Option<T>` instead of `T`. Adding something like
// this to std is being discussed: https://github.com/rust-lang/rust/issues/64260

pub trait BoolThen {
    fn and_then<T>(self, f: impl FnOnce() -> Option<T>) -> Option<T>;
}

impl BoolThen for bool {
    fn and_then<T>(self, f: impl FnOnce() -> Option<T>) -> Option<T> {
        if self {
            f()
        } else {
            None
        }
    }
}

pub fn create_socket(addr: &SocketAddr) -> Socket {
    let domain = match &addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket =
        Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).expect("creating socket failed");

    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .expect("cannot enable SO_REUSEPORT");

    socket.bind(&addr.clone().into()).expect("cannot bind");

    socket
}

/// A module used for serde serialization of bytes in hexadecimal format.
///
/// The module is compatible with the serde attribute.
///
/// Copied from https://github.com/rust-bitcoin/rust-bitcoincore-rpc/blob/master/json/src/lib.rs
pub mod serde_hex {
    use bitcoin::hashes::hex::{FromHex, ToHex};
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let hex_str: String = ::serde::Deserialize::deserialize(d)?;
        Ok(FromHex::from_hex(&hex_str).map_err(D::Error::custom)?)
    }

    pub mod opt {
        use bitcoin::hashes::hex::{FromHex, ToHex};
        use serde::de::Error;
        use serde::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match *b {
                None => s.serialize_none(),
                Some(ref b) => s.serialize_str(&b.to_hex()),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            let hex_str: String = ::serde::Deserialize::deserialize(d)?;
            Ok(Some(FromHex::from_hex(&hex_str).map_err(D::Error::custom)?))
        }
    }
}
