//! Multi-dimensional key-value documents with an efficient synchronization protocol
//!
//! The crate operates on [Replicas](Replica). A replica contains an unlimited number of
//! [Entrys][Entry]. Each entry is identified by a key, its author, and the replica's
//! namespace. Its value is the [32-byte BLAKE3 hash](iroh_bytes::Hash)
//! of the entry's content data, the size of this content data, and a timestamp.
//! The content data itself is not stored or transfered through a replica.
//!
//! All entries in a replica are signed with two keypairs:
//!
//! * The [`NamespaceSecret`] key, as a token of write capability. The public key is the
//!   [`NamespaceId`], which also serves as the unique identifier for a replica.
//! * The [Author] key, as a proof of authorship. Any number of authors may be created, and
//!   their semantic meaning is application-specific. The public key of an author is the [AuthorId].
//!
//! Replicas can be synchronized between peers by exchanging messages. The synchronization algorithm
//! is based on a technique called *range-based set reconciliation*, based on [this paper][paper] by
//! Aljoscha Meyer:
//!
//! > Range-based set reconciliation is a simple approach to efficiently compute the union of two
//! sets over a network, based on recursively partitioning the sets and comparing fingerprints of
//! the partitions to probabilistically detect whether a partition requires further work.
//!
//! The crate exposes a [generic storage interface](store::Store) with
//! [in-memory](store::memory::Store) and [persistent, file-based](store::fs::Store)
//! implementations. The latter makes use of [`redb`], an embedded key-value store, and persists
//! the whole store with all replicas to a single file.
//!
//! [paper]: https://arxiv.org/abs/2212.13567
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod actor;
mod heads;
mod keys;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "net")]
pub mod net;
mod ranger;
pub mod store;
pub mod sync;

pub use self::heads::*;
pub use self::keys::*;
pub use self::sync::*;
