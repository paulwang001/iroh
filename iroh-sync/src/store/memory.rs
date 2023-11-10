//! In memory storage for replicas.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use ed25519_dalek::{SignatureError, VerifyingKey};
use iroh_bytes::Hash;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard};

use crate::{
    keys::Author,
    ranger::{Fingerprint, Range, RangeEntry},
    sync::{RecordIdentifier, Replica, SignedEntry},
    AuthorId, Capability, CapabilityKind, NamespaceId, PeerIdBytes, Record,
};

use super::{pubkeys::MemPublicKeyStore, ImportNamespaceOutcome, OpenError, PublicKeyStore};

type SyncPeersCache = Arc<RwLock<HashMap<NamespaceId, lru::LruCache<PeerIdBytes, ()>>>>;

/// Manages the replicas and authors for an instance.
#[derive(Debug, Clone, Default)]
pub struct Store {
    open_replicas: Arc<RwLock<HashSet<NamespaceId>>>,
    namespaces: Arc<RwLock<HashMap<NamespaceId, Capability>>>,
    authors: Arc<RwLock<HashMap<AuthorId, Author>>>,
    /// Stores records by namespace -> identifier + timestamp
    replica_records: Arc<RwLock<ReplicaRecordsOwned>>,
    /// Stores the latest entry for each author
    latest: Arc<RwLock<LatestMapOwned>>,
    pubkeys: MemPublicKeyStore,
    /// Cache of peers that have been used for sync.
    peers_per_doc: SyncPeersCache,
}

type Rid = (AuthorId, Vec<u8>);
type Rvalue = SignedEntry;
type RecordMap = BTreeMap<Rid, Rvalue>;
type ReplicaRecordsOwned = BTreeMap<NamespaceId, RecordMap>;

type LatestByAuthorMapOwned = BTreeMap<AuthorId, (u64, Vec<u8>)>;
type LatestMapOwned = HashMap<NamespaceId, LatestByAuthorMapOwned>;
type LatestByAuthorMap<'a> = MappedRwLockReadGuard<'a, LatestByAuthorMapOwned>;

impl super::Store for Store {
    type Instance = ReplicaStoreInstance;
    type GetIter<'a> = RangeIterator<'a>;
    type ContentHashesIter<'a> = ContentHashesIterator<'a>;
    type AuthorsIter<'a> = std::vec::IntoIter<Result<Author>>;
    type NamespaceIter<'a> = std::vec::IntoIter<Result<(NamespaceId, CapabilityKind)>>;
    type PeersIter<'a> = std::vec::IntoIter<PeerIdBytes>;
    type LatestIter<'a> = LatestIterator<'a>;

    fn open_replica(&self, id: &NamespaceId) -> Result<Replica<Self::Instance>, OpenError> {
        if self.open_replicas.read().contains(id) {
            return Err(OpenError::AlreadyOpen);
        }
        let namespace = {
            let namespaces = self.namespaces.read();
            let namespace = namespaces.get(id).ok_or(OpenError::NotFound)?;
            namespace.clone()
        };
        let replica = Replica::new(namespace, ReplicaStoreInstance::new(*id, self.clone()));
        self.open_replicas.write().insert(*id);
        Ok(replica)
    }

    fn close_replica(&self, mut replica: Replica<Self::Instance>) {
        self.open_replicas.write().remove(&replica.id());
        replica.close();
    }

    fn list_namespaces(&self) -> Result<Self::NamespaceIter<'_>> {
        // TODO: avoid collect?
        Ok(self
            .namespaces
            .read()
            .iter()
            .map(|(id, capability)| Ok((*id, capability.kind())))
            .collect::<Vec<_>>()
            .into_iter())
    }

    fn get_author(&self, author: &AuthorId) -> Result<Option<Author>> {
        let authors = &*self.authors.read();
        Ok(authors.get(author).cloned())
    }

    fn import_author(&self, author: Author) -> Result<()> {
        self.authors.write().insert(author.id(), author);
        Ok(())
    }

    fn list_authors(&self) -> Result<Self::AuthorsIter<'_>> {
        // TODO: avoid collect?
        Ok(self
            .authors
            .read()
            .values()
            .cloned()
            .map(Ok)
            .collect::<Vec<_>>()
            .into_iter())
    }

    fn import_namespace(&self, capability: Capability) -> Result<ImportNamespaceOutcome> {
        let mut table = self.namespaces.write();
        let (capability, outcome) = if let Some(mut existing) = table.remove(&capability.id()) {
            if existing.merge(capability)? {
                (existing, ImportNamespaceOutcome::Upgraded)
            } else {
                (existing, ImportNamespaceOutcome::NoChange)
            }
        } else {
            (capability, ImportNamespaceOutcome::Inserted)
        };
        table.insert(capability.id(), capability);
        Ok(outcome)
    }

    fn remove_replica(&self, namespace: &NamespaceId) -> Result<()> {
        if self.open_replicas.read().contains(namespace) {
            return Err(anyhow!("replica is not closed"));
        }
        self.replica_records.write().remove(namespace);
        self.namespaces.write().remove(namespace);
        Ok(())
    }

    fn get_many(
        &self,
        namespace: NamespaceId,
        filter: super::GetFilter,
    ) -> Result<Self::GetIter<'_>> {
        match filter {
            super::GetFilter::All => self.get_all(namespace),
            super::GetFilter::Key(key) => self.get_by_key(namespace, key),
            super::GetFilter::Prefix(prefix) => self.get_by_prefix(namespace, prefix),
            super::GetFilter::Author(author) => self.get_by_author(namespace, author),
            super::GetFilter::AuthorAndPrefix(author, prefix) => {
                self.get_by_author_and_prefix(namespace, author, prefix)
            }
        }
    }

    fn get_one(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>> {
        let inner = self.replica_records.read();

        let value = inner
            .get(&namespace)
            .and_then(|records| records.get(&(author, key.as_ref().to_vec())));
        Ok(match value {
            None => None,
            Some(value) if value.is_empty() => None,
            Some(value) => Some(value.clone()),
        })
    }

    /// Get all content hashes of all replicas in the store.
    fn content_hashes(&self) -> Result<Self::ContentHashesIter<'_>> {
        let records = self.replica_records.read();
        Ok(ContentHashesIterator {
            records,
            namespace_i: 0,
            record_i: 0,
        })
    }

    fn get_latest_for_each_author(&self, namespace: NamespaceId) -> Result<LatestIterator<'_>> {
        let records =
            RwLockReadGuard::try_map(self.latest.read(), move |map| map.get(&namespace)).ok();
        Ok(LatestIterator {
            records,
            author_i: 0,
        })
    }

    fn register_useful_peer(&self, namespace: NamespaceId, peer: crate::PeerIdBytes) -> Result<()> {
        let mut per_doc_cache = self.peers_per_doc.write();
        per_doc_cache
            .entry(namespace)
            .or_insert_with(|| lru::LruCache::new(super::PEERS_PER_DOC_CACHE_SIZE))
            .put(peer, ());
        Ok(())
    }

    fn get_sync_peers(&self, namespace: &NamespaceId) -> Result<Option<Self::PeersIter<'_>>> {
        let per_doc_cache = self.peers_per_doc.read();
        let cache = match per_doc_cache.get(namespace) {
            Some(cache) => cache,
            None => return Ok(None),
        };

        let peers: Vec<PeerIdBytes> = cache.iter().map(|(peer_id, _empty_val)| *peer_id).collect();
        Ok(Some(peers.into_iter()))
    }
}

impl Store {
    fn get_by_key(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
    ) -> Result<RangeIterator<'_>> {
        let records = self.replica_records.read();
        let key = key.as_ref().to_vec();
        let filter = GetFilter::Key { namespace, key };

        Ok(RangeIterator {
            records,
            filter,
            index: 0,
        })
    }

    fn get_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> Result<RangeIterator<'_>> {
        let records = self.replica_records.read();
        let prefix = prefix.as_ref().to_vec();
        let filter = GetFilter::Prefix { namespace, prefix };

        Ok(RangeIterator {
            records,
            filter,
            index: 0,
        })
    }

    fn get_by_author(&self, namespace: NamespaceId, author: AuthorId) -> Result<RangeIterator<'_>> {
        let records = self.replica_records.read();
        let filter = GetFilter::Author { namespace, author };

        Ok(RangeIterator {
            records,
            filter,
            index: 0,
        })
    }

    fn get_by_author_and_prefix(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        prefix: Vec<u8>,
    ) -> Result<RangeIterator<'_>> {
        let records = self.replica_records.read();
        let filter = GetFilter::AuthorAndPrefix {
            namespace,
            author,
            prefix,
        };

        Ok(RangeIterator {
            records,
            filter,
            index: 0,
        })
    }

    fn get_all(&self, namespace: NamespaceId) -> Result<RangeIterator<'_>> {
        let records = self.replica_records.read();
        let filter = GetFilter::All { namespace };

        Ok(RangeIterator {
            records,
            filter,
            index: 0,
        })
    }
}

#[derive(Debug)]
enum GetFilter {
    /// All entries.
    All { namespace: NamespaceId },
    /// Filter by author.
    Author {
        namespace: NamespaceId,
        author: AuthorId,
    },
    /// Filter by key only.
    Key {
        namespace: NamespaceId,
        key: Vec<u8>,
    },
    /// Filter by prefix only.
    Prefix {
        namespace: NamespaceId,
        prefix: Vec<u8>,
    },
    /// Filter by author and prefix.
    AuthorAndPrefix {
        namespace: NamespaceId,
        prefix: Vec<u8>,
        author: AuthorId,
    },
}

impl GetFilter {
    fn namespace(&self) -> NamespaceId {
        match self {
            GetFilter::All { namespace } => *namespace,
            GetFilter::Key { namespace, .. } => *namespace,
            GetFilter::Prefix { namespace, .. } => *namespace,
            GetFilter::Author { namespace, .. } => *namespace,
            GetFilter::AuthorAndPrefix { namespace, .. } => *namespace,
        }
    }
}

/// Iterator over all content hashes in the memory store.
#[derive(Debug)]
pub struct ContentHashesIterator<'a> {
    records: ReplicaRecords<'a>,
    namespace_i: usize,
    record_i: usize,
}

impl<'a> Iterator for ContentHashesIterator<'a> {
    type Item = Result<Hash>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let records = self.records.values().nth(self.namespace_i)?;
            match records.values().nth(self.record_i) {
                None => {
                    self.namespace_i += 1;
                    self.record_i = 0;
                }
                Some(record) => {
                    self.record_i += 1;
                    return Some(Ok(record.content_hash()));
                }
            }
        }
    }
}

/// Iterator over the latest timestamp/key for each author
#[derive(Debug)]
pub struct LatestIterator<'a> {
    records: Option<LatestByAuthorMap<'a>>,
    author_i: usize,
}

impl<'a> Iterator for LatestIterator<'a> {
    type Item = Result<(AuthorId, u64, Vec<u8>)>;
    fn next(&mut self) -> Option<Self::Item> {
        let records = self.records.as_ref()?;
        match records.iter().nth(self.author_i) {
            None => None,
            Some((author, (timestamp, key))) => {
                self.author_i += 1;
                Some(Ok((*author, *timestamp, key.to_vec())))
            }
        }
    }
}

/// Iterator over entries in the memory store
#[derive(Debug)]
pub struct RangeIterator<'a> {
    records: ReplicaRecords<'a>,
    filter: GetFilter,
    /// Current iteration index.
    index: usize,
}

impl<'a> Iterator for RangeIterator<'a> {
    type Item = Result<SignedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let records = self.records.get(&self.filter.namespace())?;
            let entry = match self.filter {
                GetFilter::All { .. } => records.iter().nth(self.index)?,
                GetFilter::Key { ref key, .. } => records
                    .iter()
                    .filter(|((_, k), _)| k == key)
                    .nth(self.index)?,
                GetFilter::Prefix { ref prefix, .. } => records
                    .iter()
                    .filter(|((_, k), _)| k.starts_with(prefix))
                    .nth(self.index)?,
                GetFilter::Author { ref author, .. } => records
                    .iter()
                    .filter(|((a, _), _)| a == author)
                    .nth(self.index)?,
                GetFilter::AuthorAndPrefix {
                    ref prefix,
                    ref author,
                    ..
                } => records
                    .iter()
                    .filter(|((a, k), _)| a == author && k.starts_with(prefix))
                    .nth(self.index)?,
            };
            self.index += 1;
            if entry.1.is_empty() {
                continue;
            } else {
                return Some(Ok(entry.1.clone()));
            }
        }
    }
}

/// Instance of a [`Store`]
#[derive(Debug, Clone)]
pub struct ReplicaStoreInstance {
    namespace: NamespaceId,
    store: Store,
}

impl PublicKeyStore for ReplicaStoreInstance {
    fn public_key(&self, id: &[u8; 32]) -> std::result::Result<VerifyingKey, SignatureError> {
        self.store.pubkeys.public_key(id)
    }
}

impl ReplicaStoreInstance {
    fn new(namespace: NamespaceId, store: Store) -> Self {
        ReplicaStoreInstance { namespace, store }
    }

    fn with_records<F, T>(&self, f: F) -> T
    where
        F: FnOnce(Option<&RecordMap>) -> T,
    {
        let guard = self.store.replica_records.read();
        let value = guard.get(&self.namespace);
        f(value)
    }

    fn with_records_mut<F, T>(&self, f: F) -> T
    where
        F: FnOnce(Option<&mut RecordMap>) -> T,
    {
        let mut guard = self.store.replica_records.write();
        let value = guard.get_mut(&self.namespace);
        f(value)
    }

    fn with_records_mut_with_default<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut RecordMap) -> T,
    {
        let mut guard = self.store.replica_records.write();
        let value = guard.entry(self.namespace).or_default();
        f(value)
    }

    fn with_latest_mut_with_default<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut LatestByAuthorMapOwned) -> T,
    {
        let mut guard = self.store.latest.write();
        let value = guard.entry(self.namespace).or_default();
        f(value)
    }

    fn records_iter(&self) -> RecordsIter<'_> {
        RecordsIter {
            namespace: self.namespace,
            replica_records: self.store.replica_records.read(),
            i: 0,
        }
    }
}

type ReplicaRecords<'a> = RwLockReadGuard<'a, ReplicaRecordsOwned>;

#[derive(Debug)]
struct RecordsIter<'a> {
    namespace: NamespaceId,
    replica_records: ReplicaRecords<'a>,
    i: usize,
}

impl Iterator for RecordsIter<'_> {
    type Item = (RecordIdentifier, SignedEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let records = self.replica_records.get(&self.namespace)?;
        let ((author, key), value) = records.iter().nth(self.i)?;
        let id = RecordIdentifier::new(self.namespace, *author, key);
        self.i += 1;
        Some((id, value.clone()))
    }
}

impl crate::ranger::Store<SignedEntry> for ReplicaStoreInstance {
    type Error = Infallible;

    /// Get a the first key (or the default if none is available).
    fn get_first(&self) -> Result<RecordIdentifier, Self::Error> {
        Ok(self.with_records(|records| {
            records
                .and_then(|r| {
                    r.first_key_value().map(|((author, key), _value)| {
                        RecordIdentifier::new(self.namespace, *author, key.clone())
                    })
                })
                .unwrap_or_default()
        }))
    }

    fn get(&self, key: &RecordIdentifier) -> Result<Option<SignedEntry>, Self::Error> {
        Ok(self.with_records(|records| {
            records.and_then(|r| {
                let v = r.get(&(key.author(), key.key().to_vec()))?;
                Some(v.clone())
            })
        }))
    }

    fn len(&self) -> Result<usize, Self::Error> {
        Ok(self.with_records(|records| records.map(|v| v.len()).unwrap_or_default()))
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self.len()? == 0)
    }

    fn get_fingerprint(&self, range: &Range<RecordIdentifier>) -> Result<Fingerprint, Self::Error> {
        let elements = self.get_range(range.clone())?;
        let mut fp = Fingerprint::empty();
        for el in elements {
            let el = el?;
            fp ^= el.as_fingerprint();
        }
        Ok(fp)
    }

    fn put(&mut self, e: SignedEntry) -> Result<(), Self::Error> {
        self.with_latest_mut_with_default(|records| {
            records.insert(e.author_bytes(), (e.timestamp(), e.key().to_vec()));
        });
        self.with_records_mut_with_default(|records| {
            records.insert((e.author_bytes(), e.key().to_vec()), e);
        });
        Ok(())
    }

    type RangeIterator<'a> = InstanceRangeIterator<'a>;

    fn get_range(
        &self,
        range: Range<RecordIdentifier>,
    ) -> Result<Self::RangeIterator<'_>, Self::Error> {
        Ok(InstanceRangeIterator {
            iter: self.records_iter(),
            filter: InstanceRangeFilter::Range(range),
        })
    }

    fn remove(&mut self, key: &RecordIdentifier) -> Result<Option<SignedEntry>, Self::Error> {
        // TODO: what if we are trying to remove with the wrong timestamp?
        let res = self.with_records_mut(|records| {
            records.and_then(|records| records.remove(&(key.author(), key.key().to_vec())))
        });
        Ok(res)
    }

    fn all(&self) -> Result<Self::RangeIterator<'_>, Self::Error> {
        Ok(InstanceRangeIterator {
            iter: self.records_iter(),
            filter: InstanceRangeFilter::None,
        })
    }

    // TODO: Not horrible.
    type ParentIterator<'a> = std::vec::IntoIter<Result<SignedEntry, Infallible>>;
    fn prefixes_of(&self, id: &RecordIdentifier) -> Result<Self::ParentIterator<'_>, Self::Error> {
        let mut entries = vec![];
        let mut key = id.key().to_vec();
        while !key.is_empty() {
            let id = RecordIdentifier::new(id.namespace(), id.author(), &key);
            match self.get(&id) {
                Ok(Some(entry)) => entries.push(Ok(entry)),
                Ok(None) => {}
                Err(err) => entries.push(Err(err)),
            }
            key.pop();
        }
        Ok(entries.into_iter())
    }

    fn prefixed_by(
        &self,
        prefix: &RecordIdentifier,
    ) -> std::result::Result<Self::RangeIterator<'_>, Self::Error> {
        Ok(InstanceRangeIterator {
            iter: self.records_iter(),
            filter: InstanceRangeFilter::Prefix(prefix.author(), prefix.key().to_vec()),
        })
    }

    fn remove_prefix_filtered(
        &mut self,
        prefix: &RecordIdentifier,
        predicate: impl Fn(&Record) -> bool,
    ) -> Result<usize, Self::Error> {
        self.with_records_mut(|records| {
            let Some(records) = records else {
                return Ok(0);
            };
            let old_len = records.len();
            records.retain(|(a, k), v| {
                !(a == &prefix.author() && k.starts_with(prefix.key()) && predicate(v.entry()))
            });
            Ok(old_len - records.len())
        })
    }
}

/// Range iterator for a [`ReplicaStoreInstance`]
#[derive(Debug)]
pub struct InstanceRangeIterator<'a> {
    iter: RecordsIter<'a>,
    filter: InstanceRangeFilter,
}

/// Filter for an [`InstanceRangeIterator`]
#[derive(Debug)]
enum InstanceRangeFilter {
    None,
    Range(Range<RecordIdentifier>),
    Prefix(AuthorId, Vec<u8>),
}

impl InstanceRangeFilter {
    fn matches(&self, x: &RecordIdentifier) -> bool {
        match self {
            Self::None => true,
            Self::Range(range) => range.contains(x),
            Self::Prefix(author, prefix) => x.author() == *author && x.key().starts_with(prefix),
        }
    }
}

impl Iterator for InstanceRangeIterator<'_> {
    type Item = Result<SignedEntry, Infallible>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut next = self.iter.next()?;
        loop {
            let (record_id, v) = next;
            if self.filter.matches(&record_id) {
                return Some(Ok(v));
            }

            next = self.iter.next()?;
        }
    }
}
