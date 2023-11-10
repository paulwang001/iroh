//! Client to an iroh node. Is generic over the connection (in-memory or RPC).
//!
//! TODO: Contains only iroh sync related methods. Add other methods.

use std::collections::HashMap;
use std::io::{self, Cursor};
use std::path::PathBuf;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{SinkExt, Stream, StreamExt, TryStreamExt};
use iroh_bytes::provider::AddProgress;
use iroh_bytes::store::ValidateProgress;
use iroh_bytes::util::runtime;
use iroh_bytes::Hash;
use iroh_bytes::{BlobFormat, Tag};
use iroh_net::{key::PublicKey, magic_endpoint::ConnectionInfo, NodeAddr};
use iroh_sync::actor::OpenState;
use iroh_sync::CapabilityKind;
use iroh_sync::{store::GetFilter, AuthorId, Entry, NamespaceId};
use quic_rpc::message::RpcMsg;
use quic_rpc::{RpcClient, ServiceConnection};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::warn;

use crate::rpc_protocol::{
    AuthorCreateRequest, AuthorListRequest, BlobAddPathRequest, BlobAddStreamRequest,
    BlobAddStreamUpdate, BlobDeleteBlobRequest, BlobDownloadRequest, BlobListCollectionsRequest,
    BlobListCollectionsResponse, BlobListIncompleteRequest, BlobListIncompleteResponse,
    BlobListRequest, BlobListResponse, BlobReadRequest, BlobReadResponse, BlobValidateRequest,
    CounterStats, DeleteTagRequest, DocCloseRequest, DocCreateRequest, DocDelRequest,
    DocDelResponse, DocDropRequest, DocGetManyRequest, DocGetOneRequest, DocImportRequest,
    DocLeaveRequest, DocListRequest, DocOpenRequest, DocSetHashRequest, DocSetRequest,
    DocShareRequest, DocStartSyncRequest, DocStatusRequest, DocSubscribeRequest, DocTicket,
    DownloadProgress, ListTagsRequest, ListTagsResponse, NodeConnectionInfoRequest,
    NodeConnectionInfoResponse, NodeConnectionsRequest, NodeShutdownRequest, NodeStatsRequest,
    NodeStatusRequest, NodeStatusResponse, ProviderService, SetTagOption, ShareMode, WrapOption,
};
use crate::sync_engine::LiveEvent;

pub mod mem;
#[cfg(feature = "cli")]
pub mod quic;

/// Iroh client
#[derive(Debug, Clone)]
pub struct Iroh<C> {
    /// Client for node operations.
    pub node: NodeClient<C>,
    /// Client for blobs operations.
    pub blobs: BlobsClient<C>,
    /// Client for docs operations.
    pub docs: DocsClient<C>,
    /// Client for author operations.
    pub authors: AuthorsClient<C>,
    /// Client for tags operations.
    pub tags: TagsClient<C>,
}

impl<C> Iroh<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Create a new high-level client to a Iroh node from the low-level RPC client.
    pub fn new(rpc: RpcClient<ProviderService, C>, rt: runtime::Handle) -> Self {
        Self {
            node: NodeClient { rpc: rpc.clone() },
            blobs: BlobsClient { rpc: rpc.clone() },
            docs: DocsClient {
                rpc: rpc.clone(),
                rt,
            },
            authors: AuthorsClient { rpc: rpc.clone() },
            tags: TagsClient { rpc },
        }
    }
}

/// Iroh node client.
#[derive(Debug, Clone)]
pub struct NodeClient<C> {
    rpc: RpcClient<ProviderService, C>,
}

impl<C> NodeClient<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Get statistics of the running node.
    pub async fn stats(&self) -> Result<HashMap<String, CounterStats>> {
        let res = self.rpc.rpc(NodeStatsRequest {}).await??;
        Ok(res.stats)
    }

    /// Get information about the different connections we have made
    pub async fn connections(&self) -> Result<impl Stream<Item = Result<ConnectionInfo>>> {
        let stream = self.rpc.server_streaming(NodeConnectionsRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| res.conn_info))
    }

    /// Get connection information about a node
    pub async fn connection_info(&self, node_id: PublicKey) -> Result<Option<ConnectionInfo>> {
        let NodeConnectionInfoResponse { conn_info } = self
            .rpc
            .rpc(NodeConnectionInfoRequest { node_id })
            .await??;
        Ok(conn_info)
    }

    /// Get status information about a node
    pub async fn status(&self) -> Result<NodeStatusResponse> {
        let response = self.rpc.rpc(NodeStatusRequest).await??;
        Ok(response)
    }

    /// Shutdown the node.
    ///
    /// If `force` is true, the node will be killed instantly without waiting for things to
    /// shutdown gracefully.
    pub async fn shutdown(&self, force: bool) -> Result<()> {
        self.rpc.rpc(NodeShutdownRequest { force }).await?;
        Ok(())
    }
}

/// Iroh docs client.
#[derive(Debug, Clone)]
pub struct DocsClient<C> {
    rpc: RpcClient<ProviderService, C>,
    rt: runtime::Handle,
}

impl<C> DocsClient<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Create a new document.
    pub async fn create(&self) -> Result<Doc<C>> {
        let res = self.rpc.rpc(DocCreateRequest {}).await??;
        let doc = Doc::new(self.rt.clone(), self.rpc.clone(), res.id);
        Ok(doc)
    }

    /// Delete a document from the local node.
    ///
    /// This is a destructive operation. Both the document secret key and all entries in the
    /// document will be permanently deleted from the node's storage. Content blobs will be deleted
    /// through garbage collection unless they are referenced from another document or tag.
    pub async fn drop_doc(&self, doc_id: NamespaceId) -> Result<()> {
        self.rpc.rpc(DocDropRequest { doc_id }).await??;
        Ok(())
    }

    /// Import a document from a ticket and join all peers in the ticket.
    pub async fn import(&self, ticket: DocTicket) -> Result<Doc<C>> {
        let res = self.rpc.rpc(DocImportRequest(ticket)).await??;
        let doc = Doc::new(self.rt.clone(), self.rpc.clone(), res.doc_id);
        Ok(doc)
    }

    /// List all documents.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<(NamespaceId, CapabilityKind)>>> {
        let stream = self.rpc.server_streaming(DocListRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| (res.id, res.capability)))
    }

    /// Get a [`Doc`] client for a single document. Return None if the document cannot be found.
    pub async fn open(&self, id: NamespaceId) -> Result<Option<Doc<C>>> {
        self.rpc.rpc(DocOpenRequest { doc_id: id }).await??;
        let doc = Doc::new(self.rt.clone(), self.rpc.clone(), id);
        Ok(Some(doc))
    }
}

/// Iroh authors client.
#[derive(Debug, Clone)]
pub struct AuthorsClient<C> {
    rpc: RpcClient<ProviderService, C>,
}

impl<C> AuthorsClient<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Create a new document author.
    pub async fn create(&self) -> Result<AuthorId> {
        let res = self.rpc.rpc(AuthorCreateRequest).await??;
        Ok(res.author_id)
    }

    /// List document authors for which we have a secret key.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<AuthorId>>> {
        let stream = self.rpc.server_streaming(AuthorListRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| res.author_id))
    }
}

/// Iroh tags client.
#[derive(Debug, Clone)]
pub struct TagsClient<C> {
    rpc: RpcClient<ProviderService, C>,
}

impl<C> TagsClient<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// List all tags.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<ListTagsResponse>>> {
        let stream = self.rpc.server_streaming(ListTagsRequest).await?;
        Ok(stream.map_err(anyhow::Error::from))
    }

    /// Delete a tag.
    pub async fn delete(&self, name: Tag) -> Result<()> {
        self.rpc.rpc(DeleteTagRequest { name }).await??;
        Ok(())
    }
}

/// Iroh blobs client.
#[derive(Debug, Clone)]
pub struct BlobsClient<C> {
    rpc: RpcClient<ProviderService, C>,
}

impl<C> BlobsClient<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Stream the contents of a a single blob.
    ///
    /// Returns a [`BlobReader`], which can report the size of the blob before reading it.
    pub async fn read(&self, hash: Hash) -> Result<BlobReader> {
        BlobReader::from_rpc(&self.rpc, hash).await
    }

    /// Read all bytes of single blob.
    ///
    /// This allocates a buffer for the full blob. Use only if you know that the blob you're
    /// reading is small. If not sure, use [`Self::read`] and check the size with
    /// [`BlobReader::size`] before calling [`BlobReader::read_to_bytes`].
    pub async fn read_to_bytes(&self, hash: Hash) -> Result<Bytes> {
        BlobReader::from_rpc(&self.rpc, hash)
            .await?
            .read_to_bytes()
            .await
    }

    /// Import a blob from a filesystem path.
    ///
    /// `path` should be an absolute path valid for the file system on which
    /// the node runs.
    /// If `in_place` is true, Iroh will assume that the data will not change and will share it in
    /// place without copying to the Iroh data directory.
    pub async fn add_from_path(
        &self,
        path: PathBuf,
        in_place: bool,
        tag: SetTagOption,
        wrap: WrapOption,
    ) -> Result<BlobAddProgress> {
        let stream = self
            .rpc
            .server_streaming(BlobAddPathRequest {
                path,
                in_place,
                tag,
                wrap,
            })
            .await?;
        Ok(BlobAddProgress::new(stream))
    }

    /// Write a blob by passing an async reader.
    pub async fn add_reader(
        &self,
        reader: impl AsyncRead + Unpin + Send + 'static,
        tag: SetTagOption,
    ) -> anyhow::Result<BlobAddProgress> {
        const CAP: usize = 1024 * 64; // send 64KB per request by default
        let (mut sink, progress) = self.rpc.bidi(BlobAddStreamRequest { tag }).await?;

        let input = ReaderStream::with_capacity(reader, CAP);
        let mut input = input.map(|chunk| match chunk {
            Ok(chunk) => Ok(BlobAddStreamUpdate::Chunk(chunk)),
            Err(err) => {
                warn!("Abort send, reason: failed to read from source stream: {err:?}");
                Ok(BlobAddStreamUpdate::Abort)
            }
        });

        tokio::spawn(async move {
            // TODO: Is it important to catch this error? It should also result in an error on the
            // response stream. If we deem it important, we could one-shot send it into the
            // BlobAddProgress and return from there. Not sure.
            if let Err(err) = sink.send_all(&mut input).await {
                warn!("Failed to send input stream to remote: {err:?}");
            }
        });

        Ok(BlobAddProgress::new(progress))
    }

    /// Write a blob by passing bytes.
    pub async fn add_bytes(
        &self,
        bytes: Bytes,
        tag: SetTagOption,
    ) -> anyhow::Result<BlobAddOutcome> {
        self.add_reader(Cursor::new(bytes), tag)
            .await?
            .finish()
            .await
    }

    /// Validate hashes on the running node.
    ///
    /// If `repair` is true, repair the store by removing invalid data.
    pub async fn validate(
        &self,
        repair: bool,
    ) -> Result<impl Stream<Item = Result<ValidateProgress>>> {
        let stream = self
            .rpc
            .server_streaming(BlobValidateRequest { repair })
            .await?;
        Ok(stream.map_err(anyhow::Error::from))
    }

    /// Download a blob from another node and add it to the local database.
    pub async fn download(
        &self,
        req: BlobDownloadRequest,
    ) -> Result<impl Stream<Item = Result<DownloadProgress>>> {
        let stream = self.rpc.server_streaming(req).await?;
        Ok(stream.map_err(anyhow::Error::from))
    }

    /// List all complete blobs.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<BlobListResponse>>> {
        let stream = self.rpc.server_streaming(BlobListRequest).await?;
        Ok(stream.map_err(anyhow::Error::from))
    }

    /// List all incomplete (partial) blobs.
    pub async fn list_incomplete(
        &self,
    ) -> Result<impl Stream<Item = Result<BlobListIncompleteResponse>>> {
        let stream = self.rpc.server_streaming(BlobListIncompleteRequest).await?;
        Ok(stream.map_err(anyhow::Error::from))
    }

    /// List all collections.
    pub async fn list_collections(
        &self,
    ) -> Result<impl Stream<Item = Result<BlobListCollectionsResponse>>> {
        let stream = self
            .rpc
            .server_streaming(BlobListCollectionsRequest)
            .await?;
        Ok(stream.map_err(anyhow::Error::from))
    }

    /// Delete a blob.
    pub async fn delete_blob(&self, hash: Hash) -> Result<()> {
        self.rpc.rpc(BlobDeleteBlobRequest { hash }).await??;
        Ok(())
    }
}

/// Outcome of a blob add operation.
#[derive(Debug, Clone)]
pub struct BlobAddOutcome {
    /// The hash of the blob
    pub hash: Hash,
    /// The format the blob
    pub format: BlobFormat,
    /// The size of the blob
    pub size: u64,
    /// The tag of the blob
    pub tag: Tag,
}

/// Progress stream for blob add operations.
#[derive(derive_more::Debug)]
pub struct BlobAddProgress {
    #[debug(skip)]
    stream: Pin<Box<dyn Stream<Item = Result<AddProgress>> + Send + Unpin + 'static>>,
}

impl BlobAddProgress {
    fn new(
        stream: (impl Stream<Item = Result<impl Into<AddProgress>, impl Into<anyhow::Error>>>
             + Send
             + Unpin
             + 'static),
    ) -> Self {
        let stream = stream.map(|item| match item {
            Ok(item) => Ok(item.into()),
            Err(err) => Err(err.into()),
        });
        Self {
            stream: Box::pin(stream),
        }
    }
    /// Finish writing the stream, ignoring all intermediate progress events.
    ///
    /// Returns a [`BlobAddOutcome`] which contains a tag, format, hash and a size.
    /// When importing a single blob, this is the hash and size of that blob.
    /// When importing a collection, the hash is the hash of the collection and the size
    /// is the total size of all imported blobs (but excluding the size of the collection blob
    /// itself).
    pub async fn finish(mut self) -> Result<BlobAddOutcome> {
        let mut total_size = 0;
        while let Some(msg) = self.next().await {
            match msg? {
                AddProgress::Found { size, .. } => {
                    total_size += size;
                }
                AddProgress::AllDone { hash, format, tag } => {
                    let outcome = BlobAddOutcome {
                        hash,
                        format,
                        tag,
                        size: total_size,
                    };
                    return Ok(outcome);
                }
                AddProgress::Abort(err) => return Err(err.into()),
                AddProgress::Progress { .. } => {}
                AddProgress::Done { .. } => {}
            }
        }
        Err(anyhow!("Response stream ended prematurely"))
    }
}

impl Stream for BlobAddProgress {
    type Item = Result<AddProgress>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.poll_next_unpin(cx)
    }
}

/// Data reader for a single blob.
///
/// Implements [`AsyncRead`].
#[derive(derive_more::Debug)]
pub struct BlobReader {
    size: u64,
    is_complete: bool,
    #[debug("StreamReader")]
    stream: tokio_util::io::StreamReader<BoxStream<'static, io::Result<Bytes>>, Bytes>,
}
impl BlobReader {
    fn new(size: u64, is_complete: bool, stream: BoxStream<'static, io::Result<Bytes>>) -> Self {
        Self {
            size,
            is_complete,
            stream: StreamReader::new(stream),
        }
    }

    async fn from_rpc<C: ServiceConnection<ProviderService>>(
        rpc: &RpcClient<ProviderService, C>,
        hash: Hash,
    ) -> anyhow::Result<Self> {
        let stream = rpc.server_streaming(BlobReadRequest { hash }).await?;
        let mut stream = flatten(stream);

        let (size, is_complete) = match stream.next().await {
            Some(Ok(BlobReadResponse::Entry { size, is_complete })) => (size, is_complete),
            Some(Err(err)) => return Err(err),
            None | Some(Ok(_)) => return Err(anyhow!("Expected header frame")),
        };

        let stream = stream.map(|item| match item {
            Ok(BlobReadResponse::Data { chunk }) => Ok(chunk),
            Ok(_) => Err(io::Error::new(io::ErrorKind::Other, "Expected data frame")),
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, format!("{err}"))),
        });
        Ok(Self::new(size, is_complete, stream.boxed()))
    }

    /// Total size of this blob.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether this blob has been downloaded completely.
    ///
    /// Returns false for partial blobs for which some chunks are missing.
    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    /// Read all bytes of the blob.
    pub async fn read_to_bytes(&mut self) -> anyhow::Result<Bytes> {
        let mut buf = Vec::with_capacity(self.size() as usize);
        self.read_to_end(&mut buf).await?;
        Ok(buf.into())
    }
}

impl AsyncRead for BlobReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

/// Document handle
#[derive(Debug, Clone)]
pub struct Doc<C: ServiceConnection<ProviderService>>(Arc<DocInner<C>>);

#[derive(Debug)]
struct DocInner<C: ServiceConnection<ProviderService>> {
    id: NamespaceId,
    rpc: RpcClient<ProviderService, C>,
    closed: AtomicBool,
    rt: runtime::Handle,
}

impl<C> Drop for DocInner<C>
where
    C: ServiceConnection<ProviderService>,
{
    fn drop(&mut self) {
        let doc_id = self.id;
        let rpc = self.rpc.clone();
        self.rt.main().spawn(async move {
            rpc.rpc(DocCloseRequest { doc_id }).await.ok();
        });
    }
}

impl<C> Doc<C>
where
    C: ServiceConnection<ProviderService>,
{
    fn new(rt: runtime::Handle, rpc: RpcClient<ProviderService, C>, id: NamespaceId) -> Self {
        Self(Arc::new(DocInner {
            rpc,
            id,
            closed: AtomicBool::new(false),
            rt,
        }))
    }

    async fn rpc<M>(&self, msg: M) -> Result<M::Response>
    where
        M: RpcMsg<ProviderService>,
    {
        let res = self.0.rpc.rpc(msg).await?;
        Ok(res)
    }

    /// Get the document id of this doc.
    pub fn id(&self) -> NamespaceId {
        self.0.id
    }

    /// Close the document.
    pub async fn close(&self) -> Result<()> {
        self.0.closed.store(true, Ordering::Release);
        self.rpc(DocCloseRequest { doc_id: self.id() }).await??;
        Ok(())
    }

    fn ensure_open(&self) -> Result<()> {
        if self.0.closed.load(Ordering::Acquire) {
            Err(anyhow!("document is closed"))
        } else {
            Ok(())
        }
    }

    /// Set the content of a key to a byte array.
    pub async fn set_bytes(
        &self,
        author_id: AuthorId,
        key: impl Into<Bytes>,
        value: impl Into<Bytes>,
    ) -> Result<Hash> {
        self.ensure_open()?;
        let res = self
            .rpc(DocSetRequest {
                doc_id: self.id(),
                author_id,
                key: key.into(),
                value: value.into(),
            })
            .await??;
        Ok(res.entry.content_hash())
    }

    /// Set an entries on the doc via its key, hash, and size.
    pub async fn set_hash(
        &self,
        author_id: AuthorId,
        key: impl Into<Bytes>,
        hash: Hash,
        size: u64,
    ) -> Result<()> {
        self.ensure_open()?;
        self.rpc(DocSetHashRequest {
            doc_id: self.id(),
            author_id,
            key: key.into(),
            hash,
            size,
        })
        .await??;
        Ok(())
    }

    /// Read the content of an [`Entry`] as a streaming [`BlobReader`].
    pub async fn read(&self, entry: &Entry) -> Result<BlobReader> {
        self.ensure_open()?;
        BlobReader::from_rpc(&self.0.rpc, entry.content_hash()).await
    }

    /// Read all content of an [`Entry`] into a buffer.
    pub async fn read_to_bytes(&self, entry: &Entry) -> Result<Bytes> {
        self.ensure_open()?;
        BlobReader::from_rpc(&self.0.rpc, entry.content_hash())
            .await?
            .read_to_bytes()
            .await
    }

    /// Delete entries that match the given `author` and key `prefix`.
    ///
    /// This inserts an empty entry with the key set to `prefix`, effectively clearing all other
    /// entries whose key starts with or is equal to the given `prefix`.
    ///
    /// Returns the number of entries deleted.
    pub async fn del(&self, author_id: AuthorId, prefix: impl Into<Bytes>) -> Result<usize> {
        self.ensure_open()?;
        let res = self
            .rpc(DocDelRequest {
                doc_id: self.id(),
                author_id,
                prefix: prefix.into(),
            })
            .await??;
        let DocDelResponse { removed } = res;
        Ok(removed)
    }

    /// Get the latest entry for a key and author.
    pub async fn get_one(&self, author: AuthorId, key: impl Into<Bytes>) -> Result<Option<Entry>> {
        self.ensure_open()?;
        let res = self
            .rpc(DocGetOneRequest {
                author,
                key: key.into(),
                doc_id: self.id(),
            })
            .await??;
        Ok(res.entry.map(|entry| entry.into()))
    }

    /// Get entries.
    pub async fn get_many(&self, filter: GetFilter) -> Result<impl Stream<Item = Result<Entry>>> {
        self.ensure_open()?;
        let stream = self
            .0
            .rpc
            .server_streaming(DocGetManyRequest {
                doc_id: self.id(),
                filter,
            })
            .await?;
        Ok(flatten(stream).map_ok(|res| res.entry.into()))
    }

    /// Share this document with peers over a ticket.
    pub async fn share(&self, mode: ShareMode) -> anyhow::Result<DocTicket> {
        self.ensure_open()?;
        let res = self
            .rpc(DocShareRequest {
                doc_id: self.id(),
                mode,
            })
            .await??;
        Ok(res.0)
    }

    /// Start to sync this document with a list of peers.
    pub async fn start_sync(&self, peers: Vec<NodeAddr>) -> Result<()> {
        self.ensure_open()?;
        let _res = self
            .rpc(DocStartSyncRequest {
                doc_id: self.id(),
                peers,
            })
            .await??;
        Ok(())
    }

    /// Stop the live sync for this document.
    pub async fn leave(&self) -> Result<()> {
        self.ensure_open()?;
        let _res = self.rpc(DocLeaveRequest { doc_id: self.id() }).await??;
        Ok(())
    }

    /// Subscribe to events for this document.
    pub async fn subscribe(&self) -> anyhow::Result<impl Stream<Item = anyhow::Result<LiveEvent>>> {
        self.ensure_open()?;
        let stream = self
            .0
            .rpc
            .server_streaming(DocSubscribeRequest { doc_id: self.id() })
            .await?;
        Ok(flatten(stream).map_ok(|res| res.event).map_err(Into::into))
    }

    /// Get status info for this document
    pub async fn status(&self) -> anyhow::Result<OpenState> {
        self.ensure_open()?;
        let res = self.rpc(DocStatusRequest { doc_id: self.id() }).await??;
        Ok(res.status)
    }
}

fn flatten<T, E1, E2>(
    s: impl Stream<Item = StdResult<StdResult<T, E1>, E2>>,
) -> impl Stream<Item = Result<T>>
where
    E1: std::error::Error + Send + Sync + 'static,
    E2: std::error::Error + Send + Sync + 'static,
{
    s.map(|res| match res {
        Ok(Ok(res)) => Ok(res),
        Ok(Err(err)) => Err(err.into()),
        Err(err) => Err(err.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use iroh_bytes::util::runtime;

    #[tokio::test]
    async fn test_drop_doc_client_sync() -> Result<()> {
        let db = iroh_bytes::store::readonly_mem::Store::default();
        let doc_store = iroh_sync::store::memory::Store::default();
        let rt = runtime::Handle::from_current(1)?;
        let node = crate::node::Node::builder(db, doc_store)
            .runtime(&rt)
            .spawn()
            .await?;

        let client = node.client();
        let doc = client.docs.create().await?;

        let res = std::thread::spawn(move || {
            drop(doc);
            drop(client);
            drop(node);
        });

        tokio::task::spawn_blocking(move || res.join().map_err(|e| anyhow::anyhow!("{:?}", e)))
            .await??;

        Ok(())
    }
}
