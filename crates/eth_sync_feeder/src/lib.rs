//! Minimal sync client core for pulling state updates from reth-like sources
//! and publishing them into `eth_privatestate` admin RPC.
//!
use std::error::Error as StdError;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;

use eth_privatestate::state::MissingProofQuery;

pub mod admin_rpc_sink;
pub mod reth_rpc_source;
pub mod reth_source;

/// Boxed future used by source and sink trait methods.
pub type FeederFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Minimal block identity used for reverted/orphan notifications.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRef {
  /// Canonical block number.
  pub number: u64,
  /// `0x`-prefixed canonical block hash.
  pub hash_hex: String,
}

/// Block payload published by the feeder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDelta {
  /// Canonical block number.
  pub number: u64,
  /// `0x`-prefixed canonical block hash.
  pub hash_hex: String,
  /// `0x`-prefixed post-state root.
  pub state_root_hex: String,
  /// Full RLP-encoded trie nodes touched by this block.
  pub changed_trie_nodes_rlp: Vec<Vec<u8>>,
}

/// Canonical chain notifications consumed by the feeder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainUpdate {
  /// New canonical blocks.
  Committed(Vec<BlockDelta>),
  /// Canonical reorg replacing `old_chain` with `new_chain`.
  Reorg {
    /// Previous canonical segment.
    old_chain: Vec<BlockRef>,
    /// Replacement canonical segment.
    new_chain: Vec<BlockDelta>,
  },
  /// Canonical rollback without replacement in the same update.
  Reverted(Vec<BlockRef>),
}

/// Source side contract expected from a reth-backed sync adapter.
///
/// - `initial_state_blocks`: startup snapshot
/// - `next_update`: live committed/reorg/reverted updates
/// - `fetch_missing_proof_nodes`: on-demand missing-proof backfill
///
/// Important: this source is expected to emit trie-node preimages directly
/// from execution-client state/trie update facilities (for example reth ExEx
/// notifications or execution witness APIs). It is not intended to scan all
/// chain accounts every block.
pub trait RethSyncSource {
  /// Source-specific error type.
  type Error: StdError + Send + Sync + 'static;

  /// Returns initial canonical state blocks to seed the node at startup.
  fn initial_state_blocks(&mut self) -> FeederFuture<'_, Result<Vec<BlockDelta>, Self::Error>>;

  /// Returns the next canonical update or `None` when stream is exhausted.
  fn next_update(&mut self) -> FeederFuture<'_, Result<Option<ChainUpdate>, Self::Error>>;

  /// Fetches proof nodes for one missing `(address, storage_keys, block)` query.
  fn fetch_missing_proof_nodes(
    &mut self,
    query: MissingProofQuery,
  ) -> FeederFuture<'_, Result<Vec<Vec<u8>>, Self::Error>>;
}

/// Consumer side contract: publishes updates into `eth_privatestate` admin API.
pub trait AdminSink {
  /// Sink-specific error type.
  type Error: StdError + Send + Sync + 'static;

  /// Publishes one touched trie node as `0x`-hex RLP.
  fn submit_node_rlp_hex(&mut self, node_hex: String) -> FeederFuture<'_, Result<(), Self::Error>>;

  /// Publishes `block_hash -> state_root`.
  fn set_root_by_hash(
    &mut self,
    block_hash_hex: String,
    state_root_hex: String,
  ) -> FeederFuture<'_, Result<(), Self::Error>>;

  /// Publishes `block_number -> state_root`.
  fn set_root_by_number(
    &mut self,
    block_number: u64,
    state_root_hex: String,
  ) -> FeederFuture<'_, Result<(), Self::Error>>;

  /// Atomically takes and clears server-side missing-proof queue.
  fn take_missing_proof_queries(
    &mut self,
  ) -> FeederFuture<'_, Result<Vec<MissingProofQuery>, Self::Error>>;

  /// Publishes all node/root updates for one block.
  fn publish_block_delta<'a>(
    &'a mut self,
    block: &'a BlockDelta,
    publish_root_by_number: bool,
  ) -> FeederFuture<'a, Result<(), Self::Error>>
  where
    Self: Send,
  {
    Box::pin(async move {
      for node in &block.changed_trie_nodes_rlp {
        let node_hex = format!("0x{}", hex::encode(node));
        self.submit_node_rlp_hex(node_hex).await?;
      }

      self.set_root_by_hash(block.hash_hex.clone(), block.state_root_hex.clone()).await?;
      if publish_root_by_number {
        self.set_root_by_number(block.number, block.state_root_hex.clone()).await?;
      }
      Ok(())
    })
  }
}

/// Backfill operation result.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MissingNodeBackfillResult {
  /// Number of nodes successfully fetched from source and published to sink.
  pub published: u64,
  /// Number of grouped `eth_getProof` requests issued to source.
  pub proof_requests: u64,
  /// Number of grouped requests where source returned no proof nodes.
  pub unresolved_queries: u64,
}

/// Sync runner that wires a reth source to an admin sink.
pub struct RethSyncClient<S, K> {
  source: S,
  sink: K,
  publish_root_by_number: bool,
}

impl<S, K> RethSyncClient<S, K> {
  /// Creates a sync client.
  pub fn new(source: S, sink: K, publish_root_by_number: bool) -> Self {
    Self { source, sink, publish_root_by_number }
  }

  /// Splits the client back into source and sink.
  pub fn into_parts(self) -> (S, K) {
    (self.source, self.sink)
  }
}

impl<S, K> RethSyncClient<S, K>
where
  S: RethSyncSource,
  K: AdminSink + Send,
{
  /// Runs startup bootstrap by publishing initial state blocks from source.
  pub async fn sync_initial_state(&mut self) -> Result<u64, SyncError<S::Error, K::Error>> {
    let mut published = 0u64;
    loop {
      let blocks = self.source.initial_state_blocks().await.map_err(SyncError::Source)?;
      if blocks.is_empty() {
        break;
      }
      for block in blocks {
        self.publish_block(&block).await?;
        published = published.saturating_add(1);
      }
    }
    Ok(published)
  }

  /// Processes at most one live update.
  /// Returns `Ok(false)` when the source stream is exhausted.
  pub async fn sync_next_update(&mut self) -> Result<bool, SyncError<S::Error, K::Error>> {
    let maybe_update = self.source.next_update().await.map_err(SyncError::Source)?;
    let update = match maybe_update {
      Some(v) => v,
      None => return Ok(false),
    };

    let blocks = match update {
      ChainUpdate::Committed(blocks) => blocks,
      ChainUpdate::Reorg { old_chain: _, new_chain } => new_chain,
      ChainUpdate::Reverted(_) => Vec::new(),
    };

    for block in blocks {
      self.publish_block(&block).await?;
    }
    Ok(true)
  }

  /// Processes live updates until source returns `None`.
  pub async fn sync_updates_until_exhausted(
    &mut self,
  ) -> Result<u64, SyncError<S::Error, K::Error>> {
    let mut updates = 0u64;
    while self.sync_next_update().await? {
      updates = updates.saturating_add(1);
    }
    Ok(updates)
  }

  /// Fetches and publishes missing proof nodes from source by query.
  pub async fn backfill_missing_nodes(
    &mut self,
    missing_queries: Vec<MissingProofQuery>,
  ) -> Result<MissingNodeBackfillResult, SyncError<S::Error, K::Error>> {
    let mut out = MissingNodeBackfillResult::default();

    for query in missing_queries {
      out.proof_requests = out.proof_requests.saturating_add(1);
      let nodes = self.source.fetch_missing_proof_nodes(query).await.map_err(SyncError::Source)?;
      if nodes.is_empty() {
        out.unresolved_queries = out.unresolved_queries.saturating_add(1);
        continue;
      }
      for node_rlp in nodes {
        self
          .sink
          .submit_node_rlp_hex(format!("0x{}", hex::encode(node_rlp)))
          .await
          .map_err(SyncError::Sink)?;
        out.published = out.published.saturating_add(1);
      }
    }

    Ok(out)
  }

  /// Polls sink for missing-proof queries and backfills them from source.
  pub async fn sync_missing_nodes_once(
    &mut self,
  ) -> Result<MissingNodeBackfillResult, SyncError<S::Error, K::Error>> {
    let missing_queries = self.sink.take_missing_proof_queries().await.map_err(SyncError::Sink)?;
    if missing_queries.is_empty() {
      return Ok(MissingNodeBackfillResult::default());
    }
    self.backfill_missing_nodes(missing_queries).await
  }

  async fn publish_block(
    &mut self,
    block: &BlockDelta,
  ) -> Result<(), SyncError<S::Error, K::Error>> {
    self.sink.publish_block_delta(block, self.publish_root_by_number).await.map_err(SyncError::Sink)
  }
}

/// Error returned by sync execution.
#[derive(Debug)]
pub enum SyncError<S, K> {
  /// Error from reth source adapter.
  Source(S),
  /// Error from admin sink.
  Sink(K),
}

impl<S, K> Display for SyncError<S, K>
where
  S: Display,
  K: Display,
{
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Source(err) => write!(f, "source error: {}", err),
      Self::Sink(err) => write!(f, "sink error: {}", err),
    }
  }
}

impl<S, K> StdError for SyncError<S, K>
where
  S: StdError + 'static,
  K: StdError + 'static,
{
}

#[cfg(test)]
mod tests {
  use super::*;
  use eth_privatestate::state::MissingBlockId;
  use std::collections::{HashMap, VecDeque};

  #[derive(Debug)]
  struct FakeError(&'static str);

  impl Display for FakeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
      write!(f, "{}", self.0)
    }
  }

  impl StdError for FakeError {}

  #[derive(Default)]
  struct FakeRethSource {
    initial: Vec<BlockDelta>,
    initial_served: bool,
    updates: VecDeque<ChainUpdate>,
    missing_nodes_by_query: HashMap<(String, MissingBlockId), Vec<Vec<u8>>>,
    seen_missing_queries: Vec<MissingProofQuery>,
  }

  impl FakeRethSource {
    fn with_initial(blocks: Vec<BlockDelta>) -> Self {
      Self { initial: blocks, ..Self::default() }
    }

    fn with_updates(updates: Vec<ChainUpdate>) -> Self {
      Self { updates: VecDeque::from(updates), ..Self::default() }
    }

    fn with_missing_query_nodes(mut self, entries: Vec<(MissingProofQuery, Vec<Vec<u8>>)>) -> Self {
      for (query, nodes) in entries {
        self.missing_nodes_by_query.insert((query.address, query.block), nodes);
      }
      self
    }
  }

  impl RethSyncSource for FakeRethSource {
    type Error = FakeError;

    fn initial_state_blocks(&mut self) -> FeederFuture<'_, Result<Vec<BlockDelta>, Self::Error>> {
      Box::pin(async move {
        if self.initial_served {
          return Ok(Vec::new());
        }
        self.initial_served = true;
        Ok(std::mem::take(&mut self.initial))
      })
    }

    fn next_update(&mut self) -> FeederFuture<'_, Result<Option<ChainUpdate>, Self::Error>> {
      Box::pin(async move { Ok(self.updates.pop_front()) })
    }

    fn fetch_missing_proof_nodes(
      &mut self,
      query: MissingProofQuery,
    ) -> FeederFuture<'_, Result<Vec<Vec<u8>>, Self::Error>> {
      Box::pin(async move {
        self.seen_missing_queries.push(query.clone());
        let key = (query.address, query.block);
        Ok(self.missing_nodes_by_query.get(&key).cloned().unwrap_or_default())
      })
    }
  }

  #[derive(Default)]
  struct FakeSink {
    submitted_nodes: Vec<String>,
    roots_by_hash: Vec<(String, String)>,
    roots_by_number: Vec<(u64, String)>,
    missing_queries_queue: Vec<MissingProofQuery>,
  }

  impl AdminSink for FakeSink {
    type Error = FakeError;

    fn submit_node_rlp_hex(
      &mut self,
      node_hex: String,
    ) -> FeederFuture<'_, Result<(), Self::Error>> {
      Box::pin(async move {
        self.submitted_nodes.push(node_hex);
        Ok(())
      })
    }

    fn set_root_by_hash(
      &mut self,
      block_hash_hex: String,
      state_root_hex: String,
    ) -> FeederFuture<'_, Result<(), Self::Error>> {
      Box::pin(async move {
        self.roots_by_hash.push((block_hash_hex, state_root_hex));
        Ok(())
      })
    }

    fn set_root_by_number(
      &mut self,
      block_number: u64,
      state_root_hex: String,
    ) -> FeederFuture<'_, Result<(), Self::Error>> {
      Box::pin(async move {
        self.roots_by_number.push((block_number, state_root_hex));
        Ok(())
      })
    }

    fn take_missing_proof_queries(
      &mut self,
    ) -> FeederFuture<'_, Result<Vec<MissingProofQuery>, Self::Error>> {
      Box::pin(async move { Ok(std::mem::take(&mut self.missing_queries_queue)) })
    }
  }

  fn block_delta(number: u64, hash_hex: &str, root_hex: &str, nodes: &[&[u8]]) -> BlockDelta {
    BlockDelta {
      number,
      hash_hex: hash_hex.to_string(),
      state_root_hex: root_hex.to_string(),
      changed_trie_nodes_rlp: nodes.iter().map(|n| n.to_vec()).collect(),
    }
  }

  #[tokio::test]
  async fn startup_sync_publishes_initial_blocks() {
    let source = FakeRethSource::with_initial(vec![
      block_delta(1, "0x01", "0xaa", &[b"\x01"]),
      block_delta(2, "0x02", "0xbb", &[b"\x02"]),
    ]);
    let sink = FakeSink::default();
    let mut client = RethSyncClient::new(source, sink, true);

    let n = client.sync_initial_state().await.unwrap();
    assert_eq!(n, 2);

    let (_, sink) = client.into_parts();
    assert_eq!(sink.submitted_nodes, vec!["0x01".to_string(), "0x02".to_string()]);
    assert_eq!(
      sink.roots_by_hash,
      vec![("0x01".to_string(), "0xaa".to_string()), ("0x02".to_string(), "0xbb".to_string())]
    );
    assert_eq!(sink.roots_by_number, vec![(1, "0xaa".to_string()), (2, "0xbb".to_string())]);
  }

  #[tokio::test]
  async fn live_sync_processes_committed_and_reorg_new_chain() {
    let source = FakeRethSource::with_updates(vec![
      ChainUpdate::Committed(vec![block_delta(10, "0x10", "0xa0", &[b"\x10"])]),
      ChainUpdate::Reorg {
        old_chain: vec![BlockRef { number: 11, hash_hex: "0xold".to_string() }],
        new_chain: vec![
          block_delta(11, "0x11", "0xb1", &[b"\x11"]),
          block_delta(12, "0x12", "0xb2", &[b"\x12"]),
        ],
      },
      ChainUpdate::Reverted(vec![BlockRef { number: 13, hash_hex: "0x13".to_string() }]),
    ]);
    let sink = FakeSink::default();
    let mut client = RethSyncClient::new(source, sink, false);

    let updates = client.sync_updates_until_exhausted().await.unwrap();
    assert_eq!(updates, 3);

    let (_, sink) = client.into_parts();
    assert_eq!(
      sink.submitted_nodes,
      vec!["0x10".to_string(), "0x11".to_string(), "0x12".to_string()]
    );
    assert_eq!(
      sink.roots_by_hash,
      vec![
        ("0x10".to_string(), "0xa0".to_string()),
        ("0x11".to_string(), "0xb1".to_string()),
        ("0x12".to_string(), "0xb2".to_string()),
      ]
    );
    assert!(sink.roots_by_number.is_empty());
  }

  #[tokio::test]
  async fn backfill_missing_nodes_fetches_from_source() {
    let q1 = MissingProofQuery {
      address: "0x1111111111111111111111111111111111111111".to_string(),
      storage_keys: vec!["0x01".to_string()],
      block: MissingBlockId::Number(12),
    };
    let q2 = MissingProofQuery {
      address: "0x1111111111111111111111111111111111111111".to_string(),
      storage_keys: vec!["0x03".to_string()],
      block: MissingBlockId::Number(13),
    };

    let source = FakeRethSource::default().with_missing_query_nodes(vec![
      (q1.clone(), vec![vec![0x01u8, 0x02u8], vec![0x03u8]]),
      (q2.clone(), Vec::new()),
    ]);
    let sink = FakeSink::default();
    let mut client = RethSyncClient::new(source, sink, false);

    let result = client.backfill_missing_nodes(vec![q1.clone(), q2]).await.unwrap();

    assert_eq!(result.published, 2);
    assert_eq!(result.proof_requests, 2);
    assert_eq!(result.unresolved_queries, 1);

    let (source, sink) = client.into_parts();
    assert_eq!(sink.submitted_nodes, vec!["0x0102".to_string(), "0x03".to_string()]);
    assert_eq!(source.seen_missing_queries.len(), 2);
  }

  #[tokio::test]
  async fn sync_missing_nodes_once_polls_sink_and_backfills() {
    let query = MissingProofQuery {
      address: "0x2222222222222222222222222222222222222222".to_string(),
      storage_keys: vec!["0x0a".to_string()],
      block: MissingBlockId::Number(22),
    };
    let source =
      FakeRethSource::default().with_missing_query_nodes(vec![(query.clone(), vec![vec![0x0a]])]);
    let sink = FakeSink { missing_queries_queue: vec![query], ..FakeSink::default() };
    let mut client = RethSyncClient::new(source, sink, false);

    let result = client.sync_missing_nodes_once().await.unwrap();
    assert_eq!(result.published, 1);
    assert_eq!(result.proof_requests, 1);
    assert_eq!(result.unresolved_queries, 0);

    let (_, sink) = client.into_parts();
    assert_eq!(sink.submitted_nodes, vec!["0x0a".to_string()]);
    assert!(sink.missing_queries_queue.is_empty());
  }
}
