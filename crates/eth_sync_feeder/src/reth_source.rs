//! Reth-oriented source adapter for feeder sync.
//!
//! This module defines a narrow provider contract where block updates arrive as
//! changed trie-node RLP plus block identity/root. Missing-node backfill is
//! handled via direct `(address, storage_keys, block)` proof queries.

use std::error::Error as StdError;
use std::fmt::{Display, Formatter};

use eth_privatestate::state::MissingProofQuery;

use crate::{BlockDelta, BlockRef, ChainUpdate, FeederFuture, RethSyncSource};

/// One canonical block payload produced by a reth-facing provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RethBlockBundle {
  /// Canonical block number.
  pub number: u64,
  /// Canonical block hash (`0x` hex).
  pub hash_hex: String,
  /// Post-state root (`0x` hex).
  pub state_root_hex: String,
  /// Changed trie nodes in this block as raw RLP.
  pub changed_trie_nodes_rlp: Vec<Vec<u8>>,
}

/// Canonical notifications from reth source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RethNotification {
  /// Newly committed canonical blocks.
  Committed(Vec<RethBlockBundle>),
  /// Canonical reorg where `old_chain` is replaced by `new_chain`.
  Reorg {
    /// Previous canonical segment.
    old_chain: Vec<BlockRef>,
    /// New canonical segment.
    new_chain: Vec<RethBlockBundle>,
  },
  /// Canonical revert without replacement in the same notification.
  Reverted(Vec<BlockRef>),
}

/// Provider contract implemented by reth-facing code.
pub trait RethUpdateProvider {
  /// Provider-specific error.
  type Error: StdError + Send + Sync + 'static;

  /// Startup canonical block bundles.
  fn initial_block_bundles(
    &mut self,
  ) -> FeederFuture<'_, Result<Vec<RethBlockBundle>, Self::Error>>;

  /// Next canonical notification.
  fn next_notification(
    &mut self,
  ) -> FeederFuture<'_, Result<Option<RethNotification>, Self::Error>>;

  /// Fetches proof nodes for one missing-proof query.
  fn fetch_missing_proof_nodes(
    &mut self,
    query: MissingProofQuery,
  ) -> FeederFuture<'_, Result<Vec<Vec<u8>>, Self::Error>>;
}

/// Error wrapper used by `RethSourceAdapter`.
#[derive(Debug)]
pub enum RethSourceError<E> {
  /// Provider failure.
  Provider(E),
}

impl<E> Display for RethSourceError<E>
where
  E: Display,
{
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Provider(err) => write!(f, "provider error: {}", err),
    }
  }
}

impl<E> StdError for RethSourceError<E> where E: StdError + 'static {}

/// Adapter from `RethUpdateProvider` into `RethSyncSource`.
pub struct RethSourceAdapter<P> {
  provider: P,
}

impl<P> RethSourceAdapter<P> {
  /// Creates a new adapter.
  pub fn new(provider: P) -> Self {
    Self { provider }
  }

  /// Returns the wrapped provider.
  pub fn into_provider(self) -> P {
    self.provider
  }

  fn bundle_to_delta(bundle: RethBlockBundle) -> BlockDelta {
    BlockDelta {
      number: bundle.number,
      hash_hex: bundle.hash_hex,
      state_root_hex: bundle.state_root_hex,
      changed_trie_nodes_rlp: bundle.changed_trie_nodes_rlp,
    }
  }
}

impl<P> RethSyncSource for RethSourceAdapter<P>
where
  P: RethUpdateProvider + Send,
{
  type Error = RethSourceError<P::Error>;

  fn initial_state_blocks(&mut self) -> FeederFuture<'_, Result<Vec<BlockDelta>, Self::Error>> {
    Box::pin(async move {
      let bundles =
        self.provider.initial_block_bundles().await.map_err(RethSourceError::Provider)?;
      Ok(bundles.into_iter().map(Self::bundle_to_delta).collect())
    })
  }

  fn next_update(&mut self) -> FeederFuture<'_, Result<Option<ChainUpdate>, Self::Error>> {
    Box::pin(async move {
      let notification =
        self.provider.next_notification().await.map_err(RethSourceError::Provider)?;

      let update = notification.map(|notification| match notification {
        RethNotification::Committed(blocks) => {
          ChainUpdate::Committed(blocks.into_iter().map(Self::bundle_to_delta).collect())
        }
        RethNotification::Reorg { old_chain, new_chain } => ChainUpdate::Reorg {
          old_chain,
          new_chain: new_chain.into_iter().map(Self::bundle_to_delta).collect(),
        },
        RethNotification::Reverted(blocks) => ChainUpdate::Reverted(blocks),
      });

      Ok(update)
    })
  }

  fn fetch_missing_proof_nodes(
    &mut self,
    query: MissingProofQuery,
  ) -> FeederFuture<'_, Result<Vec<Vec<u8>>, Self::Error>> {
    Box::pin(async move {
      self.provider.fetch_missing_proof_nodes(query).await.map_err(RethSourceError::Provider)
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::{HashMap, VecDeque};

  use eth_privatestate::state::MissingBlockId;

  #[derive(Debug)]
  struct FakeError(&'static str);

  impl Display for FakeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
      write!(f, "{}", self.0)
    }
  }

  impl StdError for FakeError {}

  #[derive(Default)]
  struct FakeProvider {
    initial: Vec<RethBlockBundle>,
    notifications: VecDeque<RethNotification>,
    nodes_by_query: HashMap<(String, MissingBlockId), Vec<Vec<u8>>>,
    requested_queries: Vec<MissingProofQuery>,
  }

  impl RethUpdateProvider for FakeProvider {
    type Error = FakeError;

    fn initial_block_bundles(
      &mut self,
    ) -> FeederFuture<'_, Result<Vec<RethBlockBundle>, Self::Error>> {
      Box::pin(async move { Ok(self.initial.clone()) })
    }

    fn next_notification(
      &mut self,
    ) -> FeederFuture<'_, Result<Option<RethNotification>, Self::Error>> {
      Box::pin(async move { Ok(self.notifications.pop_front()) })
    }

    fn fetch_missing_proof_nodes(
      &mut self,
      query: MissingProofQuery,
    ) -> FeederFuture<'_, Result<Vec<Vec<u8>>, Self::Error>> {
      Box::pin(async move {
        self.requested_queries.push(query.clone());
        let key = (query.address, query.block);
        Ok(self.nodes_by_query.get(&key).cloned().unwrap_or_default())
      })
    }
  }

  #[tokio::test]
  async fn adapter_maps_bundles_and_forwards_missing_query() {
    let query = MissingProofQuery {
      address: "0x1111111111111111111111111111111111111111".to_string(),
      storage_keys: vec!["0x00".to_string()],
      block: MissingBlockId::Number(1),
    };
    let provider = FakeProvider {
      initial: vec![RethBlockBundle {
        number: 1,
        hash_hex: "0x11".to_string(),
        state_root_hex: "0xaa".to_string(),
        changed_trie_nodes_rlp: vec![vec![0x01u8, 0x02u8]],
      }],
      notifications: VecDeque::new(),
      nodes_by_query: HashMap::from([(
        (query.address.clone(), query.block.clone()),
        vec![vec![0x03u8]],
      )]),
      requested_queries: Vec::new(),
    };

    let mut adapter = RethSourceAdapter::new(provider);

    let initial = adapter.initial_state_blocks().await.unwrap();
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].changed_trie_nodes_rlp, vec![vec![0x01u8, 0x02u8]]);

    let fetched = adapter.fetch_missing_proof_nodes(query.clone()).await.unwrap();
    assert_eq!(fetched, vec![vec![0x03u8]]);

    let provider = adapter.into_provider();
    assert_eq!(provider.requested_queries, vec![query]);
  }

  #[tokio::test]
  async fn adapter_maps_reorg_and_revert_notifications() {
    let provider = FakeProvider {
      initial: Vec::new(),
      notifications: VecDeque::from(vec![
        RethNotification::Reorg {
          old_chain: vec![BlockRef { number: 10, hash_hex: "0xold".to_string() }],
          new_chain: vec![RethBlockBundle {
            number: 10,
            hash_hex: "0xnew".to_string(),
            state_root_hex: "0xroot".to_string(),
            changed_trie_nodes_rlp: vec![vec![0x99]],
          }],
        },
        RethNotification::Reverted(vec![BlockRef { number: 11, hash_hex: "0x11".to_string() }]),
      ]),
      nodes_by_query: HashMap::new(),
      requested_queries: Vec::new(),
    };

    let mut adapter = RethSourceAdapter::new(provider);

    let update_1 = adapter.next_update().await.unwrap().unwrap();
    match update_1 {
      ChainUpdate::Reorg { old_chain, new_chain } => {
        assert_eq!(old_chain, vec![BlockRef { number: 10, hash_hex: "0xold".to_string() }]);
        assert_eq!(new_chain.len(), 1);
        assert_eq!(new_chain[0].number, 10);
      }
      _ => panic!("expected reorg update"),
    }

    let update_2 = adapter.next_update().await.unwrap().unwrap();
    match update_2 {
      ChainUpdate::Reverted(old_chain) => {
        assert_eq!(old_chain, vec![BlockRef { number: 11, hash_hex: "0x11".to_string() }]);
      }
      _ => panic!("expected reverted update"),
    }
  }
}
