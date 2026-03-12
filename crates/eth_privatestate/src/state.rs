//! Shared state for the rpc service.
//!
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rostl_datastructures::map::UnsortedMap;
use rostl_primitives::traits::Cmov;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::authentication::{ApiKeyController, ApiKeyError};
use crate::{oblivious_node::ObliviousNode, types::B256};

#[derive(Clone, Debug, Serialize, Default)]
pub struct RpcMetrics {
  pub requests_total: u64,
  pub requests_ok: u64,
  pub requests_err: u64,

  pub errors_invalid_params: u64,
  pub errors_data_non_availability: u64,
  pub errors_traversal_cap_exceeded: u64,
  pub errors_other: u64,

  pub latency_count: u64,
  pub latency_total_us: u64,
  pub latency_max_us: u64,
  pub latency_avg_us: u64,
}

impl RpcMetrics {
  pub fn record_oblivious(&mut self, ok: bool, err_code: i32, latency_us: u64) {
    let one = 1u64;

    let mut inc_ok = 0u64;
    inc_ok.cmov(&one, ok);

    let mut inc_err = 0u64;
    inc_err.cmov(&one, !ok);

    let mut inc_invalid_params = 0u64;
    inc_invalid_params.cmov(&one, (!ok) & (err_code == -32602));

    let mut inc_data_unavailable = 0u64;
    inc_data_unavailable.cmov(&one, (!ok) & (err_code == -32001));

    let mut inc_traversal_cap = 0u64;
    inc_traversal_cap.cmov(&one, (!ok) & (err_code == -32002));

    let mut inc_other = 0u64;
    inc_other
      .cmov(&one, (!ok) & (err_code != -32602) & (err_code != -32001) & (err_code != -32002));

    self.requests_total = self.requests_total.saturating_add(1);
    self.requests_ok = self.requests_ok.saturating_add(inc_ok);
    self.requests_err = self.requests_err.saturating_add(inc_err);

    self.errors_invalid_params = self.errors_invalid_params.saturating_add(inc_invalid_params);
    self.errors_data_non_availability =
      self.errors_data_non_availability.saturating_add(inc_data_unavailable);
    self.errors_traversal_cap_exceeded =
      self.errors_traversal_cap_exceeded.saturating_add(inc_traversal_cap);
    self.errors_other = self.errors_other.saturating_add(inc_other);

    self.latency_count = self.latency_count.saturating_add(1);
    self.latency_total_us = self.latency_total_us.saturating_add(latency_us);
    self.latency_max_us.cmov(&latency_us, latency_us > self.latency_max_us);

    let mut denom = 1u64;
    denom.cmov(&self.latency_count, self.latency_count > 0);
    self.latency_avg_us = self.latency_total_us / denom;
  }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MissingBlockHashSelector {
  #[serde(rename = "blockHash")]
  pub block_hash: String,
  #[serde(rename = "requireCanonical")]
  pub require_canonical: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(untagged)]
pub enum MissingBlockId {
  Number(u64),
  BlockHash(MissingBlockHashSelector),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MissingProofQuery {
  pub address: String,
  pub storage_keys: Vec<String>,
  pub block: MissingBlockId,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct MissingProofGroupKey {
  address: String,
  block: MissingBlockId,
}

pub struct SharedState {
  pub storage: Arc<Mutex<UnsortedMap<B256, ObliviousNode>>>,
  /// block_number -> state_root
  pub roots_by_number: Arc<Mutex<UnsortedMap<u64, B256>>>,
  /// latest root set via `admin_set_root` (block_number, state_root)
  pub latest_root_by_number: Arc<Mutex<Option<(u64, B256)>>>,
  /// block_hash -> state_root
  pub roots_by_hash: Arc<Mutex<UnsortedMap<B256, B256>>>,
  /// NOTE(obliviousness): this cache is not secret-data-independent.
  /// It leaks block selector and duplicate status for `(address, block, storage_key)`
  /// via instruction and memory-access traces in map/set insertions.
  /// Missing proof queries grouped by `(address, block)` with deduped storage keys.
  missing_proof_queries: Arc<Mutex<HashMap<MissingProofGroupKey, HashSet<String>>>>,
  /// Runtime toggle for leaky error recovery (missing-proof queue/backfill path).
  pub leaky_error_recovery: bool,
  pub metrics: Arc<Mutex<RpcMetrics>>,
  pub api_keys: Arc<Mutex<ApiKeyController>>,
}

impl SharedState {
  pub fn new(cap: usize) -> Self {
    Self::new_with_admin_key_and_leaky_error_recovery(
      cap,
      "olabs-admin-dev-key-please-change".to_string(),
      true,
    )
  }

  pub fn new_with_admin_key(cap: usize, admin_api_key: String) -> Self {
    Self::new_with_admin_key_and_leaky_error_recovery(cap, admin_api_key, true)
  }

  pub fn new_with_admin_key_and_leaky_error_recovery(
    cap: usize,
    admin_api_key: String,
    leaky_error_recovery: bool,
  ) -> Self {
    Self {
      storage: Arc::new(Mutex::new(UnsortedMap::new(1 << 10))),
      roots_by_number: Arc::new(Mutex::new(UnsortedMap::new(cap))),
      latest_root_by_number: Arc::new(Mutex::new(None)),
      roots_by_hash: Arc::new(Mutex::new(UnsortedMap::new(cap))),
      missing_proof_queries: Arc::new(Mutex::new(HashMap::new())),
      leaky_error_recovery,
      metrics: Arc::new(Mutex::new(RpcMetrics::default())),
      api_keys: Arc::new(Mutex::new(ApiKeyController::new(admin_api_key))),
    }
  }

  pub async fn set_root(&self, block: u64, root: B256) {
    let mut guard = self.roots_by_number.lock().await;
    guard.insert(block, root);

    let mut latest_guard = self.latest_root_by_number.lock().await;
    let should_update =
      latest_guard.as_ref().map_or(true, |(latest_block, _)| block >= *latest_block);
    if should_update {
      *latest_guard = Some((block, root));
    }
  }

  // NOTE: We are leaking whether the root exists or not, this is acceptable as we don't care about hiding data in invalid requests.
  pub async fn get_root(&self, block: u64) -> Option<B256> {
    let mut guard = self.roots_by_number.lock().await;
    let mut ret = B256::zero();
    let v = guard.get(block, &mut ret);
    if v {
      Some(ret)
    } else {
      None
    }
  }

  pub async fn set_root_by_hash(&self, block_hash: B256, root: B256) {
    let mut guard = self.roots_by_hash.lock().await;
    guard.insert(block_hash, root);
  }

  // NOTE: We are leaking whether the root exists or not, this is acceptable as we don't care about hiding data in invalid requests.
  pub async fn get_root_by_hash(&self, block_hash: B256) -> Option<B256> {
    let mut guard = self.roots_by_hash.lock().await;
    let mut ret = B256::zero();
    let v = guard.get(block_hash, &mut ret);
    if v {
      Some(ret)
    } else {
      None
    }
  }

  pub async fn get_latest_root(&self) -> Option<B256> {
    self.latest_root_by_number.lock().await.as_ref().map(|(_, root)| *root)
  }

  pub async fn get_latest_root_with_number(&self) -> Option<(u64, B256)> {
    self.latest_root_by_number.lock().await.as_ref().copied()
  }

  pub async fn record_missing_proof_query(&self, query: MissingProofQuery) {
    if !self.leaky_error_recovery {
      return;
    }
    let mut guard = self.missing_proof_queries.lock().await;
    let key = MissingProofGroupKey { address: query.address, block: query.block };
    let entry = guard.entry(key).or_insert_with(HashSet::new);
    for storage_key in query.storage_keys {
      entry.insert(storage_key);
    }
  }

  pub async fn take_missing_proof_queries(&self) -> Vec<MissingProofQuery> {
    if !self.leaky_error_recovery {
      return Vec::new();
    }
    let mut guard = self.missing_proof_queries.lock().await;
    let groups = std::mem::take(&mut *guard);
    let mut out = Vec::with_capacity(groups.len());
    for (group, storage_keys) in groups {
      let mut keys: Vec<String> = storage_keys.into_iter().collect();
      keys.sort_unstable();
      out.push(MissingProofQuery {
        address: group.address,
        storage_keys: keys,
        block: group.block,
      });
    }
    out.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.block.cmp(&b.block)));
    out
  }

  pub async fn metrics_snapshot(&self) -> RpcMetrics {
    self.metrics.lock().await.clone()
  }

  pub async fn create_client_api_key(&self) -> String {
    self.api_keys.lock().await.create_key()
  }

  pub async fn add_tokens_to_api_key(&self, key: &str, tokens: u64) -> Result<(), ApiKeyError> {
    self.api_keys.lock().await.add_tokens(key, tokens)
  }

  pub async fn set_hourly_limit_for_api_key(
    &self,
    key: &str,
    hourly_limit: u64,
  ) -> Result<(), ApiKeyError> {
    self.api_keys.lock().await.set_hourly_limit(key, hourly_limit)
  }

  pub async fn disable_api_key(&self, key: &str) -> Result<(), ApiKeyError> {
    self.api_keys.lock().await.disable_key(key)
  }

  pub async fn delete_api_key(&self, key: &str) -> Result<(), ApiKeyError> {
    self.api_keys.lock().await.delete_key(key)
  }

  pub async fn authorize_public_api_key(&self, key: &str) -> Result<(), ApiKeyError> {
    self.api_keys.lock().await.authorize_public_request(key)
  }

  pub async fn authorize_admin_api_key(&self, key: &str) -> Result<(), ApiKeyError> {
    self.api_keys.lock().await.authorize_admin_request(key)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_set_and_get_root_by_number() {
    let state = SharedState::new(1 << 10);
    let root =
      B256::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();

    state.set_root(100, root).await;

    assert_eq!(state.get_root(100).await, Some(root));
    assert_eq!(state.get_root(101).await, None);
  }

  #[tokio::test]
  async fn test_set_and_get_root_by_hash() {
    let state = SharedState::new(1 << 10);
    let block_hash =
      B256::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let root =
      B256::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();

    state.set_root_by_hash(block_hash, root).await;

    assert_eq!(state.get_root_by_hash(block_hash).await, Some(root));
    assert_eq!(state.get_root_by_hash(B256([0x11; 32])).await, None);
  }

  #[tokio::test]
  async fn test_set_and_get_latest_root_by_number() {
    let state = SharedState::new(1 << 10);
    let root_100 =
      B256::from_hex("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
    let root_101 =
      B256::from_hex("2222222222222222222222222222222222222222222222222222222222222222").unwrap();
    let root_099 =
      B256::from_hex("3333333333333333333333333333333333333333333333333333333333333333").unwrap();

    assert_eq!(state.get_latest_root().await, None);

    state.set_root(100, root_100).await;
    assert_eq!(state.get_latest_root().await, Some(root_100));

    state.set_root(99, root_099).await;
    assert_eq!(state.get_latest_root().await, Some(root_100));

    state.set_root(101, root_101).await;
    assert_eq!(state.get_latest_root().await, Some(root_101));
  }

  #[tokio::test]
  async fn test_record_and_take_missing_proof_queries_merges_and_clears_queue() {
    let state = SharedState::new(1 << 10);
    let block = MissingBlockId::Number(42);
    state
      .record_missing_proof_query(MissingProofQuery {
        address: "0x1111111111111111111111111111111111111111".to_string(),
        storage_keys: vec!["0x01".to_string()],
        block: block.clone(),
      })
      .await;
    state
      .record_missing_proof_query(MissingProofQuery {
        address: "0x1111111111111111111111111111111111111111".to_string(),
        storage_keys: vec!["0x02".to_string()],
        block: block.clone(),
      })
      .await;
    state
      .record_missing_proof_query(MissingProofQuery {
        address: "0x1111111111111111111111111111111111111111".to_string(),
        storage_keys: vec!["0x01".to_string()],
        block,
      })
      .await;

    let taken = state.take_missing_proof_queries().await;
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].storage_keys, vec!["0x01".to_string(), "0x02".to_string()]);

    let taken_again = state.take_missing_proof_queries().await;
    assert!(taken_again.is_empty());
  }

  #[tokio::test]
  async fn test_leaky_error_recovery_disabled_does_not_store_queries() {
    let state = SharedState::new_with_admin_key_and_leaky_error_recovery(
      1 << 10,
      "olabs-admin-key-test".to_string(),
      false,
    );
    state
      .record_missing_proof_query(MissingProofQuery {
        address: "0x1111111111111111111111111111111111111111".to_string(),
        storage_keys: vec!["0x01".to_string()],
        block: MissingBlockId::Number(1),
      })
      .await;
    assert!(state.take_missing_proof_queries().await.is_empty());
  }

  #[test]
  fn test_metrics_record_oblivious_classifies_status_and_codes() {
    let mut m = RpcMetrics::default();

    m.record_oblivious(true, 0, 120);
    m.record_oblivious(false, -32602, 200);
    m.record_oblivious(false, -32001, 80);
    m.record_oblivious(false, -32002, 60);
    m.record_oblivious(false, -32603, 100);

    assert_eq!(m.requests_total, 5);
    assert_eq!(m.requests_ok, 1);
    assert_eq!(m.requests_err, 4);

    assert_eq!(m.errors_invalid_params, 1);
    assert_eq!(m.errors_data_non_availability, 1);
    assert_eq!(m.errors_traversal_cap_exceeded, 1);
    assert_eq!(m.errors_other, 1);

    assert_eq!(m.latency_count, 5);
    assert_eq!(m.latency_total_us, 560);
    assert_eq!(m.latency_max_us, 200);
    assert_eq!(m.latency_avg_us, 112);
  }

  #[tokio::test]
  async fn test_api_key_controller_create_and_consume_tokens() {
    let state = SharedState::new_with_admin_key(1 << 10, "olabs-admin-key-test".to_string());
    let key = state.create_client_api_key().await;
    assert!(key.starts_with("olabs-api-"));
    assert!(state.authorize_public_api_key(&key).await.is_err());

    state.add_tokens_to_api_key(&key, 2).await.unwrap();
    state.set_hourly_limit_for_api_key(&key, 2).await.unwrap();

    assert_eq!(state.authorize_public_api_key(&key).await, Ok(()));
    assert_eq!(state.authorize_public_api_key(&key).await, Ok(()));
    assert_eq!(state.authorize_public_api_key(&key).await, Err(ApiKeyError::TokenExhausted));
  }

  #[tokio::test]
  async fn test_api_key_controller_requires_admin_for_admin_route() {
    let state = SharedState::new_with_admin_key(1 << 10, "olabs-admin-key-test".to_string());
    let key = state.create_client_api_key().await;

    assert_eq!(state.authorize_admin_api_key(&key).await, Err(ApiKeyError::NotAdmin));
    assert_eq!(state.authorize_admin_api_key("olabs-admin-key-test").await, Ok(()));
  }

  #[tokio::test]
  async fn test_admin_api_key_has_no_hourly_limit() {
    let admin = "olabs-admin-key-test-0000000000000000";
    let state = SharedState::new_with_admin_key(1 << 10, admin.to_string());

    for _ in 0..16 {
      assert_eq!(state.authorize_admin_api_key(admin).await, Ok(()));
    }
  }

  #[tokio::test]
  async fn test_api_key_disable_and_delete() {
    let admin = "olabs-admin-key-test-1111111111111111";
    let state = SharedState::new_with_admin_key(1 << 10, admin.to_string());
    let key = state.create_client_api_key().await;

    state.add_tokens_to_api_key(&key, 2).await.unwrap();
    state.set_hourly_limit_for_api_key(&key, 2).await.unwrap();
    assert_eq!(state.authorize_public_api_key(&key).await, Ok(()));

    state.disable_api_key(&key).await.unwrap();
    assert_eq!(state.authorize_public_api_key(&key).await, Err(ApiKeyError::DisabledKey));

    state.delete_api_key(&key).await.unwrap();
    assert_eq!(state.authorize_public_api_key(&key).await, Err(ApiKeyError::UnknownKey));
  }

  #[tokio::test]
  async fn test_admin_key_cannot_be_disabled_or_deleted() {
    let admin = "olabs-admin-key-test-2222222222222222";
    let state = SharedState::new_with_admin_key(1 << 10, admin.to_string());

    assert_eq!(state.disable_api_key(admin).await, Err(ApiKeyError::ProtectedAdminKey));
    assert_eq!(state.delete_api_key(admin).await, Err(ApiKeyError::ProtectedAdminKey));
  }
}
