//! Shared state for the rpc service.
//!
use std::sync::Arc;

use rostl_datastructures::map::UnsortedMap;
use rostl_primitives::traits::Cmov;
use serde::Serialize;
use tokio::sync::Mutex;

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

pub struct SharedState {
  pub storage: Arc<Mutex<UnsortedMap<B256, ObliviousNode>>>,
  /// block_number -> state_root
  pub roots_by_number: Arc<Mutex<UnsortedMap<u64, B256>>>,
  /// block_hash -> state_root
  pub roots_by_hash: Arc<Mutex<UnsortedMap<B256, B256>>>,
  pub metrics: Arc<Mutex<RpcMetrics>>,
}

impl SharedState {
  pub fn new(cap: usize) -> Self {
    Self {
      storage: Arc::new(Mutex::new(UnsortedMap::new(1 << 10))),
      roots_by_number: Arc::new(Mutex::new(UnsortedMap::new(cap))),
      roots_by_hash: Arc::new(Mutex::new(UnsortedMap::new(cap))),
      metrics: Arc::new(Mutex::new(RpcMetrics::default())),
    }
  }

  pub async fn set_root(&self, block: u64, root: B256) {
    let mut guard = self.roots_by_number.lock().await;
    guard.insert(block, root);
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

  pub async fn metrics_snapshot(&self) -> RpcMetrics {
    self.metrics.lock().await.clone()
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
}
