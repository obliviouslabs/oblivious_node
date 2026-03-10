//! Shared state for the rpc service.
//!
use std::sync::Arc;

use rostl_datastructures::map::UnsortedMap;
use tokio::sync::Mutex;

use crate::{oblivious_node::ObliviousNode, types::B256};

pub struct SharedState {
  pub storage: Arc<Mutex<UnsortedMap<B256, ObliviousNode>>>,
  /// block_number -> state_root
  pub roots_by_number: Arc<Mutex<UnsortedMap<u64, B256>>>,
  /// block_hash -> state_root
  pub roots_by_hash: Arc<Mutex<UnsortedMap<B256, B256>>>,
}

impl SharedState {
  pub fn new(cap: usize) -> Self {
    Self {
      storage: Arc::new(Mutex::new(UnsortedMap::new(1 << 10))),
      roots_by_number: Arc::new(Mutex::new(UnsortedMap::new(cap))),
      roots_by_hash: Arc::new(Mutex::new(UnsortedMap::new(cap))),
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
}
