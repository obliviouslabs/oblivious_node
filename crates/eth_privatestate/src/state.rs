//! Shared state for the rpc service.
//!
use std::sync::Arc;

use rostl_datastructures::map::UnsortedMap;
use tokio::sync::Mutex;

use crate::{oblivious_node::ObliviousNode, types::B256};

pub struct SharedState {
  pub storage: Arc<Mutex<UnsortedMap<B256, ObliviousNode>>>,
  /// block_number -> state_root
  pub roots: Arc<Mutex<UnsortedMap<u64, B256>>>,
}

impl SharedState {
  pub fn new(cap: usize) -> Self {
    Self {
      storage: Arc::new(Mutex::new(UnsortedMap::new(1 << 10))),
      roots: Arc::new(Mutex::new(UnsortedMap::new(cap))),
    }
  }

  pub async fn set_root(&self, block: u64, root: B256) {
    let mut guard = self.roots.lock().await;
    guard.insert(block, root);
  }

  // NOTE: We are leaking whether the root exists or not, this is acceptable as we don't care about hiding data in invalid requests.
  pub async fn get_root(&self, block: u64) -> Option<B256> {
    let mut guard = self.roots.lock().await;
    let mut ret = B256::zero();
    let v = guard.get(block, &mut ret);
    if v {
      Some(ret)
    } else {
      None
    }
  }
}
