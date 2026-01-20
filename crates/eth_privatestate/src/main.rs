//! EthPrivateState: A privacy-preserving Ethereum state prover.
//!
#[macro_use]
extern crate rostl_primitives;

pub mod oblivious_node;
pub mod rpc;
pub mod state;
pub mod trie;
pub mod types;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use log::info;
use tokio::time;

use state::SharedState;

#[tokio::main]
async fn main() -> Result<()> {
  env_logger::init();
  info!("Starting eth_proof_server PoC");

  let shared = Arc::new(SharedState::new(1 << 20));

  // Background writer
  let _shared_clone = shared.clone();
  tokio::spawn(async move {
    loop {
      // UNDONE(): sync with consensus data from the rust code
      time::sleep(Duration::from_secs(1)).await;
    }
  });

  // start rpc
  rpc::start_rpc(shared).await?;
  Ok(())
}
