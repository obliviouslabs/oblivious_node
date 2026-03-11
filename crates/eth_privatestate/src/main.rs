//! EthPrivateState: A privacy-preserving Ethereum state prover.
//!
#[macro_use]
extern crate rostl_primitives;

pub mod authentication;
pub mod frontend;
pub mod oblivious_node;
pub mod rpc;
pub mod rpc_admin;
pub mod state;
pub mod trie;
pub mod types;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use log::info;
use tokio::time;

use state::SharedState;

#[tokio::main]
async fn main() -> Result<()> {
  env_logger::init();
  info!("Starting eth_proof_server PoC");

  let admin_api_key = parse_admin_key_arg()?;
  let shared = Arc::new(SharedState::new_with_admin_key(1 << 20, admin_api_key));

  // Background writer
  let _shared_clone = shared.clone();
  tokio::spawn(async move {
    loop {
      // UNDONE(): sync with consensus data from the rust code
      time::sleep(Duration::from_secs(1)).await;
    }
  });

  // start rpc
  frontend::start_rpc(shared).await?;
  Ok(())
}

fn parse_admin_key_arg() -> Result<String> {
  let mut args = std::env::args().skip(1);
  while let Some(arg) = args.next() {
    if arg == "--admin-api-key" {
      let key = args.next().ok_or_else(|| anyhow!("missing value for --admin-api-key"))?;
      if key.len() < 32 {
        return Err(anyhow!("--admin-api-key must be at least 32 bytes/chars"));
      }
      return Ok(key);
    }
  }
  Err(anyhow!("missing --admin-api-key <key>"))
}
