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
use log::{info, warn};
use tokio::time;

use state::SharedState;

struct RuntimeArgs {
  admin_api_key: String,
  leaky_error_recovery: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
  env_logger::init();
  info!("Starting eth_proof_server PoC");

  let args = parse_runtime_args()?;
  if args.leaky_error_recovery {
    warn!(
      "leaky error recovery enabled: missing-proof cache/backfill is on; this leaks block \
       selector and duplicate status in instruction/memory traces"
    );
  } else {
    warn!(
      "leaky error recovery disabled: backfill via admin_take_missing_nodes is off; this avoids \
       persisting/querying missing-proof requests"
    );
  }
  let shared = Arc::new(SharedState::new_with_admin_key_and_leaky_error_recovery(
    1 << 20,
    args.admin_api_key,
    args.leaky_error_recovery,
  ));

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

fn parse_runtime_args() -> Result<RuntimeArgs> {
  let mut args = std::env::args().skip(1);
  let mut admin_api_key: Option<String> = None;
  let mut leaky_error_recovery = false;

  while let Some(arg) = args.next() {
    match arg.as_str() {
      "--admin-api-key" => {
        let key = args.next().ok_or_else(|| anyhow!("missing value for --admin-api-key"))?;
        if key.len() < 32 {
          return Err(anyhow!("--admin-api-key must be at least 32 bytes/chars"));
        }
        admin_api_key = Some(key);
      }
      "--leaky-error-recovery" => {
        leaky_error_recovery = true;
      }
      _ => return Err(anyhow!("unknown argument: {}", arg)),
    }
  }

  Ok(RuntimeArgs {
    admin_api_key: admin_api_key.ok_or_else(|| anyhow!("missing --admin-api-key <key>"))?,
    leaky_error_recovery,
  })
}
