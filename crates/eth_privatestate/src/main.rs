//! EthPrivateState: A privacy-preserving Ethereum state prover.
//!
#[macro_use]
extern crate rostl_primitives;

pub mod attestation;
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

use state::{SharedState, SharedStateConfig, DEFAULT_NODE_MAP_CAPACITY, DEFAULT_ROOT_MAP_CAPACITY};

struct RuntimeArgs {
  admin_api_key: String,
  leaky_error_recovery: bool,
  listen_addr: String,
  root_map_capacity: usize,
  node_map_capacity: usize,
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
  info!("Map capacities: roots={}, trie_nodes={}", args.root_map_capacity, args.node_map_capacity);
  if args.node_map_capacity >= 16_000_000 {
    warn!(
      "large trie node map requested; 16M nodes consumes far more than 1 GB with the current ORAM \
       layout and needs a high-memory CVM"
    );
  }

  let shared = Arc::new(SharedState::with_config(SharedStateConfig {
    root_map_capacity: args.root_map_capacity,
    node_map_capacity: args.node_map_capacity,
    admin_api_key: args.admin_api_key,
    leaky_error_recovery: args.leaky_error_recovery,
  }));

  // Background writer
  let _shared_clone = shared.clone();
  tokio::spawn(async move {
    loop {
      // UNDONE(): sync with consensus data from the rust code
      time::sleep(Duration::from_secs(1)).await;
    }
  });

  // start rpc
  let (handle, addr) = frontend::start_rpc_server(shared, &args.listen_addr).await?;
  info!("Server listening on {}", addr);
  info!("Public endpoint: http://{}/{{api_key}}/json_rpc", addr);
  info!("Admin endpoint: http://{}/{{admin_api_key}}/admin", addr);
  handle.stopped().await;
  Ok(())
}

fn parse_runtime_args() -> Result<RuntimeArgs> {
  let mut args = std::env::args().skip(1);
  let mut admin_api_key: Option<String> = None;
  let mut leaky_error_recovery = false;
  let mut listen_addr = "127.0.0.1:8545".to_string();
  let mut root_map_capacity = env_capacity("ROOT_MAP_CAPACITY", DEFAULT_ROOT_MAP_CAPACITY)?;
  let mut node_map_capacity = env_capacity("NODE_MAP_CAPACITY", DEFAULT_NODE_MAP_CAPACITY)?;

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
      "--listen-addr" => {
        listen_addr = args.next().ok_or_else(|| anyhow!("missing value for --listen-addr"))?;
      }
      "--root-map-capacity" => {
        let value = args.next().ok_or_else(|| anyhow!("missing value for --root-map-capacity"))?;
        root_map_capacity = parse_capacity(&value, "--root-map-capacity")?;
      }
      "--node-map-capacity" => {
        let value = args.next().ok_or_else(|| anyhow!("missing value for --node-map-capacity"))?;
        node_map_capacity = parse_capacity(&value, "--node-map-capacity")?;
      }
      _ => return Err(anyhow!("unknown argument: {}", arg)),
    }
  }

  Ok(RuntimeArgs {
    admin_api_key: admin_api_key.ok_or_else(|| anyhow!("missing --admin-api-key <key>"))?,
    leaky_error_recovery,
    listen_addr,
    root_map_capacity,
    node_map_capacity,
  })
}

fn env_capacity(name: &str, default: usize) -> Result<usize> {
  match std::env::var(name) {
    Ok(value) if !value.trim().is_empty() => parse_capacity(&value, name),
    Ok(_) | Err(std::env::VarError::NotPresent) => Ok(default),
    Err(err) => Err(anyhow!("failed reading {name}: {err}")),
  }
}

fn parse_capacity(value: &str, name: &str) -> Result<usize> {
  let capacity =
    value.parse::<usize>().map_err(|err| anyhow!("{name} must be a positive integer: {err}"))?;
  if capacity == 0 {
    return Err(anyhow!("{name} must be greater than zero"));
  }
  Ok(capacity)
}
