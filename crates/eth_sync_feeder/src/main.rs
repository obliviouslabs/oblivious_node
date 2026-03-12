//! CLI entrypoint for syncing reth trie updates into `eth_privatestate`.

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use log::{error, info};

use eth_sync_feeder::admin_rpc_sink::HttpAdminSink;
use eth_sync_feeder::reth_rpc_source::RethRpcSource;
use eth_sync_feeder::reth_source::RethSourceAdapter;
use eth_sync_feeder::RethSyncClient;

const RETRY_SLEEP: Duration = Duration::from_secs(1);
const LIVE_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MISSING_NODE_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Sync reth block trie updates into eth_privatestate admin RPC.
#[derive(Debug, Parser)]
#[command(name = "eth_sync_feeder")]
#[command(about = "Push reth trie updates into eth_privatestate")]
struct Args {
  /// Reth HTTP RPC URL, e.g. http://127.0.0.1:8546
  #[arg(long)]
  reth_rpc_url: String,
  /// eth_privatestate base URL, e.g. http://127.0.0.1:8545
  #[arg(long)]
  admin_base_url: String,
  /// Admin API key used for path auth (minimum 32 chars)
  #[arg(long)]
  admin_api_key: String,
  /// Skip startup bootstrap sync from genesis to current tip.
  #[arg(long, default_value_t = false)]
  skip_initial_sync: bool,
  /// Skip live block update syncing.
  #[arg(long, default_value_t = false)]
  skip_live_sync: bool,
  /// Skip missing-node backfill polling.
  #[arg(long, default_value_t = false)]
  skip_missing_node_sync: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
  env_logger::init();
  let args = Args::parse();

  let startup_source =
    RethSourceAdapter::new(RethRpcSource::bootstrap_from_genesis(args.reth_rpc_url.clone()));
  let startup_sink = HttpAdminSink::from_base_url(&args.admin_base_url, &args.admin_api_key)?;
  let mut startup_client = RethSyncClient::new(startup_source, startup_sink, true);

  let live_source = RethSourceAdapter::new(RethRpcSource::live_from_tip(args.reth_rpc_url.clone()));
  let live_sink = HttpAdminSink::from_base_url(&args.admin_base_url, &args.admin_api_key)?;
  let mut live_client = RethSyncClient::new(live_source, live_sink, true);

  let skip_initial_sync = args.skip_initial_sync;
  let skip_live_sync = args.skip_live_sync;
  let skip_missing_node_sync = args.skip_missing_node_sync;

  if skip_initial_sync {
    info!("startup bootstrap sync disabled by --skip-initial-sync");
  }
  if skip_live_sync {
    info!("live block sync disabled by --skip-live-sync");
  }
  if skip_missing_node_sync {
    info!("missing-node sync disabled by --skip-missing-node-sync");
  }
  if skip_live_sync && skip_missing_node_sync {
    info!("feeder idle mode: only startup sync (if enabled) + waiting for shutdown");
  }

  let mut startup_handle = tokio::spawn(async move {
    if skip_initial_sync {
      return;
    }
    match startup_client.sync_initial_state().await {
      Ok(startup) => {
        info!("startup sync completed in background (published {} block bundle(s))", startup)
      }
      Err(err) => error!("startup sync failed: {}", err),
    }
  });
  let mut startup_finished = false;

  let mut live_tick = tokio::time::interval(LIVE_POLL_INTERVAL);
  let mut missing_tick = tokio::time::interval(MISSING_NODE_POLL_INTERVAL);

  loop {
    tokio::select! {
      _ = tokio::signal::ctrl_c() => {
        info!("shutdown signal received");
        break;
      }
      _ = live_tick.tick(), if !skip_live_sync => {
        if let Err(err) = live_client.sync_next_update().await {
          error!("sync update failed: {}", err);
          tokio::time::sleep(RETRY_SLEEP).await;
        }
      }
      _ = missing_tick.tick(), if !skip_missing_node_sync => {
        match live_client.sync_missing_nodes_once().await {
          Ok(backfill) => {
            if backfill.published > 0 || backfill.unresolved_queries > 0 {
              info!(
                "missing-node backfill published={} proof_requests={} unresolved_queries={}",
                backfill.published,
                backfill.proof_requests,
                backfill.unresolved_queries
              );
            }
          }
          Err(err) => {
            error!("missing-node sync failed: {}", err);
            tokio::time::sleep(RETRY_SLEEP).await;
          }
        }
      }
      res = &mut startup_handle, if !startup_finished => {
        startup_finished = true;
        if let Err(err) = res {
          error!("startup task join error: {}", err);
        }
      }
    }
  }

  Ok(())
}
