//! CLI entrypoint for syncing reth trie updates into `eth_privatestate`.

use std::time::Duration;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use log::{error, info};

use eth_sync_feeder::admin_rpc_sink::HttpAdminSink;
use eth_sync_feeder::reth_rpc_source::{NodeSyncMode, RethRpcSource};
use eth_sync_feeder::reth_source::RethSourceAdapter;
use eth_sync_feeder::RethSyncClient;

const RETRY_SLEEP: Duration = Duration::from_secs(1);
const LIVE_POLL_INTERVAL: Duration = Duration::from_millis(500);
const LIVE_NODE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MISSING_NODE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const LIVE_START_OVERLAP_BLOCKS: u64 = 64;

fn redact_admin_key(message: impl ToString, admin_api_key: &str) -> String {
  message.to_string().replace(admin_api_key, "<admin-api-key>")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum CliNodeSyncMode {
  /// Publish roots only and fetch proof nodes lazily on missing-query backfill.
  RootsOnly,
  /// Publish roots quickly while fetching historical and live witness nodes in background.
  RootsAndWitness,
  /// Fetch trie nodes proactively with reth debug_executionWitness in the main sync streams.
  ExecutionWitness,
}

impl From<CliNodeSyncMode> for NodeSyncMode {
  fn from(value: CliNodeSyncMode) -> Self {
    match value {
      CliNodeSyncMode::RootsOnly => Self::RootsOnly,
      CliNodeSyncMode::RootsAndWitness => Self::RootsOnly,
      CliNodeSyncMode::ExecutionWitness => Self::ExecutionWitness,
    }
  }
}

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
  /// Skip startup bootstrap sync.
  #[arg(long, default_value_t = false)]
  skip_initial_sync: bool,
  /// Skip live block update syncing.
  #[arg(long, default_value_t = false)]
  skip_live_sync: bool,
  /// Skip missing-node backfill polling.
  #[arg(long, default_value_t = false)]
  skip_missing_node_sync: bool,
  /// Start root/bootstrap sync at this block.
  #[arg(long)]
  initial_sync_start_block: Option<u64>,
  /// Bootstrap only the last N blocks at startup tip.
  #[arg(long)]
  initial_sync_tail_blocks: Option<u64>,
  /// Cap startup/bootstrap sync at this inclusive block.
  #[arg(long)]
  initial_sync_end_block: Option<u64>,
  /// Proactive node ingest mode.
  #[arg(long, value_enum, default_value_t = CliNodeSyncMode::RootsAndWitness)]
  node_sync_mode: CliNodeSyncMode,
}

#[tokio::main]
async fn main() -> Result<()> {
  env_logger::init();
  let args = Args::parse();

  if args.initial_sync_start_block.is_some() && args.initial_sync_tail_blocks.is_some() {
    anyhow::bail!(
      "--initial-sync-start-block and --initial-sync-tail-blocks are mutually exclusive"
    );
  }
  if args.initial_sync_end_block.is_some() && args.initial_sync_tail_blocks.is_some() {
    anyhow::bail!("--initial-sync-end-block and --initial-sync-tail-blocks are mutually exclusive");
  }
  if let (Some(start), Some(end)) = (args.initial_sync_start_block, args.initial_sync_end_block) {
    if end < start.max(1) {
      anyhow::bail!("--initial-sync-end-block must be >= --initial-sync-start-block");
    }
  }

  let root_node_sync_mode = NodeSyncMode::from(args.node_sync_mode);
  let spawn_background_witness = args.node_sync_mode == CliNodeSyncMode::RootsAndWitness;
  let admin_api_key_for_logs = args.admin_api_key.clone();
  info!("node sync mode: {:?}", args.node_sync_mode);

  let startup_rpc_source = match (args.initial_sync_start_block, args.initial_sync_tail_blocks) {
    (Some(start_block), None) => {
      info!("startup bootstrap begins at block {}", start_block.max(1));
      RethRpcSource::bootstrap_from_block(args.reth_rpc_url.clone(), start_block)
    }
    (None, Some(tail_blocks)) => {
      info!("startup bootstrap limited to last {} block(s) at startup tip", tail_blocks.max(1));
      RethRpcSource::bootstrap_recent(args.reth_rpc_url.clone(), tail_blocks)
    }
    (None, None) => {
      info!("startup bootstrap begins at genesis");
      RethRpcSource::bootstrap_from_genesis(args.reth_rpc_url.clone())
    }
    (Some(_), Some(_)) => unreachable!("validated mutually exclusive startup options"),
  }
  .with_bootstrap_end_block(args.initial_sync_end_block)
  .with_node_sync_mode(root_node_sync_mode);
  let startup_source = RethSourceAdapter::new(startup_rpc_source);
  let startup_sink = HttpAdminSink::from_base_url(&args.admin_base_url, &args.admin_api_key)?;
  let mut startup_client = RethSyncClient::new(startup_source, startup_sink, true);

  let live_source = RethSourceAdapter::new(
    RethRpcSource::live_from_recent(args.reth_rpc_url.clone(), LIVE_START_OVERLAP_BLOCKS)
      .with_node_sync_mode(root_node_sync_mode),
  );
  let live_sink = HttpAdminSink::from_base_url(&args.admin_base_url, &args.admin_api_key)?;
  let mut live_client = RethSyncClient::new(live_source, live_sink, true);

  let missing_source = RethSourceAdapter::new(
    RethRpcSource::live_from_tip(args.reth_rpc_url.clone())
      .with_node_sync_mode(NodeSyncMode::RootsOnly),
  );
  let missing_sink = HttpAdminSink::from_base_url(&args.admin_base_url, &args.admin_api_key)?;
  let mut missing_client = RethSyncClient::new(missing_source, missing_sink, true);

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
  if skip_live_sync && skip_missing_node_sync && !spawn_background_witness {
    info!("feeder idle mode: only startup root sync (if enabled) + waiting for shutdown");
  }

  let startup_log_key = admin_api_key_for_logs.clone();
  let mut startup_root_handle = tokio::spawn(async move {
    if skip_initial_sync {
      return;
    }
    loop {
      match startup_client.sync_initial_state().await {
        Ok(0) => {
          info!("startup root sync found no blocks yet; retrying");
          tokio::time::sleep(RETRY_SLEEP).await;
        }
        Ok(startup) => {
          info!("startup root sync completed in background (published {} block root(s))", startup);
          break;
        }
        Err(err) => {
          error!(
            "startup root sync failed: {}; retrying",
            redact_admin_key(&err, &startup_log_key)
          );
          tokio::time::sleep(RETRY_SLEEP).await;
        }
      }
    }
  });
  let mut startup_root_finished = false;

  let mut historical_node_handle = if spawn_background_witness && !skip_initial_sync {
    let historical_node_source =
      match (args.initial_sync_start_block, args.initial_sync_tail_blocks) {
        (Some(start_block), None) => {
          RethRpcSource::bootstrap_from_block(args.reth_rpc_url.clone(), start_block)
        }
        (None, Some(tail_blocks)) => {
          RethRpcSource::bootstrap_recent(args.reth_rpc_url.clone(), tail_blocks)
        }
        (None, None) => RethRpcSource::bootstrap_from_genesis(args.reth_rpc_url.clone()),
        (Some(_), Some(_)) => unreachable!("validated mutually exclusive startup options"),
      }
      .with_bootstrap_end_block(args.initial_sync_end_block)
      .with_node_sync_mode(NodeSyncMode::ExecutionWitness);
    let historical_node_source = RethSourceAdapter::new(historical_node_source);
    let historical_node_sink =
      HttpAdminSink::from_base_url(&args.admin_base_url, &args.admin_api_key)?;
    let mut historical_node_client =
      RethSyncClient::new(historical_node_source, historical_node_sink, true);
    let historical_log_key = admin_api_key_for_logs.clone();
    Some(tokio::spawn(async move {
      loop {
        match historical_node_client.sync_initial_state().await {
          Ok(0) => {
            info!("historical witness node sync found no blocks yet; retrying");
            tokio::time::sleep(RETRY_SLEEP).await;
          }
          Ok(blocks) => {
            info!(
              "historical witness node sync completed in background (published {} block bundle(s))",
              blocks
            );
            break;
          }
          Err(err) => {
            error!(
              "historical witness node sync failed: {}; retrying",
              redact_admin_key(&err, &historical_log_key)
            );
            tokio::time::sleep(RETRY_SLEEP).await;
          }
        }
      }
    }))
  } else {
    None
  };
  let mut historical_node_finished = historical_node_handle.is_none();

  let mut live_node_handle = if spawn_background_witness && !skip_live_sync {
    let live_node_source = RethSourceAdapter::new(
      RethRpcSource::live_from_recent(args.reth_rpc_url.clone(), LIVE_START_OVERLAP_BLOCKS)
        .with_node_sync_mode(NodeSyncMode::ExecutionWitness),
    );
    let live_node_sink = HttpAdminSink::from_base_url(&args.admin_base_url, &args.admin_api_key)?;
    let mut live_node_client = RethSyncClient::new(live_node_source, live_node_sink, true);
    let live_node_log_key = admin_api_key_for_logs.clone();
    Some(tokio::spawn(async move {
      let mut live_node_tick = tokio::time::interval(LIVE_NODE_POLL_INTERVAL);
      loop {
        live_node_tick.tick().await;
        if let Err(err) = live_node_client.sync_next_update().await {
          error!("live witness node sync failed: {}", redact_admin_key(&err, &live_node_log_key));
          tokio::time::sleep(RETRY_SLEEP).await;
        }
      }
    }))
  } else {
    None
  };
  let mut live_node_finished = live_node_handle.is_none();

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
          error!("sync update failed: {}", redact_admin_key(&err, &admin_api_key_for_logs));
          tokio::time::sleep(RETRY_SLEEP).await;
        }
      }
      _ = missing_tick.tick(), if !skip_missing_node_sync => {
        match missing_client.sync_missing_nodes_once().await {
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
            error!("missing-node sync failed: {}", redact_admin_key(&err, &admin_api_key_for_logs));
            tokio::time::sleep(RETRY_SLEEP).await;
          }
        }
      }
      res = &mut startup_root_handle, if !startup_root_finished => {
        startup_root_finished = true;
        if let Err(err) = res {
          error!("startup root task join error: {}", err);
        }
      }
      res = async {
        match historical_node_handle.as_mut() {
          Some(handle) => handle.await,
          None => Ok(()),
        }
      }, if !historical_node_finished => {
        historical_node_finished = true;
        if let Err(err) = res {
          error!("historical witness node task join error: {}", err);
        }
      }
      res = async {
        match live_node_handle.as_mut() {
          Some(handle) => handle.await,
          None => Ok(()),
        }
      }, if !live_node_finished => {
        live_node_finished = true;
        if let Err(err) = res {
          error!("live witness node task join error: {}", err);
        }
      }
    }
  }

  Ok(())
}
