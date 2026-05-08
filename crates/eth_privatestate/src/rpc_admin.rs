//! Administrative RPC methods for EthPrivateState.
//!
use std::sync::Arc;
use std::time::Instant;

use jsonrpsee::server::RpcModule;
use jsonrpsee::types::error::ErrorObjectOwned;
use jsonrpsee::types::ErrorCode;
use rostl_datastructures::map::UnsortedMap;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::authentication::ApiKeyError;
use crate::oblivious_node::ObliviousNode;
use crate::rpc::{decode_b256_hex, invalid_params_error, observe_rpc_result};
use crate::state::{MissingProofQuery, SharedState, SyncProgressLane};
use crate::types::B256;

fn parse_oblivious_node(node_hex: &str) -> Result<ObliviousNode, ErrorObjectOwned> {
  let raw = node_hex.strip_prefix("0x").unwrap_or(node_hex);
  let node_bytes = hex::decode(raw).map_err(|_| {
    ErrorObjectOwned::owned(-32602, "Failed to decode node hex".to_string(), None::<()>)
  })?;
  ObliviousNode::from_rlp(&node_bytes).ok_or(ErrorObjectOwned::owned(
    -32602,
    "Failed to parse node RLP into ObliviousNode".to_string(),
    None::<()>,
  ))
}

fn upsert_node(
  storage: &mut UnsortedMap<B256, ObliviousNode>,
  node_hash: B256,
  node: ObliviousNode,
) {
  let mut existing = ObliviousNode::default();
  if storage.get(node_hash, &mut existing) {
    storage.write(node_hash, node);
  } else {
    storage.insert(node_hash, node);
  }
  for _ in 0..16 {
    storage.deamortize_insertion_queue();
  }
}

fn map_api_key_error(err: ApiKeyError) -> ErrorObjectOwned {
  match err {
    ApiKeyError::UnknownKey => ErrorObjectOwned::owned(
      ErrorCode::InvalidParams.code(),
      "Unknown API key".to_string(),
      None::<()>,
    ),
    ApiKeyError::NotAdmin => ErrorObjectOwned::owned(
      ErrorCode::InvalidParams.code(),
      "API key is not authorized for admin endpoint".to_string(),
      None::<()>,
    ),
    ApiKeyError::DisabledKey => {
      ErrorObjectOwned::owned(-32012, "API key is disabled".to_string(), None::<()>)
    }
    ApiKeyError::ProtectedAdminKey => ErrorObjectOwned::owned(
      ErrorCode::InvalidParams.code(),
      "Admin API key cannot be disabled or deleted".to_string(),
      None::<()>,
    ),
    ApiKeyError::TokenExhausted => {
      ErrorObjectOwned::owned(-32010, "API key has no remaining tokens".to_string(), None::<()>)
    }
    ApiKeyError::HourlyLimitExceeded => {
      ErrorObjectOwned::owned(-32011, "API key exceeded hourly allowance".to_string(), None::<()>)
    }
  }
}

fn parse_value<T: DeserializeOwned>(value: Option<&Value>) -> Result<T, ErrorObjectOwned> {
  let value = value.ok_or_else(invalid_params_error)?;
  serde_json::from_value(value.clone()).map_err(|_| invalid_params_error())
}

fn parse_sync_lane(
  value: Option<&Value>,
  default: Option<SyncProgressLane>,
) -> Result<Option<SyncProgressLane>, ErrorObjectOwned> {
  let Some(value) = value else {
    return Ok(default);
  };
  let lane = value.as_str().ok_or_else(invalid_params_error)?;
  SyncProgressLane::parse(lane).map(Some).ok_or_else(invalid_params_error)
}

fn lag_blocks(newer: Option<u64>, older: Option<u64>) -> Option<u64> {
  match (newer, older) {
    (Some(newer), Some(older)) => Some(newer.saturating_sub(older)),
    _ => None,
  }
}

#[derive(Clone, Debug, Serialize)]
struct AdminSyncStatus {
  latest_root_number: Option<u64>,
  latest_root: Option<String>,
  historical_root_number: Option<u64>,
  live_root_number: Option<u64>,
  latest_node_delta_number: Option<u64>,
  historical_node_delta_number: Option<u64>,
  live_node_delta_number: Option<u64>,
  historical_root_lag_to_latest: Option<u64>,
  live_root_lag_to_latest: Option<u64>,
  latest_node_lag_to_latest_root: Option<u64>,
  historical_node_lag_to_historical_root: Option<u64>,
  live_node_lag_to_live_root: Option<u64>,
  latest_root_number_meaning: &'static str,
  latest_node_delta_number_meaning: &'static str,
  historical_root_number_meaning: &'static str,
  live_root_number_meaning: &'static str,
  historical_node_delta_number_meaning: &'static str,
  live_node_delta_number_meaning: &'static str,
  historical_root_lag_to_latest_meaning: &'static str,
  live_root_lag_to_latest_meaning: &'static str,
  latest_node_lag_to_latest_root_meaning: &'static str,
  historical_node_lag_to_historical_root_meaning: &'static str,
  live_node_lag_to_live_root_meaning: &'static str,
}

/// Register administrative RPC methods (`admin_*`) onto a new module.
pub fn register_admin_rpc(state: Arc<SharedState>) -> anyhow::Result<RpcModule<Arc<SharedState>>> {
  let mut module = RpcModule::new(state.clone());

  module.register_async_method("admin_put_node", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let node_hex: String = params.parse().map_err(|_| invalid_params_error())?;
        let ob = parse_oblivious_node(&node_hex)?;
        let hh = ob.keccak_hash();
        {
          let mut guard = state.storage.lock().await;
          upsert_node(&mut guard, hh, ob);
        }
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_put_node", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_set_root", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let (block_num, root_hex): (u64, String) =
          params.parse().map_err(|_| invalid_params_error())?;
        let root_b256 = decode_b256_hex(&root_hex, "root")?;
        state.set_root(block_num, root_b256).await;
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_set_root", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_set_root_by_hash", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let (block_hash_hex, root_hex): (String, String) =
          params.parse().map_err(|_| invalid_params_error())?;
        let block_hash = decode_b256_hex(&block_hash_hex, "block hash")?;
        let root_b256 = decode_b256_hex(&root_hex, "root")?;
        state.set_root_by_hash(block_hash, root_b256).await;
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_set_root_by_hash", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_apply_block_delta", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let values: Vec<Value> = params.parse().map_err(|_| invalid_params_error())?;
        let block_number: u64 = parse_value(values.first())?;
        let block_hash_hex: String = parse_value(values.get(1))?;
        let root_hex: String = parse_value(values.get(2))?;
        let node_hexes: Vec<String> = parse_value(values.get(3))?;
        let publish_root_by_number: bool = parse_value(values.get(4))?;
        let sync_lane = parse_sync_lane(values.get(5), None)?;

        let block_hash = decode_b256_hex(&block_hash_hex, "block hash")?;
        let root = decode_b256_hex(&root_hex, "root")?;

        let mut parsed_nodes = Vec::with_capacity(node_hexes.len());
        for node_hex in node_hexes {
          parsed_nodes.push(parse_oblivious_node(&node_hex)?);
        }

        {
          let mut guard = state.storage.lock().await;
          for ob in parsed_nodes {
            let hh = ob.keccak_hash();
            upsert_node(&mut guard, hh, ob);
          }
        }

        state
          .apply_root_batch(&[(block_number, block_hash, root)], publish_root_by_number, sync_lane)
          .await;
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_apply_block_delta", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_apply_root_batch", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let values: Vec<Value> = params.parse().map_err(|_| invalid_params_error())?;
        let root_params: Vec<(u64, String, String)> = parse_value(values.first())?;
        let publish_root_by_number: bool = parse_value(values.get(1))?;
        let sync_lane = parse_sync_lane(values.get(2), None)?;

        let mut roots = Vec::with_capacity(root_params.len());
        for (block_number, block_hash_hex, root_hex) in root_params {
          let block_hash = decode_b256_hex(&block_hash_hex, "block hash")?;
          let root = decode_b256_hex(&root_hex, "root")?;
          roots.push((block_number, block_hash, root));
        }

        state.apply_root_batch(&roots, publish_root_by_number, sync_lane).await;
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_apply_root_batch", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_mark_node_delta_complete", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let values: Vec<Value> = params.parse().map_err(|_| invalid_params_error())?;
        let block_number: u64 = parse_value(values.first())?;
        let sync_lane = parse_sync_lane(values.get(1), Some(SyncProgressLane::Historical))?
          .unwrap_or(SyncProgressLane::Historical);
        state.mark_node_delta_complete(block_number, sync_lane).await;
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_mark_node_delta_complete", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_get_metrics", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let _ = params;
      let res: Result<_, ErrorObjectOwned> = Ok(state.metrics_snapshot().await);
      observe_rpc_result(state.as_ref(), "admin_get_metrics", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_get_sync_status", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let _ = params;
      let latest = state.get_latest_root_with_number().await;
      let latest_root_number = latest.map(|(number, _)| number);
      let historical_root_number = state.get_latest_historical_root_number().await;
      let live_root_number = state.get_latest_live_root_number().await;
      let latest_node_delta_number = state.get_latest_node_delta_number().await;
      let historical_node_delta_number =
        state.get_latest_historical_node_delta_number().await;
      let live_node_delta_number = state.get_latest_live_node_delta_number().await;
      let res: Result<_, ErrorObjectOwned> = Ok(AdminSyncStatus {
        latest_root_number,
        latest_root: latest.map(|(_, root)| root.to_hex()),
        historical_root_number,
        live_root_number,
        latest_node_delta_number,
        historical_node_delta_number,
        live_node_delta_number,
        historical_root_lag_to_latest: lag_blocks(latest_root_number, historical_root_number),
        live_root_lag_to_latest: lag_blocks(latest_root_number, live_root_number),
        latest_node_lag_to_latest_root: lag_blocks(latest_root_number, latest_node_delta_number),
        historical_node_lag_to_historical_root: lag_blocks(
          historical_root_number,
          historical_node_delta_number,
        ),
        live_node_lag_to_live_root: lag_blocks(live_root_number, live_node_delta_number),
        latest_root_number_meaning:
          "highest block root accepted from any path; live roots can make this jump to tip before historical prefetch catches up",
        latest_node_delta_number_meaning:
          "max of historical and live proactive witness/node lanes; not a historical completeness marker",
        historical_root_number_meaning:
          "highest block published by the startup root prefetch lane for the configured start/tail scope",
        live_root_number_meaning:
          "highest block root published by the live-follow root lane",
        historical_node_delta_number_meaning:
          "highest block whose startup/historical proactive witness/node delta was applied",
        live_node_delta_number_meaning:
          "highest block whose live proactive witness/node delta was applied",
        historical_root_lag_to_latest_meaning:
          "distance from the fixed startup historical root snapshot to the newest accepted root; this normally grows after startup because live sync owns new blocks",
        live_root_lag_to_latest_meaning:
          "distance from live-follow roots to the newest accepted root; this is the main current-root catch-up indicator",
        latest_node_lag_to_latest_root_meaning:
          "distance from newest accepted root to newest proactive node delta from any lane; use lane-specific lags to separate startup and live completeness",
        historical_node_lag_to_historical_root_meaning:
          "remaining startup/historical witness-node lag within the fixed startup snapshot range",
        live_node_lag_to_live_root_meaning:
          "remaining live witness-node lag for newly followed blocks",
      });
      observe_rpc_result(state.as_ref(), "admin_get_sync_status", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_take_missing_nodes", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<Vec<MissingProofQuery>, ErrorObjectOwned> = async {
        let _: Vec<serde_json::Value> = params.parse().map_err(|_| invalid_params_error())?;
        Ok::<_, ErrorObjectOwned>(state.take_missing_proof_queries().await)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_take_missing_nodes", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_create_api_key", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<String, ErrorObjectOwned> = async {
        let _: Vec<serde_json::Value> = params.parse().map_err(|_| invalid_params_error())?;
        Ok::<_, ErrorObjectOwned>(state.create_client_api_key().await)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_create_api_key", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_add_tokens", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let (api_key, tokens): (String, u64) =
          params.parse().map_err(|_| invalid_params_error())?;
        state.add_tokens_to_api_key(&api_key, tokens).await.map_err(map_api_key_error)?;
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_add_tokens", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_set_hourly_limit", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let (api_key, hourly_limit): (String, u64) =
          params.parse().map_err(|_| invalid_params_error())?;
        state
          .set_hourly_limit_for_api_key(&api_key, hourly_limit)
          .await
          .map_err(map_api_key_error)?;
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_set_hourly_limit", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_disable_api_key", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let (api_key,): (String,) = params.parse().map_err(|_| invalid_params_error())?;
        state.disable_api_key(&api_key).await.map_err(map_api_key_error)?;
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_disable_api_key", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_delete_api_key", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let (api_key,): (String,) = params.parse().map_err(|_| invalid_params_error())?;
        state.delete_api_key(&api_key).await.map_err(map_api_key_error)?;
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_delete_api_key", started, &res).await;
      res
    }
  })?;

  Ok(module)
}
