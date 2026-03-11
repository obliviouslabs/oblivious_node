//! Administrative RPC methods for EthPrivateState.
//!
use std::sync::Arc;
use std::time::Instant;

use jsonrpsee::server::RpcModule;
use jsonrpsee::types::error::ErrorObjectOwned;
use jsonrpsee::types::ErrorCode;

use crate::authentication::ApiKeyError;
use crate::oblivious_node::ObliviousNode;
use crate::rpc::{decode_b256_hex, invalid_params_error, observe_rpc_result};
use crate::state::SharedState;

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

/// Register administrative RPC methods (`admin_*`) onto a new module.
pub fn register_admin_rpc(state: Arc<SharedState>) -> anyhow::Result<RpcModule<Arc<SharedState>>> {
  let mut module = RpcModule::new(state.clone());

  module.register_async_method("admin_put_node", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let node_hex: String = params.parse().map_err(|_| invalid_params_error())?;
        let node_bytes = hex::decode(node_hex.trim_start_matches("0x")).map_err(|_| {
          ErrorObjectOwned::owned(-32602, "Failed to decode node hex".to_string(), None::<()>)
        })?;
        let ob = ObliviousNode::from_rlp(&node_bytes).ok_or(ErrorObjectOwned::owned(
          -32602,
          "Failed to parse node RLP into ObliviousNode".to_string(),
          None::<()>,
        ))?;
        let hh = ob.keccak_hash();
        {
          let mut guard = state.storage.lock().await;
          guard.insert(hh, ob);
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
