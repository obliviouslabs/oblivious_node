//! RPC methods for EthPrivateState.
//!
use std::sync::Arc;
use std::time::Instant;

use jsonrpsee::server::{RpcModule, ServerBuilder};
use jsonrpsee::types::error::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::oblivious_node::{ObliviousNode, VALUE_BUF};
use crate::state::SharedState;
use crate::trie::{self, parse_account, ProofError};
use crate::types::{B256, H160};

#[derive(Clone, Deserialize, Debug)]
pub struct BlockHashSelector {
  #[serde(rename = "blockHash")]
  pub block_hash: String,
  #[serde(default, rename = "requireCanonical")]
  pub require_canonical: Option<bool>,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(untagged)]
pub enum BlockSelector {
  /// Block number selector (e.g. `1`).
  Number(u64),
  /// Block hash selector object (e.g. `{"blockHash":"0x...", "requireCanonical": false}`).
  BlockHash(BlockHashSelector),
  /// Named block selector tag (currently only `"latest"`).
  Tag(String),
}

/// RPC params for `eth_getProof`: (address, storage_keys, block_selector)
#[derive(Deserialize, Debug)]
pub struct GetProofParams(pub String, pub Vec<String>, pub BlockSelector);

#[derive(Clone, Serialize, Debug)]
pub struct StorageProofBoxed {
  pub key: String,
  pub value: Box<RawValue>,
  pub proof: Box<RawValue>,
}
#[derive(Clone, Serialize, Debug)]
pub struct StorageProof {
  pub key: String,
  pub value: String,
  pub proof: Vec<String>,
}

#[derive(Clone, Serialize, Debug)]
pub struct EthGetProofResultBoxed {
  pub nonce: Box<RawValue>,
  pub balance: Box<RawValue>,
  #[serde(rename = "storageHash")]
  pub storage_hash: String,
  #[serde(rename = "codeHash")]
  pub code_hash: String,
  #[serde(rename = "accountProof")]
  pub account_proof: Box<RawValue>,
  #[serde(rename = "storageProof")]
  pub storage_proof: Vec<StorageProofBoxed>,
}
#[derive(Clone, Serialize, Debug)]
pub struct EthGetProofResult {
  pub nonce: String,
  pub balance: String,
  #[serde(rename = "storageHash")]
  pub storage_hash: String,
  #[serde(rename = "codeHash")]
  pub code_hash: String,
  #[serde(rename = "accountProof")]
  pub account_proof: Vec<String>,
  #[serde(rename = "storageProof")]
  pub storage_proof: Vec<StorageProof>,
}

fn invalid_hex_error(field: &str) -> ErrorObjectOwned {
  ErrorObjectOwned::owned(-32602, format!("Failed to decode {} hex", field), None::<()>)
}

fn unsupported_error(message: &str) -> ErrorObjectOwned {
  ErrorObjectOwned::owned(-32602, message.to_string(), None::<()>)
}

fn data_non_availability_error() -> ErrorObjectOwned {
  ErrorObjectOwned::owned(-32001, "Failed due to data non availability".to_string(), None::<()>)
}

fn traversal_cap_exceeded_error() -> ErrorObjectOwned {
  ErrorObjectOwned::owned(-32002, "Failed due to traversal cap exceeded".to_string(), None::<()>)
}

fn map_proof_error(err: ProofError) -> ErrorObjectOwned {
  match err {
    ProofError::MissingNode => data_non_availability_error(),
    ProofError::TraversalCapExceeded => traversal_cap_exceeded_error(),
  }
}

fn serialization_error<E: std::fmt::Display>(err: E) -> ErrorObjectOwned {
  ErrorObjectOwned::owned(-32603, format!("Serialization error: {}", err), None::<()>)
}

async fn observe_rpc_result<T>(
  state: &SharedState,
  method: &'static str,
  started: Instant,
  res: &Result<T, ErrorObjectOwned>,
) {
  let ok = res.is_ok();
  let err_code = if ok { 0 } else { res.as_ref().err().map(|e| e.code()).unwrap_or_default() };
  let latency_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;

  {
    let mut metrics = state.metrics.lock().await;
    metrics.record_oblivious(ok, err_code, latency_us);
  }
  log::info!(
    "event=rpc_call method={} status={} code={} latency_us={}",
    method,
    if ok { "ok" } else { "err" },
    err_code,
    latency_us
  );
}

fn decode_b256_hex(value: &str, field: &str) -> Result<B256, ErrorObjectOwned> {
  let parsed = B256::from_hex(value);
  if !parsed.is_some() {
    return Err(invalid_hex_error(field));
  }
  Ok(parsed.unwrap_or_default())
}

fn decode_h160_hex(value: &str, field: &str) -> Result<H160, ErrorObjectOwned> {
  let parsed = H160::from_hex(value);
  if !parsed.is_some() {
    return Err(invalid_hex_error(field));
  }
  Ok(parsed.unwrap())
}

async fn resolve_root_for_selector(
  state: &SharedState,
  block_selector: BlockSelector,
) -> Result<Option<B256>, ErrorObjectOwned> {
  match block_selector {
    BlockSelector::Number(block_num) => Ok(state.get_root(block_num).await),
    BlockSelector::BlockHash(selector) => {
      if selector.require_canonical == Some(true) {
        return Err(unsupported_error("requireCanonical=true is unsupported"));
      }
      let block_hash = decode_b256_hex(&selector.block_hash, "block hash")?;
      Ok(state.get_root_by_hash(block_hash).await)
    }
    BlockSelector::Tag(tag) => match tag.as_str() {
      "latest" => Ok(state.get_latest_root().await),
      _ => Err(unsupported_error("Unsupported block tag")),
    },
  }
}

/// Register all RPC methods onto a new `RpcModule` using the provided `state`.
pub fn register_rpc(state: Arc<SharedState>) -> anyhow::Result<RpcModule<Arc<SharedState>>> {
  let mut module = RpcModule::new(state.clone());

  module.register_async_method("eth_getProof", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res = match params.parse::<GetProofParams>() {
        Ok(p) => eth_get_proof_handler(p, state.clone()).await,
        Err(_) => Err(ErrorObjectOwned::owned(-32602, "Invalid params".to_string(), None::<()>)),
      };
      observe_rpc_result(state.as_ref(), "eth_getProof", started, &res).await;
      res
    }
  })?;

  // Administrative helper to put a raw node and set it as the root for a block.
  // Params: (block_number: u64, node_rlp_hex: String)
  module.register_async_method("admin_put_node", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let node_hex: String = params
          .parse()
          .map_err(|_| ErrorObjectOwned::owned(-32602, "Invalid params".to_string(), None::<()>))?;
        let node_bytes = hex::decode(node_hex.trim_start_matches("0x")).map_err(|_| {
          ErrorObjectOwned::owned(-32602, "Failed to decode node hex".to_string(), None::<()>)
        })?;
        // Parse RLP into ObliviousNode and insert into in-memory storage
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

  module.register_async_method("admin_set_root", move |paramst, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let (block_num, root_hex): (u64, String) = paramst
          .parse()
          .map_err(|_| ErrorObjectOwned::owned(-32602, "Invalid params".to_string(), None::<()>))?;
        let root_b256 = decode_b256_hex(&root_hex, "root")?;
        state.set_root(block_num, root_b256).await;
        Ok::<_, ErrorObjectOwned>(true)
      }
      .await;
      observe_rpc_result(state.as_ref(), "admin_set_root", started, &res).await;
      res
    }
  })?;

  module.register_async_method("admin_set_root_by_hash", move |paramst, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res: Result<bool, ErrorObjectOwned> = async {
        let (block_hash_hex, root_hex): (String, String) = paramst
          .parse()
          .map_err(|_| ErrorObjectOwned::owned(-32602, "Invalid params".to_string(), None::<()>))?;
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

  Ok(module)
}

pub async fn eth_get_proof_handler(
  params: GetProofParams,
  state: Arc<SharedState>,
) -> Result<EthGetProofResultBoxed, ErrorObjectOwned> {
  let GetProofParams(address_hex, storage_keys, block_selector) = params;

  // Parse all public request fields before touching trie state.
  let address = decode_h160_hex(&address_hex, "address")?.keccak_hash();
  let mut parsed_storage_keys: Vec<(String, B256)> = Vec::with_capacity(storage_keys.len());
  for key_hex in storage_keys {
    let key_hash = decode_b256_hex(&key_hex, "storage key")?.keccak_hash();
    parsed_storage_keys.push((key_hex, key_hash));
  }

  // get root for the requested block selector
  let root_opt = resolve_root_for_selector(state.as_ref(), block_selector).await?;
  let root = root_opt.ok_or_else(data_non_availability_error)?;

  // generate account proof; if missing -> error
  let mut ret_proof = String::new();
  let mut ret_value = [0u8; VALUE_BUF];
  trie::generate_proof::<64>(
    &state.storage,
    root,
    &address.to_nibbles(),
    &mut ret_proof,
    &mut ret_value,
  )
  .await
  .map_err(map_proof_error)?;

  let account_proof_rv = RawValue::from_string(ret_proof).map_err(serialization_error)?;

  let (nonce, balance, storage_hash, code_hash) = parse_account(ret_value.as_slice());

  let mut storage_proofs = Vec::new();
  for (key_hex, key_hash) in parsed_storage_keys {
    let mut ret_proof = String::new();
    let mut ret_value = [0u8; VALUE_BUF];
    trie::generate_proof::<64>(
      &state.storage,
      storage_hash,
      &key_hash.to_nibbles(),
      &mut ret_proof,
      &mut ret_value,
    )
    .await
    .map_err(map_proof_error)?;
    let proof_rv = RawValue::from_string(ret_proof).map_err(serialization_error)?;

    let value_rv = trie::parse_value(ret_value.as_slice());
    let value_rv = RawValue::from_string(value_rv).map_err(serialization_error)?;
    storage_proofs.push(StorageProofBoxed { key: key_hex, value: value_rv, proof: proof_rv });
  }

  let nonce_rv = RawValue::from_string(nonce).map_err(serialization_error)?;
  let balance_rv = RawValue::from_string(balance).map_err(serialization_error)?;

  let result = EthGetProofResultBoxed {
    nonce: nonce_rv,
    balance: balance_rv,
    storage_hash: storage_hash.to_hex(),
    code_hash: code_hash.to_hex(),
    account_proof: account_proof_rv,
    storage_proof: storage_proofs,
  };

  Ok(result)
}

pub async fn start_rpc(state: Arc<SharedState>) -> anyhow::Result<()> {
  let addr = "127.0.0.1:8545";
  let server = ServerBuilder::default().build(addr).await?;

  let module = register_rpc(state.clone())?;
  let local_addr = server.local_addr().ok();

  let handle = server.start(module);

  if let Some(addr) = local_addr {
    log::info!("Server listening on {}", addr);
  } else {
    log::info!("Server started with no local addr available");
  }

  handle.stopped().await;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use rlp::RlpStream;
  use std::sync::Arc;

  #[tokio::test]
  async fn test_missing_root_returns_error() {
    let state = Arc::new(SharedState::new(1 << 10));
    let params = GetProofParams(
      "0x0000000000000000000000000000000000000000".to_string(),
      vec![],
      BlockSelector::Number(42),
    );
    let res = eth_get_proof_handler(params, state).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    let msg = format!("{:?}", err);
    assert!(msg.contains("Failed due to data non availability"));
  }

  #[tokio::test]
  async fn test_missing_node_maps_to_data_non_availability_error() {
    let state = Arc::new(SharedState::new(1 << 10));
    // Set a root that does not exist in `state.storage`.
    state.set_root(1, B256([0x11; 32])).await;
    let params = GetProofParams(
      "0x0000000000000000000000000000000000000000".to_string(),
      vec![],
      BlockSelector::Number(1),
    );
    let res = eth_get_proof_handler(params, state).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.code(), -32001);
    assert!(err.message().contains("data non availability"));
  }

  #[tokio::test]
  async fn test_traversal_cap_maps_to_traversal_cap_error() {
    let state = Arc::new(SharedState::new(1 << 10));

    // Build one branch node where every child points to `child_hash`.
    // Inserting the same node under both `root_hash` and `child_hash` creates
    // a cycle that always advances one nibble per step until max slots are hit.
    let child_hash = [0x77u8; 32];
    let mut s = RlpStream::new_list(17);
    for _ in 0..16 {
      s.append(&child_hash.as_ref());
    }
    s.append(&"");
    let node_bytes = s.out();
    let ob = ObliviousNode::from_rlp(&node_bytes).unwrap();
    let root_hash = ob.keccak_hash();
    {
      let mut guard = state.storage.lock().await;
      guard.insert(root_hash, ob);
      guard.insert(B256(child_hash), ob);
    }
    state.set_root(1, root_hash).await;

    let params = GetProofParams(
      "0x0000000000000000000000000000000000000000".to_string(),
      vec![],
      BlockSelector::Number(1),
    );
    let res = eth_get_proof_handler(params, state).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.code(), -32002);
    assert!(err.message().contains("traversal cap exceeded"));
  }

  #[tokio::test]
  async fn test_invalid_address_returns_invalid_params_error() {
    let state = Arc::new(SharedState::new(1 << 10));
    let params = GetProofParams("0x1234".to_string(), vec![], BlockSelector::Number(42));
    let res = eth_get_proof_handler(params, state).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.code(), -32602);
    assert!(err.message().contains("Failed to decode address hex"));
  }

  #[tokio::test]
  async fn test_invalid_storage_key_returns_invalid_params_error() {
    let state = Arc::new(SharedState::new(1 << 10));
    let params = GetProofParams(
      "0x0000000000000000000000000000000000000000".to_string(),
      vec!["0x1234".to_string()],
      BlockSelector::Number(42),
    );
    let res = eth_get_proof_handler(params, state).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.code(), -32602);
    assert!(err.message().contains("Failed to decode storage key hex"));
  }

  #[tokio::test]
  async fn test_require_canonical_true_is_unsupported() {
    let state = Arc::new(SharedState::new(1 << 10));
    let params = GetProofParams(
      "0x0000000000000000000000000000000000000000".to_string(),
      vec![],
      BlockSelector::BlockHash(BlockHashSelector {
        block_hash: B256::zero().to_hex(),
        require_canonical: Some(true),
      }),
    );
    let res = eth_get_proof_handler(params, state).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.code(), -32602);
    assert!(err.message().contains("requireCanonical=true is unsupported"));
  }

  #[tokio::test]
  async fn test_invalid_block_hash_selector_returns_invalid_params_error() {
    let state = Arc::new(SharedState::new(1 << 10));
    let params = GetProofParams(
      "0x0000000000000000000000000000000000000000".to_string(),
      vec![],
      BlockSelector::BlockHash(BlockHashSelector {
        block_hash: "0x1234".to_string(),
        require_canonical: Some(false),
      }),
    );
    let res = eth_get_proof_handler(params, state).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.code(), -32602);
    assert!(err.message().contains("Failed to decode block hash hex"));
  }

  #[tokio::test]
  async fn test_block_hash_selector_without_mapped_root_returns_data_non_availability_error() {
    let state = Arc::new(SharedState::new(1 << 10));
    let params = GetProofParams(
      "0x0000000000000000000000000000000000000000".to_string(),
      vec![],
      BlockSelector::BlockHash(BlockHashSelector {
        block_hash: B256([0x22; 32]).to_hex(),
        require_canonical: Some(false),
      }),
    );
    let res = eth_get_proof_handler(params, state).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.code(), -32001);
    assert!(err.message().contains("data non availability"));
  }

  #[tokio::test]
  async fn test_latest_tag_without_root_returns_data_non_availability_error() {
    let state = Arc::new(SharedState::new(1 << 10));
    let params = GetProofParams(
      "0x0000000000000000000000000000000000000000".to_string(),
      vec![],
      BlockSelector::Tag("latest".to_string()),
    );
    let res = eth_get_proof_handler(params, state).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.code(), -32001);
    assert!(err.message().contains("data non availability"));
  }

  #[tokio::test]
  async fn test_unsupported_block_tag_returns_invalid_params_error() {
    let state = Arc::new(SharedState::new(1 << 10));
    let params = GetProofParams(
      "0x0000000000000000000000000000000000000000".to_string(),
      vec![],
      BlockSelector::Tag("earliest".to_string()),
    );
    let res = eth_get_proof_handler(params, state).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.code(), -32602);
    assert!(err.message().contains("Unsupported block tag"));
  }
}
