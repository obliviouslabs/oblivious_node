//! RPC methods for EthPrivateState.
//!
use std::sync::Arc;
use std::time::Instant;

use jsonrpsee::server::RpcModule;
use jsonrpsee::types::error::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::oblivious_node::VALUE_BUF;
use crate::state::{MissingBlockHashSelector, MissingBlockId, MissingProofQuery, SharedState};
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

pub(crate) fn invalid_params_error() -> ErrorObjectOwned {
  ErrorObjectOwned::owned(-32602, "Invalid params".to_string(), None::<()>)
}

fn data_non_availability_error() -> ErrorObjectOwned {
  ErrorObjectOwned::owned(-32001, "Failed due to data non availability".to_string(), None::<()>)
}

fn traversal_cap_exceeded_error() -> ErrorObjectOwned {
  ErrorObjectOwned::owned(-32002, "Failed due to traversal cap exceeded".to_string(), None::<()>)
}

fn serialization_error<E: std::fmt::Display>(err: E) -> ErrorObjectOwned {
  ErrorObjectOwned::owned(-32603, format!("Serialization error: {}", err), None::<()>)
}

pub(crate) async fn observe_rpc_result<T>(
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

pub(crate) fn decode_b256_hex(value: &str, field: &str) -> Result<B256, ErrorObjectOwned> {
  let parsed = B256::from_hex(value);
  if parsed.is_some() {
    Ok(parsed.unwrap_or_default())
  } else {
    Err(invalid_hex_error(field))
  }
}

fn decode_h160_hex(value: &str, field: &str) -> Result<H160, ErrorObjectOwned> {
  let parsed = H160::from_hex(value);
  if parsed.is_some() {
    Ok(parsed.unwrap())
  } else {
    Err(invalid_hex_error(field))
  }
}

async fn handle_proof_result(
  state: &SharedState,
  missing_query: &MissingProofQuery,
  res: Result<(), ProofError>,
) -> Result<(), ErrorObjectOwned> {
  match res {
    Ok(()) => Ok(()),
    Err(ProofError::MissingNode(_)) => {
      state.record_missing_proof_query(missing_query.clone()).await;
      Err(data_non_availability_error())
    }
    Err(ProofError::TraversalCapExceeded) => Err(traversal_cap_exceeded_error()),
  }
}

async fn resolve_root_for_selector(
  state: &SharedState,
  block_selector: BlockSelector,
) -> Result<Option<(B256, MissingBlockId)>, ErrorObjectOwned> {
  match block_selector {
    BlockSelector::Number(block_num) => {
      Ok(state.get_root(block_num).await.map(|root| (root, MissingBlockId::Number(block_num))))
    }
    BlockSelector::BlockHash(selector) => {
      if selector.require_canonical == Some(true) {
        return Err(unsupported_error("requireCanonical=true is unsupported"));
      }
      let block_hash = decode_b256_hex(&selector.block_hash, "block hash")?;
      Ok(state.get_root_by_hash(block_hash).await.map(|root| {
        (
          root,
          MissingBlockId::BlockHash(MissingBlockHashSelector {
            block_hash: block_hash.to_hex(),
            require_canonical: false,
          }),
        )
      }))
    }
    BlockSelector::Tag(tag) => match tag.as_str() {
      "latest" => Ok(
        state
          .get_latest_root_with_number()
          .await
          .map(|(number, root)| (root, MissingBlockId::Number(number))),
      ),
      _ => Err(unsupported_error("Unsupported block tag")),
    },
  }
}

/// Register public RPC methods (`eth_*`) onto a new module.
pub fn register_public_rpc(state: Arc<SharedState>) -> anyhow::Result<RpcModule<Arc<SharedState>>> {
  let mut module = RpcModule::new(state.clone());

  module.register_async_method("eth_getProof", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let started = Instant::now();
      let res = match params.parse::<GetProofParams>() {
        Ok(p) => eth_get_proof_handler(p, state.clone()).await,
        Err(_) => Err(invalid_params_error()),
      };
      observe_rpc_result(state.as_ref(), "eth_getProof", started, &res).await;
      res
    }
  })?;

  Ok(module)
}

/// Register all methods in one module (used by unit/integration tests).
pub fn register_rpc(state: Arc<SharedState>) -> anyhow::Result<RpcModule<Arc<SharedState>>> {
  let mut module = register_public_rpc(state.clone())?;
  module.merge(crate::rpc_admin::register_admin_rpc(state)?)?;
  Ok(module)
}

pub async fn eth_get_proof_handler(
  params: GetProofParams,
  state: Arc<SharedState>,
) -> Result<EthGetProofResultBoxed, ErrorObjectOwned> {
  let GetProofParams(address_hex, storage_keys, block_selector) = params;

  // Parse all public request fields before touching trie state.
  let parsed_address = decode_h160_hex(&address_hex, "address")?;
  let address_hex = parsed_address.to_hex();
  let address = parsed_address.keccak_hash();
  let mut parsed_storage_keys: Vec<(String, B256)> = Vec::with_capacity(storage_keys.len());
  let mut missing_storage_keys: Vec<String> = Vec::with_capacity(storage_keys.len());
  for key_hex in storage_keys {
    let key = decode_b256_hex(&key_hex, "storage key")?;
    let key_hash = key.keccak_hash();
    missing_storage_keys.push(key.to_hex());
    parsed_storage_keys.push((key_hex, key_hash));
  }

  // get root for the requested block selector
  let root_with_selector = resolve_root_for_selector(state.as_ref(), block_selector).await?;
  let (root, missing_block) = root_with_selector.ok_or_else(data_non_availability_error)?;
  let missing_query = MissingProofQuery {
    address: address_hex,
    storage_keys: missing_storage_keys,
    block: missing_block,
  };

  // generate account proof; if missing -> error
  let mut ret_proof = String::new();
  let mut ret_value = [0u8; VALUE_BUF];
  handle_proof_result(
    state.as_ref(),
    &missing_query,
    trie::generate_proof::<64>(
      &state.storage,
      root,
      &address.to_nibbles(),
      &mut ret_proof,
      &mut ret_value,
    )
    .await,
  )
  .await?;

  let account_proof_rv = RawValue::from_string(ret_proof).map_err(serialization_error)?;

  let (nonce, balance, storage_hash, code_hash) = parse_account(ret_value.as_slice());

  let mut storage_proofs = Vec::new();
  for (key_hex, key_hash) in parsed_storage_keys {
    let mut ret_proof = String::new();
    let mut ret_value = [0u8; VALUE_BUF];
    handle_proof_result(
      state.as_ref(),
      &missing_query,
      trie::generate_proof::<64>(
        &state.storage,
        storage_hash,
        &key_hash.to_nibbles(),
        &mut ret_proof,
        &mut ret_value,
      )
      .await,
    )
    .await?;
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::oblivious_node::ObliviousNode;
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
