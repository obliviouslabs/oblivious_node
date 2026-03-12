//! Reth JSON-RPC source implementation for feeder runtime.
use std::io;

use eth_privatestate::oblivious_node::ObliviousNode;
use eth_privatestate::state::{MissingBlockId, MissingProofQuery};
use serde_json::{json, Value};

use crate::reth_source::{RethBlockBundle, RethNotification, RethUpdateProvider};
use crate::FeederFuture;

const INITIAL_SYNC_BATCH_BLOCKS: u64 = 128;

#[derive(Clone)]
struct RethRpcClient {
  rpc_url: String,
  client: reqwest::Client,
}

impl RethRpcClient {
  fn new(rpc_url: String) -> Self {
    Self { rpc_url, client: reqwest::Client::new() }
  }

  async fn call(&self, method: &str, params: Value) -> io::Result<Value> {
    let payload = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    let response =
      self.client.post(&self.rpc_url).json(&payload).send().await.map_err(io_err_from)?;

    let body: Value = response.json().await.map_err(io_err_from)?;
    if let Some(err) = body.get("error") {
      return Err(io_err(format!("reth rpc error for {}: {}", method, err)));
    }

    body
      .get("result")
      .cloned()
      .ok_or_else(|| io_err(format!("missing result for method {}", method)))
  }

  async fn block_number(&self) -> io::Result<u64> {
    let value = self.call("eth_blockNumber", json!([])).await?;
    let value = value.as_str().ok_or_else(|| io_err("eth_blockNumber must be a string"))?;
    parse_u64_hex(value)
  }

  async fn block_by_number(&self, block_number: u64) -> io::Result<BlockInfo> {
    let tag = format!("0x{:x}", block_number);
    let block = self.call("eth_getBlockByNumber", json!([tag, false])).await?;

    let hash_hex = block
      .get("hash")
      .and_then(Value::as_str)
      .ok_or_else(|| io_err("block hash missing"))?
      .to_string();
    let state_root_hex = block
      .get("stateRoot")
      .and_then(Value::as_str)
      .ok_or_else(|| io_err("block stateRoot missing"))?
      .to_string();

    Ok(BlockInfo { number: block_number, hash_hex, state_root_hex })
  }

  async fn witness_nodes_for_block(&self, block_number: u64) -> io::Result<Vec<Vec<u8>>> {
    let tag = format!("0x{:x}", block_number);
    let witness = self.call("debug_executionWitness", json!([tag])).await?;
    let state = witness
      .get("state")
      .and_then(Value::as_array)
      .ok_or_else(|| io_err("debug_executionWitness.result.state missing"))?;

    let mut out = Vec::new();

    for entry in state {
      let node_hex = entry.as_str().ok_or_else(|| io_err("witness node entry must be string"))?;
      let node_rlp = decode_hex(node_hex)?;

      // Witness may contain non-trie data entries.
      if ObliviousNode::from_rlp(&node_rlp).is_some() {
        out.push(node_rlp);
      }
    }

    Ok(out)
  }

  async fn proof_nodes_for_query(&self, query: &MissingProofQuery) -> io::Result<Vec<Vec<u8>>> {
    let block_selector = match &query.block {
      MissingBlockId::Number(number) => json!(format!("0x{:x}", number)),
      MissingBlockId::BlockHash(selector) => {
        json!({"blockHash": selector.block_hash, "requireCanonical": selector.require_canonical})
      }
    };

    let proof =
      self.call("eth_getProof", json!([query.address, query.storage_keys, block_selector])).await?;

    let mut out = Vec::new();

    let account_proof = proof
      .get("accountProof")
      .and_then(Value::as_array)
      .ok_or_else(|| io_err("eth_getProof.accountProof missing"))?;
    collect_proof_nodes(account_proof, &mut out)?;

    let storage_proofs = proof
      .get("storageProof")
      .and_then(Value::as_array)
      .ok_or_else(|| io_err("eth_getProof.storageProof missing"))?;
    for storage in storage_proofs {
      let storage_nodes = storage
        .get("proof")
        .and_then(Value::as_array)
        .ok_or_else(|| io_err("eth_getProof.storageProof[i].proof missing"))?;
      collect_proof_nodes(storage_nodes, &mut out)?;
    }

    Ok(out)
  }
}

fn collect_proof_nodes(entries: &[Value], out: &mut Vec<Vec<u8>>) -> io::Result<()> {
  for entry in entries {
    let node_hex = entry.as_str().ok_or_else(|| io_err("proof node entry must be string"))?;
    let node_rlp = decode_hex(node_hex)?;
    if ObliviousNode::from_rlp(&node_rlp).is_some() {
      out.push(node_rlp);
    }
  }
  Ok(())
}

#[derive(Clone, Debug)]
struct BlockInfo {
  number: u64,
  hash_hex: String,
  state_root_hex: String,
}

#[derive(Clone, Copy, Debug)]
enum SourceMode {
  BootstrapFromGenesis,
  LiveFromTip,
}

/// Polling reth source used by feeder runtime.
pub struct RethRpcSource {
  rpc: RethRpcClient,
  mode: SourceMode,
  bootstrap_tip: Option<u64>,
  bootstrap_next_block: u64,
  next_block_number: Option<u64>,
}

impl RethRpcSource {
  /// Source used for startup bootstrap: emits historical canonical blocks
  /// in chunks through repeated `initial_block_bundles` calls.
  pub fn bootstrap_from_genesis(reth_rpc_url: String) -> Self {
    Self {
      rpc: RethRpcClient::new(reth_rpc_url),
      mode: SourceMode::BootstrapFromGenesis,
      bootstrap_tip: None,
      bootstrap_next_block: 1,
      next_block_number: None,
    }
  }

  /// Source used for live syncing: starts from current tip + 1 and emits new
  /// committed blocks through `next_notification`.
  pub fn live_from_tip(reth_rpc_url: String) -> Self {
    Self {
      rpc: RethRpcClient::new(reth_rpc_url),
      mode: SourceMode::LiveFromTip,
      bootstrap_tip: None,
      bootstrap_next_block: 1,
      next_block_number: None,
    }
  }

  fn bundle_from_parts(&self, info: BlockInfo, nodes: Vec<Vec<u8>>) -> RethBlockBundle {
    RethBlockBundle {
      number: info.number,
      hash_hex: info.hash_hex,
      state_root_hex: info.state_root_hex,
      changed_trie_nodes_rlp: nodes,
    }
  }

  async fn fetch_bundle(&self, block_number: u64) -> io::Result<RethBlockBundle> {
    let info = self.rpc.block_by_number(block_number).await?;
    let nodes = self.rpc.witness_nodes_for_block(block_number).await?;
    Ok(self.bundle_from_parts(info, nodes))
  }
}

impl RethUpdateProvider for RethRpcSource {
  type Error = io::Error;

  fn initial_block_bundles(
    &mut self,
  ) -> FeederFuture<'_, Result<Vec<RethBlockBundle>, Self::Error>> {
    Box::pin(async move {
      match self.mode {
        SourceMode::BootstrapFromGenesis => {
          if self.bootstrap_tip.is_none() {
            self.bootstrap_tip = Some(self.rpc.block_number().await?);
          }
          let tip = self.bootstrap_tip.unwrap_or(0);
          if tip == 0 || self.bootstrap_next_block > tip {
            return Ok(Vec::new());
          }

          let start = self.bootstrap_next_block;
          let end = start.saturating_add(INITIAL_SYNC_BATCH_BLOCKS.saturating_sub(1)).min(tip);
          let mut out = Vec::with_capacity((end - start + 1) as usize);
          for block_number in start..=end {
            out.push(self.fetch_bundle(block_number).await?);
          }
          self.bootstrap_next_block = end.saturating_add(1);
          Ok(out)
        }
        SourceMode::LiveFromTip => {
          if self.next_block_number.is_none() {
            let tip = self.rpc.block_number().await?;
            self.next_block_number = Some(tip.saturating_add(1));
          }
          Ok(Vec::new())
        }
      }
    })
  }

  fn next_notification(
    &mut self,
  ) -> FeederFuture<'_, Result<Option<RethNotification>, Self::Error>> {
    Box::pin(async move {
      match self.mode {
        SourceMode::BootstrapFromGenesis => Ok(None),
        SourceMode::LiveFromTip => {
          if self.next_block_number.is_none() {
            let tip = self.rpc.block_number().await?;
            self.next_block_number = Some(tip.saturating_add(1));
          }

          let next = self.next_block_number.unwrap_or(1);
          let tip = self.rpc.block_number().await?;
          if tip < next {
            return Ok(None);
          }

          let mut bundles = Vec::with_capacity((tip - next + 1) as usize);
          for block_number in next..=tip {
            bundles.push(self.fetch_bundle(block_number).await?);
          }
          self.next_block_number = Some(tip.saturating_add(1));
          Ok(Some(RethNotification::Committed(bundles)))
        }
      }
    })
  }

  fn fetch_missing_proof_nodes(
    &mut self,
    query: MissingProofQuery,
  ) -> FeederFuture<'_, Result<Vec<Vec<u8>>, Self::Error>> {
    Box::pin(async move { self.rpc.proof_nodes_for_query(&query).await })
  }
}

fn decode_hex(prefixed_hex: &str) -> io::Result<Vec<u8>> {
  let raw = prefixed_hex.strip_prefix("0x").unwrap_or(prefixed_hex);
  hex::decode(raw).map_err(io_err_from)
}

fn parse_u64_hex(value: &str) -> io::Result<u64> {
  let raw = value.strip_prefix("0x").unwrap_or(value);
  u64::from_str_radix(raw, 16).map_err(io_err_from)
}

fn io_err(msg: impl Into<String>) -> io::Error {
  io::Error::other(msg.into())
}

fn io_err_from<E: std::fmt::Display>(err: E) -> io::Error {
  io::Error::other(err.to_string())
}
