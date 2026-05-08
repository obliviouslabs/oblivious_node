//! Reth JSON-RPC source implementation for feeder runtime.
use std::collections::{HashMap, VecDeque};
use std::io;
use std::time::Duration;

use eth_privatestate::oblivious_node::ObliviousNode;
use eth_privatestate::state::{MissingBlockId, MissingProofQuery};
use log::warn;
use serde_json::{json, Value};
use tokio::task::JoinSet;

use crate::reth_source::{RethBlockBundle, RethNotification, RethUpdateProvider};
use crate::{FeederFuture, MissingProofBackfill, SyncLane};

const INITIAL_SYNC_BATCH_BLOCKS: u64 = 1024;
const WITNESS_FETCH_CONCURRENCY: usize = 4;
const WITNESS_FETCH_TIMEOUT: Duration = Duration::from_secs(120);

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

  async fn call_batch(&self, calls: Vec<(&str, Value)>) -> io::Result<Vec<Value>> {
    if calls.is_empty() {
      return Ok(Vec::new());
    }

    let payload: Vec<Value> = calls
      .into_iter()
      .enumerate()
      .map(
        |(id, (method, params))| json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
      )
      .collect();
    let response =
      self.client.post(&self.rpc_url).json(&payload).send().await.map_err(io_err_from)?;
    let body: Value = response.json().await.map_err(io_err_from)?;
    let responses = body.as_array().ok_or_else(|| io_err("batch response must be an array"))?;

    let mut out = vec![None; payload.len()];
    for response in responses {
      let id =
        response.get("id").and_then(Value::as_u64).ok_or_else(|| io_err("batch id missing"))?;
      let index = usize::try_from(id).map_err(io_err_from)?;
      if index >= out.len() {
        return Err(io_err(format!("batch id {} out of range", id)));
      }
      if let Some(err) = response.get("error") {
        return Err(io_err(format!("reth rpc batch error for id {}: {}", id, err)));
      }
      out[index] = Some(
        response
          .get("result")
          .cloned()
          .ok_or_else(|| io_err(format!("missing result for batch id {}", id)))?,
      );
    }

    out
      .into_iter()
      .map(|value| value.ok_or_else(|| io_err("batch response missing one or more ids")))
      .collect()
  }

  async fn block_number(&self) -> io::Result<u64> {
    let value = self.call("eth_blockNumber", json!([])).await?;
    let value = value.as_str().ok_or_else(|| io_err("eth_blockNumber must be a string"))?;
    parse_u64_hex(value)
  }

  async fn block_by_number(&self, block_number: u64) -> io::Result<BlockInfo> {
    let tag = format!("0x{:x}", block_number);
    let block = self.call("eth_getBlockByNumber", json!([tag, false])).await?;
    block_info_from_value(block, Some(block_number))
  }

  async fn blocks_by_number(&self, start: u64, end: u64) -> io::Result<Vec<BlockInfo>> {
    if start > end {
      return Ok(Vec::new());
    }

    let calls: Vec<(&str, Value)> = (start..=end)
      .map(|block_number| {
        let tag = format!("0x{:x}", block_number);
        ("eth_getBlockByNumber", json!([tag, false]))
      })
      .collect();
    let blocks = self.call_batch(calls).await?;
    blocks
      .into_iter()
      .zip(start..=end)
      .map(|(block, block_number)| block_info_from_value(block, Some(block_number)))
      .collect()
  }

  async fn block_by_hash(&self, block_hash_hex: &str) -> io::Result<BlockInfo> {
    let block = self.call("eth_getBlockByHash", json!([block_hash_hex, false])).await?;
    block_info_from_value(block, None)
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

  async fn proof_backfill_for_query(
    &self,
    query: &MissingProofQuery,
  ) -> io::Result<MissingProofBackfill> {
    let info = match &query.block {
      MissingBlockId::Number(number) => self.block_by_number(*number).await?,
      MissingBlockId::BlockHash(selector) => self.block_by_hash(&selector.block_hash).await?,
    };
    let nodes_rlp = self.proof_nodes_for_query(query).await?;
    let state_root_hex = info.state_root_hex.clone();
    Ok(MissingProofBackfill {
      nodes_rlp,
      root_by_number: Some((info.number, state_root_hex.clone())),
      root_by_hash: Some((info.hash_hex, state_root_hex)),
    })
  }
}

fn block_info_from_value(block: Value, fallback_number: Option<u64>) -> io::Result<BlockInfo> {
  if block.is_null() {
    return Err(io_err("block not found"));
  }
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
  let number = match fallback_number {
    Some(number) => number,
    None => {
      let number_hex = block
        .get("number")
        .and_then(Value::as_str)
        .ok_or_else(|| io_err("block number missing"))?;
      parse_u64_hex(number_hex)?
    }
  };

  Ok(BlockInfo { number, hash_hex, state_root_hex })
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

#[derive(Clone, Debug)]
struct StateRootRun {
  changed_from_previous: bool,
  previous_root_complete: bool,
  blocks: Vec<BlockInfo>,
}

#[derive(Clone, Copy, Debug)]
enum SourceMode {
  Bootstrap,
  LiveFromTip,
}

/// Controls how much block data the JSON-RPC feeder ingests proactively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeSyncMode {
  /// Publish block roots only; proof nodes are fetched on demand via missing-query backfill.
  RootsOnly,
  /// Publish block roots plus trie nodes from `debug_executionWitness`.
  ExecutionWitness,
}

/// Polling reth source used by feeder runtime.
pub struct RethRpcSource {
  rpc: RethRpcClient,
  mode: SourceMode,
  node_sync_mode: NodeSyncMode,
  bootstrap_tip: Option<u64>,
  bootstrap_next_block: u64,
  bootstrap_tail_blocks: Option<u64>,
  bootstrap_last_state_root_hex: Option<String>,
  bootstrap_last_state_root_complete: bool,
  next_block_number: Option<u64>,
  sync_lane: SyncLane,
}

impl RethRpcSource {
  /// Source used for startup bootstrap: emits historical canonical blocks
  /// in chunks through repeated `initial_block_bundles` calls.
  pub fn bootstrap_from_genesis(reth_rpc_url: String) -> Self {
    Self::bootstrap_from_block(reth_rpc_url, 1)
  }

  /// Source used for startup bootstrap from a specific canonical block.
  pub fn bootstrap_from_block(reth_rpc_url: String, start_block: u64) -> Self {
    Self {
      rpc: RethRpcClient::new(reth_rpc_url),
      mode: SourceMode::Bootstrap,
      node_sync_mode: NodeSyncMode::RootsOnly,
      bootstrap_tip: None,
      bootstrap_next_block: start_block.max(1),
      bootstrap_tail_blocks: None,
      bootstrap_last_state_root_hex: None,
      bootstrap_last_state_root_complete: false,
      next_block_number: None,
      sync_lane: SyncLane::Historical,
    }
  }

  /// Source used for startup bootstrap of the last `tail_blocks` at startup tip.
  pub fn bootstrap_recent(reth_rpc_url: String, tail_blocks: u64) -> Self {
    Self {
      rpc: RethRpcClient::new(reth_rpc_url),
      mode: SourceMode::Bootstrap,
      node_sync_mode: NodeSyncMode::RootsOnly,
      bootstrap_tip: None,
      bootstrap_next_block: 1,
      bootstrap_tail_blocks: Some(tail_blocks.max(1)),
      bootstrap_last_state_root_hex: None,
      bootstrap_last_state_root_complete: false,
      next_block_number: None,
      sync_lane: SyncLane::Historical,
    }
  }

  /// Source used for live syncing: starts from current tip + 1 and emits new
  /// committed blocks through `next_notification`.
  pub fn live_from_tip(reth_rpc_url: String) -> Self {
    Self {
      rpc: RethRpcClient::new(reth_rpc_url),
      mode: SourceMode::LiveFromTip,
      node_sync_mode: NodeSyncMode::RootsOnly,
      bootstrap_tip: None,
      bootstrap_next_block: 1,
      bootstrap_tail_blocks: None,
      bootstrap_last_state_root_hex: None,
      bootstrap_last_state_root_complete: false,
      next_block_number: None,
      sync_lane: SyncLane::Live,
    }
  }

  /// Source used for live syncing with a small overlap before the current tip.
  ///
  /// Re-publishing roots/nodes is idempotent and this overlap avoids small gaps
  /// between startup snapshots and live poll initialization.
  pub fn live_from_recent(reth_rpc_url: String, overlap_blocks: u64) -> Self {
    let mut source = Self::live_from_tip(reth_rpc_url);
    source.next_block_number = Some(1);
    source.bootstrap_tail_blocks = Some(overlap_blocks.max(1));
    source
  }

  /// Sets the proactive node ingestion strategy.
  pub fn with_node_sync_mode(mut self, node_sync_mode: NodeSyncMode) -> Self {
    self.node_sync_mode = node_sync_mode;
    self
  }

  /// Sets the sync lane reported with emitted bundles.
  pub fn with_sync_lane(mut self, sync_lane: SyncLane) -> Self {
    self.sync_lane = sync_lane;
    self
  }

  fn bundle_from_parts(
    &self,
    info: BlockInfo,
    nodes: Vec<Vec<u8>>,
    node_delta_complete: bool,
  ) -> RethBlockBundle {
    RethBlockBundle {
      number: info.number,
      hash_hex: info.hash_hex,
      state_root_hex: info.state_root_hex,
      changed_trie_nodes_rlp: nodes,
      sync_lane: self.sync_lane,
      node_delta_complete,
    }
  }

  async fn ensure_parent_state_root_before(&mut self, start: u64) -> io::Result<()> {
    if self.bootstrap_last_state_root_hex.is_some() || start == 0 {
      return Ok(());
    }
    let parent = start.saturating_sub(1);
    let parent_info = self.rpc.block_by_number(parent).await?;
    self.bootstrap_last_state_root_hex = Some(parent_info.state_root_hex);
    self.bootstrap_last_state_root_complete = false;
    Ok(())
  }

  async fn fetch_witness_nodes_for_blocks(
    &self,
    blocks: Vec<u64>,
  ) -> HashMap<u64, Option<Vec<Vec<u8>>>> {
    let mut pending = VecDeque::from(blocks);
    let mut tasks = JoinSet::new();
    let mut results = HashMap::new();

    while !pending.is_empty() || !tasks.is_empty() {
      while tasks.len() < WITNESS_FETCH_CONCURRENCY {
        let Some(block_number) = pending.pop_front() else {
          break;
        };
        let rpc = self.rpc.clone();
        tasks.spawn(async move {
          let result =
            tokio::time::timeout(WITNESS_FETCH_TIMEOUT, rpc.witness_nodes_for_block(block_number))
              .await;
          let result = match result {
            Ok(Ok(nodes)) => Ok(Some(nodes)),
            Ok(Err(err)) => Err(err),
            Err(_) => Ok(None),
          };
          (block_number, result)
        });
      }

      let Some(joined) = tasks.join_next().await else {
        break;
      };
      match joined {
        Ok((block_number, Ok(nodes))) => {
          if nodes.is_none() {
            warn!(
              "debug_executionWitness timed out for block {} after {:?}; publishing root without marking node delta complete",
              block_number, WITNESS_FETCH_TIMEOUT
            );
          }
          results.insert(block_number, nodes);
        }
        Ok((block_number, Err(err))) => {
          warn!(
            "debug_executionWitness failed for block {}: {}; publishing root without marking node delta complete",
            block_number, err
          );
          results.insert(block_number, None);
        }
        Err(err) => warn!("debug_executionWitness task join failed: {}", err),
      }
    }

    results
  }

  async fn fetch_execution_witness_bundles(
    &mut self,
    start: u64,
    end: u64,
  ) -> io::Result<Vec<RethBlockBundle>> {
    self.ensure_parent_state_root_before(start).await?;
    let infos = self.rpc.blocks_by_number(start, end).await?;
    let mut runs: Vec<StateRootRun> = Vec::new();
    let mut last_state_root_hex = self.bootstrap_last_state_root_hex.clone();
    let mut last_state_root_complete = self.bootstrap_last_state_root_complete;

    for info in infos {
      let root_hex = info.state_root_hex.clone();
      let changed_from_previous = last_state_root_hex.as_deref() != Some(root_hex.as_str());
      if let Some(run) = runs.last_mut().filter(|run| {
        run.blocks.last().map(|block| block.state_root_hex.as_str()) == Some(root_hex.as_str())
      }) {
        run.blocks.push(info);
      } else {
        runs.push(StateRootRun {
          changed_from_previous,
          previous_root_complete: last_state_root_complete,
          blocks: vec![info],
        });
      }
      last_state_root_hex = Some(root_hex);
      if changed_from_previous {
        last_state_root_complete = false;
      }
    }

    let witness_blocks: Vec<u64> = runs
      .iter()
      .filter(|run| run.changed_from_previous || !run.previous_root_complete)
      .filter_map(|run| run.blocks.first().map(|block| block.number))
      .collect();
    let mut witness_nodes = self.fetch_witness_nodes_for_blocks(witness_blocks).await;

    let mut out = Vec::new();
    let mut last_state_root_complete = self.bootstrap_last_state_root_complete;
    for run in runs {
      let mut blocks = run.blocks.into_iter();
      let Some(head) = blocks.next() else {
        continue;
      };
      let root_hex = head.state_root_hex.clone();

      let should_fetch_witness = run.changed_from_previous || !run.previous_root_complete;
      let (head_nodes, run_complete) = if should_fetch_witness {
        match witness_nodes.remove(&head.number).flatten() {
          Some(nodes) => (nodes, true),
          None => (Vec::new(), false),
        }
      } else {
        (Vec::new(), last_state_root_complete)
      };

      out.push(self.bundle_from_parts(head, head_nodes, run_complete));
      for block in blocks {
        out.push(self.bundle_from_parts(block, Vec::new(), run_complete));
      }

      self.bootstrap_last_state_root_hex = Some(root_hex);
      self.bootstrap_last_state_root_complete = run_complete;
      last_state_root_complete = run_complete;
    }

    Ok(out)
  }

  async fn fetch_bundles(&mut self, start: u64, end: u64) -> io::Result<Vec<RethBlockBundle>> {
    if start > end {
      return Ok(Vec::new());
    }
    match self.node_sync_mode {
      NodeSyncMode::RootsOnly => {
        let infos = self.rpc.blocks_by_number(start, end).await?;
        Ok(infos.into_iter().map(|info| self.bundle_from_parts(info, Vec::new(), false)).collect())
      }
      NodeSyncMode::ExecutionWitness => self.fetch_execution_witness_bundles(start, end).await,
    }
  }

  async fn fetch_bootstrap_bundles(
    &mut self,
    start: u64,
    end: u64,
  ) -> io::Result<Vec<RethBlockBundle>> {
    if start > end {
      return Ok(Vec::new());
    }
    match self.node_sync_mode {
      NodeSyncMode::RootsOnly => {
        let infos = self.rpc.blocks_by_number(start, end).await?;
        let last_state_root = infos.last().map(|info| info.state_root_hex.clone());
        let out =
          infos.into_iter().map(|info| self.bundle_from_parts(info, Vec::new(), false)).collect();
        self.bootstrap_last_state_root_hex = last_state_root;
        Ok(out)
      }
      NodeSyncMode::ExecutionWitness => self.fetch_execution_witness_bundles(start, end).await,
    }
  }
}

impl RethUpdateProvider for RethRpcSource {
  type Error = io::Error;

  fn initial_block_bundles(
    &mut self,
  ) -> FeederFuture<'_, Result<Vec<RethBlockBundle>, Self::Error>> {
    Box::pin(async move {
      match self.mode {
        SourceMode::Bootstrap => {
          if self.bootstrap_tip.is_none() {
            let tip = self.rpc.block_number().await?;
            self.bootstrap_tip = Some(tip);
            if let Some(tail_blocks) = self.bootstrap_tail_blocks {
              let start = tip.saturating_sub(tail_blocks.saturating_sub(1)).max(1);
              self.bootstrap_next_block = self.bootstrap_next_block.max(start);
            }
          }
          let tip = self.bootstrap_tip.unwrap_or(0);
          if tip == 0 || self.bootstrap_next_block > tip {
            return Ok(Vec::new());
          }

          let start = self.bootstrap_next_block;
          let end = start.saturating_add(INITIAL_SYNC_BATCH_BLOCKS.saturating_sub(1)).min(tip);
          let out = self.fetch_bootstrap_bundles(start, end).await?;
          self.bootstrap_next_block = out
            .last()
            .map_or_else(|| end.saturating_add(1), |block| block.number.saturating_add(1));
          Ok(out)
        }
        SourceMode::LiveFromTip => {
          if self.next_block_number.is_none() {
            let tip = self.rpc.block_number().await?;
            self.next_block_number = Some(tip.saturating_add(1));
          } else if self.next_block_number == Some(1) {
            let tip = self.rpc.block_number().await?;
            let overlap = self.bootstrap_tail_blocks.unwrap_or(1);
            let start = tip.saturating_sub(overlap.saturating_sub(1)).max(1);
            self.next_block_number = Some(start);
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
        SourceMode::Bootstrap => Ok(None),
        SourceMode::LiveFromTip => {
          if self.next_block_number.is_none() {
            let tip = self.rpc.block_number().await?;
            self.next_block_number = Some(tip.saturating_add(1));
          } else if self.next_block_number == Some(1) {
            let tip = self.rpc.block_number().await?;
            let overlap = self.bootstrap_tail_blocks.unwrap_or(1);
            let start = tip.saturating_sub(overlap.saturating_sub(1)).max(1);
            self.next_block_number = Some(start);
          }

          let next = self.next_block_number.unwrap_or(1);
          let tip = self.rpc.block_number().await?;
          if tip < next {
            return Ok(None);
          }

          let bundles = self.fetch_bundles(next, tip).await?;
          self.next_block_number = Some(
            bundles
              .last()
              .map_or_else(|| tip.saturating_add(1), |block| block.number.saturating_add(1)),
          );
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

  fn fetch_missing_proof(
    &mut self,
    query: MissingProofQuery,
  ) -> FeederFuture<'_, Result<MissingProofBackfill, Self::Error>> {
    Box::pin(async move { self.rpc.proof_backfill_for_query(&query).await })
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
