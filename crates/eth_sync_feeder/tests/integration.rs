//! End-to-end feeder integration test against real `reth --dev` and in-process
//! `eth_privatestate`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

use eth_privatestate::frontend::start_rpc_server;
use eth_privatestate::oblivious_node::ObliviousNode;
use eth_privatestate::state::{
  MissingBlockHashSelector, MissingBlockId, MissingProofQuery, SharedState,
};
use eth_privatestate::types::B256;
use eth_sync_feeder::admin_rpc_sink::HttpAdminSink;
use eth_sync_feeder::reth_source::{
  RethBlockBundle, RethNotification, RethSourceAdapter, RethUpdateProvider,
};
use eth_sync_feeder::{FeederFuture, RethSyncClient};
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::{
  Address as EthAddress, Bytes as EthBytes, NameOrAddress, Signature, TransactionRequest, U256,
};
use ethers_signers::coins_bip39::English;
use ethers_signers::{LocalWallet, MnemonicBuilder, Signer};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tokio::process::{Child, Command};
use tokio::time::{sleep, Duration};

const RETH_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(20);
const PROOF_WAIT_TIMEOUT: Duration = Duration::from_secs(20);
const SLOT_0_HEX: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const DEV_MNEMONIC: &str = "test test test test test test test test test test test junk";

#[derive(Clone)]
struct RethRpcClient {
  rpc_url: String,
  client: reqwest::Client,
}

impl RethRpcClient {
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

  async fn wait_ready(&self) -> io::Result<()> {
    let started = tokio::time::Instant::now();
    while started.elapsed() < RETH_STARTUP_TIMEOUT {
      if self.call("eth_chainId", json!([])).await.is_ok() {
        return Ok(());
      }
      sleep(Duration::from_millis(100)).await;
    }
    Err(io_err("reth did not become ready in time"))
  }

  async fn chain_id(&self) -> io::Result<u64> {
    let value = self.call("eth_chainId", json!([])).await?;
    parse_u64_hex(value.as_str().ok_or_else(|| io_err("eth_chainId must be string"))?)
  }

  async fn gas_price(&self) -> io::Result<u64> {
    let value = self.call("eth_gasPrice", json!([])).await?;
    parse_u64_hex(value.as_str().ok_or_else(|| io_err("eth_gasPrice must be string"))?)
  }

  async fn nonce_for_address(&self, address_hex: &str) -> io::Result<u64> {
    let value = self.call("eth_getTransactionCount", json!([address_hex, "latest"])).await?;
    parse_u64_hex(
      value.as_str().ok_or_else(|| io_err("eth_getTransactionCount must return a string"))?,
    )
  }

  async fn send_raw_transaction(&self, raw_tx_hex: &str) -> io::Result<String> {
    let tx_hash = self.call("eth_sendRawTransaction", json!([raw_tx_hex])).await?;
    tx_hash.as_str().map(|s| s.to_string()).ok_or_else(|| io_err("tx hash must be string"))
  }

  async fn send_signed_legacy_transaction(
    &self,
    wallet: &LocalWallet,
    nonce: u64,
    to: Option<EthAddress>,
    data: Vec<u8>,
  ) -> io::Result<String> {
    let chain_id = self.chain_id().await?;
    let gas_price = self.gas_price().await?;

    let mut req = TransactionRequest::new();
    req.from = Some(wallet.address());
    req.to = to.map(NameOrAddress::Address);
    req.nonce = Some(U256::from(nonce));
    req.gas = Some(U256::from(3_000_000u64));
    req.gas_price = Some(U256::from(gas_price));
    req.value = Some(U256::zero());
    req.data = Some(EthBytes::from(data));
    req.chain_id = Some(chain_id.into());

    let tx = TypedTransaction::Legacy(req);
    let signer = wallet.clone().with_chain_id(chain_id);
    let signature: Signature = signer.sign_transaction(&tx).await.map_err(io_err_from)?;
    let raw = tx.rlp_signed(&signature);
    let raw_hex = format!("0x{}", hex::encode(raw));
    self.send_raw_transaction(&raw_hex).await
  }

  async fn wait_for_receipt(&self, tx_hash: &str) -> io::Result<Value> {
    let started = tokio::time::Instant::now();
    while started.elapsed() < RECEIPT_TIMEOUT {
      let receipt = self.call("eth_getTransactionReceipt", json!([tx_hash])).await?;
      if !receipt.is_null() {
        return Ok(receipt);
      }
      sleep(Duration::from_millis(100)).await;
    }
    Err(io_err("timed out waiting for transaction receipt"))
  }

  async fn deploy_storage_writer_contract(
    &self,
    wallet: &LocalWallet,
    nonce: u64,
  ) -> io::Result<(String, u64)> {
    // Runtime: 0x60003560005500 -> sstore(0, calldataload(0)); stop
    // Init: copies/returns runtime.
    let init_code = decode_hex("0x6007600c60003960076000f360003560005500")?;
    let tx_hash = self.send_signed_legacy_transaction(wallet, nonce, None, init_code).await?;
    let receipt = self.wait_for_receipt(&tx_hash).await?;
    if !receipt_status_success(&receipt)? {
      return Err(io_err(format!("deploy tx failed: {}", receipt)));
    }
    let contract = receipt
      .get("contractAddress")
      .and_then(Value::as_str)
      .ok_or_else(|| io_err("contractAddress missing from deploy receipt"))?
      .to_string();
    let block_number = parse_u64_hex(
      receipt
        .get("blockNumber")
        .and_then(Value::as_str)
        .ok_or_else(|| io_err("blockNumber missing from deploy receipt"))?,
    )?;
    Ok((contract, block_number))
  }

  async fn set_contract_slot0_u64(
    &self,
    wallet: &LocalWallet,
    nonce: u64,
    contract: &str,
    value: u64,
  ) -> io::Result<u64> {
    let calldata = decode_hex(&format!("0x{:064x}", value))?;
    let contract_address = contract
      .parse::<EthAddress>()
      .map_err(|e| io_err(format!("invalid contract address: {}", e)))?;
    let tx_hash =
      self.send_signed_legacy_transaction(wallet, nonce, Some(contract_address), calldata).await?;
    let receipt = self.wait_for_receipt(&tx_hash).await?;
    if !receipt_status_success(&receipt)? {
      return Err(io_err(format!("slot write tx failed: {}", receipt)));
    }
    parse_u64_hex(
      receipt
        .get("blockNumber")
        .and_then(Value::as_str)
        .ok_or_else(|| io_err("blockNumber missing from call receipt"))?,
    )
  }

  async fn block_by_number(&self, block_number: u64) -> io::Result<BlockInfo> {
    let tag = format!("0x{:x}", block_number);
    let block = self.call("eth_getBlockByNumber", json!([tag, false])).await?;
    let hash_hex =
      block.get("hash").and_then(Value::as_str).ok_or_else(|| io_err("block hash missing"))?;
    let state_root_hex = block
      .get("stateRoot")
      .and_then(Value::as_str)
      .ok_or_else(|| io_err("block stateRoot missing"))?;
    Ok(BlockInfo {
      number: block_number,
      hash_hex: hash_hex.to_string(),
      state_root_hex: state_root_hex.to_string(),
    })
  }

  async fn witness_nodes_for_block(&self, block_number: u64) -> io::Result<Vec<Vec<u8>>> {
    let tag = format!("0x{:x}", block_number);
    let witness = self.call("debug_executionWitness", json!([tag])).await?;
    let state = witness
      .get("state")
      .and_then(Value::as_array)
      .ok_or_else(|| io_err("debug_executionWitness.result.state missing"))?;

    let mut out = Vec::new();
    let mut seen_hashes = HashSet::new();
    for entry in state {
      let node_hex = entry.as_str().ok_or_else(|| io_err("witness node entry must be string"))?;
      let node_rlp = decode_hex(node_hex)?;
      if let Some(node) = ObliviousNode::from_rlp(&node_rlp) {
        let hash = node.keccak_hash().to_hex();
        if seen_hashes.insert(hash) {
          out.push(node_rlp);
        }
      }
    }
    Ok(out)
  }

  async fn proof_nodes_for_storage(
    &self,
    account: &str,
    slot_key_hex: &str,
    block_hash_hex: &str,
  ) -> io::Result<Vec<Vec<u8>>> {
    let result = self
      .call(
        "eth_getProof",
        json!([
          account,
          [slot_key_hex],
          {"blockHash": block_hash_hex, "requireCanonical": false}
        ]),
      )
      .await?;

    let mut out = Vec::new();
    let account_proof = result
      .get("accountProof")
      .and_then(Value::as_array)
      .ok_or_else(|| io_err("eth_getProof.accountProof missing"))?;
    for entry in account_proof {
      let node_hex = entry.as_str().ok_or_else(|| io_err("accountProof node must be string"))?;
      let node_rlp = decode_hex(node_hex)?;
      if ObliviousNode::from_rlp(&node_rlp).is_some() {
        out.push(node_rlp);
      }
    }

    let storage_proof = result
      .get("storageProof")
      .and_then(Value::as_array)
      .ok_or_else(|| io_err("eth_getProof.storageProof missing"))?;
    let first = storage_proof.first().ok_or_else(|| io_err("storageProof[0] missing"))?;
    let proof_nodes = first
      .get("proof")
      .and_then(Value::as_array)
      .ok_or_else(|| io_err("storageProof[0].proof missing"))?;
    for entry in proof_nodes {
      let node_hex = entry.as_str().ok_or_else(|| io_err("storage proof node must be string"))?;
      let node_rlp = decode_hex(node_hex)?;
      if ObliviousNode::from_rlp(&node_rlp).is_some() {
        out.push(node_rlp);
      }
    }
    Ok(out)
  }
}

struct RethDevNode {
  rpc: RethRpcClient,
  child: Child,
  datadir: PathBuf,
}

impl RethDevNode {
  async fn start() -> io::Result<Self> {
    let reth_bin = resolve_reth_bin().ok_or_else(|| {
      io_err(
        "reth binary not found; set RETH_BIN or install `reth` in PATH (or /tmp/reth-bin/reth)",
      )
    })?;

    let port = reserve_tcp_port()?;
    let datadir = unique_temp_dir("reth_dev_test");
    std::fs::create_dir_all(&datadir).map_err(io_err_from)?;

    let child = Command::new(&reth_bin)
      .args([
        "node",
        "--dev",
        "--dev.mnemonic",
        DEV_MNEMONIC,
        "--dev.block-time",
        "1sec",
        "--datadir",
        datadir.to_str().ok_or_else(|| io_err("invalid datadir path"))?,
        "--http",
        "--http.addr",
        "127.0.0.1",
        "--http.port",
        &port.to_string(),
        "--http.api",
        "eth,debug,net,web3,admin,reth,txpool,trace,rpc",
        "--rpc.eth-proof-window",
        "100000",
        "--ipcdisable",
      ])
      .stdin(Stdio::null())
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .spawn()
      .map_err(io_err_from)?;

    let rpc = RethRpcClient {
      rpc_url: format!("http://127.0.0.1:{}", port),
      client: reqwest::Client::new(),
    };
    rpc.wait_ready().await?;

    Ok(Self { rpc, child, datadir })
  }

  fn rpc(&self) -> RethRpcClient {
    self.rpc.clone()
  }
}

impl Drop for RethDevNode {
  fn drop(&mut self) {
    let _ = self.child.start_kill();
    let _ = std::fs::remove_dir_all(&self.datadir);
  }
}

#[derive(Clone, Debug)]
struct BlockInfo {
  number: u64,
  hash_hex: String,
  state_root_hex: String,
}

struct RoutedTestServer {
  base_url: String,
  handle: jsonrpsee::server::ServerHandle,
}

impl RoutedTestServer {
  async fn start(capacity: usize, admin_key: &str) -> (Self, Arc<SharedState>) {
    let state = Arc::new(SharedState::new_with_admin_key(capacity, admin_key.to_string()));
    let (handle, addr) = start_rpc_server(state.clone(), "127.0.0.1:0").await.unwrap();
    (Self { base_url: format!("http://{}", addr), handle }, state)
  }

  fn json_url_for_key(&self, key: &str) -> String {
    format!("{}/{}/json_rpc", self.base_url, key)
  }
}

impl Drop for RoutedTestServer {
  fn drop(&mut self) {
    let _ = self.handle.stop();
  }
}

#[derive(Default)]
struct RethDevProvider {
  initial_bundles: Vec<RethBlockBundle>,
  notifications: VecDeque<RethNotification>,
  missing_query_nodes: HashMap<(String, MissingBlockId), Vec<Vec<u8>>>,
  missing_requests: Vec<MissingProofQuery>,
}

impl RethUpdateProvider for RethDevProvider {
  type Error = io::Error;

  fn initial_block_bundles(
    &mut self,
  ) -> FeederFuture<'_, Result<Vec<RethBlockBundle>, Self::Error>> {
    Box::pin(async move { Ok(std::mem::take(&mut self.initial_bundles)) })
  }

  fn next_notification(
    &mut self,
  ) -> FeederFuture<'_, Result<Option<RethNotification>, Self::Error>> {
    Box::pin(async move { Ok(self.notifications.pop_front()) })
  }

  fn fetch_missing_proof_nodes(
    &mut self,
    query: MissingProofQuery,
  ) -> FeederFuture<'_, Result<Vec<Vec<u8>>, Self::Error>> {
    Box::pin(async move {
      self.missing_requests.push(query.clone());
      let key = (query.address, query.block);
      Ok(self.missing_query_nodes.get(&key).cloned().unwrap_or_default())
    })
  }
}

struct ChainFixture {
  startup_bundle: RethBlockBundle,
  update_bundle: RethBlockBundle,
  startup_info: BlockInfo,
  update_info: BlockInfo,
  missing_query: MissingProofQuery,
  missing_query_nodes: Vec<Vec<u8>>,
  missing_node_rlp: Vec<u8>,
  contract_address: String,
}

async fn build_contract_chain_fixture(
  rpc: &RethRpcClient,
  wallet: &LocalWallet,
) -> io::Result<ChainFixture> {
  let sender = wallet.address();
  let sender_hex = format!("{:#x}", sender);
  let mut nonce = rpc.nonce_for_address(&sender_hex).await?;

  let (contract_address, _deploy_block) =
    rpc
      .deploy_storage_writer_contract(wallet, nonce)
      .await
      .map_err(|e| io_err(format!("deploy_storage_writer_contract failed: {}", e)))?;
  nonce = nonce.saturating_add(1);

  let startup_block_number = rpc
    .set_contract_slot0_u64(wallet, nonce, &contract_address, 1)
    .await
    .map_err(|e| io_err(format!("set_contract_slot0_u64(value=1) failed: {}", e)))?;
  nonce = nonce.saturating_add(1);
  let startup_info = rpc.block_by_number(startup_block_number).await?;
  let mut startup_nodes = rpc.witness_nodes_for_block(startup_block_number).await?;

  let update_block_number =
    rpc
      .set_contract_slot0_u64(wallet, nonce, &contract_address, 2)
      .await
      .map_err(|e| io_err(format!("set_contract_slot0_u64(value=2) failed: {}", e)))?;
  let update_info = rpc.block_by_number(update_block_number).await?;
  let mut update_nodes = rpc.witness_nodes_for_block(update_block_number).await?;

  let startup_proof_nodes =
    rpc.proof_nodes_for_storage(&contract_address, SLOT_0_HEX, &startup_info.hash_hex).await?;
  let update_proof_nodes =
    rpc.proof_nodes_for_storage(&contract_address, SLOT_0_HEX, &update_info.hash_hex).await?;
  extend_unique_nodes(&mut startup_nodes, &startup_proof_nodes)?;
  extend_unique_nodes(&mut update_nodes, &update_proof_nodes)?;

  let startup_proof_hashes: HashSet<String> =
    startup_proof_nodes.iter().map(|node| node_hash_hex_raw(node)).collect();
  let update_proof_hashes: HashSet<String> =
    update_proof_nodes.iter().map(|node| node_hash_hex_raw(node)).collect();

  let update_node_hashes: HashSet<String> =
    update_nodes.iter().map(|node| node_hash_hex(node)).collect::<io::Result<HashSet<_>>>()?;

  let missing_node_hash = update_proof_hashes
    .iter()
    .find(|h| !startup_proof_hashes.contains(*h) && update_node_hashes.contains(*h))
    .or_else(|| update_proof_hashes.iter().find(|h| update_node_hashes.contains(*h)))
    .cloned()
    .ok_or_else(|| io_err("failed to find removable proof node in update witness"))?;

  let missing_node_rlp = update_nodes
    .iter()
    .find_map(|node| {
      node_hash_hex(node).ok().and_then(|hash| {
        if hash == missing_node_hash {
          Some(node.clone())
        } else {
          None
        }
      })
    })
    .ok_or_else(|| io_err("missing node bytes"))?;
  update_nodes.retain(|node| node_hash_hex(node).map(|h| h != missing_node_hash).unwrap_or(true));

  let normalized_contract_address = format!(
    "{:#x}",
    contract_address
      .parse::<EthAddress>()
      .map_err(|e| io_err(format!("invalid contract address: {}", e)))?
  );
  let missing_query = MissingProofQuery {
    address: normalized_contract_address,
    storage_keys: vec![SLOT_0_HEX.to_string()],
    block: MissingBlockId::BlockHash(MissingBlockHashSelector {
      block_hash: update_info.hash_hex.clone(),
      require_canonical: false,
    }),
  };

  let make_bundle = |info: &BlockInfo, nodes: Vec<Vec<u8>>| -> io::Result<RethBlockBundle> {
    Ok(RethBlockBundle {
      number: info.number,
      hash_hex: info.hash_hex.clone(),
      state_root_hex: info.state_root_hex.clone(),
      changed_trie_nodes_rlp: nodes,
    })
  };

  Ok(ChainFixture {
    startup_bundle: make_bundle(&startup_info, startup_nodes)?,
    update_bundle: make_bundle(&update_info, update_nodes)?,
    startup_info,
    update_info,
    missing_query,
    missing_query_nodes: update_proof_nodes,
    missing_node_rlp,
    contract_address,
  })
}

async fn state_contains_node(state: &SharedState, node_rlp: &[u8]) -> bool {
  let node = match ObliviousNode::from_rlp(node_rlp) {
    Some(v) => v,
    None => return false,
  };
  let node_hash = node.keccak_hash();
  let mut guard = state.storage.lock().await;
  let mut out = ObliviousNode::default();
  guard.get(node_hash, &mut out)
}

async fn call_json_rpc(url: &str, method: &str, params: Value) -> io::Result<Value> {
  let client = reqwest::Client::new();
  let payload = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
  let response = client.post(url).json(&payload).send().await.map_err(io_err_from)?;
  response.json::<Value>().await.map_err(io_err_from)
}

fn storage_value_last_byte_from_proof_response(resp: &Value) -> io::Result<u8> {
  let value = resp
    .get("result")
    .and_then(|r| r.get("storageProof"))
    .and_then(Value::as_array)
    .and_then(|arr| arr.first())
    .and_then(|e| e.get("value"))
    .and_then(Value::as_str)
    .ok_or_else(|| io_err("missing result.storageProof[0].value"))?;

  let raw = value.strip_prefix("0x").unwrap_or(value).trim_end_matches(' ');
  if raw.is_empty() {
    return Ok(0);
  }
  let bytes = hex::decode(raw).map_err(io_err_from)?;
  Ok(*bytes.last().unwrap_or(&0))
}

async fn wait_for_proof_value_byte(
  json_url: &str,
  account: &str,
  slot_key_hex: &str,
  block_hash_hex: &str,
  expected_last_byte: u8,
) -> io::Result<()> {
  let started = tokio::time::Instant::now();
  let mut last = String::new();
  while started.elapsed() < PROOF_WAIT_TIMEOUT {
    let resp = call_json_rpc(
      json_url,
      "eth_getProof",
      json!([
        account,
        [slot_key_hex],
        {"blockHash": block_hash_hex, "requireCanonical": false}
      ]),
    )
    .await?;

    if let Some(err) = resp.get("error") {
      let code = err.get("code").and_then(Value::as_i64).unwrap_or_default();
      if code == -32001 {
        last = format!("error {}", err);
        sleep(Duration::from_millis(150)).await;
        continue;
      }
      return Err(io_err(format!("unexpected eth_getProof error: {}", err)));
    }

    let got = storage_value_last_byte_from_proof_response(&resp)?;
    if got == expected_last_byte {
      return Ok(());
    }
    last = format!("got={} expected={} resp={}", got, expected_last_byte, resp);
    sleep(Duration::from_millis(150)).await;
  }
  Err(io_err(format!(
    "timed out waiting for expected storage value in eth_getProof; last={}",
    last
  )))
}

fn decode_hex(prefixed_hex: &str) -> io::Result<Vec<u8>> {
  let raw = prefixed_hex.strip_prefix("0x").unwrap_or(prefixed_hex);
  hex::decode(raw).map_err(io_err_from)
}

fn node_hash_hex(node_rlp: &[u8]) -> io::Result<String> {
  let node = ObliviousNode::from_rlp(node_rlp).ok_or_else(|| io_err("invalid trie node rlp"))?;
  Ok(node.keccak_hash().to_hex())
}

fn node_hash_hex_raw(node_rlp: &[u8]) -> String {
  let mut hasher = Keccak256::new();
  hasher.update(node_rlp);
  format!("0x{}", hex::encode(hasher.finalize()))
}

fn extend_unique_nodes(dst: &mut Vec<Vec<u8>>, src: &[Vec<u8>]) -> io::Result<()> {
  let mut seen = HashSet::new();
  for node in dst.iter() {
    seen.insert(node_hash_hex(node)?);
  }
  for node in src {
    let hash = node_hash_hex(node)?;
    if seen.insert(hash) {
      dst.push(node.clone());
    }
  }
  Ok(())
}

fn reserve_tcp_port() -> io::Result<u16> {
  let listener = TcpListener::bind("127.0.0.1:0").map_err(io_err_from)?;
  let port = listener.local_addr().map_err(io_err_from)?.port();
  drop(listener);
  Ok(port)
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
  let nanos =
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(StdDuration::from_nanos(0)).as_nanos();
  std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), nanos))
}

fn resolve_reth_bin() -> Option<PathBuf> {
  if let Ok(path) = std::env::var("RETH_BIN") {
    let p = PathBuf::from(path);
    if is_executable(&p) {
      return Some(p);
    }
  }

  let bundled = PathBuf::from("/tmp/reth-bin/reth");
  if is_executable(&bundled) {
    return Some(bundled);
  }

  if is_executable(Path::new("reth")) {
    return Some(PathBuf::from("reth"));
  }

  None
}

fn is_executable(path: &Path) -> bool {
  std::process::Command::new(path)
    .arg("--version")
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .map(|status| status.success())
    .unwrap_or(false)
}

fn parse_u64_hex(value: &str) -> io::Result<u64> {
  let raw = value.strip_prefix("0x").unwrap_or(value);
  u64::from_str_radix(raw, 16).map_err(io_err_from)
}

fn receipt_status_success(receipt: &Value) -> io::Result<bool> {
  match receipt.get("status").and_then(Value::as_str) {
    Some("0x1") => Ok(true),
    Some("0x0") => Ok(false),
    Some(other) => Err(io_err(format!("unexpected receipt status format: {}", other))),
    None => Err(io_err("receipt.status missing")),
  }
}

fn dev_wallet() -> io::Result<LocalWallet> {
  MnemonicBuilder::<English>::default()
    .phrase(DEV_MNEMONIC)
    .index(0u32)
    .map_err(io_err_from)?
    .build()
    .map_err(io_err_from)
}

fn io_err(msg: impl Into<String>) -> io::Error {
  io::Error::other(msg.into())
}

fn io_err_from<E: std::fmt::Display>(err: E) -> io::Error {
  io::Error::other(err.to_string())
}

#[tokio::test]
async fn integration_reth_contract_storage_sync_and_missing_node_backfill() {
  let admin_key = "olabs-admin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  let (srv, state) = RoutedTestServer::start(1 << 10, admin_key).await;

  let reth = RethDevNode::start().await.unwrap();
  let rpc = reth.rpc();
  let wallet = dev_wallet().unwrap();
  let fixture = build_contract_chain_fixture(&rpc, &wallet).await.unwrap();
  let missing_query_key =
    (fixture.missing_query.address.clone(), fixture.missing_query.block.clone());

  let provider = RethDevProvider {
    initial_bundles: vec![fixture.startup_bundle.clone()],
    notifications: VecDeque::from(vec![RethNotification::Committed(vec![fixture
      .update_bundle
      .clone()])]),
    missing_query_nodes: HashMap::from([(missing_query_key, fixture.missing_query_nodes.clone())]),
    missing_requests: Vec::new(),
  };

  let source = RethSourceAdapter::new(provider);
  let sink = HttpAdminSink::from_base_url(&srv.base_url, admin_key).unwrap();
  let mut client = RethSyncClient::new(source, sink, true);

  assert_eq!(client.sync_initial_state().await.unwrap(), 1);
  assert_eq!(client.sync_updates_until_exhausted().await.unwrap(), 1);

  let startup_block_hash = B256::from_hex(&fixture.startup_info.hash_hex).unwrap();
  let startup_root = B256::from_hex(&fixture.startup_info.state_root_hex).unwrap();
  assert_eq!(state.get_root_by_hash(startup_block_hash).await, Some(startup_root));
  assert_eq!(state.get_root(fixture.startup_info.number).await, Some(startup_root));

  let update_block_hash = B256::from_hex(&fixture.update_info.hash_hex).unwrap();
  let update_root = B256::from_hex(&fixture.update_info.state_root_hex).unwrap();
  assert_eq!(state.get_root_by_hash(update_block_hash).await, Some(update_root));
  assert_eq!(state.get_root(fixture.update_info.number).await, Some(update_root));

  let json_url = srv.json_url_for_key(admin_key);

  wait_for_proof_value_byte(
    &json_url,
    &fixture.contract_address,
    SLOT_0_HEX,
    &fixture.startup_info.hash_hex,
    0x01,
  )
  .await
  .unwrap();

  let before_backfill = call_json_rpc(
    &json_url,
    "eth_getProof",
    json!([
      fixture.contract_address,
      [SLOT_0_HEX],
      {"blockHash": fixture.update_info.hash_hex, "requireCanonical": false}
    ]),
  )
  .await
  .unwrap();
  let err_code = before_backfill
    .get("error")
    .and_then(|e| e.get("code"))
    .and_then(Value::as_i64)
    .unwrap_or_default();
  assert_eq!(err_code, -32001, "expected data non availability before backfill");

  let started = tokio::time::Instant::now();
  let mut published = 0u64;
  while started.elapsed() < PROOF_WAIT_TIMEOUT {
    let backfill = client.sync_missing_nodes_once().await.unwrap();
    published = published.saturating_add(backfill.published);
    if published > 0 {
      break;
    }
    sleep(Duration::from_millis(150)).await;
  }
  assert!(published >= 1, "expected periodic missing-node polling to backfill at least one node");

  wait_for_proof_value_byte(
    &json_url,
    &fixture.contract_address,
    SLOT_0_HEX,
    &fixture.update_info.hash_hex,
    0x02,
  )
  .await
  .unwrap();

  assert!(state_contains_node(state.as_ref(), &fixture.missing_node_rlp).await);

  let (source_after, _) = client.into_parts();
  let provider_after = source_after.into_provider();
  assert!(
    provider_after.missing_requests.iter().any(|q| q.address == fixture.missing_query.address
      && q.block == fixture.missing_query.block
      && q.storage_keys.iter().any(|k| k == SLOT_0_HEX)),
    "expected missing proof query to be requested from source"
  );
}
