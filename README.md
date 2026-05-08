> [!Warning]
> **Early development — proof-of-concept. Use at your own risk.**

# oblivious_node — oblivious eth_getProof node

*oblivious_node* is a PoC JSON-RPC privacy-preserving server that generates Ethereum state proofs via oblivious algorithms running in Trusted Execution Environments (TEEs), without learning or leaking clients' queries, compatible with EIP-1186.

**Definitions:**
- *Oblivious* = instruction trace and memory access trace are independent from private input data. 

- *oblivious + [doit](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html) ==> execution time independent of private-data *

- Clients can get proofs of ethereum state, without the server operator being able to learn which account addresses and storage locations are being queried. 

## Quickstart
- Build: `cargo build --workspace --release`
- Tests: `cargo test -p eth_privatestate` (or `cargo nextest run --workspace` for full suite)
- Run server: `cargo run -p eth_privatestate --release -- --admin-api-key <at-least-32-char-key>`
  - Optional: `--leaky-error-recovery` (enables missing-proof queue/backfill hook; leaks block selector + duplicate status)
  - Optional: `--listen-addr <host:port>` (default `127.0.0.1:8545`)

## Docker Deployment (with `tdx_easy_https`)
This repo includes `tdx_easy_https` as a nested repo at `external/tdx_easy_https` and a
combined compose stack at `deploy/docker-compose.tdx.yml`.

1) Prepare env file:

```bash
cp deploy/.env.tdx.example deploy/.env.tdx
# edit deploy/.env.tdx and set ACME_EMAIL, SERVER_DOMAIN, ADMIN_API_KEY
```

2) Phase 1 stack (minimal TDX + HTTPS smoke test, no Sepolia sync):

```bash
docker compose \
  --env-file deploy/.env.tdx \
  -f deploy/docker-compose.tdx.yml \
  up --build -d
```

3) Phase 3 stack (with Sepolia sync via reth/lighthouse/feeder):

```bash
docker compose \
  --env-file deploy/.env.tdx \
  -f deploy/docker-compose.tdx.yml \
  --profile sepolia \
  up --build -d
```

4) Services:
- `traefik` (HTTPS termination + ACME)
- `attestd` (from `tdx_easy_https`, mounted on `/attestd/*`)
- `eth_privatestate` (served on `https://$SERVER_DOMAIN/{api_key}/json_rpc`)
- `reth`, `lighthouse`, `eth_sync_feeder` only start when `--profile sepolia` is enabled

Notes:
- `attestd` mounts `/dev/tdx-guest`; run on a TDX-enabled host.
- `eth_privatestate` runs with `--leaky-error-recovery` in this compose stack so missing-node backfill works.
- Set `ETH_NETWORK` in `deploy/.env.tdx` to choose the network (default `sepolia`).
- Set `LIGHTHOUSE_CHECKPOINT_SYNC_URL` for that network (example provided for Sepolia) when using `--profile sepolia`.
- Public-testnet compose stacks start the public JSON-RPC endpoint immediately, then run root sync, witness-node sync, live sync, and missing-node backfill in parallel. Keep reth in archive/full-history mode so historical request backfills have the data they need. By default `INITIAL_SYNC_START_BLOCK=1` fetches all historical block roots quickly, while `NODE_SYNC_MODE=roots-and-witness` keeps fetching old and new witness nodes in the background with bounded parallel `debug_executionWitness` calls. `roots-only` is available when you only want roots plus request-driven backfill.
- For Phala deployments (image-only compose + encrypted secrets + client-side TDX attestation verification), use `phase1.md` and `deploy/phala/README.md`.

Phala dstack deployments expose extra verifier endpoints from `eth_privatestate`:

- `GET /healthz`
- `GET /attestation?report_data=0x<0-to-64-byte-hex>`
- `GET /info`

Client-side verification helper, local by default:

```bash
node deploy/phala/verify_client_tdx.mjs "https://<node-info-domain>" [expected_mrtd] --strict-digests
```

The helper verifies the TDX quote locally, checks the fresh `report_data`
challenge, replays RTMR3 from the event log, and checks compose/image evidence
when `/info` exposes it. Use `--phala-api` only as an optional comparison.

## Run From Shell
### 1) Start main service (`eth_privatestate`)
In one terminal:

```bash
ADMIN_KEY="olabs-admin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
cargo run -p eth_privatestate --release -- --admin-api-key "$ADMIN_KEY"
```

Default bind: `127.0.0.1:8545`

Optional server flag:

- `--leaky-error-recovery`: enable `admin_take_missing_nodes` backfill queue.
  This mode is intentionally leaky (block selector + duplicate status in instruction/memory trace).
  Default is disabled.

### 2) Start reth node
In a second terminal:

```bash
/tmp/reth-bin/reth node --dev \
  --dev.block-time 1sec \
  --http \
  --http.addr 127.0.0.1 \
  --http.port 8546 \
  --http.api eth,debug,net,web3,admin,reth,txpool,trace,rpc \
  --ipcdisable
```

### 3) Start sync controller (`eth_sync_feeder`)
In a third terminal:

```bash
ADMIN_KEY="olabs-admin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

cargo run -p eth_sync_feeder --release -- \
  --reth-rpc-url http://127.0.0.1:8546 \
  --admin-base-url http://127.0.0.1:8545 \
  --admin-api-key "$ADMIN_KEY"
```

This starts continuous syncing from reth into `eth_privatestate` over admin RPC.
By default the feeder publishes roots from genesis forward, live root sync follows
new blocks, historical witness-node sync fills older nodes in the background, and
missing-proof requests are backfilled directly without waiting for either sync to
finish.

Optional feeder flags:

- `--skip-initial-sync`: do not run startup bootstrap.
- `--initial-sync-start-block <n>`: start bootstrap at block `n`. Defaults to genesis when no startup scope is provided.
- `--initial-sync-tail-blocks <n>`: bootstrap only the last `n` blocks at startup tip.
- `--node-sync-mode roots-only|roots-and-witness|execution-witness`: `roots-and-witness` is the default. It publishes roots quickly and runs old/new witness-node crawling in background using batched headers and bounded-parallel witness fetches. `roots-only` disables proactive witness crawling. `execution-witness` couples roots and witness nodes in the main sync streams and is slow.
- `--skip-live-sync`: do not poll/apply live canonical block updates.
- `--skip-missing-node-sync`: do not poll `admin_take_missing_nodes` backfill queue.

Use `admin_get_sync_status` on the admin endpoint to check sync progress. The
`latest_root_number` field is the highest accepted root from any path; live sync
can make it jump to tip before startup root prefetch is done. Use
`historical_root_number` for startup root-prefetch progress,
`historical_node_delta_number` for old witness-node crawl progress, and
`live_root_number` / `live_node_delta_number` for new blocks. After startup,
`historical_root_lag_to_latest` normally grows because the historical lane is a
fixed startup snapshot; use `live_root_lag_to_latest` and
`live_node_lag_to_live_root` to tell whether the current chain tip is caught up.
Request-driven backfill can still fill individual older or newer proofs before
the proactive node crawl reaches them.

### 4) Example: write contract storage on reth, read via `oblivious_node`
This example deploys a tiny contract on `reth --dev` that writes a 32-byte calldata word into
storage slot `0`, then reads that value from `oblivious_node` using `eth_getProof`.

Requirements: `cast` (Foundry) and `jq`.

```bash
ADMIN_KEY="olabs-admin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
RETH_RPC="http://127.0.0.1:8546"
OBLIV_RPC="http://127.0.0.1:8545/$ADMIN_KEY/json_rpc"
# Account 0 private key for reth --dev mnemonic:
# "test test test test test test test test test test test junk"
PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Runtime: 0x60003560005500  => sstore(0, calldataload(0)); stop
# Init code returning that runtime:
INIT_CODE="0x6007600c60003960076000f360003560005500"

# 1) Deploy contract
DEPLOY_TX=$(cast send --rpc-url "$RETH_RPC" --private-key "$PK" --create "$INIT_CODE" --json | jq -r '.transactionHash')
CONTRACT=$(cast receipt --rpc-url "$RETH_RPC" "$DEPLOY_TX" --json | jq -r '.contractAddress')
echo "Contract: $CONTRACT"

# 2) Write value 1 into storage slot 0
WRITE1_TX=$(cast send --rpc-url "$RETH_RPC" --private-key "$PK" "$CONTRACT" "0x0000000000000000000000000000000000000000000000000000000000000001" --json | jq -r '.transactionHash')
WRITE1_BLOCK_HASH=$(cast receipt --rpc-url "$RETH_RPC" "$WRITE1_TX" --json | jq -r '.blockHash')

# Give feeder a moment to publish this block's trie updates.
sleep 2

# 3) Read slot 0 proof/value from oblivious_node at that block hash
PAYLOAD1=$(jq -nc --arg a "$CONTRACT" --arg h "$WRITE1_BLOCK_HASH" \
  '{"jsonrpc":"2.0","id":1,"method":"eth_getProof","params":[ $a, ["0x0000000000000000000000000000000000000000000000000000000000000000"], {"blockHash":$h,"requireCanonical":false} ]}')
curl -s -X POST "$OBLIV_RPC" -H 'Content-Type: application/json' --data "$PAYLOAD1" | jq '.result.storageProof[0].value'
# expected: "0x1"

# 4) Update slot 0 to value 2, then read again through oblivious_node
WRITE2_TX=$(cast send --rpc-url "$RETH_RPC" --private-key "$PK" "$CONTRACT" "0x0000000000000000000000000000000000000000000000000000000000000002" --json | jq -r '.transactionHash')
WRITE2_BLOCK_HASH=$(cast receipt --rpc-url "$RETH_RPC" "$WRITE2_TX" --json | jq -r '.blockHash')
sleep 2
PAYLOAD2=$(jq -nc --arg a "$CONTRACT" --arg h "$WRITE2_BLOCK_HASH" \
  '{"jsonrpc":"2.0","id":1,"method":"eth_getProof","params":[ $a, ["0x0000000000000000000000000000000000000000000000000000000000000000"], {"blockHash":$h,"requireCanonical":false} ]}')
curl -s -X POST "$OBLIV_RPC" -H 'Content-Type: application/json' --data "$PAYLOAD2" | jq '.result.storageProof[0].value'
# expected: "0x2"
```

## Usage
- Public endpoint path: `http://127.0.0.1:8545/{api_key}/json_rpc`
- Admin endpoint path: `http://127.0.0.1:8545/{admin_api_key}/admin`
- Public methods: `eth_getProof`
- Admin methods: `admin_put_node`, `admin_set_root`, `admin_set_root_by_hash`, `admin_get_metrics`,
  `admin_get_sync_status`, `admin_apply_block_delta`, `admin_mark_node_delta_complete`,
  `admin_apply_root_batch`, `admin_take_missing_nodes`, `admin_create_api_key`, `admin_add_tokens`,
  `admin_set_hourly_limit`, `admin_disable_api_key`, `admin_delete_api_key`
- Example (single-line):
  `curl -s -X POST http://127.0.0.1:8545/olabs-api-.../json_rpc -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_getProof","params":["0xdAC17F958D2ee523a2206206994597C13D831ec7", ["0x0"], 1],"id":1}'`

## Design notes
- Goal: make instruction and memory access patterns independent of clients' private inputs so proofs can be generated in constant time and with reduced leakage inside of TEEs.
- Core types: `ObliviousNode` and oblivious helpers (branchless json and hex helpers, `oblivious_memcpy`, `oblivious_shift`) live in `crates/eth_privatestate/src/` (`oblivious_node.rs`, `trie.rs`, `rpc.rs`).
- Core logic: `ObliviousNode::traverse_oblivious` and `trie::generate_proof`.
- Missing-node cache tradeoff: enabling `--leaky-error-recovery` allows feeder backfill, but leaks block selector + duplicate status and stores query-derived identifiers.
- Status: PoC — some helpers are marked `UNDONE()` and there are TODOs to move core oblivious primitives into [obliviouslabs/rostl](https://github.com/obliviouslabs/rostl).

## Tests & Development
- Integration tests exercise `eth_getProof` and admin endpoints (`crates/eth_privatestate/tests/`).
- See `Makefile.toml` for common tasks (tests, coverage, docs).

## License & Links
- License: **MIT OR Apache-2.0** (see `Cargo.toml`).

[Rust oblivious stl](https://github.com/obliviouslabs/rostl)

[Oblivious Labs](https://www.obliviouslabs.com/)

[eip 1186](https://eips.ethereum.org/EIPS/eip-1186#specification)
[rlp docs](https://ethereum.org/developers/docs/data-structures-and-encoding/rlp/)
[mpt docs](https://ethereum.org/developers/docs/data-structures-and-encoding/patricia-merkle-trie/)
[rlp tool](https://toolkit.abdk.consulting/ethereum#rlp)
[keccak256 tool](https://emn178.github.io/online-tools/keccak_256.html)

---
*Short, technical, Ethereum focused—feedback welcome via GitHub issues/PRs.*
