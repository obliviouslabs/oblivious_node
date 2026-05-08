# Phala Deployment Assets

This folder follows a strict secret split:

- Local-only auth/session on deploy machine (`npx phala login`; optional API key file for CI)
- CVM app secrets: `.env.app`
- CVM registry bootstrap secrets (optional): `.env.registry`

## Files

- `docker-compose.phase1.yml`: minimal phase1 stack.
- `docker-compose.phase3.sepolia.yml`: full phase3 Sepolia stack.
- `.env.local.example`: optional local deploy-machine API-key auth template (CI/non-interactive).
- `.env.app.example`: app/runtime secrets for CVM.
- `.env.registry.example`: private-registry pull secrets for CVM pre-launch.
- `merge_cvm_env.sh`: merges `.env.app` + `.env.registry` into `.env.cvm` for `--env-file`.
- `build_and_push_oblivious_node.sh`: builds/pushes image and writes digest ref.
- `verify_client_tdx.mjs`: local verifier-side challenge/quote/RTMR3 check for the public app URL.
- `tdx_quote_verifier/`: small local Rust verifier used by `verify_client_tdx.mjs`.
- `verify_tdx_quote.sh`: optional Phala API comparison for an exported quote.

## Quick Deploy (Phase 1)

```bash
cp deploy/phala/.env.app.example deploy/phala/.env.app
cp deploy/phala/.env.registry.example deploy/phala/.env.registry

# Recommended interactive login
npx phala login

# Build and publish app image
./deploy/phala/build_and_push_oblivious_node.sh ghcr.io/<org>/oblivious-node
cat deploy/phala/image-ref.env >> deploy/phala/.env.app

# Edit .env.app (ADMIN_API_KEY, etc.)
# Edit .env.registry only when private image pulls are needed
./deploy/phala/merge_cvm_env.sh

npx phala cvms create --name <app-name> \
  --compose deploy/phala/docker-compose.phase1.yml \
  --env-file deploy/phala/.env.cvm
```

Optional CI/non-interactive login:

```bash
cp deploy/phala/.env.local.example deploy/phala/.env.local
set -a; source deploy/phala/.env.local; set +a
npx phala auth login "$PHALA_CLOUD_API_KEY"
```

If API-key login returns `invalid api key`, regenerate key and ensure no extra quotes/spaces.

When prompted for base image, choose production `dstack-*` (not `dstack-dev-*`).

## Quick Deploy (Phase 3 Sepolia)

Use this when you want the CVM to include a Sepolia execution/consensus client and
start serving `eth_getProof` immediately while the clients sync.

1. Fill `.env.app` with immutable digest references for:
   - `OBLIVIOUS_NODE_IMAGE`
   - `RETH_IMAGE`
   - `LIGHTHOUSE_IMAGE`
   - `JWT_INIT_IMAGE`
2. Keep `ETH_NETWORK=sepolia`.
3. Keep `LIGHTHOUSE_CHECKPOINT_SYNC_URL` set for checkpoint sync.
4. Merge secrets and deploy:

```bash
./deploy/phala/merge_cvm_env.sh
npx phala cvms create --name <app-name-sepolia> \
  --compose deploy/phala/docker-compose.phase3.sepolia.yml \
  --env-file deploy/phala/.env.cvm
```

The Sepolia compose starts the public JSON-RPC endpoint right away while reth,
lighthouse, and `eth_sync_feeder` catch up in the background. Reth is left in
archive/full-history mode so historical request backfill can fetch proofs beyond
the short pruning horizon. By default `INITIAL_SYNC_START_BLOCK=1` syncs all
historical roots in the fast root lane, while `NODE_SYNC_MODE=roots-and-witness`
keeps crawling historical and live witness nodes in background. Early
`eth_getProof` calls can still return `-32001` data non availability, but those
failed requests are queued for missing-node backfill, which now fetches the proof
directly from reth and publishes both proof nodes and the missing block root.

The Phala default `2 vCPU / 4096 MB / 40 GB` prompt is only realistic for the
phase1 smoke test. For Sepolia, choose the smallest CVM size with enough disk for
an execution client plus consensus client data, and increase disk first if sync
fails or stalls.

## Public Endpoints

- Health: `https://<node-info-domain>/healthz`
- Public RPC: `https://<node-info-domain>/{api_key}/json_rpc`
- Admin RPC: `https://<node-info-domain>/{admin_api_key}/admin`
- TDX quote: `https://<node-info-domain>/attestation?report_data=0x<0-to-64-byte-hex>`
- dstack info: `https://<node-info-domain>/info`

## Verify TDX Image Locally

1) Local client-side challenge verification against the deployed app URL:

```bash
node deploy/phala/verify_client_tdx.mjs "https://<node-info-domain>" [expected_mrtd] --strict-digests
```

This does not call Phala by default. It:

- fetches a fresh quote from `/attestation?report_data=...`
- verifies the TDX quote locally with the embedded PCK certificate chain
- checks the quote `reportData` binds to the client challenge
- replays RTMR3 from the event log and compares it to the quoted RTMR3
- checks compose-hash and image digest pinning when `/info` exposes app compose data

2) Optional complete local platform verification with Phala/dstack's local verifier:

```bash
docker run --rm -p 8080:8080 dstacktee/dstack-verifier:latest
node deploy/phala/verify_client_tdx.mjs "https://<node-info-domain>" \
  --dstack-verifier-url http://127.0.0.1:8080 \
  --require-dstack-verifier
```

3) Optional Trust Center comparison:

- Open `https://trust.phala.com/app/<app-id>`
- Confirm `TEE type = TDX` and quote verification passes.
- Record `MRTD`, `RTMR0`, `RTMR1`, `RTMR2`, `RTMR3`.

4) Optional Phala API comparison for exported quote hex:

```bash
./deploy/phala/verify_tdx_quote.sh <quote_hex_or_quote_file> [expected_mrtd]
```

Or opt into the same comparison in the client script:

```bash
node deploy/phala/verify_client_tdx.mjs "https://<node-info-domain>" --phala-api
```
