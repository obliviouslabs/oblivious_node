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
- Run server: `cargo run -p eth_privatestate --release`

## Usage
- RPC endpoints: `eth_getProof`, `admin_put_node`, `admin_set_root`.
- Example (single-line):
  `curl -s -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_getProof","params":["0xdAC17F958D2ee523a2206206994597C13D831ec7", ["0x0"], "latest"],"id":1}'`

## Design notes
- Goal: make instruction and memory access patterns independent of clients' private inputs so proofs can be generated in constant time and with reduced leakage inside of TEEs.
- Core types: `ObliviousNode` and oblivious helpers (branchless json and hex helpers, `oblivious_memcpy`, `oblivious_shift`) live in `crates/eth_privatestate/src/` (`oblivious_node.rs`, `utils.rs`, `trie.rs`, `rpc.rs`).
- Core logic: `ObliviousNode::traverse_oblivious` and `trie::generate_proof`.
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
