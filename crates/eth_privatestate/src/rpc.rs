//! RPC methods for EthPrivateState.
//!
use std::sync::Arc;

use jsonrpsee::server::{RpcModule, ServerBuilder};
use jsonrpsee::types::error::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::oblivious_node::{ObliviousNode, VALUE_BUF};
use crate::state::SharedState;
use crate::trie::{self, parse_account};
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
  Number(u64),
  BlockHash(BlockHashSelector),
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

/// Register all RPC methods onto a new `RpcModule` using the provided `state`.
pub fn register_rpc(state: Arc<SharedState>) -> anyhow::Result<RpcModule<Arc<SharedState>>> {
  let mut module = RpcModule::new(state.clone());

  module.register_async_method("eth_getProof", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let p: GetProofParams = params
        .parse()
        .map_err(|_| ErrorObjectOwned::owned(-32602, "Invalid params".to_string(), None::<()>))?;
      eth_get_proof_handler(p, state).await
    }
  })?;

  // Administrative helper to put a raw node and set it as the root for a block.
  // Params: (block_number: u64, node_rlp_hex: String)
  module.register_async_method("admin_put_node", move |params, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
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
  })?;

  module.register_async_method("admin_set_root", move |paramst, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let (block_num, root_hex): (u64, String) = paramst
        .parse()
        .map_err(|_| ErrorObjectOwned::owned(-32602, "Invalid params".to_string(), None::<()>))?;
      let root = B256::from_hex(&root_hex);
      if !root.is_some() {
        return Err(ErrorObjectOwned::owned(
          -32602,
          "Failed to decode root hex".to_string(),
          None::<()>,
        ));
      }
      let root_b256 = root.unwrap_or_default();
      state.set_root(block_num, root_b256).await;
      Ok::<_, ErrorObjectOwned>(true)
    }
  })?;

  module.register_async_method("admin_set_root_by_hash", move |paramst, ctx, _| {
    let state = ctx.as_ref().clone();
    async move {
      let (block_hash_hex, root_hex): (String, String) = paramst
        .parse()
        .map_err(|_| ErrorObjectOwned::owned(-32602, "Invalid params".to_string(), None::<()>))?;
      let block_hash = B256::from_hex(&block_hash_hex);
      if !block_hash.is_some() {
        return Err(ErrorObjectOwned::owned(
          -32602,
          "Failed to decode block hash hex".to_string(),
          None::<()>,
        ));
      }
      let block_hash = block_hash.unwrap_or_default();

      let root = B256::from_hex(&root_hex);
      if !root.is_some() {
        return Err(ErrorObjectOwned::owned(
          -32602,
          "Failed to decode root hex".to_string(),
          None::<()>,
        ));
      }
      let root_b256 = root.unwrap_or_default();
      state.set_root_by_hash(block_hash, root_b256).await;
      Ok::<_, ErrorObjectOwned>(true)
    }
  })?;

  Ok(module)
}

pub async fn eth_get_proof_handler(
  params: GetProofParams,
  state: Arc<SharedState>,
) -> Result<EthGetProofResultBoxed, ErrorObjectOwned> {
  let GetProofParams(address_hex, storage_keys, block_selector) = params;

  // parse address
  // UNDONE(): this should not be unwrap.
  let address = H160::from_hex(&address_hex).unwrap().keccak_hash();
  println!("Getting proof for address: {}", address_hex);
  println!("Arrayed: {:x?}", address);
  println!("Storage keys: {:?}", storage_keys);

  // get root for the requested block selector
  let root_opt = match block_selector {
    BlockSelector::Number(block_num) => state.get_root(block_num).await,
    BlockSelector::BlockHash(selector) => {
      let block_hash = B256::from_hex(&selector.block_hash);
      if !block_hash.is_some() {
        return Err(ErrorObjectOwned::owned(
          -32602,
          "Failed to decode block hash hex".to_string(),
          None::<()>,
        ));
      }
      let block_hash = block_hash.unwrap_or_default();
      state.get_root_by_hash(block_hash).await
    }
  };
  if root_opt.is_none() {
    return Err(ErrorObjectOwned::owned(
      -32001,
      "Failed due to data non availability".to_string(),
      None::<()>,
    ));
  }
  let root = root_opt.unwrap();
  println!("Using state root: {}", root.to_hex());

  // generate account proof; if missing -> error
  let mut ret_proof = String::new();
  let mut ret_value = [0u8; VALUE_BUF];
  let acct_proof_opt = trie::generate_proof::<64>(
    &state.storage,
    root,
    &address.to_nibbles(),
    &mut ret_proof,
    &mut ret_value,
  )
  .await;

  println!("Account proof RLP: {}", ret_proof);
  // UNDONE(): this check leaks whether account exists.
  if acct_proof_opt.is_none() {
    return Err(ErrorObjectOwned::owned(
      -32001,
      "Failed due to data non availability".to_string(),
      None::<()>,
    ));
  }

  let account_proof_rv = RawValue::from_string(ret_proof).map_err(|e| {
    ErrorObjectOwned::owned(-32603, format!("Serialization error: {}", e), None::<()>)
  })?;
  println!("Account proof RV: {:?}", account_proof_rv);

  let (nonce, balance, storage_hash, code_hash) = parse_account(ret_value.as_slice());

  let mut storage_proofs = Vec::new();
  for key_hex in storage_keys {
    // UNDONE(): use oblivious hex decoding.
    // UNDONE(): this should not be unwrap.
    let key_bytes = B256::from_hex(&key_hex).unwrap().keccak_hash();
    let mut ret_proof = String::new();
    let mut ret_value = [0u8; VALUE_BUF];
    let sp = trie::generate_proof::<64>(
      &state.storage,
      storage_hash,
      &key_bytes.to_nibbles(),
      &mut ret_proof,
      &mut ret_value,
    )
    .await;
    if sp.is_none() {
      return Err(ErrorObjectOwned::owned(
        -32001,
        "Failed due to data non availability".to_string(),
        None::<()>,
      ));
    }
    let proof_rv = RawValue::from_string(ret_proof).map_err(|e| {
      ErrorObjectOwned::owned(-32603, format!("Serialization error: {}", e), None::<()>)
    })?;
    // UNDONE(): parse value properly into hex
    let value_rv = trie::parse_value(ret_value.as_slice());
    let value_rv = RawValue::from_string(value_rv).map_err(|e| {
      ErrorObjectOwned::owned(-32603, format!("Serialization error: {}", e), None::<()>)
    })?;
    storage_proofs.push(StorageProofBoxed { key: key_hex, value: value_rv, proof: proof_rv });
  }

  println!("Nonce: {}", nonce);
  println!("Balance: {}", balance);
  let nonce_rv = RawValue::from_string(nonce).map_err(|e| {
    ErrorObjectOwned::owned(-32603, format!("Serialization error: {}", e), None::<()>)
  })?;
  let balance_rv = RawValue::from_string(balance).map_err(|e| {
    ErrorObjectOwned::owned(-32603, format!("Serialization error: {}", e), None::<()>)
  })?;

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
  async fn test_admin_set_root() {
    let state = Arc::new(SharedState::new(1 << 10));
    let block_num = 100;
    let root_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let params = (block_num, root_hex.to_string());
    let res = {
      let state_clone = state.clone();
      async move {
        let (block_num, root_hex): (u64, String) = params;
        let root_bytes = hex::decode(root_hex.trim_start_matches("0x")).unwrap();
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(&root_bytes);
        let root_b256 = B256(root_arr);
        state_clone.set_root(block_num, root_b256).await;
        Ok::<_, ErrorObjectOwned>(true)
      }
    }
    .await;
    assert!(res.is_ok());

    // Verify that the root was set
    let retrieved_root_opt = state.get_root(block_num).await;
    assert!(retrieved_root_opt.is_some());
    let retrieved_root = retrieved_root_opt.unwrap();
    let expected_root = B256::from_hex(root_hex).unwrap();
    assert_eq!(retrieved_root, expected_root);
  }

  #[tokio::test]
  async fn test_admin_set_root_by_hash() {
    let state = Arc::new(SharedState::new(1 << 10));
    let block_hash_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let root_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let block_hash = B256::from_hex(block_hash_hex).unwrap();
    let root = B256::from_hex(root_hex).unwrap();

    state.set_root_by_hash(block_hash, root).await;

    let retrieved_root_opt = state.get_root_by_hash(block_hash).await;
    assert!(retrieved_root_opt.is_some());
    let retrieved_root = retrieved_root_opt.unwrap();
    assert_eq!(retrieved_root, root);
  }

  #[tokio::test]
  async fn test_example() {
    let state = Arc::new(SharedState::new(1 << 10));

    let account_nodes = [
      "f90211a001b72e39806107d99d29f834acb4e3681d4dabd4942e47c11c00f8ebb8f495b9a0acec77b8764f3a714f2e27be242d46849b179e7868b362f59e7dad5e6ac28fb4a0c20f90083c2e01a4cae3d883f65250ea876b28243c3a59470b4f017659f49516a09c925c339b3d0e59adb3e95c0c8eebe383151afcb4f4c86f6bdb9fcfbaef16d9a01f33aba7ad4597d7c1105568443a08413f1946915b75fe84c7329273d3adf0b9a094e870bf54ede4a50749d722d0cacc738dc7799549080189fc3af29a7328ae91a068d4cccea39242da3d79995efd1bfc39748eaf49c756cacc246b40422e4de76fa0b92d5e4b511be1259339727c16cfefe3256bba2f7d3d2752f5aa4cc3618d2a9fa034ab09dbf3a3a071371ba0889514eaa3749e3c417218942ccae44f5f1bb9e2b7a0d729761927de6cc4fe9a1740db909982f1ca3e950760e6450e02e3eba0a71b6ca03d2e25174eaeb87cb35f4fa99374f6e60fe5612a97117797f15d1068a2324935a0635cea9fd12ce1909b3bbcb1aaec95f6d94f80c454c5a239989793eeaec71fcea0b2c5ab5ae5d903a12d4c7d9e0338114c5a836af72043810200f43b93de81d047a02ba74b9917a3948699a42953d129275f360437afb1dbce30d3db6bf30e8fad7ea0b91d17ea8b20a6678c3647719fc772302d9e82f3c5da9f27d1ccdb1395d08f1da0b85ee8911aef07c3e67222bf0124adde8e5213b102c7adf23654eee85d6287f680",
      "f90211a0785b60e388fefac8a9138844ae8c6537bc65be9acfb5d6ddd42608c3c7388a86a02656133dd1b882f0f322a3cb33b2db15a98543972dbf5ec59ea97a512fea0476a0c8e326202eecdd4bbc47f51ff1e59100f39c6b7b90019df9b767a4d4e1191619a0c8312640257b81620354683fc46cf2845eb6c2d76ee4bd72f3ff8534ebe4e260a06d08fb992ff653c17ee370aead62bb955efa3d545a802389a1dbcaf36f79ead4a00deeb0f808dceb568eedf0255e849e9e88095e218e281849b42f090197fd889fa0ca4179ff501baed7983a9eab2b3bf1136e3907257f15577f00917982c41f89bca00e1006091119e1214ac069f3265ef563bbc1abf7560feefa2b9478c53c64d2fca08c808e85d9025eaac1574e2fd1a9ec648c9fea8ebd31641d3334cb218cfbdfe7a0d180c5916e7c7aa01aafcc03c219a267cbae0e14d8ae5d0e675748e6f6bfc515a0fe7dda7991ac799299ae792c3af723d01d862332cad0adca6d3fc95d7de48b02a0bd8ae35bcc75931b5f461393a73de0304e0dc07c8dae8ed5ff0b581861cdf135a073d13a1f1eec7a7f02bb1a71faae0e0693d40eb8f70fd38959c3d74226ecf1f5a0c7896b0fa56898edbc0ffe8130a1181544dd220d61fc00237bd6875a998bcd8aa0061645abd7fedae520c1abea553b972fab80d828e3d1d10e42d979149f9d9103a053a9cb22bd7aeccd9edd801c96743bdebe15144355d04d27e29d110151030d7a80",
      "f90211a0710f38297635ff41c003a73db859bbc936b8d45f51d16dd89654c236a682c212a0437f24c444108e93d829a7399fb6d0b168ec8041f403becd7dc6288c6429132aa0e0d817e774145c29707ce22fafeeaf7f0e01a0c08baa80b43171b7181b2cdc6ba0e55ae2da3d3946eed287285ae608e1d35089443cbd734cd6e32a6f31d91747afa0bab635e08f5514369906ad6418fa8da49a29107ca41efe767bf54561bccf263fa02f7d6ca14ad30c7e5f970e47d38b63016cf1a10a0cc32d228becbeb9251df58ea0e04e211c9379ff61b32330c8e80da5fb405b9e76258ffcc9d6f8c8247fba3082a0d63f478a7bf8889eb47047e472cea6697c2364320b4b7d20f8bc20039a637b6ca0e8f4229ff5ecbd6632833d0a861ae9df5ac7e577feffaa9e4382b2adf40d37c2a0b2d6b5557004acd85dc652be96099af1e5d0b850c35074fe75164a04880229bca0eae71c4cdf6eef8f500c13be0fb83cfec6c5b21c57465b1d55b450edbbf1f4c6a0b29f54dff2886fffb04adb891fc9be66d241e231707f1fd4ee5a39686104e4eda05cce7908cf5614abaa69a42db29f99a719f1cdce6f24351fa7faf293c1e7d7dba09f2fd5eccc143b14557140a34af75401114742140d9356a45ba2d0423c818ee2a077dab377a44344a0d388298c2650d2ab72ce84cfb13335cea6ccbfcf973aeb6da00f3e756ed07c4ed906555c6647018045916512f0e58ccd11859d69b23ea7acc280",
      "f90211a026491d3dd25e872d0d6a4bb32930144c2ac5ab21d5a42a2b7eb5b31de33e3c45a0fe55c56d5c2dfdef30f35ca47e7dd1a11fddf2dcf4f35a4d577a2a1295411f2ea0e435781e00aa5aac4b2a39a3f7b7ef16752181f7739b97a7b02689bf94b02aa2a0a466f639462775e323281296f2a2d9a776f3486de7b7826467227d4e6a9c5183a090542891753c859b4243a551c5b9b2d91e565d77940bc15d11e27554c30cbc48a0960f94a7fe4d66925328281f5336ba873d690cb48b37f69b0850a1671aa52667a0cc5bd7cd747e2719f51531e9b198b2deae5c1a7d954a4bcf08b317ed4789870da012bdd974c649d75e9bea0192ce5da941fb02294022626a40be5df43908836f40a0fb2b92a10bb0f992b7ad9f3fe780e9f14a08f5be2439311052654a632ff06f86a007f4b06c7ca8db008856d224058b3b009d4c57ef1a065312d94f75c2abb96b55a0dfbfbb0dd3b4a8b5d783bc33c1e387b1bdbda318add9975b4bf259621e87ec6ba0a7d9d59e761507bbbed5e74e726d00d3bd90b46a9259e3e9d9dcd2eaba98b3faa0a55132c6b966232cbbeb3d51d99e5ea4c5740a506ac77519e32da7906fe23199a01524d01d3cd1c8d5268530f7e01305786a77498035f9f8f79912a1c41fbfc850a07ae031a89b37782648b5a4c581905bb0a29f690367da91448a9b84f1da310b11a06862da5a636aa89c1994b3bb2cb9cc8f7e8b610b74211092932894340824f5bd80",
      "f90211a044f7f39b024ecda7920f93be4c4666b6be990b5f280ba5c8d118ca525561d62ba03d2848ee8ccf4e9dc0ee2dd3c0f1654e4a860d7c2660054abc0f7b43f966d085a046e8d13d79d443877e4663949206d27e1c0e403b940f6b55adaa3d1d05d6ebc7a036febd90638ff87cf389e9d18e1261343f4b848b297a2eeddb8de03f9f6f72e5a04d0f3151c98e9882005d83f979d0b1b4c72a85488d0e43df44200b9daa820f2fa006b80ec1d712b87dedbc6c83a61181f1b1660367f79f9d3621e3f13892f62f97a042643aa4d88e6773708cd0650323df62aefdf81334d19354631a2e2caad2eb56a047fd07c70c71e33c398cd2f74815539026857ff4e88aec8d42944415e631fbdca03813dcdd0f965c82d268ea961512740b4fe18ebc49f6fbcedb50e90ccb4404c8a0c0ff7466388a7efd2b765e35e0e838efd24b90941e75ca0541f5a1875a91b5e0a084da50e176766386432792d57c3c165947f5f26768df2144c280cf2f4d0b7332a0edf669b3bede65313e1d9922318a81b49974ffc779e0a2f9197f1568ba484602a0e15355659e07306c23b750cfb94a04cc08eb6c604aca2a030205ba336aa5ebf9a06ddaebde56c66d14c4e180d1b18b26c8e7054748d7d1a592c0aab1d2038a52aba06512da3e1fe6916943e43a3832970546ee3533328c72706a8280f746ba0e19c9a093e7569b010543d858f5a282aa42a3287ede1d0f20366c09c220177630ec262a80",
      "f90211a072932994e5ccba54402d8a19f17057bd51826a43e91e602b71766a297540acb2a0a8d3133eb04782485bbed5677509a2d5ebb08c90d84ada3fa39261ef1417005ca0621fbd411e8382eca54aee09289a86b382df70c3ac35a3cc02d530cba24d6103a03c2244a383970bc6fe3383e2b679a65529d4170c53106a2b41554b017bcb20b8a076c63ea834a7e26ed8d391b0174c220c81e31dd2055c44c9ba582f2b0f64f44ca0fa80489f6545acedc30cafb48eda723f79001180cbcdebf9db842af72ba53d1ca0a84a14dfc996640d6c3fec92f6bafd0bd57731de78016fa1c3ed496a7e4aa11fa0f357b56bb8ec9702ef1c7465a3b70a048b7c72b7fc991fa15d518e2649371794a067078ba5bc0eaa979b89cd969d0361517dd6e0e3838685e9395f12b1b5662462a0a13889c6816ecb9be48a55d0a418828812b099df51bc85bc5c49bb39cbf75739a0af3cc7374a179deff576bcb35ed7382978c8e260b176897142cfe6aa39eaae58a0aa165726b087ab834d6d11073eb48c2641f4d1773e90dab0d8e88a6c2c0851efa04269c388ae327435fb1a5aa6c91c8d80b3eb85a3045f078c5d69b77f40a67165a0f423dcc768dfef95d27f6285fbb8c6aa1247dd1511624f221837707652d704a5a09bbab0eb7dcfcea1d92c222800a168e009fc7349d0ec703ce82cdb5d509ca2bda0c1262e5fbd0db24879f22921f9df77d81522b08664549ed437d9177ffb288eaa80",
      "f901b1a00a7a0118e00981ab321049c9d340cd52c3a4781037540f7c48d0fdc27e899b3280a08537f2e248702a6ae2a57e9110a5740f5772c876389739ac90debd6a0692713ea00b3a26a05b5494fb3ff6f0b3897688a5581066b20b07ebab9252d169d928717fa013f314e42ea1ffed8712dd91a9ab223bc396f639f4b4682960ead4363958f81fa01e2a1ed3d1572b872bbf09ee44d2ed737da31f01de3c0f4b4e1f046740066461a060a9f1eab9f62fa7328c7a3367d68539cc3b92a015800d4f5a116e4523affa7fa07da2bce701255847cf5169ba5a7578a9700133f7ce13fa26a1d4097c20d1e0fda07acc8fa6a79f207ca3db7a490eba1f212a34844bf9cd3c02a587c4470e778455a0c8d71dd13d2806e2865a5c2cfa447f626471bf0b66182a8fd07230434e1cad26a05076a8e18bea7b27c1ff7c5f6d283addf96ccca6e48426ece9678210cc0679baa0e9864fdfaf3693b2602f56cd938ccd494b8634b1f91800ef02203a3609ca4c21a0c69d174ad6b6e58b0bd05914352839ec60915cd066dd2bee2a48016139687f21a0513dd5514fd6bad56871711441d38de2821cc6913cb192416b0385f025650731808080",
      "f8669d3802a763f7db875346d03fbf86f137de55814b191c069e721f47474733b846f844012aa062e0c37938ff1036ff792ac8fb646bb80f823f962f29bdf873fe3047f3dfceaca0b44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55"
    ];
    let proof_nodes = [
      "f90211a0eefd6b7ae5088881c289ae3cc610cd6e1203f70ce3626c2df8dede35615f8277a09b93a6c55c26133152127e7f7b63c6186fb2373ad41f1544ba86e86256f78d64a05cb9fd54b22eaae584d06fcc727ba8dce6b87091335f8a901b88c8e962a221e7a0b225f2b8f1d8873660da1c873db7139b2fe27bef18cb33662f2491f6a2efa866a0f2d6f08702b2c242b919856358aef75bd3f4cbdb4db45bb9f0f541d77afba857a0c5322f217231bdb47390b41f3d1b1df1b1db129c450bce01347e807811dade6ba0e1feb24bac5faaf94a8b9b178123a5e544687dd31e2172872cc4076f0eab1ab1a0eab54f1c39358db4a71dbe5c83e78067a1d6ac2488cd04ed994cafe2ca1875cfa0e727bf62d995b4cad959e28a46dd6d5e41e4fd31bda5764f20938cb9829edd8fa030d68d6bebe39094927cd1f3a509db8c316c9ed9fc62f823dea47d4d06902bc0a00d7c91901503618e3a7afe961e434d51d092d806d85a1ca962f6f511d7d6ada2a061f61e253d3a1c390797f243b2ad9459f480842128fe472ef749d4d286a88598a08e7a9a8a7ba922dfdd12429d076c9acadb7afbcefd03f879f2780797309b146aa02db527e046a7981408d17816f57fea5baf0b804fc76edd8a52302fadb51eb8a5a06d1cdff5d195030ea17da924c6d873dfdd45d37fc5e1829f9f8244e6c53eed0da03c6ce43604d46453bf234913bcbb6b506c69dd25c10e2f0cf81b05168488723f80",
      "f90211a0c3f223e1946a8eb5f1720e97095ffc187b7428da45924fdb48d0c26091f5b56ca035ccd4ab389de6349c2cc18601206d1213afd3103fdf7a40b880b61a0e48eca4a0336986760b52acf07a525370f764c4fef932ccb17c3443c9ad76bde76e354ccda02c2edb3269eaa32369ef413d77eb322bc170e8b532c0af9dcbf9c80e3dc7d4d0a0fbf53cb09f83f07afe664781c04cfe2d09e03f31133a8ae669c9bcd7ea98f557a049c4c6feb43ceacf414c7aa337b435237839c364ecf9efc1ae561bdb2e125d00a0e499fe675d6288d72c4489b344c878ed1e9ac45872ce4a4049ba380877e888a4a0a313b5fa2f78acf080ef7a8e945cce0efe6c8f4f5f519ff81996bed1e68fb92da0f5b811ffa8358cc615f74e5aabb4ca80ff206535d31f3a1262747ac32716b7b2a0b7b6259f4f3f7feffa8ab152a29fe94d827938dcc0bf5d5654571a5119ad1918a02add6955c53e9dee50ffaaa76d583549086c8e5fe2db607cffcfccdafedf8f98a0d13af773e10fdece5b42c10092375a447436d56f19aa44ef21f5902e9194f248a0043df57a238b4ebd0b94b6699a7cd45b0a8045339a709f88b848cbd86b897fd0a0e664e5bf8a8803b64e2b17ecf96fcb491f5c03ba25a9fc5a07c536b112f50566a0f66d944efa82f2d4bd1a508e736b054af628cbab5704a02720ba726504889d7ea0573d407a9267d6df680903a97087db349357525e810d7ae26f7f96390ab3ec8880",
      "f90211a085472d97b344f0fcfe6b9818914999c9231d65e84deb5b325a4de8ce5fc47881a087f6478228c8ac97e1914057a1753544c7d8e7916b744cba2199101aed929da4a0d0468efaf6d20c1211e7ea71b55c3d72433d66f6f6dcc1024843acbbf5f9afe9a04e0a422eafd4983dacd055f19529cfab0c68469e2d84562bcf5e448f2ee7bba9a07672723ca2ea6bd94d7cc0b97b772385b34f493fd8bf53a462fd21b533909725a089ac28eaacba8d24681ee097d8d88be21ccf6772f135903ab0e010158bab2e74a0f8e2d22ced3ef84551e846d2db080affd1781f6083b35ba4d113316edb713ae9a0e57ab2f8e3b368cf77c5004130bd041fdf5c6c848ddd2c50df19df548ce9b286a0c59173939b72848e1ac4503d46b4aaee5eac3d0c643e92f5d4e83b639a293ff6a0770735faeb7e3666f0c9e64d5ed3c8be337bff2d4451a86ea6f2c979caddd063a096a1061f8a8e181b8d273dbf4da4d49e08fde5faa510ce6bdd6c578d5a4cb15ea00fbe85ac264a539cda1947f90532826c621a188ba33e3ef89273e242aadacfd0a05a1b01079f3a60a12c3720a59f976b1cfbcd36eea7a8316cacf993c1edbf703fa00789106f3ddaab5325224866470da147a0ab50a515c18a7c759a8e7089504364a0ff4cd1d1a71bff875dda7047efd97543bac9ea8cc1c636899bab286cbdc73feda0de8b010cad915c908613cb7e02eda4208b1ee5f7d059b6b75037a35fcbb4342a80",
      "f90211a0c5edf3f1ce1266cdf9f4396cc7eb2e638629e02c6f1f30ac9b287eb24b076a5ea0f709c0097573d9eeb36e22c85a0bcbb93f7817636716baaadfd34cd1d58f436da0f5a5b2d69448085d0050f0b484ff592b5f5ed917beb3dd5d0c82190611941d70a02ae90171a757608679b3f39e39d625430ca08e0930cdfcac9884f6730d74d8b7a0fc842dc011e8ce10c03ae5c2ac2d576e7de565370197633fde0f920979ebf8aba0bee9dbb89ebfafa6576828fb9684dda405436e396e8500a8b4d3843bf5e9a0c4a0dffcf491737ce3fbb94d739d6d0d79fd7419c2312fe0b00b659e5ea264faf0c0a03e9530b2245abda133ea575623cf2cb01a6df4280be4185448984aaf0ced0c04a0e5ff563656c305a2dd8fc0a68b474695ad647e7d0ee317a96b4cc3340c48b180a0c2111914f56d56d0844407a2236bb4697d1c06184ec2b4ba8286e89a53407c4aa093e87531223e6a07b9a03a8bddacfa148b5cdf14d39226f5adf57fea8c2d08eaa092791fcc425992c7c5d060641ebb88011e32f13b6ff935b9ff6af4e2184897caa01f6b0cadb3923b455665033173c44bef44544cb52ea96a33e3de5ce2a4794b5aa0130ad49128561c19220ed4ba8ad7195470c2e07afc4e60f92e65f12342d4ffcba0bb6907f22d15dc0932a519498d405a48818d264415c630fd48ca0a3b1733da6ca0aa4e679cb7af32b5e133bba014a1b90b195f9839048a38f45aa3ff39d5ee690880",
      "f90211a01dbeb6922b3a4945e1896ed75da0986075dfc47689ba71e21053a8eb8d3f9ad4a068d1f56af050ee3dc10741f64d0c902a007205d1a6310c99edc80cd7d688cc49a07e823d24a597dc57ac868bb2f33db9a54a0d0ba1325d210d417fa2330ce1935ba06bd5955d35f4530119748e999c6adc2b3f498f914da5dd54beabe187abdadceaa075c0cfb6a1a6a3f322f0603da96e3f1e52c4167ddfa4893671fe9e7f271a93c3a00a560f3a55e61e48de43ae8199d8d778d2824df7f6af80769ab0a79d72dad54ba08dd9726433221307b55abb99969a0c9cd4b8207a2dd532462b9e99448ac60333a0c95274bcd4ac13a5a3e2d7dbb38e275ec646dae5b3bd4759ef78c561f45267dda0301b93ce3e282b4c030a42b87b4bc2fe7ad19773c2844d1c026860e2676426f5a018b0b08af3975be282d6988bec676b9b528ea39046c78691a396336e9ab7e1d4a050063315e80c192a89c57d78044eb0451d05ed5de7a9909540a71d34170fc0d1a00becc95942cd72ec277c0ffc3ea4ae4097b0aefc76311c0e7fc73add15eb7800a0e091c5d5e4bf9b0521e802c976c2e78760d1c4a61a18819fc00c186065999050a098494a878a8c5ba36c3f3c85eeca5696a4f38866d94843e3d04266e2fbd5f8a8a0f4f02aed0ac7c42b4b67afb126f3aba3db49f276ab1f7877ceb9ae3eb1aad1d5a0bdec976d4fd0a9c36778cdb86f75e12ab5ebf92eb50f09ab936ee13ea30bcd4680",
      "f90151a0baa18f2c4bb18a86faa2ace133315f9df00ee79a800ae1083fcecd2f9472f5dda0fa96774fe30f0b0ea1e7d6ed2cd49a3e6472967b47d014323ff8745526fdd4c6a00ad2d2e385dff997534ad374657268101fda36e31285552d4ac0f06209ff6df6808080a01692b254fedcc131d8f8dc54e8a1fd40a6eb80c93e2693c93a3eefc325cf0eeca0294bde53062110328103e301062faad0e1175bc1e3649eadc5b281a298f4df16a01f0af1aeb57c6824fcdc4f00a8400887a4283bafde3422211aafda47ba644c01a073e562e71e5d2cca9839c437229d4e584a182298bf9cf0547bd3741cf16946078080a073648673e3c4bf08e52be9f11a5ceeea288a868b0e4a1fe39d90b892d7afa9c2a0ace9b5fd2cc4a4e23914fdc460879c3a123a4c6471036652347ffee11d71571a80a06f23ca1f167b52e366a7cb9628d5d7d5ca2af5377e951e6907721d6a2227210380",
      "f8918080a03269a56e4a8c5a0db5480a777c04f55435708b2aa668221eca0a51597f917eed8080808080808080a0188adbc95db819328813c282bfe9d78819dff2c5c83041ba936431635424da8a80a0f4873cb7178849abe99b3515f3195aebc99d9534da6ec2e0810451fa4b9991d8a0ecc39656249293cb09392fca250f68ac8e3a3266b1ea0cd9cc7b2a157d0f95828080",
      "f49d39548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594c6cde7c39eb2f0f0095f41570af89efc2c1ea828"
    ];
    let mut first_hh = B256::zero();
    for node in account_nodes.iter() {
      let node_bytes = hex::decode(node).unwrap();
      let ob = ObliviousNode::from_rlp(&node_bytes).unwrap();
      let hh = ob.keccak_hash();
      if first_hh == B256::zero() {
        first_hh = hh;
      }
      {
        let mut guard = state.storage.lock().await;
        guard.insert(hh, ob);
      }
    }
    for node in proof_nodes.iter() {
      let node_bytes = hex::decode(node).unwrap();
      let ob = ObliviousNode::from_rlp(&node_bytes).unwrap();
      let hh = ob.keccak_hash();
      {
        let mut guard = state.storage.lock().await;
        guard.insert(hh, ob);
      }
    }
    println!("First hh: {:?}", first_hh.to_hex());
    state.set_root(1, first_hh).await;
    let addr_hex = String::from("0xdAC17F958D2ee523a2206206994597C13D831ec7");
    let params = GetProofParams(addr_hex, vec![B256::zero().to_hex()], BlockSelector::Number(1));
    let res = eth_get_proof_handler(params, state.clone()).await;
    assert!(res.is_ok());
    let ok = res.unwrap();
    println!("res: {:?}", ok);
    let account_proof = ok.account_proof.get();
    println!("Account proof (raw): {}", account_proof);
    let account_proof = serde_json::from_str::<Vec<String>>(account_proof).unwrap();
    assert!(!account_proof.is_empty());
    println!("Account proof: {:?}", account_proof);
  }
}
