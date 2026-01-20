//! Trie proof generation utilities.
//!
use std::sync::Arc;

use bytemuck::Zeroable;
use rostl_datastructures::map::UnsortedMap;
use rostl_oram::linear_oram::oblivious_memcpy;
use rostl_primitives::traits::Cmov;
use tokio::sync::Mutex;

use crate::oblivious_node::{ObliviousNode, NODE_BUF, VALUE_BUF};
use crate::types::{bytes_to_hex_oblivious_hidden_size_quoted, B256};

const MAX_SLOTS: usize = 16;

/// Generate proof by collecting RLP nodes into a fixed-size buffer and then
/// perform oblivious compaction to move valid nodes to the front.
///
/// Note: We return fixed-size node buffers (`[u8; NODE_BUF]`)
/// rather than variable-length vectors, so callers cannot learn node lengths.
pub async fn generate_proof<const ADDR_LEN: usize>(
  storage: &Arc<Mutex<UnsortedMap<B256, ObliviousNode>>>,
  root_hash: B256,
  key: &[u8],
  ret_proof: &mut String,
  ret_value: &mut [u8; VALUE_BUF],
) -> Option<()> {
  // fixed-size slots with padding
  let mut slots: Vec<[u8; NODE_BUF]> = vec![[0u8; NODE_BUF]; MAX_SLOTS];

  let mut curr_hash = root_hash.0;
  let mut ret_value_or_next_hash = [0u8; VALUE_BUF];
  let mut enabled = true;
  let mut idx = 0;
  // place root in slot 0 (do not trim; keep fixed-size representation)

  ret_proof.push('[');
  for slot in slots.iter_mut() {
    curr_hash.as_mut_slice().cmov([0u8; 32].as_slice(), !enabled);
    let ob_node = {
      let mut r = ObliviousNode::zeroed();
      let mut map = storage.lock().await;
      let _found = map.get(B256(curr_hash), &mut r);
      r
    };

    // UNDONE(): Discuss how to handle missing nodes.
    if enabled & (ob_node.rlp_length == 0) {
      return None;
    }

    ret_proof.push_str(unsafe {
      String::from_utf8_unchecked(ob_node.to_hex_bytes_with_quotes().to_vec()).as_str()
    });

    slot.copy_from_slice(&ob_node.rlp_encoded);

    ob_node.traverse_oblivious::<ADDR_LEN>(key, &mut idx, &mut ret_value_or_next_hash);

    ret_value.as_mut_slice().cmov(ret_value_or_next_hash.as_slice(), enabled & (idx == key.len()));
    enabled &= idx < key.len();
    let extra_char = {
      let mut r = b' ';
      r.cmov(&b',', enabled);
      r
    };
    ret_proof.push(extra_char as char);

    curr_hash.copy_from_slice(&ret_value_or_next_hash[1..33]);
  }
  ret_proof.push(']');

  Some(())
}

pub fn parse_account(rlp_bytes: &[u8]) -> (String, String, B256, B256) {
  let rlp_bytes = &rlp_bytes[2..];
  let mut s_nonce = [0u8; 32];
  let mut s_balance = [0u8; 32];
  let mut s_storage_root = [0u8; 32];
  let mut s_code_hash = [0u8; 32];

  let (_tp, _size, start) = ObliviousNode::rlp_decode_type_and_size(rlp_bytes, 0);

  let (_tp_nonce, size_nonce, start_nonce) =
    ObliviousNode::rlp_decode_type_and_size(rlp_bytes, start);
  let (_tp_balance, size_balance, start_balance) =
    ObliviousNode::rlp_decode_type_and_size(rlp_bytes, start_nonce + size_nonce);
  let (_tp_storage_root, size_storage_root, start_storage_root) =
    ObliviousNode::rlp_decode_type_and_size(rlp_bytes, start_balance + size_balance);

  let (_tp_code_hash, _size_code_hash, start_code_hash) =
    ObliviousNode::rlp_decode_type_and_size(rlp_bytes, start_storage_root + size_storage_root);

  oblivious_memcpy(&mut s_nonce, rlp_bytes, start_nonce);
  oblivious_memcpy(&mut s_balance, rlp_bytes, start_balance);
  oblivious_memcpy(&mut s_storage_root, rlp_bytes, start_storage_root);
  oblivious_memcpy(&mut s_code_hash, rlp_bytes, start_code_hash);

  (
    bytes_to_hex_oblivious_hidden_size_quoted(&s_nonce, size_nonce),
    bytes_to_hex_oblivious_hidden_size_quoted(&s_balance, size_balance),
    B256(s_storage_root),
    B256(s_code_hash),
  )
}

pub fn parse_value(rlp_bytes: &[u8]) -> String {
  let mut rlp_bytes_local = vec![0u8; rlp_bytes.len()];
  let (_tp, size, _start) = ObliviousNode::rlp_decode_type_and_size(rlp_bytes, 0);
  oblivious_memcpy(&mut rlp_bytes_local, rlp_bytes, _start);

  bytes_to_hex_oblivious_hidden_size_quoted(&rlp_bytes_local, size)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::oblivious_node::ObliviousNode;
  use crate::types::B256;
  use crate::types::H160;
  use rlp::RlpStream;
  use rostl_datastructures::map::UnsortedMap;
  use sha3::Digest;
  use sha3::Keccak256;
  use std::sync::Arc;
  use tokio::sync::Mutex;

  #[tokio::test]
  async fn test_generate_proof_leaf_returns_value() {
    // Build a leaf node for path [4,5] (encoded as two nibbles) with a small value
    let mut s = RlpStream::new_list(2);
    let path_bytes = vec![0x20u8, 0x45u8]; // leaf encoding for [4,5]
    let value = b"leafval".to_vec();
    s.append(&path_bytes.as_slice());
    s.append(&value.as_slice());
    let out = s.out();

    // Parse as oblivious node and compute its hash
    let ob = ObliviousNode::from_rlp(&out).expect("should parse leaf");

    // Prepare storage and insert node under **zero** root hash because generate_proof
    // reads the first slot's hash from the ret_value buffer (initially zeros).
    let storage = Arc::new(Mutex::new(UnsortedMap::<B256, ObliviousNode>::new(1 << 10)));
    {
      let mut guard = storage.lock().await;
      // Insert leaf under zero hash so generate_proof will find it on first lookup
      guard.insert(ob.keccak_hash(), ob);
    }

    let mut ret_proof = String::new();
    let mut ret_value = [0u8; VALUE_BUF];
    let key = [4u8, 5u8];

    // Call generate_proof with a non-significant root hash (function currently uses stored zeros)
    let res =
      generate_proof::<2>(&storage, ob.keccak_hash(), &key, &mut ret_proof, &mut ret_value).await;
    assert!(res.is_some(), "proof should be generated");

    // Value is copied into ret_value starting at index 1
    assert_eq!(&ret_value[1..1 + value.len()], &value[..]);
    // Proof string should contain at least one quoted hex blob
    assert!(ret_proof.contains("\"0x"), "proof should contain quoted hex bytes");
  }

  #[tokio::test]
  async fn test_generate_proof_missing_node_returns_none() {
    // Empty storage - generate_proof should return None when nodes are missing
    let storage = Arc::new(Mutex::new(UnsortedMap::<B256, ObliviousNode>::new(1 << 10)));
    let mut ret_proof = String::new();
    let mut ret_value = [0u8; VALUE_BUF];
    let key = [1u8, 2u8];

    let res =
      generate_proof::<2>(&storage, B256::zero(), &key, &mut ret_proof, &mut ret_value).await;
    assert!(res.is_none(), "missing nodes should cause generate_proof to return None");
  }

  #[tokio::test]
  async fn test_generate_proof_two_level_traversal() {
    let tree = hex::decode("f9019180a0d099bd7d3abff0fcc204767c25d46431cd5860d064f8239fd059e3aa86a28315a0513bd648588366fe97a609f98c3b6acb72079447da0f6e3b48b968fe77a9c073a0da023965fae5cbff58d25ccbe28569ae68056918d47cfc24e2078b3bb486a313a0dd5fe0dcac98a33a79c02f9fa36971d8f16c41a2a85ba8adddcfd09f41c06a21808080a054824ab635846882e67b7c8164ab36b84e69f912627db2f4becc269a8ca2bd2da020be56269f26196ec9f512446e8d295d0e40616e488d0d9fe1422cd08585c1c2a0ce9bd6bb73703cb8dbc73f780600af09f2d22487ddb4386be334ca4fdd17153aa0b7c03aa826332640f1233cf08629fff3175efbd8de4f10ffa83dc1cfaac99bb6a00a6f203d6d738440c6e363aceeb30f5e4b8ba2df4e38712a3117253d602d781aa049be0800e8f888681050428a1fce245b22b6445e38cbcffee1567a9cf501a72fa081a01475ac9b72444b3457c9b0acb43c937aa02d3b5a842a3a556ad0b9dca020a032d51b502b092309f45978054150378058ce5037e945da2240e09632bf72375080").unwrap();
    let leaf = hex::decode("f8518080808080a077c371b54a8affc7cf04d7a869778d43735c89b66f68fdb27ff0f1c014b8d6d0808080808080808080a0a0427726145981ce344c0af8eb7ba123edc8034cfa878c80bb78443ef79eae3a80").unwrap();
    let root_ob = ObliviousNode::from_rlp(&tree).expect("should parse root");
    let leaf_ob = ObliviousNode::from_rlp(&leaf).expect("should parse leaf");

    let storage = Arc::new(Mutex::new(UnsortedMap::<B256, ObliviousNode>::new(1 << 10)));
    {
      let mut guard = storage.lock().await;
      guard.insert(root_ob.keccak_hash(), root_ob);
      guard.insert(leaf_ob.keccak_hash(), leaf_ob);
    }

    let mut ret_proof = String::new();
    let mut ret_value = [0u8; VALUE_BUF];
    let key = [10u8, 0u8];

    let root_hash = root_ob.keccak_hash();
    let res = generate_proof::<2>(&storage, root_hash, &key, &mut ret_proof, &mut ret_value).await;
    assert!(res.is_some(), "proof should be generated");

    // Value should be copied into ret_value
    assert_eq!(&ret_value, &[0u8; VALUE_BUF]);

    // Proof should contain at least three quoted node hex entries (one per level)
    let occurrences = ret_proof.matches("\"0x").count();
    assert!(occurrences == 2, "expected 2 nodes in proof, got {}", occurrences);
  }

  #[tokio::test]
  async fn test_generate_proof_traversal_realistic_with_value() {
    let nodes = [
      hex::decode("f90211a0566708ef4aff27b9fc8accd70049913fa5b9c8093467fb0a2140e44b334915e8a0dd8e625373cc891c78fdd4986655ac7e2b5578a35e5959770b567f03046a95d1a08642bfb65d5008cf4e22586b3804d4aed6c64a45d2ad63b99fe7dab85d0a0a03a08f2bb34ec1dcd9824e0747e05629176e541a0630a7540bf97bfeb5bca26a3303a0823eff09ef9945aeba4d152285983073a6047324a4bbfe37f4621cb805d7be93a04e9b7529a43413ebf50f24da23828759e0a53c662c914eb7eada84f9102daba7a06579edfe2f0f4ca137c72fc41338a9f67fe10f0405f4d61baef032e772b70a2ba04294d192eaae0dd7497252e9dc984fb87dd64137461f372621570944e3341952a01d352ff864367b18fe10c4c14bfa855adc24584290ee459d3da2175e16cec8afa02a5bc07abc543717dc3b126a5eef8c6c9f72ea88e4a015673769de2390268358a0a387c95fee96a37762d755b41346825e097ddde2dc242d21cf5a7a6d9dc098efa061f9cc2741c519d99742b2c87209d6f0c37c391cb2ea267833e82dd45c4e62dda06d78e00ae64fc0722dc5fe37f027750d02f5d24a4926e478c33c0dd9d4985f29a0d55f1f6dcd7dba07a67671d33e32867753babf6342512cbfc20e77b7ae04df30a059de2d780f78b03095612400499d69ec0052e77b8f33be20ab49420635cf200ea0c76b2023420717ee51c984a805f2e21da9f970d76ce4a543f7f80539e1959c5b80").unwrap(),
      hex::decode("f90211a000e90caedea19c813aa22144ec9b18cfc976cdcfc407ea2e2dcf09c3a7349fcaa058659211d9c72d3c3b97bba4c6105ec7c21e6300f7e32142da3d6357cc412281a043ebf2c20b9b9be48155a9dd398bd48d10ee275c6b9874e941c19b2405fa3e2ba06bd5955d35f4530119748e999c6adc2b3f498f914da5dd54beabe187abdadceaa075c0cfb6a1a6a3f322f0603da96e3f1e52c4167ddfa4893671fe9e7f271a93c3a00a560f3a55e61e48de43ae8199d8d778d2824df7f6af80769ab0a79d72dad54ba08dd9726433221307b55abb99969a0c9cd4b8207a2dd532462b9e99448ac60333a0c95274bcd4ac13a5a3e2d7dbb38e275ec646dae5b3bd4759ef78c561f45267dda0f10eb5862cfc3765d980a9b5c16ded813222c5dc06bd30baea09855e3941ba86a018b0b08af3975be282d6988bec676b9b528ea39046c78691a396336e9ab7e1d4a0f2af0fd836ea7f2514a1ddd42a1d2e482be09aae3376e999c98a360aac824229a00becc95942cd72ec277c0ffc3ea4ae4097b0aefc76311c0e7fc73add15eb7800a0654bb7a00f5df9c0e3bbdb2d3a4bf049d8d7c8097370d3334a454e3292879dc1a098494a878a8c5ba36c3f3c85eeca5696a4f38866d94843e3d04266e2fbd5f8a8a0556cb732ac9928cdae051968d817be9f21ac1a0438f9d3587aee3992725b2d33a0bdec976d4fd0a9c36778cdb86f75e12ab5ebf92eb50f09ab936ee13ea30bcd4680").unwrap(),
      hex::decode("f90151a022b9d68ec893e46a41c316bde1406b19b1b15e51f5c35f3dfbbaeff3e302661ea0fa96774fe30f0b0ea1e7d6ed2cd49a3e6472967b47d014323ff8745526fdd4c6a00ad2d2e385dff997534ad374657268101fda36e31285552d4ac0f06209ff6df6808080a01692b254fedcc131d8f8dc54e8a1fd40a6eb80c93e2693c93a3eefc325cf0eeca0294bde53062110328103e301062faad0e1175bc1e3649eadc5b281a298f4df16a01f0af1aeb57c6824fcdc4f00a8400887a4283bafde3422211aafda47ba644c01a073e562e71e5d2cca9839c437229d4e584a182298bf9cf0547bd3741cf16946078080a073648673e3c4bf08e52be9f11a5ceeea288a868b0e4a1fe39d90b892d7afa9c2a0ace9b5fd2cc4a4e23914fdc460879c3a123a4c6471036652347ffee11d71571a80a06f23ca1f167b52e366a7cb9628d5d7d5ca2af5377e951e6907721d6a2227210380").unwrap(),
      hex::decode("f8918080a03269a56e4a8c5a0db5480a777c04f55435708b2aa668221eca0a51597f917eed8080808080808080a0188adbc95db819328813c282bfe9d78819dff2c5c83041ba936431635424da8a80a0f4873cb7178849abe99b3515f3195aebc99d9534da6ec2e0810451fa4b9991d8a0ecc39656249293cb09392fca250f68ac8e3a3266b1ea0cd9cc7b2a157d0f95828080").unwrap(),
      hex::decode("f49d39548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594c6cde7c39eb2f0f0095f41570af89efc2c1ea828").unwrap(),
    ];
    let val = hex::decode("9594c6cde7c39eb2f0f0095f41570af89efc2c1ea828").unwrap();

    let storage = Arc::new(Mutex::new(UnsortedMap::<B256, ObliviousNode>::new(1 << 10)));
    {
      let mut guard = storage.lock().await;
      for n in nodes.iter() {
        let ob = ObliviousNode::from_rlp(n).expect("should parse node");
        guard.insert(ob.keccak_hash(), ob);
      }
    }

    let mut ret_proof = String::new();
    let mut ret_value = [0u8; VALUE_BUF];
    let key = [
      13, 14, 12, 13, 9, 5, 4, 8, 0xb, 6, 2, 0xa, 8, 0xd, 6, 0, 3, 4, 5, 0xa, 9, 8, 8, 3, 8, 6,
      0xf, 0xc, 8, 4, 0xb, 0xa, 6, 0xb, 0xc, 9, 5, 4, 8, 4, 0, 0, 8, 0xf, 6, 3, 6, 2, 0xf, 9, 3, 1,
      6, 0, 0xe, 0xf, 3, 0xe, 5, 6, 3,
    ];

    let root_hash = ObliviousNode::from_rlp(&nodes[0]).unwrap().keccak_hash();
    let res = generate_proof::<61>(&storage, root_hash, &key, &mut ret_proof, &mut ret_value).await;
    assert!(res.is_some(), "proof should be generated");

    // Proof should contain at least three quoted node hex entries (one per level)
    let occurrences = ret_proof.matches("\"0x").count();
    assert_eq!(occurrences, 5);

    // Value should be copied into ret_value
    assert_eq!(&ret_value[..val.len()], &val[..]);
  }

  #[tokio::test]
  async fn test_generate_proof_account() {
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

    let storage = Arc::new(Mutex::new(UnsortedMap::<B256, ObliviousNode>::new(1 << 10)));
    {
      let mut guard = storage.lock().await;
      for n in account_nodes.iter() {
        let n = hex::decode(n).expect("should decode hex");
        let ob = ObliviousNode::from_rlp(n.as_slice()).expect("should parse node");
        let hh = ob.keccak_hash();
        println!("Inserting account node with hash: {}", hh.to_hex());
        guard.insert(ob.keccak_hash(), ob);
      }
    }
    let root_hash =
      ObliviousNode::from_rlp(&hex::decode(account_nodes[0]).unwrap()).unwrap().keccak_hash();

    let mut ret_proof = String::new();
    let mut ret_value = [0u8; VALUE_BUF];
    let key = H160::from_hex("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap().keccak_hash();

    let res =
      generate_proof::<64>(&storage, root_hash, &key.to_nibbles(), &mut ret_proof, &mut ret_value)
        .await;
    assert!(res.is_some(), "proof should be generated");

    // Proof should contain at least three quoted node hex entries (one per level)
    let occurrences = ret_proof.matches("\"0x").count();
    assert_eq!(occurrences, 8);
  }

  #[tokio::test]
  async fn test_generate_proof_three_level_traversal() {
    // Build a three-level chain: root(branch) -> intermediate(branch) -> leaf(leaf)
    // Key: [1,4,5]

    // 1) leaf: path [5] encoded as single-nibble leaf (hp=3, nibble=5)
    let mut s_leaf = RlpStream::new_list(2);
    let leaf_path = vec![0x35u8]; // single-nibble leaf: hp=3 (odd+leaf), nibble=5
    let leaf_value = b"deep_leaf".to_vec();
    s_leaf.append(&leaf_path.as_slice());
    s_leaf.append(&leaf_value.as_slice());
    let leaf_out = s_leaf.out();
    let leaf_ob = ObliviousNode::from_rlp(&leaf_out).expect("should parse leaf");
    let leaf_hash = Keccak256::digest(&leaf_out);
    let mut leaf_h_arr = [0u8; 32];
    leaf_h_arr.copy_from_slice(&leaf_hash);

    // 2) intermediate: branch with child at index 4 = hash(leaf)
    let mut s_int = RlpStream::new_list(17);
    for i in 0..16 {
      if i == 4 {
        s_int.append(&leaf_h_arr.as_ref());
      } else {
        s_int.append(&"");
      }
    }
    s_int.append(&""); // value
    let int_out = s_int.out();
    let int_ob = ObliviousNode::from_rlp(&int_out).expect("should parse branch");
    let int_hash = Keccak256::digest(&int_out);
    let mut int_h_arr = [0u8; 32];
    int_h_arr.copy_from_slice(&int_hash);

    // 3) root: branch with child at index 1 = hash(intermediate)
    let mut s_root = RlpStream::new_list(17);
    for i in 0..16 {
      if i == 1 {
        s_root.append(&int_h_arr.as_ref());
      } else {
        s_root.append(&"");
      }
    }
    s_root.append(&"");
    let root_out = s_root.out();
    let root_ob = ObliviousNode::from_rlp(&root_out).expect("should parse branch");

    // Insert nodes into storage under their canonical Keccak hashes, except the root
    // which we insert under zero so generate_proof picks it on the first iteration.
    let mut leaf_h_arr = [0u8; 32];
    leaf_h_arr.copy_from_slice(&leaf_hash);
    let mut int_h_arr = [0u8; 32];
    int_h_arr.copy_from_slice(&int_hash);

    let storage = Arc::new(Mutex::new(UnsortedMap::<B256, ObliviousNode>::new(1 << 10)));
    {
      let mut guard = storage.lock().await;
      guard.insert(B256(leaf_h_arr), leaf_ob);
      guard.insert(B256(int_h_arr), int_ob);
      // root stored under zero hash for first lookup
      guard.insert(B256([0u8; 32]), root_ob);
    }

    let mut ret_proof = String::new();
    let mut ret_value = [0u8; VALUE_BUF];
    let key = [1u8, 4u8, 5u8];

    let res =
      generate_proof::<3>(&storage, B256::zero(), &key, &mut ret_proof, &mut ret_value).await;
    assert!(res.is_some(), "proof should be generated for three-level chain");

    // Value should be copied into ret_value
    assert_eq!(&ret_value[1..1 + leaf_value.len()], &leaf_value[..]);

    // Proof should contain at least three quoted node hex entries (one per level)
    let occurrences = ret_proof.matches("\"0x").count();
    assert!(occurrences >= 3, "expected at least 3 nodes in proof, got {}", occurrences);
  }
}
