//! Oblivious representation of a trie node and utils to traverse it.
//
use bytemuck::{Pod, Zeroable};
use rostl_oram::linear_oram::oblivious_memcpy;
use rostl_primitives::traits::{Cmov, _Cmovbase};
use serde_json::value::RawValue;
use sha3::{Digest, Keccak256};

use crate::types::{bytes_to_hex_oblivious, nibble_to_hex_oblivious, B256};

/// Fixed buffer size for oblivious nodes (maximum size should be max(33*16 + 1, 33 + VALUE_BUF) + small k)
pub const NODE_BUF: usize = 512 + 32 - 1; // 512 bytes + some extra slack so that Oblivious Node is aligned to 8 bytes without wasting space.

/// Metadata sizes for the precomputed node layout used by the oblivious traversal
pub const MAX_CHILDREN: usize = 16;
/// Maximum path size for an extension node
pub const PATH_MAX: usize = 64;
/// Maximum value for a leaf node (we only support accounts and storage values, so the max size is the max size of account)
pub const VALUE_BUF: usize = 2 + 9 + 15 + (33) * 2; // ([nonce_8, balance_14, storageRoot_32, codeHash_32])
/// Maximum size of an inline node (in this case leaf node of account trie)
pub const MAX_INLINE_NODE: usize = VALUE_BUF + 33 + 2 + 1; // max size of inline node, +1 is just padding
/// Special index value indicating non-membership, just needs to be a value larger than 64.
pub const IDX_NONMEMBER: usize = 73;

/// Oblivious representation of a trie node, storing the RLP encoding and simple metadata.
/// NODE_BUF is large enough to store any node.
/// Nodes are either branch nodes (17-item lists) or leaf/extension nodes (2-item lists).
/// When processing nodes, we make the assumption that there are no inline branch nodes. This is acceptable as inline branch nodes would require an RLP prefix collision of at least 20 bytes. If there are inline branch nodes, we just lose the ability to produce proofs for those nodes.
#[repr(align(8))]
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObliviousNode {
  /// RLP encoded bytes of the node, padded to NODE_BUF length.
  pub rlp_encoded: [u8; NODE_BUF],
  /// Actual length of the RLP encoded bytes.
  pub rlp_length: usize,
  /// Whether this node is a branch node (17-item list).
  pub is_branch: u8,
}
unsafe impl Zeroable for ObliviousNode {}
unsafe impl Pod for ObliviousNode {}
impl Default for ObliviousNode {
  fn default() -> Self {
    ObliviousNode { rlp_encoded: [0u8; NODE_BUF], rlp_length: 0, is_branch: 0 }
  }
}
impl_cmov_for_pod!(ObliviousNode);

impl ObliviousNode {
  /// Decodes the type and size from an rlp prefix. If the prefix requires more bytes to decode the size, size will be 0 and start_offset will be the number of bytes after this needed to read the full size - 1.
  /// Returns (type, size, start_offset)
  pub fn rlp_decode_type_and_size_from_prefix(prefix: u8) -> (u8, usize, usize) {
    let mut tp = 0u8;
    let mut rlen = 0usize;
    let mut r_extraoffset = 0usize;

    let is_inline_char = prefix <= 0x7f;
    let is_short_string = (prefix > 0x7f) & (prefix <= 0xb7);
    let is_long_string = (prefix >= 0xb8) & (prefix <= 0xbf);
    let is_short_list = (prefix >= 0xc0) & (prefix <= 0xf7);
    let is_long_list = prefix >= 0xf8;

    // Types:
    tp.cmov(&1u8, is_inline_char | is_short_string | is_long_string); // string
    tp.cmov(&2u8, is_short_list | is_long_list); // list

    // Lengths and offsets:
    rlen.cmov(&1, is_inline_char);

    rlen.cmov(&((prefix as usize).wrapping_sub(0x80)), is_short_string);
    rlen.cmov(&((prefix as usize).wrapping_sub(0xc0)), is_short_list);
    r_extraoffset.cmov(&1, is_short_string | is_short_list);

    // Code only for long string/list length parsing:
    let base = {
      let mut base = 0xb7usize;
      base.cmov(&0xf7, is_long_list);
      base
    };

    // compute prefix_size only when long string/list
    r_extraoffset.cmov(
      &(1usize.wrapping_add((prefix as usize).wrapping_sub(base))),
      is_long_string | is_long_list,
    );

    (tp, rlen, r_extraoffset)
  }
  /// Decodes the type and size of an rlp inline node.
  /// Returns (type, size, start_offset)
  /// Requires that size <= 0xffff
  pub fn rlp_decode_type_and_size(node_bytes: &[u8], offset: usize) -> (u8, usize, usize) {
    assert!(node_bytes.len() >= 3, "rlp_decode_type_and_size requires at least 3 bytes");

    let (prefix, prefix2, prefix3) = {
      let mut prefixes = [0u8; 3];
      oblivious_memcpy(&mut prefixes, node_bytes, offset);
      (prefixes[0], prefixes[1], prefixes[2])
    };
    let (tp, mut rlen, r_extraoffset) = Self::rlp_decode_type_and_size_from_prefix(prefix);

    let long_len = {
      let mut long_len = 0usize;

      // UNDONE(): Assertion disabled until we add an enabled flag to this function
      // assert!(r_extraoffset <= 3, "UNDONE(): implement very large rlp encoding parsing");
      long_len.cmov(&(prefix2 as usize), r_extraoffset == 2);
      long_len.cmov(&((prefix2 as usize) << 8 | (prefix3 as usize)), r_extraoffset == 3);
      long_len
    };

    rlen.cmov(&long_len, r_extraoffset > 1);

    (tp, rlen, offset + r_extraoffset)
  }

  /// Traverse the inline node given an address we are parsing.
  /// Requires that |node_bytes| >= 3
  /// For the account trie, this can never be a branch node. For the storage trie, it is extremely unlikely this is a branch node (equivalent to finding a keccak hash collision). Thus, we do not implement branch node parsing here.
  pub fn traverse_inline_node<const ADDR_LEN: usize>(
    enabled: bool,
    addr_nibbles: &[u8],
    idx: &mut usize,
    node_bytes: &[u8],
    ret_value_or_next_hash: &mut [u8; VALUE_BUF],
  ) {
    let mut enabled = enabled;
    assert!(node_bytes.len() >= 4, "inline node must have at least 4 bytes for RLP decoding");

    let (_tp, _size, start) = Self::rlp_decode_type_and_size(&node_bytes[..3], 0);

    let mut curr_idx = start;

    // Decode first element: compact encoded path
    let (path_tp, path_size, path_start) =
      Self::rlp_decode_type_and_size(&node_bytes[..4], curr_idx);
    curr_idx = path_start + path_size;

    let path_nibbles = {
      let mut path_nibbles = [0u8; 1 + PATH_MAX / 2];
      oblivious_memcpy(path_nibbles.as_mut_slice(), node_bytes, path_start);
      path_nibbles
    };

    // Compact path header (hp) is stored in the high nibble of the first path byte.
    // hp: low bit = odd flag, bit 1 = leaf flag (standard hex-prefix encoding)
    let hp_nibble = path_nibbles[0] >> 4;
    // let is_leaf = (hp_nibble & 0x2) != 0;
    let is_odd = (hp_nibble & 0x1) != 0;
    let path_len = {
      let mut pl = 0usize;
      pl.cmov(&((path_size * 2).wrapping_sub(1)), is_odd);
      pl.cmov(&((path_size * 2).wrapping_sub(2)), !is_odd);
      pl
    };

    assert!((!enabled) | (path_tp == 1u8), "impossible path type");

    let addr_nibles_shifted = {
      let mut r = [0u8; ADDR_LEN];
      oblivious_memcpy(&mut r, addr_nibbles, *idx);
      r
    };

    // Process compact path bytes
    #[allow(clippy::needless_range_loop)]
    for i in 0..PATH_MAX.min(ADDR_LEN) {
      let idx_even = 1 + (i >> 1);
      let idx_odd = (i + 1) >> 1;
      let byte_even = path_nibbles[idx_even];
      let byte_odd = path_nibbles[idx_odd];
      let nib_even = {
        if i % 2 == 0 {
          (byte_even >> 4) & 0x0F
        } else {
          byte_even & 0x0F
        }
      };
      let nib_odd = {
        if (i + 1) % 2 == 0 {
          (byte_odd >> 4) & 0x0F
        } else {
          byte_odd & 0x0F
        }
      };
      let curr_nib = {
        let mut r = nib_even;
        r.cmov(&nib_odd, is_odd);
        r
      };
      let matched = curr_nib == addr_nibles_shifted[i];
      let should_check = enabled & (i < path_len);
      idx.cmov(&IDX_NONMEMBER, should_check & !matched);
      idx.cmov(&(*idx + 1), should_check & matched);
      enabled.cmov(&false, should_check & !matched);
    }

    // After processing the path nibbles, decode second RLP element (value or child). Only process if still enabled.
    let copy_index = {
      let mut r = curr_idx;
      r.cmov(&node_bytes.len(), !enabled);
      r
    };

    oblivious_memcpy(ret_value_or_next_hash, node_bytes, copy_index);
  }

  /// Traverse the node given a full address nibble array `addr_nibbles` and a current
  /// nibble index `idx`.
  /// `ADDR_LEN` - public length (nibbles) of the address;
  ///
  /// if idx <= ADDR_LEN, the traversal is active and will process the next nibble at addr_nibbles[idx];
  /// if idx == ADDR_LEN + 1, the traversal has already terminated and found some value;
  /// if idx == IDX_NONMEMBER, the traversal has already terminated and found non-membership.
  pub fn traverse_oblivious<const ADDR_LEN: usize>(
    &self,
    addr_nibbles: &[u8],
    idx: &mut usize,
    ret_value_or_next_hash: &mut [u8; VALUE_BUF],
  ) {
    debug_assert_eq!(addr_nibbles.len(), ADDR_LEN);

    let enabled = *idx <= ADDR_LEN;

    // Processes branch nodes:
    let mut tmp_addr_nibble: u8 = 0;
    rostl_oram::linear_oram::oblivious_read_index::<u8>(addr_nibbles, *idx, &mut tmp_addr_nibble);

    let is_branch_node = self.is_branch != 0;

    let (_tp, size, start) = Self::rlp_decode_type_and_size(&self.rlp_encoded[..3], 0);

    let mut state_branch_count = 0;
    let mut state_curr_remaining = start;
    let mut state_target_len = 0;
    let mut state_target_offset = 0;
    for (i, curr_byte) in self.rlp_encoded.iter().enumerate() {
      let inside_encoding = enabled & is_branch_node & (i < size + start);

      // UNDONE(): we can create a specialization of rlp_decode_type_and_size_from_prefix that only checks for short types, since branch children cannot be long types.
      let (_tp_new, size_new, start_new) = Self::rlp_decode_type_and_size_from_prefix(*curr_byte);

      let at_element_start = inside_encoding & (state_curr_remaining == 0);
      let at_target_element_start =
        at_element_start & (state_branch_count == (tmp_addr_nibble as usize));
      state_target_len.cmov(&size_new, at_target_element_start);
      state_target_offset.cmov(&i, at_target_element_start);

      state_curr_remaining.cmov(&(size_new + start_new), at_element_start);
      state_branch_count = state_branch_count.wrapping_add(at_element_start as usize);
      state_curr_remaining = state_curr_remaining.wrapping_sub(1);
    }

    let reached_nonmember_node = enabled & is_branch_node & (state_target_len == 0);
    let has_inline_child =
      enabled & is_branch_node & (state_target_len < 32) & (state_target_len > 0);
    let has_child_hash = enabled & is_branch_node & (state_target_len == 32);

    let should_parse_inline_node = enabled & (has_inline_child | !is_branch_node);

    idx.cmov(&(*idx + 1), has_inline_child | has_child_hash);
    idx.cmov(&IDX_NONMEMBER, reached_nonmember_node);

    let mut buffer = [0u8; MAX_INLINE_NODE];

    // Process the inside of the inline node. This node comes either from the rlp encoding of a leaf/extension, or from the inline child of a branch node (which is also a leaf/extension node).
    buffer.copy_from_slice(&self.rlp_encoded[..MAX_INLINE_NODE]);
    let mut buffer2 = [0u8; 33];
    oblivious_memcpy(&mut buffer2, &self.rlp_encoded, state_target_offset);
    buffer[..33].as_mut().cmov(buffer2.as_mut_slice(), is_branch_node);
    ret_value_or_next_hash[..33]
      .as_mut()
      .cmov(&buffer2[..33], enabled & is_branch_node & (state_target_len == 32));

    Self::traverse_inline_node::<ADDR_LEN>(
      should_parse_inline_node,
      addr_nibbles,
      idx,
      &buffer,
      ret_value_or_next_hash,
    );
  }

  /// Turns a node in rlp to an ObliviousNode, leaks `node_rlp` node type and contents.
  pub fn from_rlp(node_rlp: &[u8]) -> Option<Self> {
    use rlp::Rlp;
    let r = Rlp::new(node_rlp);
    let mut ob = ObliviousNode::zeroed();
    ob.rlp_encoded[..node_rlp.len()].copy_from_slice(node_rlp);
    ob.rlp_length = node_rlp.len();

    if !r.is_list() {
      return None;
    }

    let len = r.item_count().ok()?;
    if len == 17 {
      ob.is_branch = 1;
      return Some(ob);
    } else if len == 2 {
      return Some(ob);
    }
    None
  }

  /// Obliviously convert this `ObliviousNode` back into RLP bytes.
  /// Returns a fixed-size padded buffer of length `NODE_BUF` containing the
  /// RLP encoding of either a branch node (17-item list) or a leaf/extension
  /// node (2-item list).
  pub fn to_rlp_padded(&self) -> ([u8; NODE_BUF], usize) {
    (self.rlp_encoded, self.rlp_length)
  }

  pub fn to_hex_bytes_with_quotes(self) -> [u8; 3 + NODE_BUF * 2] {
    let mut out = [0u8; 3 + NODE_BUF * 2];
    out[0] = b'"';
    out[1] = b'0';
    out[2] = b'x';

    for i in 0..NODE_BUF {
      let b = self.rlp_encoded[i];
      let mut hi = nibble_to_hex_oblivious(b >> 4);
      let mut lo = nibble_to_hex_oblivious(b & 0x0F);
      hi.cmov(&b' ', i >= self.rlp_length);
      hi.cmov(&b'"', i == self.rlp_length);
      lo.cmov(&b' ', i >= self.rlp_length);
      out[3 + i * 2] = hi;
      out[3 + i * 2 + 1] = lo;
    }
    out[0].cmov(&b' ', self.rlp_length == 0);
    out[1].cmov(&b' ', self.rlp_length == 0);
    out[2].cmov(&b' ', self.rlp_length == 0);
    out[3].cmov(&b' ', self.rlp_length == 0);

    out
  }

  /// Obliviously convert this `ObliviousNode` into a serde_json `RawValue`
  /// containing a fixed-length JSON string with the hex encoding of the
  /// RLP bytes for this node, padded with spaces to a constant length.
  pub fn to_raw_value(&self) -> Box<RawValue> {
    let (rlp_bytes, rlp_len) = self.to_rlp_padded();
    let hex_full = bytes_to_hex_oblivious(&rlp_bytes); // length = 2 + 2*NODE_BUF

    let visible_len = 2 + 2 * rlp_len;
    let pub_inner_len = 2 + 2 * NODE_BUF; // inner length inside the quotes

    // Final JSON value length: quotes + inner + quotes
    let mut buf = vec![b' '; pub_inner_len + 2];
    buf[0] = b'\"';
    let last_idx = buf.len() - 1;
    buf[last_idx] = b'\"';

    // Copy each position using a branchless mask so the instruction/memory trace
    // is independent of the secret `visible_len`.
    let hex_bytes = hex_full.as_bytes();
    for pub_pos in 0..pub_inner_len {
      let sel = (pub_pos < visible_len) as u8;
      let sm = 0u8.wrapping_sub(sel);
      let cur = buf[1 + pub_pos];
      let src = hex_bytes[pub_pos];
      buf[1 + pub_pos] = (cur & !sm) | (src & sm);
    }

    // SAFE: it's valid ASCII hex + spaces + quotes
    let s = unsafe { String::from_utf8_unchecked(buf) };
    serde_json::value::RawValue::from_string(s).expect("valid raw json value")
  }

  pub fn keccak_hash(&self) -> B256 {
    let mut hasher = Keccak256::new();
    // UNDONE(): do not leak rlp_length?
    hasher.update(&self.rlp_encoded[..self.rlp_length]);
    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result[..32]);
    B256(hash_bytes)
  }
}

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
mod tests {
  use super::*;

  #[test]
  fn test_rlp_decode_type_and_size() {
    // Test inline single byte
    let data = vec![0x7fu8, 0x00u8, 0x00u8];
    let (tp, size, start) = ObliviousNode::rlp_decode_type_and_size(&data, 0);
    assert_eq!(tp, 1);
    assert_eq!(size, 1);
    assert_eq!(start, 0);

    // Test short string
    let data = vec![0x83u8, 0x01, 0x02, 0x03];
    let (tp, size, start) = ObliviousNode::rlp_decode_type_and_size(&data, 0);
    assert_eq!(tp, 1);
    assert_eq!(size, 3);
    assert_eq!(start, 1);

    // Test long string
    let data = vec![0xb8u8, 0x20u8]; // length = 32
    let mut data_full = data.clone();
    data_full.extend(vec![0u8; 32]);
    let (tp, size, start) = ObliviousNode::rlp_decode_type_and_size(&data_full, 0);
    assert_eq!(tp, 1);
    assert_eq!(size, 32);
    assert_eq!(start, 2);

    // Test short list
    let data = vec![0xc4u8, 0x01, 0x02, 0x03, 0x04];
    let (tp, size, start) = ObliviousNode::rlp_decode_type_and_size(&data, 0);
    assert_eq!(tp, 2);
    assert_eq!(size, 4);
    assert_eq!(start, 1);

    // Test long list
    let data = vec![0xf8u8, 0x20u8]; // length = 32
    let mut data_full = data.clone();
    data_full.extend(vec![0u8; 32]);
    let (tp, size, start) = ObliviousNode::rlp_decode_type_and_size(&data_full, 0);
    assert_eq!(tp, 2);
    assert_eq!(size, 32);
    assert_eq!(start, 2);
  }

  #[test]
  fn test_traverse_branch_child_selection() {
    let node_rlp = hex::decode("f90211a0a0b540903a23df72ee5d15cead8fb1d1c4293ca8f6e2624528a99cc54bd2db81a0381cda9638b50fa7adae0e92c4ddf186b10983b3930f07f5cf136499aeedc553a07bef8a9136211f51f82122312ceae4f7d4e651acd6786b6a0f06ac4e422332a7a097cf81a55c66d95d1adb5b7def05a82cffb44f23eb557bc1c9f0a4174422b6daa0a8d28f7c857ad9c27da1c01f15d29a75cbc9760805c111fd01bcc3f67ea88925a0ec3b38324e4507fd0e4546dd7c1a413d5bc3c58b1fc8797406eecce0e8ac786fa0a13b4675cd6d389759885970ef05c19e611d963e5325cedc9c8d83d6f46cb286a0f31705eec2a3db626249d2dcdcaf1945dfee10e8b7f50abb0a4657cae4ff32c2a0cbd1da84181423b4a9dcd6a59b5330fcd7ca1b619ce84bedc5418219f897344fa08b7fb1f9376e2c8ece09e77ef2a5769c2b4893e2eb71d8ef1af0768bafa6e45ba09b5f38f76e4c723458444afbe77ff099dbedb8802c3766329c9fb677341e4e5ca0e437ac748ba5baba530340a4f26e663b89845391f9a1ea07e96f3973864374f0a058efdc0c6f8e0c542c32f8218f95cc84e42e5aa5e049d9570d682fc0f367d84ea0bf97854ce99f62cae9e5af9c639bf41959d6247265fddd8c7c8c7138b1823474a015e87076f384c4849b80116f528bce30e2e20e4cac06116eb0f0745beab550d7a0a762dbf67e070345cc18cb945e070f8234be7c55b630fb75bf13f11d27c6c39b80").unwrap();

    let n = ObliviousNode::from_rlp(node_rlp.as_slice()).unwrap();

    let addr = [5u8];
    let target_hash =
      hex::decode("ec3b38324e4507fd0e4546dd7c1a413d5bc3c58b1fc8797406eecce0e8ac786f").unwrap();

    let mut idx = 0usize;
    let mut ret_value_or_next_hash = [0u8; VALUE_BUF];
    n.traverse_oblivious::<1>(&addr, &mut idx, &mut ret_value_or_next_hash);

    assert_eq!(idx, 1);
    assert_eq!(ret_value_or_next_hash[0], 0xa0);
    assert_eq!(ret_value_or_next_hash[1..33], target_hash[..32]);
  }

  #[test]
  fn test_traverse_branch_child_selection_2() {
    let node_rlp = hex::decode("f9019180a0d099bd7d3abff0fcc204767c25d46431cd5860d064f8239fd059e3aa86a28315a0513bd648588366fe97a609f98c3b6acb72079447da0f6e3b48b968fe77a9c073a0da023965fae5cbff58d25ccbe28569ae68056918d47cfc24e2078b3bb486a313a0dd5fe0dcac98a33a79c02f9fa36971d8f16c41a2a85ba8adddcfd09f41c06a21808080a054824ab635846882e67b7c8164ab36b84e69f912627db2f4becc269a8ca2bd2da020be56269f26196ec9f512446e8d295d0e40616e488d0d9fe1422cd08585c1c2a0ce9bd6bb73703cb8dbc73f780600af09f2d22487ddb4386be334ca4fdd17153aa0b7c03aa826332640f1233cf08629fff3175efbd8de4f10ffa83dc1cfaac99bb6a00a6f203d6d738440c6e363aceeb30f5e4b8ba2df4e38712a3117253d602d781aa049be0800e8f888681050428a1fce245b22b6445e38cbcffee1567a9cf501a72fa081a01475ac9b72444b3457c9b0acb43c937aa02d3b5a842a3a556ad0b9dca020a032d51b502b092309f45978054150378058ce5037e945da2240e09632bf72375080").unwrap();

    let n = ObliviousNode::from_rlp(node_rlp.as_slice()).unwrap();

    let addr = [10u8];
    let target_hash =
      hex::decode("ce9bd6bb73703cb8dbc73f780600af09f2d22487ddb4386be334ca4fdd17153a").unwrap();

    let mut idx = 0usize;
    let mut ret_value_or_next_hash = [0u8; VALUE_BUF];
    n.traverse_oblivious::<1>(&addr, &mut idx, &mut ret_value_or_next_hash);

    assert_eq!(idx, 1);
    assert_eq!(ret_value_or_next_hash[0], 0xa0);
    assert_eq!(ret_value_or_next_hash[1..33], target_hash[..32]);
  }

  #[test]
  fn test_from_rlp_branch_parses_child_hashes() {
    // Build a branch RLP with a single child at index 5 as a 32-byte hash
    let mut s = rlp::RlpStream::new_list(17);
    for i in 0..16 {
      if i == 5 {
        let mut h = [0u8; 32];
        for j in 0..32 {
          h[j] = (100u8).wrapping_add(j as u8);
        }
        s.append(&h.as_ref());
      } else {
        s.append(&"");
      }
    }
    s.append(&""); // value element (empty)
    let out = s.out();

    let ob = ObliviousNode::from_rlp(&out).expect("should parse branch");
    assert_eq!(ob.rlp_length, out.len(), "parsed node should have the correct length");
    assert_eq!(ob.is_branch, 1u8, "should be marked as branch");
    assert_eq!(ob.rlp_encoded[..out.len()], out, "parsed rlp_encoded should match input");
  }

  #[test]
  fn test_from_rlp_leaf_parses_value() {
    // Leaf with compact path and value bytes
    let mut s = rlp::RlpStream::new_list(2);
    // path: start with hp nibble indicating leaf (hp=2 -> 0x20)
    let path = vec![0x20u8, 0x45u8]; // yields nibbles and parser will remove first nibble
    let value = vec![10u8, 11u8, 12u8];
    s.append(&path.as_slice());
    s.append(&value.as_slice());
    let out = s.out();
    // println!("{out:x}");
    let ob = ObliviousNode::from_rlp(&out).expect("should parse leaf");
    assert_eq!(ob.is_branch, 0u8, "should not be marked as branch");
    assert_eq!(ob.rlp_length, out.len(), "parsed node should have the correct length");
    assert_eq!(&ob.rlp_encoded[..out.len()], &out[..], "parsed rlp_encoded should match input");
  }

  #[test]
  fn test_from_rlp_extension_parses_child_hash() {
    // Extension with compact path and 32-byte child hash
    let mut s = rlp::RlpStream::new_list(2);
    let path = vec![0x00u8]; // extension flags (hp with leaf bit unset)
    let mut h = [0u8; 32];
    for j in 0..32 {
      h[j] = (200u8).wrapping_add(j as u8);
    }
    s.append(&path.as_slice());
    s.append(&h.as_ref());
    let out = s.out();
    // println!("{out:x}");
    let ob = ObliviousNode::from_rlp(&out).expect("should parse extension");
    assert_eq!(ob.is_branch, 0u8, "should not be marked as branch");
    assert_eq!(ob.rlp_length, out.len(), "parsed node should have the correct length");
    assert_eq!(&ob.rlp_encoded[..out.len()], &out[..], "parsed rlp_encoded should match input");
  }

  #[test]
  fn test_traverse_extension_consumes_path() {
    // Build an extension node via RLP with path [1,2,3] and child hash
    let mut s = rlp::RlpStream::new_list(2);
    let path_bytes = vec![0x11u8, 0x23u8]; // hp=1 (odd, not leaf), first nibble=1, then 2 and 3 packed
    let mut h = [0u8; 32];
    for i in 0..32 {
      h[i] = (20u8).wrapping_add(i as u8);
    }
    s.append(&path_bytes.as_slice());
    s.append(&h.as_ref());
    let out = s.out();
    println!("{out:x}");
    let n = ObliviousNode::from_rlp(&out).expect("should parse extension");

    let addr = [1u8, 2u8, 3u8, 9u8];
    let mut idx = 0usize;
    let mut ret_value = [0u8; VALUE_BUF];
    n.traverse_oblivious::<4>(&addr, &mut idx, &mut ret_value);
    assert_eq!(idx, 3);
    // next hash should be in ret_value as 0xa0 || hash
    assert_eq!(ret_value[0], 0xa0);
    assert_eq!(&ret_value[1..33], &h[..]);
  }

  #[test]
  fn test_traverse_leaf_terminal_copy() {
    // Leaf with path [4,5] and value (even encoding uses a zero low nibble in first byte)
    let mut s = rlp::RlpStream::new_list(2);
    let path_bytes = vec![0x20u8, 0x45u8]; // 0x20 then 0x45 encodes [4,5] as leaf (hp=2, even)
    let value = vec![10u8, 11u8, 12u8, 13u8];
    s.append(&path_bytes.as_slice());
    s.append(&value.as_slice());
    let out = s.out();
    let n = ObliviousNode::from_rlp(&out).expect("should parse leaf");

    let addr = [4u8, 5u8];
    let mut idx = 0usize;
    let mut ret_value = [0u8; VALUE_BUF];
    n.traverse_oblivious::<2>(&addr, &mut idx, &mut ret_value);
    assert_eq!(idx, 2);
    assert_eq!(&ret_value[1..1 + value.len()], &value[..]);
    // leaf terminal shouldn't report a successor hash (no 0xa0 prefix)
    assert_ne!(ret_value[0], 0xa0);
  }

  #[test]
  fn test_to_rlp_padded_roundtrip_branch() {
    // Build a canonical branch RLP with a hashed child at index 3
    let mut s = rlp::RlpStream::new_list(17);
    for i in 0..16 {
      if i == 3 {
        let mut h = [0u8; 32];
        for j in 0..32 {
          h[j] = (77u8).wrapping_add(j as u8);
        }
        s.append(&h.as_ref());
      } else {
        s.append(&"");
      }
    }
    s.append(&"");
    let canonical = s.out();

    let ob = ObliviousNode::from_rlp(&canonical).expect("should parse branch");
    let (rlp_padded, rlp_len) = ob.to_rlp_padded();
    assert_eq!(rlp_len, canonical.len());
    assert_eq!(&rlp_padded[..canonical.len()], &canonical[..]);
  }

  #[test]
  fn test_to_rlp_padded_roundtrip_leaf() {
    // Build canonical leaf RLP and parse into node, then roundtrip
    let mut s = rlp::RlpStream::new_list(2);
    let path_bytes = vec![0x25u8];
    let value = vec![9u8, 10u8, 11u8];
    s.append(&path_bytes.as_slice());
    s.append(&value.as_slice());
    let out = s.out();

    let n = ObliviousNode::from_rlp(&out).expect("should parse leaf");
    let (rlp_padded, rlp_len) = n.to_rlp_padded();
    let canonical = out;
    assert_eq!(rlp_len, canonical.len());
    assert_eq!(&rlp_padded[..canonical.len()], &canonical[..]);
  }

  #[test]
  fn test_to_rlp_padded_roundtrip_extension() {
    // Build canonical extension RLP and parse into node, then roundtrip
    let mut s = rlp::RlpStream::new_list(2);
    // path [7] (even/odd doesn't matter for single nibble; use hp=0 for extension)
    let path = vec![0x07u8];
    let mut h = [0u8; 32];
    for i in 0..32 {
      h[i] = (12u8).wrapping_add(i as u8);
    }
    s.append(&path.as_slice());
    s.append(&h.as_ref());
    let out = s.out();

    let n = ObliviousNode::from_rlp(&out).expect("should parse extension");
    let (rlp_padded, rlp_len) = n.to_rlp_padded();
    let canonical = out;
    assert_eq!(rlp_len, canonical.len());
    assert_eq!(&rlp_padded[..canonical.len()], &canonical[..]);
  }

  #[test]
  fn test_to_hex_bytes_with_quotes() {
    // small leaf node: list [0x01, 0x02] encoded as [0xc2, 0x01, 0x02]
    let node_rlp = vec![0xc2u8, 0x01u8, 0x02u8];
    let n = ObliviousNode::from_rlp(&node_rlp).expect("should parse node");
    let out = n.to_hex_bytes_with_quotes();

    // visible portion should be "0x" + hex of the three bytes
    let expected_prefix = b"\"0xc20102\"";
    assert_eq!(out.len(), 3 + NODE_BUF * 2);
    assert_eq!(&out[..expected_prefix.len()], expected_prefix);

    // remainder should be spaces
    for (i, &b) in out[expected_prefix.len()..].iter().enumerate() {
      assert_eq!(b, b' ', "byte at pos {} after prefix should be space", expected_prefix.len() + i);
    }
  }

  #[test]
  fn test_to_hex_bytes_with_quotes_zeroed() {
    let n = ObliviousNode::zeroed();
    let out = n.to_hex_bytes_with_quotes();
    for &b in out.iter() {
      assert_eq!(b, b' ', "all bytes should be spaces for zeroed node");
    }
  }

  #[test]
  fn test_from_rlp_branch_parses_inline_child() {
    // Build a branch RLP with a single inline child at index 4
    let mut s = rlp::RlpStream::new_list(17);
    for i in 0..16 {
      if i == 4 {
        let inline = vec![1u8, 2u8, 3u8];
        s.append(&inline.as_slice());
      } else {
        s.append(&"");
      }
    }
    s.append(&""); // value element (empty)
    let out = s.out();
    let ob = ObliviousNode::from_rlp(&out).expect("should parse branch");
    assert_eq!(ob.is_branch, 1u8, "should be marked as branch");
    // verify inline child is present in the RLP encoding
    let r = rlp::Rlp::new(&out);
    let data = r.at(4).unwrap().data().unwrap();
    assert_eq!(data, &[1u8, 2u8, 3u8]);
    // ensure the parsed rlp_encoded still matches the input canonical RLP
    assert_eq!(&ob.rlp_encoded[..out.len()], &out[..]);
  }

  #[test]
  fn test_to_raw_value_padded_preserves_spaces_and_visible_hex() {
    // Build a canonical branch RLP with a hashed child at index 3
    let mut s = rlp::RlpStream::new_list(17);
    for i in 0..16 {
      if i == 3 {
        let mut h = [0u8; 32];
        for j in 0..32 {
          h[j] = (77u8).wrapping_add(j as u8);
        }
        s.append(&h.as_ref());
      } else {
        s.append(&"");
      }
    }
    s.append(&"");
    let canonical = s.out();

    let ob = ObliviousNode::from_rlp(&canonical).expect("should parse branch");
    let (rlp_bytes, rlp_len) = ob.to_rlp_padded();
    let rv = ob.to_raw_value();
    let s = rv.get();
    let inner_len = 2 + 2 * NODE_BUF;
    // result should be quoted string of length inner_len + 2
    assert_eq!(s.len(), inner_len + 2);
    assert_eq!(s.as_bytes()[0], b'"');
    assert_eq!(s.as_bytes()[s.len() - 1], b'"');

    let visible_len = 2 + 2 * rlp_len;
    let hex_full = bytes_to_hex_oblivious(&rlp_bytes);
    // visible portion should match
    assert_eq!(&s.as_bytes()[1..1 + visible_len], &hex_full.as_bytes()[..visible_len]);
    // remainder inside quotes should be spaces
    for i in (1 + visible_len)..(1 + inner_len) {
      assert_eq!(s.as_bytes()[i], b' ', "expected padding space at pos {}", i);
    }
  }
}
