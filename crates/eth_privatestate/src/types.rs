//! Useful types for automation.
//!
use bytemuck::{Pod, Zeroable};
use rostl_primitives::ooption::OOption;
use rostl_primitives::traits::{Cmov, _Cmovbase};
use sha3::{Digest, Keccak256};

#[repr(align(8))]
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Zeroable)]
pub struct H160(pub [u8; 20]);
unsafe impl Pod for H160 {}
impl_cmov_for_pod!(H160);

#[repr(align(8))]
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Zeroable, Default, PartialOrd, Ord, Hash)]
pub struct B256(pub [u8; 32]);
unsafe impl Pod for B256 {}
impl_cmov_for_pod!(B256);

impl H160 {
  pub fn zero() -> Self {
    H160([0u8; 20])
  }

  /// Oblivious hex encoding that always returns a fixed-length string ("0x" + 40 hex chars).
  pub fn to_hex(&self) -> String {
    let mut out = [0u8; 42];
    out[0] = b'0';
    out[1] = b'x';

    for i in 0..20usize {
      let b = self.0[i];
      let hi = b >> 4;
      let lo = b & 0x0F;
      out[2 + i * 2] = nibble_to_hex_oblivious(hi);
      out[2 + i * 2 + 1] = nibble_to_hex_oblivious(lo);
    }
    // SAFE: out is always valid ASCII hex
    unsafe { String::from_utf8_unchecked(out.to_vec()) }
  }

  /// Oblivious hex decoding from string, returns an `OOption` that indicates validity.
  /// Call site must ensure the stripped string length is correct (otherwise length validity is leaked).
  pub fn from_hex(s: &str) -> OOption<Self> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    // Call-site constraint: length must be exactly 40 (20 bytes * 2 nibbles)
    if s.len() != 40 {
      return OOption::new(H160::zero(), false);
    }
    let bs = s.as_bytes();
    let mut a = [0u8; 20];
    let mut valid = true;
    for i in 0..20usize {
      let hi = hex_char_to_nibble_oblivious(bs[i * 2]);
      let lo = hex_char_to_nibble_oblivious(bs[i * 2 + 1]);
      let hi_v = hi.unwrap_or_default();
      let lo_v = lo.unwrap_or_default();
      let ok = hi.is_some() & lo.is_some();
      valid &= ok;
      a[i] = (hi_v << 4) | lo_v;
    }
    OOption::new(H160(a), valid)
  }

  pub fn to_nibbles(&self) -> [u8; 40] {
    let mut nibbles = [0u8; 40];
    for i in 0..20 {
      let b = self.0[i];
      nibbles[i * 2] = b >> 4;
      nibbles[i * 2 + 1] = b & 0x0F;
    }
    nibbles
  }

  pub fn keccak_hash(&self) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(self.0);
    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result);
    B256(hash_bytes)
  }
}

// Branchless nibble -> hex ASCII conversion used by the oblivious encoders above.
#[inline]
pub fn nibble_to_hex_oblivious(n: u8) -> u8 {
  let n_minus_10 = n.wrapping_sub(10);
  let is_lt = (n_minus_10 & 0x80) >> 7;
  let mask = 0u8.wrapping_sub(is_lt);

  let c1 = b'0'.wrapping_add(n);
  let c2 = b'a'.wrapping_add(n_minus_10);

  (c1 & mask) | (c2 & (!mask))
}

// Branchless hex char -> nibble (0..=15). Returns None if not a valid hex char
#[inline]
fn hex_char_to_nibble_oblivious(c: u8) -> OOption<u8> {
  let digit = c.wrapping_sub(b'0');
  let is_digit = (digit <= 9) as u8;
  let lower = c.wrapping_sub(b'a');
  let is_lower = (lower <= 5) as u8;
  let upper = c.wrapping_sub(b'A');
  let is_upper = (upper <= 5) as u8;

  let val_digit = digit;
  let val_lower = lower.wrapping_add(10);
  let val_upper = upper.wrapping_add(10);

  let mask_digit = 0u8.wrapping_sub(is_digit);
  let mask_lower = 0u8.wrapping_sub(is_lower);
  let mask_upper = 0u8.wrapping_sub(is_upper);

  let v = (val_digit & mask_digit) | (val_lower & mask_lower) | (val_upper & mask_upper);

  OOption::new(v, (is_digit | is_lower | is_upper) != 0)
}

#[allow(dead_code)]
impl B256 {
  pub fn zero() -> Self {
    B256([0u8; 32])
  }

  /// Oblivious hex encoding that always returns a fixed-length string ("0x" + 64 hex chars).
  pub fn to_hex(&self) -> String {
    let mut out = [0u8; 66];
    out[0] = b'0';
    out[1] = b'x';

    for i in 0..32usize {
      let b = self.0[i];
      let hi = b >> 4;
      let lo = b & 0x0F;
      out[2 + i * 2] = nibble_to_hex_oblivious(hi);
      out[2 + i * 2 + 1] = nibble_to_hex_oblivious(lo);
    }
    // SAFE: out is valid ASCII hex
    unsafe { String::from_utf8_unchecked(out.to_vec()) }
  }

  /// Oblivious hex decoding from string, returns an `OOption` that indicates validity.
  /// Call site must ensure the stripped string length is correct (otherwise length validity is leaked).
  pub fn from_hex(s: &str) -> OOption<Self> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    // Call-site constraint: length must be exactly 64 (32 bytes * 2 nibbles)
    if s.len() != 64 {
      return OOption::new(B256::zero(), false);
    }
    let bs = s.as_bytes();
    let mut a = [0u8; 32];
    let mut valid = true;
    for i in 0..32usize {
      let hi = hex_char_to_nibble_oblivious(bs[i * 2]);
      let lo = hex_char_to_nibble_oblivious(bs[i * 2 + 1]);
      let hi_v = hi.unwrap_or_default();
      let lo_v = lo.unwrap_or_default();
      let ok = hi.is_some() & lo.is_some();
      valid &= ok;
      a[i] = (hi_v << 4) | lo_v;
    }
    OOption::new(B256(a), valid)
  }

  pub fn to_nibbles(&self) -> [u8; 64] {
    let mut nibbles = [0u8; 64];
    for i in 0..32 {
      let b = self.0[i];
      nibbles[i * 2] = b >> 4;
      nibbles[i * 2 + 1] = b & 0x0F;
    }
    nibbles
  }

  pub fn keccak_hash(&self) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(self.0);
    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result);
    B256(hash_bytes)
  }
}

pub fn bytes_to_hex_oblivious(bytes: &[u8]) -> String {
  let mut out = vec![0u8; 2 + bytes.len() * 2];
  out[0] = b'0';
  out[1] = b'x';

  for i in 0..bytes.len() {
    let b = bytes[i];
    let hi = b >> 4;
    let lo = b & 0x0F;
    out[2 + i * 2] = nibble_to_hex_oblivious(hi);
    out[2 + i * 2 + 1] = nibble_to_hex_oblivious(lo);
  }
  // SAFE: out is always valid ASCII hex
  unsafe { String::from_utf8_unchecked(out) }
}

pub fn bytes_to_hex_oblivious_hidden_size(bytes: &[u8], size: usize) -> String {
  let mut out = vec![0u8; 2 + bytes.len() * 2];
  out[0] = b'0';
  out[1] = b'x';

  for i in 0..bytes.len() {
    let b = bytes[i];
    let mut hi = nibble_to_hex_oblivious(b >> 4);
    let mut lo = nibble_to_hex_oblivious(b & 0x0F);
    hi.cmov(&b' ', i >= size);
    lo.cmov(&b' ', i >= size);
    out[2 + i * 2] = hi;
    out[2 + i * 2 + 1] = lo;
  }
  // SAFE: out is always valid ASCII hex
  unsafe { String::from_utf8_unchecked(out) }
}

pub fn bytes_to_hex_oblivious_hidden_size_quoted(bytes: &[u8], size: usize) -> String {
  let mut out = vec![0u8; 3 + bytes.len() * 2];
  out[0] = b'"';
  out[1] = b'0';
  out[2] = b'x';

  for i in 0..bytes.len() {
    let b = bytes[i];
    let mut hi = nibble_to_hex_oblivious(b >> 4);
    let mut lo = nibble_to_hex_oblivious(b & 0x0F);
    hi.cmov(&b' ', i >= size);
    hi.cmov(&b'"', i == size);
    lo.cmov(&b' ', i >= size);
    out[3 + i * 2] = hi;
    out[3 + i * 2 + 1] = lo;
  }

  unsafe { String::from_utf8_unchecked(out) }
}

#[cfg(test)]
#[allow(clippy::all)]
mod tests {
  use super::*;

  #[test]
  fn test_hex_oblivious_h160() {
    let mut v = [0u8; 20];
    for i in 0..20 {
      v[i] = i as u8;
    }
    let h = H160(v);
    let s = h.to_hex();
    assert_eq!(s.len(), 42);
    assert_eq!(&s[0..2], "0x");
    // compare against hex crate
    assert_eq!(s, format!("0x{}", hex::encode(h.0)));
    assert_eq!(s, "0x000102030405060708090a0b0c0d0e0f10111213");

    let mut v = [0u8; 20];
    v[0] = 0xFF;
    let h = H160(v);
    let s = h.to_hex();
    assert_eq!(s, "0xff00000000000000000000000000000000000000");
  }

  #[test]
  fn test_hex_oblivious_b256() {
    let mut v = [0u8; 32];
    for i in 0..32 {
      v[i] = (i * 3) as u8;
    }
    let b = B256(v);
    let s = b.to_hex();
    assert_eq!(s.len(), 66);
    assert_eq!(&s[0..2], "0x");
    assert_eq!(s, format!("0x{}", hex::encode(b.0)));
    assert_eq!(s, "0x000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d");

    let mut v = [0u8; 32];
    v[31] = 0xAB;
    let b = B256(v);
    let s = b.to_hex();
    assert_eq!(s, "0x00000000000000000000000000000000000000000000000000000000000000ab");
  }

  #[test]
  fn test_nibble_to_hex_and_back_roundtrip() {
    // check hex output for all 0..=15 nibble values and round-trip acceptance
    for n in 0u8..16u8 {
      let ch = nibble_to_hex_oblivious(n);
      // expected ASCII
      let expected = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
      assert_eq!(ch, expected, "nibble {} -> hex mismatch", n);

      // lowercase roundtrip
      let decoded = hex_char_to_nibble_oblivious(ch).unwrap();
      assert_eq!(decoded, n, "roundtrip lower failed for {}", n);

      // uppercase variants should decode too (for a-f)
      if n >= 10 {
        let up = (ch as char).to_ascii_uppercase() as u8;
        let decoded_up = hex_char_to_nibble_oblivious(up).unwrap();
        assert_eq!(decoded_up, n, "roundtrip upper failed for {}", n);
      }
    }
  }

  #[test]
  fn test_hex_char_to_nibble_invalids() {
    // invalid characters should return None
    for &c in b"gGz/: @\n" {
      assert!(!hex_char_to_nibble_oblivious(c).is_some(), "char {:?} should be invalid", c as char);
    }
  }

  #[test]
  fn test_from_hex_ooption_h160_b256() {
    let h_str = "0x000102030405060708090a0b0c0d0e0f10111213";
    let h = H160::from_hex(h_str);
    assert!(h.is_some(), "valid H160 hex should be some");
    let h_val: H160 = h.unwrap();
    assert_eq!(h_val.0, [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);

    let b_str = "0x000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d";
    let b = B256::from_hex(b_str);
    assert!(b.is_some(), "valid B256 hex should be some");

    // invalid nibble should set is_some=false but still produce a value
    let invalid_h = H160::from_hex("0xzz0102030405060708090a0b0c0d0e0f10111213");
    assert!(!invalid_h.is_some(), "invalid hex should be marked none");
  }
}
