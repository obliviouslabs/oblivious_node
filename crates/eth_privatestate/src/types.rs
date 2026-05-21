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
  if size == 0 {
    let mut out = vec![b' '; (3 + bytes.len() * 2).max(5)];
    out[0] = b'"';
    out[1] = b'0';
    out[2] = b'x';
    out[3] = b'0';
    out[4] = b'"';
    return unsafe { String::from_utf8_unchecked(out) };
  }

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

/// Encode a big-endian integer as an EIP-1474 `Quantity` JSON string while
/// keeping the raw JSON token fixed-width. The significant `"0x..."` string is
/// right-aligned and the unused prefix is JSON whitespace, so serde clients see
/// a canonical quantity without requiring data-dependent string trimming.
pub fn bytes_to_quantity_oblivious_quoted_left_padded(bytes: &[u8], size: usize) -> String {
  let mut bounded_size = size;
  bounded_size.cmov(&bytes.len(), size > bytes.len());

  let max_digits = bytes.len() * 2;
  let total_len = (4 + max_digits).max(5);

  let mut first_nonzero = bytes.len();
  let mut found = false;
  for (i, byte) in bytes.iter().enumerate() {
    let is_first = (i < bounded_size) & (*byte != 0) & !found;
    first_nonzero.cmov(&i, is_first);
    found |= (i < bounded_size) & (*byte != 0);
  }

  let mut first_byte = 0u8;
  for (i, byte) in bytes.iter().enumerate() {
    first_byte.cmov(byte, found & (i == first_nonzero));
  }

  let high_nibble_is_zero = first_byte < 0x10;
  let mut canonical_start_digit = first_nonzero * 2;
  canonical_start_digit = canonical_start_digit.wrapping_add(high_nibble_is_zero as usize);
  canonical_start_digit.cmov(&0, !found);

  let mut digit_count = 1usize;
  let mut nonzero_digit_count = bounded_size.wrapping_sub(first_nonzero).wrapping_mul(2);
  nonzero_digit_count = nonzero_digit_count.wrapping_sub(high_nibble_is_zero as usize);
  digit_count.cmov(&nonzero_digit_count, found);

  let open_quote = total_len - (digit_count + 4);
  let digit_start = open_quote + 3;
  let last = total_len - 1;
  let source_digit_end = bounded_size * 2;

  let mut out = vec![b' '; total_len];
  for (pos, out_byte) in out.iter_mut().enumerate() {
    let mut ch = b' ';
    ch.cmov(&b'"', pos == open_quote);
    ch.cmov(&b'0', pos == open_quote + 1);
    ch.cmov(&b'x', pos == open_quote + 2);
    ch.cmov(&b'"', pos == last);

    let target_digit = pos.wrapping_sub(digit_start);
    let is_digit_pos = target_digit < digit_count;
    let mut digit = b'0';
    for source_digit in 0..max_digits {
      let byte = bytes[source_digit / 2];
      let nibble = if source_digit % 2 == 0 { byte >> 4 } else { byte & 0x0f };
      let source_target_digit = source_digit.wrapping_sub(canonical_start_digit);
      let is_source = found
        & is_digit_pos
        & (source_digit < source_digit_end)
        & (source_target_digit == target_digit);
      digit.cmov(&nibble_to_hex_oblivious(nibble), is_source);
    }
    ch.cmov(&digit, is_digit_pos);
    *out_byte = ch;
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

  #[test]
  fn test_quantity_encoder_left_pads_raw_json_and_canonicalizes() {
    let cases: Vec<(&[u8], usize, &str)> = vec![
      (&[0, 0, 0], 0, "0x0"),
      (&[0, 0, 0], 3, "0x0"),
      (&[0x0f, 0, 0], 1, "0xf"),
      (&[0, 0x0f, 0], 2, "0xf"),
      (&[0x12, 0x34, 0], 2, "0x1234"),
      (&[0x01, 0x23, 0], 2, "0x123"),
    ];

    let mut out_len = None;
    for (bytes, size, expected) in cases {
      let raw = bytes_to_quantity_oblivious_quoted_left_padded(bytes, size);
      if let Some(len) = out_len {
        assert_eq!(raw.len(), len, "raw JSON token length should be fixed");
      } else {
        out_len = Some(raw.len());
      }
      let parsed: String = serde_json::from_str(&raw).expect("valid padded raw JSON string");
      assert_eq!(parsed, expected);
      assert_eq!(raw.as_bytes()[raw.len() - 1], b'"', "closing quote should be fixed at end");
    }
  }
}
