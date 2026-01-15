//! Some utils that need to be reimplemented obliviously and moved to rostl
//!

use rostl_primitives::traits::Cmov;

// UNDONE(): make oblivious
#[inline]
fn reverse<T: Copy>(arr: &mut [T], mut i: usize, mut j: usize) {
  // reverse arr[i..j)
  while i < j {
    j -= 1;
    if i >= j {
      break;
    }
    arr.swap(i, j);
    i += 1;
  }
}

// UNDONE(): make oblivious
pub fn oblivious_shift<T: Cmov + Copy>(arr: &mut [T], k: usize) {
  let n = arr.len();
  if n <= 1 {
    return;
  }

  let k = k % n;
  if k == 0 {
    return;
  }

  // Rotate right by k == rotate left by n-k
  let left = n - k;

  reverse(arr, 0, left);
  reverse(arr, left, n);
  reverse(arr, 0, n);
}

/// Copies a range from `src` to `dst` starting at `src_offset` respectively, if there are out of bound bytes, the values after the overflow offset in `dst` will have arbitrary data from other parts of `old(dst)`. If `src_offset` >= src.len(), `dst` will remain unchanged.
///
/// # Arguments
/// * `dst` - A mutable slice of destination data.
/// * `src` - A slice of source data.
/// * `src_offset` - The starting offset in the source slice.
#[inline]
pub fn oblivious_memcpy<T: Cmov + Copy>(dst: &mut [T], src: &[T], src_offset: usize) {
  let len = dst.len();
  for (i, item) in src.iter().enumerate() {
    let choice = (i >= src_offset) && (i < src_offset + len);
    dst[i % len].cmov(item, choice);
  }
  let diff = (len * src_offset).wrapping_sub(src_offset);
  let mut shift_amount = diff % len;
  shift_amount.cmov(&0, src_offset >= src.len());
  oblivious_shift(dst, shift_amount);
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_oblivious_memcpy() {
    let src = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut dst = vec![0u8; 5];

    oblivious_memcpy(&mut dst, &src, 0);
    assert_eq!(dst, vec![1, 2, 3, 4, 5]);
    oblivious_memcpy(&mut dst, &src, 1);
    assert_eq!(dst, vec![2, 3, 4, 5, 6]);
    oblivious_memcpy(&mut dst, &src, 2);
    assert_eq!(dst, vec![3, 4, 5, 6, 7]);
    oblivious_memcpy(&mut dst, &src, 3);
    assert_eq!(dst, vec![4, 5, 6, 7, 8]);
    oblivious_memcpy(&mut dst, &src, 4);
    assert_eq!(dst, vec![5, 6, 7, 8, 9]);
    oblivious_memcpy(&mut dst, &src, 5);
    assert_eq!(dst, vec![6, 7, 8, 9, 10]);
    oblivious_memcpy(&mut dst, &src, 6);
    assert_eq!(dst[..4], vec![7, 8, 9, 10]);
    oblivious_memcpy(&mut dst, &src, 7);
    assert_eq!(dst[..3], vec![8, 9, 10]);
    oblivious_memcpy(&mut dst, &src, 8);
    assert_eq!(dst[..2], vec![9, 10]);
    oblivious_memcpy(&mut dst, &src, 9);
    assert_eq!(dst[..1], vec![10]);
    oblivious_memcpy(&mut dst, &src, 10);
  }
}

// UNDONE(): make cmov for arrays take non-mut argument
