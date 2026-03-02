use anyhow::{Result, bail};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// P-256 group order
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Half of P-256 group order (for low-S check)
const P256_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
    0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

/// Convert an ASN.1 DER ECDSA signature to raw (r || s) format, 64 bytes.
pub fn der_to_raw(der: &[u8]) -> Result<[u8; 64]> {
    if der.len() < 8 || der[0] != 0x30 {
        bail!("Invalid DER signature: expected SEQUENCE tag 0x30");
    }

    let mut pos = 2; // skip 0x30 and length byte
    // Handle multi-byte length
    if der[1] & 0x80 != 0 {
        let len_bytes = (der[1] & 0x7f) as usize;
        pos = 2 + len_bytes;
    }

    // Parse r
    if der[pos] != 0x02 {
        bail!("Invalid DER signature: expected INTEGER tag 0x02 for r");
    }
    pos += 1;
    let r_len = der[pos] as usize;
    pos += 1;
    let r_bytes = &der[pos..pos + r_len];
    pos += r_len;

    // Parse s
    if der[pos] != 0x02 {
        bail!("Invalid DER signature: expected INTEGER tag 0x02 for s");
    }
    pos += 1;
    let s_len = der[pos] as usize;
    pos += 1;
    let s_bytes = &der[pos..pos + s_len];

    let mut raw = [0u8; 64];

    // Copy r, stripping leading zero and left-padding to 32 bytes
    let r_trimmed = strip_leading_zero(r_bytes);
    if r_trimmed.len() > 32 {
        bail!("r component too long: {} bytes", r_trimmed.len());
    }
    let r_offset = 32 - r_trimmed.len();
    raw[r_offset..32].copy_from_slice(r_trimmed);

    // Copy s, stripping leading zero and left-padding to 32 bytes
    let s_trimmed = strip_leading_zero(s_bytes);
    if s_trimmed.len() > 32 {
        bail!("s component too long: {} bytes", s_trimmed.len());
    }
    let s_offset = 32 - s_trimmed.len();
    raw[32 + s_offset..64].copy_from_slice(s_trimmed);

    Ok(raw)
}

fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    if bytes.len() > 1 && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        bytes
    }
}

/// Normalize signature to low-S form for P-256.
/// If s > n/2, replace s with n - s.
pub fn normalize_low_s(raw: &mut [u8; 64]) {
    let s = &raw[32..64];

    if is_greater_than(s, &P256_HALF_ORDER) {
        let new_s = subtract_mod(&P256_ORDER, &raw[32..64]);
        raw[32..64].copy_from_slice(&new_s);
    }
}

/// Compare two 32-byte big-endian integers: returns true if a > b.
fn is_greater_than(a: &[u8], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    false
}

/// Subtract two 32-byte big-endian integers: a - b (assumes a >= b).
fn subtract_mod(a: &[u8; 32], b: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;

    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }

    result
}

/// Sign a PLC operation: takes DAG-CBOR bytes and a signing function.
/// The sign_fn should call the Secure Enclave and return DER bytes.
/// Returns a base64url-encoded signature string.
pub fn sign_operation<F>(dag_cbor_bytes: &[u8], sign_fn: F) -> Result<String>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    let der_sig = sign_fn(dag_cbor_bytes)?;
    let mut raw = der_to_raw(&der_sig)?;
    normalize_low_s(&mut raw);
    Ok(URL_SAFE_NO_PAD.encode(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_to_raw_basic() {
        // Construct a simple DER signature
        // r = 32 bytes of 0x01, s = 32 bytes of 0x02
        let mut der = vec![0x30, 0x44]; // SEQUENCE, length 68
        der.push(0x02); // INTEGER
        der.push(0x20); // length 32
        der.extend_from_slice(&[0x01; 32]); // r
        der.push(0x02); // INTEGER
        der.push(0x20); // length 32
        der.extend_from_slice(&[0x02; 32]); // s

        let raw = der_to_raw(&der).unwrap();
        assert_eq!(&raw[..32], &[0x01; 32]);
        assert_eq!(&raw[32..], &[0x02; 32]);
    }

    #[test]
    fn test_der_to_raw_with_leading_zeros() {
        // r has leading 0x00 (high bit set), s is short
        let mut der = vec![0x30, 0x45]; // SEQUENCE
        der.push(0x02); // INTEGER
        der.push(0x21); // length 33 (leading zero)
        der.push(0x00); // leading zero
        der.extend_from_slice(&[0x80; 32]); // r (with high bit set)
        der.push(0x02); // INTEGER
        der.push(0x20); // length 32
        der.extend_from_slice(&[0x03; 32]); // s

        let raw = der_to_raw(&der).unwrap();
        assert_eq!(&raw[..32], &[0x80; 32]); // leading zero stripped
        assert_eq!(&raw[32..], &[0x03; 32]);
    }

    #[test]
    fn test_der_to_raw_short_components() {
        // r and s are only 30 bytes each (need left-padding)
        let mut der = vec![0x30, 0x40];
        der.push(0x02);
        der.push(0x1e); // 30 bytes
        der.extend_from_slice(&[0xab; 30]);
        der.push(0x02);
        der.push(0x1e); // 30 bytes
        der.extend_from_slice(&[0xcd; 30]);

        let raw = der_to_raw(&der).unwrap();
        // First 2 bytes should be zero-padded
        assert_eq!(&raw[..2], &[0x00, 0x00]);
        assert_eq!(&raw[2..32], &[0xab; 30]);
        assert_eq!(&raw[32..34], &[0x00, 0x00]);
        assert_eq!(&raw[34..], &[0xcd; 30]);
    }

    #[test]
    fn test_normalize_low_s_already_low() {
        let mut raw = [0u8; 64];
        raw[63] = 0x01; // s = 1, which is < n/2
        normalize_low_s(&mut raw);
        assert_eq!(raw[63], 0x01); // unchanged
    }

    #[test]
    fn test_normalize_low_s_high_s() {
        let mut raw = [0u8; 64];
        // Set s = n - 1 (which is > n/2)
        raw[32..64].copy_from_slice(&P256_ORDER);
        raw[63] -= 1; // n - 1

        normalize_low_s(&mut raw);
        // After normalization, s should be n - (n-1) = 1
        assert_eq!(raw[63], 0x01);
        assert!(raw[32..63].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_sign_operation_with_mock() {
        // Mock sign function that returns a valid DER signature
        let mut der = vec![0x30, 0x44];
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&[0x01; 32]);
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&[0x02; 32]); // s = small value, already low-S

        let der_clone = der.clone();
        let result = sign_operation(b"test data", |_data| Ok(der_clone)).unwrap();

        // Should be base64url encoded
        assert!(!result.contains('='));
        assert!(!result.contains('+'));
        assert!(!result.contains('/'));
    }

    #[test]
    fn test_is_greater_than() {
        let a = [0xFF; 32];
        let b = [0x00; 32];
        assert!(is_greater_than(&a, &b.try_into().unwrap()));
        assert!(!is_greater_than(&b, &a.try_into().unwrap()));
    }

    // --- Additional tests ---

    #[test]
    fn test_is_greater_than_equal() {
        let a = [0x42; 32];
        assert!(!is_greater_than(&a, &a)); // equal is not greater
    }

    #[test]
    fn test_is_greater_than_differs_in_middle() {
        let mut a = [0x00; 32];
        let mut b = [0x00; 32];
        a[15] = 0x01;
        b[15] = 0x00;
        assert!(is_greater_than(&a, &b));
        assert!(!is_greater_than(&b, &a));
    }

    #[test]
    fn test_subtract_mod_basic() {
        let a = [0x00; 32];
        let mut a_mod = a;
        a_mod[31] = 0x0A; // a = 10
        let mut b = [0x00; 32];
        b[31] = 0x03; // b = 3
        let result = subtract_mod(&a_mod, &b);
        assert_eq!(result[31], 0x07); // 10 - 3 = 7
    }

    #[test]
    fn test_subtract_mod_with_borrow() {
        let mut a = [0x00; 32];
        a[30] = 0x01;
        a[31] = 0x00; // a = 256
        let mut b = [0x00; 32];
        b[31] = 0x01; // b = 1
        let result = subtract_mod(&a, &b);
        assert_eq!(result[30], 0x00);
        assert_eq!(result[31], 0xFF); // 256 - 1 = 255
    }

    #[test]
    fn test_der_to_raw_invalid_tag() {
        let der = vec![0x31, 0x44, 0x02, 0x20]; // wrong tag (0x31 instead of 0x30)
        let result = der_to_raw(&der);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_to_raw_too_short() {
        let der = vec![0x30, 0x02, 0x02, 0x00];
        let result = der_to_raw(&der);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_to_raw_missing_s_integer_tag() {
        // Valid r, but s has wrong tag
        let mut der = vec![0x30, 0x26];
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&[0x01; 32]);
        der.push(0x03); // wrong tag, should be 0x02
        der.push(0x01);
        der.push(0x01);
        let result = der_to_raw(&der);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_to_raw_both_have_leading_zeros() {
        // Both r and s have leading 0x00 bytes (high bit set in both)
        let mut der = vec![0x30, 0x46]; // SEQUENCE, length 70
        der.push(0x02);
        der.push(0x21); // 33 bytes
        der.push(0x00); // leading zero
        der.extend_from_slice(&[0xFF; 32]); // r (high bit set)
        der.push(0x02);
        der.push(0x21); // 33 bytes
        der.push(0x00); // leading zero
        der.extend_from_slice(&[0x80; 32]); // s (high bit set)

        let raw = der_to_raw(&der).unwrap();
        assert_eq!(&raw[..32], &[0xFF; 32]);
        assert_eq!(&raw[32..], &[0x80; 32]);
    }

    #[test]
    fn test_der_to_raw_single_byte_components() {
        // r = 1, s = 2 (single byte each)
        let mut der = vec![0x30, 0x06];
        der.push(0x02);
        der.push(0x01);
        der.push(0x01); // r = 1
        der.push(0x02);
        der.push(0x01);
        der.push(0x02); // s = 2

        let raw = der_to_raw(&der).unwrap();
        assert_eq!(raw[31], 0x01);
        assert!(raw[..31].iter().all(|&b| b == 0));
        assert_eq!(raw[63], 0x02);
        assert!(raw[32..63].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_normalize_low_s_at_boundary() {
        // s = exactly n/2 (should NOT be normalized since s must be > n/2)
        let mut raw = [0u8; 64];
        raw[32..64].copy_from_slice(&P256_HALF_ORDER);
        let original_s = raw[32..64].to_vec();
        normalize_low_s(&mut raw);
        assert_eq!(&raw[32..64], &original_s[..], "s == n/2 should not be changed");
    }

    #[test]
    fn test_normalize_low_s_just_above_boundary() {
        // s = n/2 + 1 (should be normalized)
        let mut raw = [0u8; 64];
        raw[32..64].copy_from_slice(&P256_HALF_ORDER);
        // Add 1 to s
        let mut carry = 1u16;
        for i in (32..64).rev() {
            let sum = raw[i] as u16 + carry;
            raw[i] = sum as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }

        let s_before = raw[32..64].to_vec();
        normalize_low_s(&mut raw);
        // s should have been changed
        assert_ne!(&raw[32..64], &s_before[..], "s > n/2 should be normalized");
        // Verify: new_s = n - old_s, so new_s + old_s = n
        let new_s = &raw[32..64];
        let mut sum = [0u8; 32];
        let mut carry_sum: u16 = 0;
        for i in (0..32).rev() {
            let s = new_s[i] as u16 + s_before[i] as u16 + carry_sum;
            sum[i] = s as u8;
            carry_sum = s >> 8;
        }
        assert_eq!(sum, P256_ORDER, "new_s + old_s should equal n");
    }

    #[test]
    fn test_normalize_low_s_preserves_r() {
        let mut raw = [0u8; 64];
        raw[0..32].copy_from_slice(&[0xAB; 32]); // r = fixed value
        raw[32..64].copy_from_slice(&P256_ORDER);
        raw[63] -= 1; // s = n - 1 (high S)

        normalize_low_s(&mut raw);
        assert_eq!(&raw[0..32], &[0xAB; 32], "r should not be modified");
    }

    #[test]
    fn test_sign_operation_propagates_error() {
        let result = sign_operation(b"test data", |_data| {
            Err(anyhow::anyhow!("Touch ID cancelled"))
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Touch ID cancelled"));
    }

    #[test]
    fn test_sign_operation_invalid_der() {
        let result = sign_operation(b"test data", |_data| {
            Ok(vec![0x00, 0x01, 0x02]) // invalid DER
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_operation_passes_data_through() {
        let mut der = vec![0x30, 0x44];
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&[0x01; 32]);
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&[0x02; 32]);

        let input = b"specific cbor bytes";
        let der_clone = der.clone();
        let mut received_data = Vec::new();

        let _ = sign_operation(input, |data| {
            received_data = data.to_vec();
            Ok(der_clone)
        });

        assert_eq!(received_data, input.to_vec());
    }

    #[test]
    fn test_sign_operation_output_is_valid_base64url() {
        let mut der = vec![0x30, 0x44];
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&[0x01; 32]);
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&[0x02; 32]);

        let result = sign_operation(b"test", |_| Ok(der)).unwrap();

        // Verify it's valid base64url
        let decoded = URL_SAFE_NO_PAD.decode(&result);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), 64); // raw signature is 64 bytes
    }

    #[test]
    fn test_sign_operation_normalizes_high_s() {
        // Construct DER with high S value (s = n - 1)
        let mut der = vec![0x30, 0x44];
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&[0x01; 32]); // r
        der.push(0x02);
        der.push(0x20);
        let mut high_s = P256_ORDER;
        high_s[31] -= 1; // s = n - 1
        der.extend_from_slice(&high_s);

        let result = sign_operation(b"test", |_| Ok(der)).unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(&result).unwrap();

        // The s component should have been normalized to 1
        assert_eq!(decoded[63], 0x01);
        assert!(decoded[32..63].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_strip_leading_zero_no_zero() {
        assert_eq!(strip_leading_zero(&[0x80, 0x01]), &[0x80, 0x01]);
    }

    #[test]
    fn test_strip_leading_zero_single_byte() {
        assert_eq!(strip_leading_zero(&[0x42]), &[0x42]);
    }

    #[test]
    fn test_strip_leading_zero_single_zero() {
        // Single zero byte should NOT be stripped (would leave empty)
        assert_eq!(strip_leading_zero(&[0x00]), &[0x00]);
    }

    #[test]
    fn test_strip_leading_zero_with_zero() {
        assert_eq!(strip_leading_zero(&[0x00, 0x80]), &[0x80]);
    }
}
