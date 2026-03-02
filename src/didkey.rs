use anyhow::{Result, bail};

/// Multicodec varint prefixes
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24]; // varint of 0x1200
const K256_MULTICODEC: [u8; 2] = [0xe7, 0x01]; // varint of 0xe7

#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    P256,
    K256,
}

/// Compress an uncompressed P-256 public key (65 bytes: 04 || x || y) to 33 bytes (02/03 || x).
pub fn compress_p256_pubkey(uncompressed: &[u8]) -> Result<Vec<u8>> {
    if uncompressed.len() == 33 && (uncompressed[0] == 0x02 || uncompressed[0] == 0x03) {
        // Already compressed
        return Ok(uncompressed.to_vec());
    }

    if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
        bail!(
            "Expected uncompressed P-256 key (65 bytes starting with 0x04), got {} bytes",
            uncompressed.len()
        );
    }

    let x = &uncompressed[1..33];
    let y = &uncompressed[33..65];

    // If y is even, prefix is 0x02; if odd, prefix is 0x03
    let prefix = if y[31] & 1 == 0 { 0x02 } else { 0x03 };

    let mut compressed = Vec::with_capacity(33);
    compressed.push(prefix);
    compressed.extend_from_slice(x);
    Ok(compressed)
}

/// Encode a P-256 public key as a did:key string.
/// Accepts either uncompressed (65 bytes) or compressed (33 bytes) format.
pub fn encode_p256_didkey(pub_key: &[u8]) -> Result<String> {
    let compressed = compress_p256_pubkey(pub_key)?;

    // Prepend multicodec varint for P-256
    let mut prefixed = Vec::with_capacity(2 + compressed.len());
    prefixed.extend_from_slice(&P256_MULTICODEC);
    prefixed.extend_from_slice(&compressed);

    // Base58btc encode with 'z' multibase prefix
    let encoded = bs58::encode(&prefixed).into_string();

    Ok(format!("did:key:z{}", encoded))
}

/// Decode a did:key string back to its raw public key bytes and key type.
pub fn decode_didkey(did_key: &str) -> Result<(Vec<u8>, KeyType)> {
    let stripped = did_key
        .strip_prefix("did:key:z")
        .ok_or_else(|| anyhow::anyhow!("Invalid did:key format: must start with 'did:key:z'"))?;

    let decoded = bs58::decode(stripped).into_vec()?;

    if decoded.len() < 2 {
        bail!("did:key payload too short");
    }

    if decoded[0] == P256_MULTICODEC[0] && decoded[1] == P256_MULTICODEC[1] {
        let key_bytes = decoded[2..].to_vec();
        if key_bytes.len() != 33 {
            bail!("P-256 compressed key should be 33 bytes, got {}", key_bytes.len());
        }
        Ok((key_bytes, KeyType::P256))
    } else if decoded[0] == K256_MULTICODEC[0] && decoded[1] == K256_MULTICODEC[1] {
        let key_bytes = decoded[2..].to_vec();
        if key_bytes.len() != 33 {
            bail!("K-256 compressed key should be 33 bytes, got {}", key_bytes.len());
        }
        Ok((key_bytes, KeyType::K256))
    } else {
        bail!(
            "Unknown multicodec prefix: 0x{:02x} 0x{:02x}",
            decoded[0],
            decoded[1]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_already_compressed() {
        let mut compressed = vec![0x02];
        compressed.extend_from_slice(&[0xaa; 32]);
        let result = compress_p256_pubkey(&compressed).unwrap();
        assert_eq!(result, compressed);
    }

    #[test]
    fn test_compress_uncompressed_even_y() {
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&[0xab; 32]); // x
        let mut y = vec![0xcd; 32];
        y[31] = 0x02; // even
        uncompressed.extend_from_slice(&y);

        let result = compress_p256_pubkey(&uncompressed).unwrap();
        assert_eq!(result.len(), 33);
        assert_eq!(result[0], 0x02); // even y -> 0x02
    }

    #[test]
    fn test_compress_uncompressed_odd_y() {
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&[0xab; 32]); // x
        let mut y = vec![0xcd; 32];
        y[31] = 0x03; // odd
        uncompressed.extend_from_slice(&y);

        let result = compress_p256_pubkey(&uncompressed).unwrap();
        assert_eq!(result.len(), 33);
        assert_eq!(result[0], 0x03); // odd y -> 0x03
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        // Generate a fake compressed P-256 key
        let mut compressed = vec![0x02];
        compressed.extend_from_slice(&[0x42; 32]);

        let did_key = encode_p256_didkey(&compressed).unwrap();
        assert!(did_key.starts_with("did:key:zDnae"));

        let (decoded, key_type) = decode_didkey(&did_key).unwrap();
        assert_eq!(key_type, KeyType::P256);
        assert_eq!(decoded, compressed);
    }

    #[test]
    fn test_encode_from_uncompressed() {
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&[0x42; 32]); // x
        let mut y = vec![0x43; 32];
        y[31] = 0x00; // even
        uncompressed.extend_from_slice(&y);

        let did_key = encode_p256_didkey(&uncompressed).unwrap();
        assert!(did_key.starts_with("did:key:zDnae"));

        let (decoded, key_type) = decode_didkey(&did_key).unwrap();
        assert_eq!(key_type, KeyType::P256);
        assert_eq!(decoded.len(), 33);
        assert_eq!(decoded[0], 0x02); // even y
    }

    #[test]
    fn test_decode_invalid_prefix() {
        let result = decode_didkey("did:key:zInvalidKey");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_k256() {
        // Construct a valid K-256 did:key
        let mut payload = Vec::new();
        payload.extend_from_slice(&K256_MULTICODEC);
        let mut key = vec![0x02];
        key.extend_from_slice(&[0x55; 32]);
        payload.extend_from_slice(&key);

        let encoded = bs58::encode(&payload).into_string();
        let did_key = format!("did:key:z{}", encoded);

        let (decoded, key_type) = decode_didkey(&did_key).unwrap();
        assert_eq!(key_type, KeyType::K256);
        assert_eq!(decoded, key);
    }

    // Known test vector: a well-known P-256 did:key
    #[test]
    fn test_known_p256_didkey_prefix() {
        // All P-256 did:keys start with "did:key:zDnae"
        let mut compressed = vec![0x03];
        compressed.extend_from_slice(&[0x00; 32]);
        let did_key = encode_p256_didkey(&compressed).unwrap();
        assert!(did_key.starts_with("did:key:zDnae"), "P-256 did:key should start with 'zDnae', got: {}", did_key);
    }

    // --- Additional tests ---

    #[test]
    fn test_compress_invalid_length() {
        // Too short
        let result = compress_p256_pubkey(&[0x04, 0x01, 0x02]);
        assert!(result.is_err());

        // Wrong prefix
        let mut bad = vec![0x05];
        bad.extend_from_slice(&[0x00; 64]);
        let result = compress_p256_pubkey(&bad);
        assert!(result.is_err());
    }

    #[test]
    fn test_compress_preserves_x_coordinate() {
        let mut uncompressed = vec![0x04];
        let x: Vec<u8> = (0..32).collect();
        let mut y = vec![0x00; 32];
        y[31] = 0x04; // even
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);

        let compressed = compress_p256_pubkey(&uncompressed).unwrap();
        assert_eq!(&compressed[1..], &x[..]);
    }

    #[test]
    fn test_compress_03_prefix_passthrough() {
        let mut compressed = vec![0x03];
        compressed.extend_from_slice(&[0xbb; 32]);
        let result = compress_p256_pubkey(&compressed).unwrap();
        assert_eq!(result, compressed);
    }

    #[test]
    fn test_decode_missing_did_key_prefix() {
        assert!(decode_didkey("zDnae123").is_err());
        assert!(decode_didkey("did:web:example.com").is_err());
        assert!(decode_didkey("").is_err());
    }

    #[test]
    fn test_decode_too_short_payload() {
        // Valid base58 but only 1 byte after decoding
        let encoded = bs58::encode(&[0x80]).into_string();
        let result = decode_didkey(&format!("did:key:z{}", encoded));
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_wrong_key_length() {
        // P256 prefix but wrong key length (only 10 bytes instead of 33)
        let mut payload = Vec::new();
        payload.extend_from_slice(&P256_MULTICODEC);
        payload.extend_from_slice(&[0x02; 10]); // too short

        let encoded = bs58::encode(&payload).into_string();
        let result = decode_didkey(&format!("did:key:z{}", encoded));
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip_multiple_keys() {
        // Test with several different key values
        for prefix_byte in [0x02u8, 0x03] {
            for fill in [0x00u8, 0x42, 0xFF] {
                let mut compressed = vec![prefix_byte];
                compressed.extend_from_slice(&[fill; 32]);

                let did_key = encode_p256_didkey(&compressed).unwrap();
                let (decoded, key_type) = decode_didkey(&did_key).unwrap();
                assert_eq!(key_type, KeyType::P256);
                assert_eq!(decoded, compressed, "Roundtrip failed for prefix={:#04x} fill={:#04x}", prefix_byte, fill);
            }
        }
    }

    #[test]
    fn test_encode_uncompressed_then_decode_matches_compressed() {
        // Create an uncompressed key, encode it, decode it, and verify
        // the decoded version matches the compressed form
        let mut uncompressed = vec![0x04];
        let x = [0x99u8; 32];
        let mut y = [0xAA; 32];
        y[31] = 0x01; // odd -> should get 0x03 prefix
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);

        let did_key = encode_p256_didkey(&uncompressed).unwrap();
        let (decoded, _) = decode_didkey(&did_key).unwrap();

        assert_eq!(decoded[0], 0x03); // odd y
        assert_eq!(&decoded[1..], &x);
    }

    #[test]
    fn test_k256_roundtrip() {
        // Manually construct and decode a K-256 key
        let mut key = vec![0x03];
        key.extend_from_slice(&[0x77; 32]);

        let mut payload = Vec::new();
        payload.extend_from_slice(&K256_MULTICODEC);
        payload.extend_from_slice(&key);

        let encoded = bs58::encode(&payload).into_string();
        let did_key = format!("did:key:z{}", encoded);

        let (decoded, key_type) = decode_didkey(&did_key).unwrap();
        assert_eq!(key_type, KeyType::K256);
        assert_eq!(decoded, key);
    }

    #[test]
    fn test_p256_and_k256_didkeys_differ() {
        let key_bytes = vec![0x02; 33];

        // Encode as P256
        let p256_did = encode_p256_didkey(&key_bytes).unwrap();

        // Encode as K256 manually
        let mut k256_payload = Vec::new();
        k256_payload.extend_from_slice(&K256_MULTICODEC);
        k256_payload.extend_from_slice(&key_bytes);
        let k256_did = format!("did:key:z{}", bs58::encode(&k256_payload).into_string());

        assert_ne!(p256_did, k256_did);

        // P256 starts with zDnae, K256 starts with zQ3s
        assert!(p256_did.starts_with("did:key:zDnae"));
        assert!(k256_did.starts_with("did:key:zQ3s"));
    }

    #[test]
    fn test_unknown_multicodec_prefix() {
        let mut payload = vec![0x01, 0x02]; // unknown prefix
        payload.extend_from_slice(&[0x02; 33]);

        let encoded = bs58::encode(&payload).into_string();
        let result = decode_didkey(&format!("did:key:z{}", encoded));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unknown multicodec prefix"));
    }
}
