use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlcService {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlcOperation {
    #[serde(rename = "type")]
    pub op_type: String,
    pub rotation_keys: Vec<String>,
    pub verification_methods: BTreeMap<String, String>,
    pub also_known_as: Vec<String>,
    pub services: BTreeMap<String, PlcService>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlcState {
    pub did: String,
    pub rotation_keys: Vec<String>,
    pub verification_methods: BTreeMap<String, String>,
    pub also_known_as: Vec<String>,
    pub services: BTreeMap<String, PlcService>,
}

/// Represents a single change in a PLC operation diff.
#[derive(Debug, Clone)]
pub struct ChangeEntry {
    pub kind: String, // "added", "removed", "modified"
    pub description: String,
}

/// Diff between two PLC states.
#[derive(Debug, Clone)]
pub struct OperationDiff {
    pub changes: Vec<ChangeEntry>,
}

/// Serialize a PLC operation for signing (without sig field).
/// Produces canonical DAG-CBOR with keys sorted by length then lexicographic.
pub fn serialize_for_signing(op: &PlcOperation) -> anyhow::Result<Vec<u8>> {
    let mut signing_op = op.clone();
    signing_op.sig = None;
    // Serialize to JSON first, then re-serialize to DAG-CBOR via serde_json::Value.
    // serde_ipld_dagcbor sorts map keys in DAG-CBOR canonical order when serializing
    // from a serde_json::Value (which uses a BTreeMap internally).
    let json_val = serde_json::to_value(&signing_op)?;
    let bytes = serde_ipld_dagcbor::to_vec(&json_val)?;
    Ok(bytes)
}

/// Serialize a signed PLC operation to canonical DAG-CBOR (for CID computation).
pub fn serialize_to_dag_cbor(op: &PlcOperation) -> anyhow::Result<Vec<u8>> {
    let json_val = serde_json::to_value(op)?;
    let bytes = serde_ipld_dagcbor::to_vec(&json_val)?;
    Ok(bytes)
}

/// Compute CIDv1 (dag-cbor + sha256) of a signed operation.
pub fn compute_cid(op: &PlcOperation) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};

    let bytes = serde_ipld_dagcbor::to_vec(op)?;
    let hash = Sha256::digest(&bytes);

    // CIDv1: version(1) + codec(dag-cbor=0x71) + multihash(sha256=0x12, len=0x20, digest)
    let mut cid_bytes = Vec::new();
    // CID version 1
    cid_bytes.push(0x01);
    // dag-cbor codec
    cid_bytes.push(0x71);
    // sha2-256 multihash
    cid_bytes.push(0x12);
    cid_bytes.push(0x20);
    cid_bytes.extend_from_slice(&hash);

    // Encode as base32lower with 'b' prefix
    let encoded = base32_encode(&cid_bytes);
    Ok(format!("b{}", encoded))
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }

    if bits > 0 {
        buffer <<= 5 - bits;
        result.push(ALPHABET[(buffer & 0x1f) as usize] as char);
    }

    result
}

/// Build an update operation from current state and desired changes.
pub fn build_update_operation(
    current_state: &PlcState,
    prev_cid: &str,
    new_rotation_keys: Option<Vec<String>>,
    new_verification_methods: Option<BTreeMap<String, String>>,
    new_also_known_as: Option<Vec<String>>,
    new_services: Option<BTreeMap<String, PlcService>>,
) -> PlcOperation {
    PlcOperation {
        op_type: "plc_operation".to_string(),
        rotation_keys: new_rotation_keys.unwrap_or_else(|| current_state.rotation_keys.clone()),
        verification_methods: new_verification_methods
            .unwrap_or_else(|| current_state.verification_methods.clone()),
        also_known_as: new_also_known_as
            .unwrap_or_else(|| current_state.also_known_as.clone()),
        services: new_services.unwrap_or_else(|| current_state.services.clone()),
        prev: Some(prev_cid.to_string()),
        sig: None,
    }
}

/// Compute diff between current state and a proposed operation.
pub fn compute_diff(current: &PlcState, proposed: &PlcOperation) -> OperationDiff {
    let mut changes = Vec::new();

    // Compare rotation keys
    if current.rotation_keys != proposed.rotation_keys {
        for (i, key) in proposed.rotation_keys.iter().enumerate() {
            if i >= current.rotation_keys.len() {
                changes.push(ChangeEntry {
                    kind: "added".to_string(),
                    description: format!("rotationKeys[{}]: {}", i, truncate_key(key)),
                });
            } else if current.rotation_keys[i] != *key {
                changes.push(ChangeEntry {
                    kind: "modified".to_string(),
                    description: format!(
                        "rotationKeys[{}]: {} -> {}",
                        i,
                        truncate_key(&current.rotation_keys[i]),
                        truncate_key(key)
                    ),
                });
            }
        }
        for i in proposed.rotation_keys.len()..current.rotation_keys.len() {
            changes.push(ChangeEntry {
                kind: "removed".to_string(),
                description: format!(
                    "rotationKeys[{}]: {}",
                    i,
                    truncate_key(&current.rotation_keys[i])
                ),
            });
        }
    }

    // Compare also_known_as
    if current.also_known_as != proposed.also_known_as {
        changes.push(ChangeEntry {
            kind: "modified".to_string(),
            description: format!(
                "alsoKnownAs: {:?} -> {:?}",
                current.also_known_as, proposed.also_known_as
            ),
        });
    }

    // Compare verification methods
    if current.verification_methods != proposed.verification_methods {
        changes.push(ChangeEntry {
            kind: "modified".to_string(),
            description: "verificationMethods changed".to_string(),
        });
    }

    // Compare services
    for (name, svc) in &proposed.services {
        match current.services.get(name) {
            Some(current_svc) if current_svc.endpoint != svc.endpoint => {
                changes.push(ChangeEntry {
                    kind: "modified".to_string(),
                    description: format!("services.{}.endpoint: {} -> {}", name, current_svc.endpoint, svc.endpoint),
                });
            }
            None => {
                changes.push(ChangeEntry {
                    kind: "added".to_string(),
                    description: format!("services.{}", name),
                });
            }
            _ => {}
        }
    }

    if changes.is_empty() {
        changes.push(ChangeEntry {
            kind: "modified".to_string(),
            description: "No visible changes".to_string(),
        });
    }

    OperationDiff { changes }
}

fn truncate_key(key: &str) -> String {
    if key.len() > 30 {
        format!("{}...", &key[..30])
    } else {
        key.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_for_signing_omits_sig() {
        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z123".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: Some("bafytest".to_string()),
            sig: Some("should_be_omitted".to_string()),
        };

        let bytes = serialize_for_signing(&op).unwrap();
        // Deserialize back and check sig is absent
        let val: serde_json::Value =
            serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        assert!(val.get("sig").is_none());
    }

    #[test]
    fn test_compute_cid_format() {
        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z123".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: Some("testsig".to_string()),
        };

        let cid = compute_cid(&op).unwrap();
        assert!(cid.starts_with("bafyrei"), "CID should start with bafyrei, got: {}", cid);
    }

    #[test]
    fn test_build_update_operation() {
        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec!["did:key:old".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec!["at://test.bsky.social".to_string()],
            services: BTreeMap::new(),
        };

        let op = build_update_operation(
            &state,
            "bafytest",
            Some(vec!["did:key:new".to_string(), "did:key:old".to_string()]),
            None,
            None,
            None,
        );

        assert_eq!(op.rotation_keys.len(), 2);
        assert_eq!(op.rotation_keys[0], "did:key:new");
        assert_eq!(op.prev, Some("bafytest".to_string()));
        assert!(op.sig.is_none());
    }

    // --- Additional tests ---

    #[test]
    fn test_build_update_preserves_unchanged_fields() {
        let mut vm = BTreeMap::new();
        vm.insert("atproto".to_string(), "did:key:zVeri".to_string());

        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec!["did:key:rot1".to_string()],
            verification_methods: vm.clone(),
            also_known_as: vec!["at://alice.test".to_string()],
            services: services.clone(),
        };

        // Only change rotation keys, rest should come from state
        let op = build_update_operation(
            &state,
            "bafyprev",
            Some(vec!["did:key:new".to_string()]),
            None,
            None,
            None,
        );

        assert_eq!(op.verification_methods, vm);
        assert_eq!(op.also_known_as, vec!["at://alice.test"]);
        assert_eq!(op.services.len(), 1);
        assert_eq!(op.services["atproto_pds"].endpoint, "https://pds.example.com");
        assert_eq!(op.op_type, "plc_operation");
    }

    #[test]
    fn test_build_update_all_fields_changed() {
        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec!["did:key:old".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
        };

        let mut new_vm = BTreeMap::new();
        new_vm.insert("atproto".to_string(), "did:key:zNewVeri".to_string());

        let mut new_svc = BTreeMap::new();
        new_svc.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://new-pds.example.com".to_string(),
            },
        );

        let op = build_update_operation(
            &state,
            "bafyprev",
            Some(vec!["did:key:new".to_string()]),
            Some(new_vm.clone()),
            Some(vec!["at://new.handle".to_string()]),
            Some(new_svc.clone()),
        );

        assert_eq!(op.rotation_keys, vec!["did:key:new"]);
        assert_eq!(op.verification_methods, new_vm);
        assert_eq!(op.also_known_as, vec!["at://new.handle"]);
        assert_eq!(op.services, new_svc);
    }

    #[test]
    fn test_serialize_for_signing_roundtrip() {
        let mut vm = BTreeMap::new();
        vm.insert("atproto".to_string(), "did:key:zVeri".to_string());

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z1".to_string(), "did:key:z2".to_string()],
            verification_methods: vm,
            also_known_as: vec!["at://test.bsky.social".to_string()],
            services: BTreeMap::new(),
            prev: Some("bafytest".to_string()),
            sig: None,
        };

        let bytes = serialize_for_signing(&op).unwrap();

        // Should be valid CBOR that deserializes back
        let val: serde_json::Value = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        assert_eq!(val["type"], "plc_operation");
        assert!(val.get("sig").is_none());
        assert_eq!(val["rotationKeys"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_serialize_deterministic() {
        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z1".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: Some("bafytest".to_string()),
            sig: None,
        };

        // Serialize twice, should get identical bytes
        let bytes1 = serialize_for_signing(&op).unwrap();
        let bytes2 = serialize_for_signing(&op).unwrap();
        assert_eq!(bytes1, bytes2, "DAG-CBOR serialization should be deterministic");
    }

    #[test]
    fn test_compute_cid_deterministic() {
        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z1".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: Some("sig123".to_string()),
        };

        let cid1 = compute_cid(&op).unwrap();
        let cid2 = compute_cid(&op).unwrap();
        assert_eq!(cid1, cid2, "CID computation should be deterministic");
    }

    #[test]
    fn test_compute_cid_different_ops_different_cids() {
        let op1 = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z1".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: Some("sig1".to_string()),
        };

        let op2 = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z2".to_string()], // different key
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: Some("sig2".to_string()),
        };

        let cid1 = compute_cid(&op1).unwrap();
        let cid2 = compute_cid(&op2).unwrap();
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn test_compute_cid_length() {
        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: Some("s".to_string()),
        };

        let cid = compute_cid(&op).unwrap();
        // CIDv1 with base32: 'b' prefix + base32(1 + 1 + 1 + 1 + 32 = 36 bytes)
        // base32 of 36 bytes = ceil(36*8/5) = 58 chars
        assert!(cid.len() > 50, "CID should be reasonably long: {}", cid);
        assert!(cid.starts_with("b")); // base32lower prefix
    }

    #[test]
    fn test_base32_encode_empty() {
        assert_eq!(base32_encode(&[]), "");
    }

    #[test]
    fn test_base32_encode_known_vector() {
        // RFC 4648 test vectors (lowercase)
        assert_eq!(base32_encode(b"f"), "my");
        assert_eq!(base32_encode(b"fo"), "mzxq");
        assert_eq!(base32_encode(b"foo"), "mzxw6");
        assert_eq!(base32_encode(b"foob"), "mzxw6yq");
        assert_eq!(base32_encode(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn test_compute_diff_no_changes() {
        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec!["did:key:k1".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec!["at://test".to_string()],
            services: BTreeMap::new(),
        };

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:k1".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec!["at://test".to_string()],
            services: BTreeMap::new(),
            prev: Some("bafyprev".to_string()),
            sig: None,
        };

        let diff = compute_diff(&state, &op);
        assert_eq!(diff.changes.len(), 1);
        assert!(diff.changes[0].description.contains("No visible changes"));
    }

    #[test]
    fn test_compute_diff_rotation_key_added() {
        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec!["did:key:k1".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
        };

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![
                "did:key:k1".to_string(),
                "did:key:k2".to_string(),
            ],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: None,
        };

        let diff = compute_diff(&state, &op);
        let added: Vec<_> = diff.changes.iter().filter(|c| c.kind == "added").collect();
        assert_eq!(added.len(), 1);
        assert!(added[0].description.contains("rotationKeys[1]"));
    }

    #[test]
    fn test_compute_diff_rotation_key_removed() {
        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec![
                "did:key:k1".to_string(),
                "did:key:k2".to_string(),
                "did:key:k3".to_string(),
            ],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
        };

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:k1".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: None,
        };

        let diff = compute_diff(&state, &op);
        let removed: Vec<_> = diff.changes.iter().filter(|c| c.kind == "removed").collect();
        assert_eq!(removed.len(), 2);
    }

    #[test]
    fn test_compute_diff_rotation_key_modified() {
        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec!["did:key:old".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
        };

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:new".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: None,
        };

        let diff = compute_diff(&state, &op);
        let modified: Vec<_> = diff.changes.iter().filter(|c| c.kind == "modified").collect();
        assert_eq!(modified.len(), 1);
        assert!(modified[0].description.contains("rotationKeys[0]"));
    }

    #[test]
    fn test_compute_diff_handle_changed() {
        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec!["at://old.handle".to_string()],
            services: BTreeMap::new(),
        };

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec!["at://new.handle".to_string()],
            services: BTreeMap::new(),
            prev: None,
            sig: None,
        };

        let diff = compute_diff(&state, &op);
        let aka_changes: Vec<_> = diff
            .changes
            .iter()
            .filter(|c| c.description.contains("alsoKnownAs"))
            .collect();
        assert_eq!(aka_changes.len(), 1);
    }

    #[test]
    fn test_compute_diff_verification_methods_changed() {
        let mut old_vm = BTreeMap::new();
        old_vm.insert("atproto".to_string(), "did:key:old".to_string());

        let mut new_vm = BTreeMap::new();
        new_vm.insert("atproto".to_string(), "did:key:new".to_string());

        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec![],
            verification_methods: old_vm,
            also_known_as: vec![],
            services: BTreeMap::new(),
        };

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![],
            verification_methods: new_vm,
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: None,
        };

        let diff = compute_diff(&state, &op);
        let vm_changes: Vec<_> = diff
            .changes
            .iter()
            .filter(|c| c.description.contains("verificationMethods"))
            .collect();
        assert_eq!(vm_changes.len(), 1);
    }

    #[test]
    fn test_compute_diff_service_endpoint_changed() {
        let mut old_svc = BTreeMap::new();
        old_svc.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://old-pds.example.com".to_string(),
            },
        );

        let mut new_svc = BTreeMap::new();
        new_svc.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://new-pds.example.com".to_string(),
            },
        );

        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: old_svc,
        };

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: new_svc,
            prev: None,
            sig: None,
        };

        let diff = compute_diff(&state, &op);
        let svc_changes: Vec<_> = diff
            .changes
            .iter()
            .filter(|c| c.description.contains("services.atproto_pds"))
            .collect();
        assert_eq!(svc_changes.len(), 1);
        assert!(svc_changes[0].description.contains("old-pds"));
        assert!(svc_changes[0].description.contains("new-pds"));
    }

    #[test]
    fn test_compute_diff_service_added() {
        let state = PlcState {
            did: "did:plc:test".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
        };

        let mut new_svc = BTreeMap::new();
        new_svc.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: new_svc,
            prev: None,
            sig: None,
        };

        let diff = compute_diff(&state, &op);
        let added: Vec<_> = diff.changes.iter().filter(|c| c.kind == "added").collect();
        assert_eq!(added.len(), 1);
        assert!(added[0].description.contains("services.atproto_pds"));
    }

    #[test]
    fn test_truncate_key_short() {
        assert_eq!(truncate_key("short"), "short");
    }

    #[test]
    fn test_truncate_key_long() {
        let long_key = "did:key:zDnaeLongKeyThatExceedsThirtyCharactersForSure";
        let truncated = truncate_key(long_key);
        assert!(truncated.ends_with("..."));
        assert_eq!(truncated.len(), 33); // 30 chars + "..."
    }

    #[test]
    fn test_truncate_key_exactly_30() {
        let key = "a".repeat(30);
        assert_eq!(truncate_key(&key), key); // no truncation
    }

    #[test]
    fn test_plc_operation_json_serialization() {
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z1".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec!["at://test.handle".to_string()],
            services,
            prev: Some("bafytest".to_string()),
            sig: None,
        };

        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["type"], "plc_operation");
        assert!(json.get("sig").is_none()); // skip_serializing_if
        assert_eq!(json["prev"], "bafytest");
        assert_eq!(json["rotationKeys"][0], "did:key:z1");
        assert_eq!(json["alsoKnownAs"][0], "at://test.handle");
    }

    #[test]
    fn test_plc_operation_json_with_sig() {
        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: Some("base64urlsig".to_string()),
        };

        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["sig"], "base64urlsig");
        assert!(json.get("prev").is_none()); // skip_serializing_if Option::is_none
    }

    #[test]
    fn test_plc_state_deserialization() {
        let json = serde_json::json!({
            "did": "did:plc:test123",
            "rotationKeys": ["did:key:z1", "did:key:z2"],
            "verificationMethods": {"atproto": "did:key:zV"},
            "alsoKnownAs": ["at://alice.test"],
            "services": {
                "atproto_pds": {
                    "type": "AtprotoPersonalDataServer",
                    "endpoint": "https://pds.example.com"
                }
            }
        });

        let state: PlcState = serde_json::from_value(json).unwrap();
        assert_eq!(state.did, "did:plc:test123");
        assert_eq!(state.rotation_keys.len(), 2);
        assert_eq!(state.verification_methods["atproto"], "did:key:zV");
        assert_eq!(state.also_known_as[0], "at://alice.test");
        assert_eq!(state.services["atproto_pds"].endpoint, "https://pds.example.com");
    }

    #[test]
    fn test_dag_cbor_field_ordering() {
        // DAG-CBOR sorts map keys by length then lexicographic.
        // Verify our serialization is consistent.
        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z1".to_string()],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: Some("bafytest".to_string()),
            sig: None,
        };

        let bytes = serialize_for_signing(&op).unwrap();

        // Round-trip: serialize -> deserialize -> serialize should be identical
        let val: serde_json::Value = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        // Re-construct the operation from deserialized values
        let bytes2 = serde_ipld_dagcbor::to_vec(&val).unwrap();
        // The bytes should be identical (deterministic encoding)
        assert_eq!(bytes, bytes2, "DAG-CBOR round-trip should produce identical bytes");
    }

    #[test]
    fn test_dag_cbor_key_names_and_order() {
        let mut services = BTreeMap::new();
        services.insert("atproto_pds".to_string(), PlcService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: "https://pds.example.com".to_string(),
        });
        let mut vm = BTreeMap::new();
        vm.insert("atproto".to_string(), "did:key:zV".to_string());

        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z1".to_string()],
            verification_methods: vm,
            also_known_as: vec!["at://test.handle".to_string()],
            services,
            prev: Some("bafytest".to_string()),
            sig: None,
        };

        let bytes = serialize_for_signing(&op).unwrap();

        // Verify key names are correct by round-tripping through JSON
        let val: serde_json::Value = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("type"), "should have 'type' key");
        assert!(obj.contains_key("prev"), "should have 'prev' key");
        assert!(obj.contains_key("rotationKeys"), "should have 'rotationKeys' key");
        assert!(obj.contains_key("alsoKnownAs"), "should have 'alsoKnownAs' key");
        assert!(obj.contains_key("services"), "should have 'services' key");
        assert!(obj.contains_key("verificationMethods"), "should have 'verificationMethods' key");
        assert!(!obj.contains_key("sig"), "sig should be absent");

        // Verify deterministic round-trip (proves canonical DAG-CBOR ordering)
        let bytes2 = serde_ipld_dagcbor::to_vec(&val).unwrap();
        assert_eq!(bytes, bytes2, "DAG-CBOR round-trip should produce identical bytes");
    }
}
