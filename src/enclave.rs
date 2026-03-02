use anyhow::{Result, bail};
use core_foundation::base::{CFType, TCFType, kCFAllocatorDefault};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::CFRelease;
use security_framework_sys::access_control::*;
use security_framework_sys::base::{SecKeyRef, errSecSuccess};
use security_framework_sys::item::*;
use security_framework_sys::key::*;
use std::ptr;
use std::sync::mpsc;

// LocalAuthentication framework FFI
#[link(name = "LocalAuthentication", kind = "framework")]
extern "C" {}

// Objective-C runtime
#[link(name = "objc", kind = "dylib")]
extern "C" {
    fn objc_getClass(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    fn sel_registerName(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    fn objc_msgSend(obj: *mut std::ffi::c_void, sel: *mut std::ffi::c_void, ...) -> *mut std::ffi::c_void;
}

const TAG_PREFIX: &str = "com.plc-touch.rotation-key.";

// kSecAttrApplicationTag isn't exported by security-framework-sys.
// Its value is the CFString "atag".
fn attr_application_tag() -> CFString {
    CFString::new("atag")
}

/// Keychain access group for syncable keys.
/// Set KEYCHAIN_ACCESS_GROUP env var at compile time, or it defaults to a placeholder.
fn keychain_access_group() -> &'static str {
    option_env!("KEYCHAIN_ACCESS_GROUP").unwrap_or("XXXXXXXXXX.com.example.plc-touch")
}

/// A Secure Enclave key with metadata.
#[derive(Debug, Clone)]
pub struct EnclaveKey {
    pub label: String,
    pub did_key: String,
    pub syncable: bool,
    pub public_key_bytes: Vec<u8>, // uncompressed X9.63
}

/// Generate a new P-256 key.
/// When syncable is true, generates a software key that syncs via iCloud Keychain.
/// When false, generates a hardware-backed Secure Enclave key (device-only).
/// Both are protected by Touch ID via access control.
pub fn generate_key(label: &str, syncable: bool) -> Result<EnclaveKey> {
    let tag = format!("{}{}", TAG_PREFIX, label);

    unsafe {
        // Create access control
        let mut error: core_foundation_sys::error::CFErrorRef = ptr::null_mut();
        let protection = if syncable {
            kSecAttrAccessibleWhenUnlocked
        } else {
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        };

        let flags: core_foundation_sys::base::CFOptionFlags = if syncable {
            // Software key: biometry for signing
            kSecAccessControlBiometryAny as _
        } else {
            // SE key: biometry + private key usage
            (kSecAccessControlBiometryAny | kSecAccessControlPrivateKeyUsage) as _
        };

        let access_control = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            protection as *const _,
            flags,
            &mut error,
        );

        if access_control.is_null() {
            let err_msg = if !error.is_null() {
                let cf_error = core_foundation::error::CFError::wrap_under_create_rule(error);
                format!("Access control error: {} (code: {})", cf_error.description(), cf_error.code())
            } else {
                "Unknown access control error".to_string()
            };
            bail!("{}", err_msg);
        }

        // Build private key attributes
        let mut priv_pairs: Vec<(CFString, CFType)> = vec![
            (
                CFString::wrap_under_get_rule(kSecAttrIsPermanent),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                attr_application_tag(),
                CFData::from_buffer(tag.as_bytes()).as_CFType(),
            ),
        ];

        // Only add access control for non-syncable (SE) keys.
        // Syncable software keys can't have biometric access control.
        if !syncable {
            priv_pairs.push((
                CFString::wrap_under_get_rule(kSecAttrAccessControl),
                CFType::wrap_under_get_rule(access_control as *const _),
            ));
        }

        let private_key_attrs = CFDictionary::from_CFType_pairs(&priv_pairs);

        // Build key generation attributes
        let mut attrs_pairs: Vec<(CFString, CFType)> = vec![
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as *const _),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                CFNumber::from(256i32).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecPrivateKeyAttrs),
                private_key_attrs.as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrLabel),
                CFString::new(label).as_CFType(),
            ),
        ];

        // Only use Secure Enclave for device-only keys
        if !syncable {
            attrs_pairs.push((
                CFString::wrap_under_get_rule(kSecAttrTokenID),
                CFType::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave as *const _),
            ));
        }

        if syncable {
            attrs_pairs.push((
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFBoolean::true_value().as_CFType(),
            ));
            // Use explicit access group so the key is findable across devices
            attrs_pairs.push((
                CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                CFString::new(keychain_access_group()).as_CFType(),
            ));
        }

        let attrs = CFDictionary::from_CFType_pairs(&attrs_pairs);

        let mut gen_error: core_foundation_sys::error::CFErrorRef = ptr::null_mut();
        let private_key = SecKeyCreateRandomKey(attrs.as_concrete_TypeRef(), &mut gen_error);

        CFRelease(access_control as *const _);

        if private_key.is_null() {
            let err_msg = if !gen_error.is_null() {
                let cf_error = core_foundation::error::CFError::wrap_under_create_rule(gen_error);
                format!("Secure Enclave error: {} (domain: {}, code: {})",
                    cf_error.description(), cf_error.domain(), cf_error.code())
            } else {
                "Unknown Secure Enclave error".to_string()
            };
            bail!("{}", err_msg);
        }

        // Get public key
        let public_key = SecKeyCopyPublicKey(private_key);

        if public_key.is_null() {
            CFRelease(private_key as *const _);
            bail!("Failed to extract public key");
        }

        let mut export_error: core_foundation_sys::error::CFErrorRef = ptr::null_mut();
        let pub_data = SecKeyCopyExternalRepresentation(public_key, &mut export_error);
        CFRelease(public_key as *const _);

        if pub_data.is_null() {
            bail!("Failed to export public key");
        }

        let cf_data = CFData::wrap_under_create_rule(pub_data);
        let pub_bytes = cf_data.bytes().to_vec();

        // Verify the key was persisted by trying to find it
        let verify_query = CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFType::wrap_under_get_rule(kSecClassKey as *const _),
            ),
            (
                attr_application_tag(),
                CFData::from_buffer(tag.as_bytes()).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFType::wrap_under_get_rule(kSecAttrSynchronizableAny as *const _),
            ),
        ]);

        let mut verify_result: core_foundation_sys::base::CFTypeRef = ptr::null_mut();
        let verify_status = security_framework_sys::keychain_item::SecItemCopyMatching(
            verify_query.as_concrete_TypeRef(),
            &mut verify_result,
        );
        if !verify_result.is_null() {
            CFRelease(verify_result);
        }

        if verify_status != errSecSuccess {
            // Key was created in SE but not persisted to keychain.
            // This usually means entitlements are missing.
            CFRelease(private_key as *const _);
            bail!(
                "Key was generated in Secure Enclave but failed to persist to Keychain \
                 (OSStatus {}). Check that the app has keychain-access-groups entitlement.",
                verify_status
            );
        }

        CFRelease(private_key as *const _);

        let did_key = crate::didkey::encode_p256_didkey(&pub_bytes)?;

        Ok(EnclaveKey {
            label: label.to_string(),
            did_key,
            syncable,
            public_key_bytes: pub_bytes,
        })
    }
}

/// List all plc-touch keys in the Keychain.
/// Queries separately for SE keys and software keys to avoid touching other apps' items.
pub fn list_keys() -> Result<Vec<EnclaveKey>> {
    let mut all_keys = Vec::new();

    // Query SE keys (device-only)
    all_keys.extend(query_keys_with_token(true)?);
    // Query software keys (potentially synced)
    all_keys.extend(query_keys_with_token(false)?);

    Ok(all_keys)
}

fn query_keys_with_token(secure_enclave: bool) -> Result<Vec<EnclaveKey>> {
    unsafe {
        let mut query_pairs: Vec<(CFString, CFType)> = vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFType::wrap_under_get_rule(kSecClassKey as *const _),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as *const _),
            ),
            (
                CFString::wrap_under_get_rule(kSecReturnAttributes),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecReturnRef),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecMatchLimit),
                CFType::wrap_under_get_rule(kSecMatchLimitAll as *const _),
            ),
        ];

        if secure_enclave {
            // SE keys: search all (sync and non-sync)
            query_pairs.push((
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFType::wrap_under_get_rule(kSecAttrSynchronizableAny as *const _),
            ));
            query_pairs.push((
                CFString::wrap_under_get_rule(kSecAttrTokenID),
                CFType::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave as *const _),
            ));
        } else {
            // Software keys: only syncable ones (our software keys are always syncable)
            query_pairs.push((
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFBoolean::true_value().as_CFType(),
            ));
        }

        let query = CFDictionary::from_CFType_pairs(&query_pairs);

        let mut result: core_foundation_sys::base::CFTypeRef = ptr::null_mut();
        let status = security_framework_sys::keychain_item::SecItemCopyMatching(
            query.as_concrete_TypeRef(),
            &mut result,
        );

        if status == security_framework_sys::base::errSecItemNotFound || result.is_null() {
            return Ok(vec![]);
        }

        if status != errSecSuccess {
            bail!("Failed to query keychain: OSStatus {}", status);
        }

        let array = core_foundation::array::CFArray::<CFDictionary>::wrap_under_create_rule(
            result as core_foundation_sys::array::CFArrayRef,
        );

        let mut keys = Vec::new();
        let tag_key = attr_application_tag();

        for i in 0..array.len() {
            let dict = &array.get(i).unwrap();

            // Check if the application tag matches our prefix
            let app_tag = dict
                .find(tag_key.as_concrete_TypeRef() as *const _)
                .map(|v| {
                    let d = CFData::wrap_under_get_rule(*v as core_foundation_sys::data::CFDataRef);
                    d.bytes().to_vec()
                });

            let tag_bytes = match app_tag {
                Some(ref d) if d.starts_with(TAG_PREFIX.as_bytes()) => d,
                _ => continue,
            };

            // Extract label from the tag (strip prefix)
            let label = String::from_utf8_lossy(&tag_bytes[TAG_PREFIX.len()..]).to_string();

            // Syncable is determined by which query found the key
            let syncable = !secure_enclave;

            // Get the key ref and extract public key
            let key_ref = dict.find(kSecValueRef as *const _);
            if let Some(key_ptr) = key_ref {
                let private_key = *key_ptr as SecKeyRef;
                let public_key = SecKeyCopyPublicKey(private_key);

                if !public_key.is_null() {
                    let mut error: core_foundation_sys::error::CFErrorRef = ptr::null_mut();
                    let pub_data = SecKeyCopyExternalRepresentation(public_key, &mut error);
                    CFRelease(public_key as *const _);

                    if !pub_data.is_null() {
                        let cf_data = CFData::wrap_under_create_rule(pub_data);
                        let pub_bytes = cf_data.bytes().to_vec();

                        if let Ok(did_key) = crate::didkey::encode_p256_didkey(&pub_bytes) {
                            keys.push(EnclaveKey {
                                label,
                                did_key,
                                syncable,
                                public_key_bytes: pub_bytes,
                            });
                        }
                    }
                }
            }
        }

        Ok(keys)
    }
}

/// Delete a key by label.
pub fn delete_key(label: &str) -> Result<()> {
    let tag = format!("{}{}", TAG_PREFIX, label);

    unsafe {
        let query = CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFType::wrap_under_get_rule(kSecClassKey as *const _),
            ),
            (
                attr_application_tag(),
                CFData::from_buffer(tag.as_bytes()).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFType::wrap_under_get_rule(kSecAttrSynchronizableAny as *const _),
            ),
        ]);

        let status = security_framework_sys::keychain_item::SecItemDelete(
            query.as_concrete_TypeRef(),
        );

        if status != errSecSuccess {
            bail!("Failed to delete key '{}': OSStatus {}", label, status);
        }
    }

    Ok(())
}

/// Require biometric authentication (Touch ID / Face ID) via LAContext.
/// Used for software keys that don't have hardware-enforced biometric access control.
fn require_biometric_auth(reason: &str) -> Result<()> {
    unsafe {
        let class = objc_getClass(b"LAContext\0".as_ptr() as *const _);
        if class.is_null() {
            bail!("LAContext not available");
        }

        let alloc_sel = sel_registerName(b"alloc\0".as_ptr() as *const _);
        let init_sel = sel_registerName(b"init\0".as_ptr() as *const _);

        let obj = objc_msgSend(class, alloc_sel);
        let context = objc_msgSend(obj, init_sel);
        if context.is_null() {
            bail!("Failed to create LAContext");
        }

        // Use a channel to wait for the async callback
        let (tx, rx) = mpsc::channel::<std::result::Result<(), String>>();

        let reason_ns = core_foundation::string::CFString::new(reason);

        // evaluatePolicy:localizedReason:reply:
        // Policy 1 = LAPolicyDeviceOwnerAuthenticationWithBiometrics
        let eval_sel = sel_registerName(
            b"evaluatePolicy:localizedReason:reply:\0".as_ptr() as *const _,
        );

        // Create a block for the callback
        let tx_clone = tx.clone();
        let block = block::ConcreteBlock::new(move |success: bool, error: *mut std::ffi::c_void| {
            if success {
                let _ = tx_clone.send(Ok(()));
            } else {
                let _ = tx_clone.send(Err("Biometric authentication cancelled or failed".to_string()));
            }
            let _ = error; // suppress unused warning
        });
        let block = block.copy();

        let _: *mut std::ffi::c_void = {
            type EvalFn = unsafe extern "C" fn(
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                i64,
                *const std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> *mut std::ffi::c_void;
            let f: EvalFn = std::mem::transmute(objc_msgSend as *const ());
            f(
                context,
                eval_sel,
                1, // LAPolicyDeviceOwnerAuthenticationWithBiometrics
                reason_ns.as_concrete_TypeRef() as *const _,
                &*block as *const _ as *const std::ffi::c_void,
            )
        };

        match rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => bail!("{}", e),
            Err(_) => bail!("Biometric authentication timed out"),
        }
    }
}

/// Sign data using a key (triggers Touch ID).
/// For SE keys, Touch ID is enforced by hardware.
/// For software keys, Touch ID is enforced via LAContext before signing.
/// Returns the raw DER-encoded ECDSA signature.
pub fn sign_with_key(label: &str, data: &[u8], is_syncable: bool) -> Result<Vec<u8>> {
    // For syncable (software) keys, require biometric auth first
    if is_syncable {
        require_biometric_auth("Authenticate to sign PLC operation")?;
    }

    let tag = format!("{}{}", TAG_PREFIX, label);

    unsafe {
        let query = CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFType::wrap_under_get_rule(kSecClassKey as *const _),
            ),
            (
                attr_application_tag(),
                CFData::from_buffer(tag.as_bytes()).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecReturnRef),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFType::wrap_under_get_rule(kSecAttrSynchronizableAny as *const _),
            ),
        ]);

        let mut result: core_foundation_sys::base::CFTypeRef = ptr::null_mut();
        let status = security_framework_sys::keychain_item::SecItemCopyMatching(
            query.as_concrete_TypeRef(),
            &mut result,
        );

        if status != errSecSuccess || result.is_null() {
            bail!("Key '{}' not found in Keychain", label);
        }

        let private_key = result as SecKeyRef;
        let cf_data = CFData::from_buffer(data);

        let mut error: core_foundation_sys::error::CFErrorRef = ptr::null_mut();
        let algorithm: SecKeyAlgorithm = Algorithm::ECDSASignatureMessageX962SHA256.into();

        let signature = SecKeyCreateSignature(
            private_key,
            algorithm,
            cf_data.as_concrete_TypeRef(),
            &mut error,
        );

        CFRelease(private_key as *const _);

        if signature.is_null() {
            bail!("Touch ID authentication cancelled or signing failed");
        }

        let sig_data = CFData::wrap_under_create_rule(signature);
        Ok(sig_data.bytes().to_vec())
    }
}

/// Get the did:key for a public key in X9.63 uncompressed format.
pub fn public_key_to_didkey(pub_bytes: &[u8]) -> Result<String> {
    crate::didkey::encode_p256_didkey(pub_bytes)
}
