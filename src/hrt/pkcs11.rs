//! hrt/pkcs11.rs — PKCS#11 (Cryptoki) hardware-token / network-HSM key store.
//!
//! This is the backend for the deployment this whole module exists to serve: a bank or
//! defense environment where the signing key is required — often by regulation — to live
//! inside a FIPS 140-2/3 validated device and never exist as bytes in application
//! memory. It targets any PKCS#11 v2.40+ token: Thales Luna, Entrust nShield, Utimaco,
//! AWS CloudHSM's client library, YubiHSM 2, and SoftHSM2 (which is what the test suite
//! uses, since it speaks the identical API).
//!
//! ## What it actually buys you
//!
//! [`crate::hrt::SoftwareKeyStore`] holds a 32-byte Ed25519 seed in this process's heap.
//! Anything that can read that memory — a core dump, `ptrace`, an unrelated
//! memory-disclosure bug elsewhere in the address space — exfiltrates the key
//! permanently, and every signature it ever made becomes forgeable. A PKCS#11 token
//! generated with `CKA_EXTRACTABLE=false` never emits the private key at all: this module
//! sends a message and receives a 64-byte signature, and the strongest possible outcome
//! of a total compromise of this process is that an attacker can ask the token to sign
//! things *for as long as they hold the session* — bounded, revocable by pulling the
//! token or de-provisioning the PIN, and (on any real HSM) logged device-side where this
//! process cannot tamper with the record.
//!
//! ## Concurrency: why the session is behind a `Mutex`
//!
//! [`HardwareKeyStore`] is `Send + Sync`, but `cryptoki::session::Session` is
//! deliberately **`!Sync`** — the C API forbids concurrent use of a single session
//! handle, and the crate encodes that in the type system rather than leaving it to
//! documentation. A `Mutex<Session>` is therefore not incidental locking but the
//! required discipline; the alternative (a session per call) would pay a login round-trip
//! on every signature, which on a network HSM is far more expensive than the lock.
//!
//! The lock is held across the token round-trip. That is a genuine serialization point,
//! and it is the right trade here because the migrated call sites are credential-issuance
//! paths (CA signing, capability issuance) — control-plane operations, not the per-packet
//! data plane. A deployment that needs concurrent signing throughput should run a session
//! pool; that is a deliberate non-goal of this pass rather than an oversight.
//!
//! ## Key lookup
//!
//! `key_id` is the token object's `CKA_LABEL`. Labels rather than raw object handles
//! because handles are session-scoped and not stable across reconnects, whereas a label
//! is what an operator actually provisions and can put in a config file.
//!
//! A lookup that matches **more than one** private key is a hard error, not a
//! "take the first". Two keys sharing a label is a provisioning mistake, and silently
//! picking whichever the token happened to enumerate first would produce signatures under
//! an unpredictable key — the kind of fault that surfaces only later, as an
//! unverifiable signature, with nothing in the logs pointing back to the real cause.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;

use super::{
    check_signature_len, HardwareKeyStore, HrtError, ED25519_PUBLIC_KEY_LEN,
};

/// Backend label used in [`HrtError`] values from this module.
const BACKEND: &str = "PKCS#11";

/// A PKCS#11-backed [`HardwareKeyStore`].
///
/// Holds one logged-in session for the token's lifetime. See the module doc for why the
/// session is behind a `Mutex` and why that is the correct design rather than a
/// concession.
pub struct Pkcs11KeyStore {
    session: Mutex<Session>,
    /// Cached `CKA_LABEL -> (private handle, raw 32-byte public key)`.
    ///
    /// Both halves are cached because both are stable for the session's lifetime and both
    /// otherwise cost a token round-trip on *every* call. `public_key()` in particular is
    /// called by the issuance paths to build a key fingerprint, and re-querying the token
    /// for a value that cannot change would make an HSM-backed authority pointlessly
    /// slower than a software one.
    cache: Mutex<HashMap<String, CachedKey>>,
    /// Kept alive: dropping the `Pkcs11` context finalizes the library, which would
    /// invalidate the session above. Never read directly.
    _context: Pkcs11,
}

#[derive(Clone)]
struct CachedKey {
    private_handle: ObjectHandle,
    public_key: Vec<u8>,
}

impl Pkcs11KeyStore {
    /// Open a token, log in as the User, and prepare it for signing.
    ///
    /// `module_path` is the vendor's PKCS#11 shared library (`libsofthsm2.so`,
    /// `libCryptoki2_64.so`, `yubihsm_pkcs11.dll`, …). `token_label` selects the token by
    /// its label; `pin` is the User PIN.
    ///
    /// Selecting by *token label* rather than slot index is deliberate: slot numbering is
    /// assigned by the driver and can shift between reboots or when another token is
    /// plugged in, so a slot index pinned in a config file is a latent
    /// wrong-key-after-reboot bug.
    ///
    /// Fails rather than degrades. A misconfigured HSM must never fall back to software
    /// keys — that would convert a loud startup failure into a silent, permanent downgrade
    /// of exactly the guarantee the operator deployed an HSM to obtain.
    pub fn open(
        module_path: impl AsRef<Path>,
        token_label: &str,
        pin: &str,
    ) -> Result<Self, HrtError> {
        let module_path = module_path.as_ref();
        let context = Pkcs11::new(module_path).map_err(|e| {
            HrtError::Configuration(format!(
                "could not load the {BACKEND} module at {}: {e}",
                module_path.display()
            ))
        })?;

        // OS_LOCKING_OK: the token's own library may use OS primitives to protect its
        // internal state. Required for any multi-threaded host process, which this is.
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| {
                HrtError::Configuration(format!("could not initialize the {BACKEND} module: {e}"))
            })?;

        let slots = context.get_slots_with_token().map_err(|e| {
            HrtError::Backend { backend: BACKEND, detail: format!("could not enumerate slots: {e}") }
        })?;

        // Find the slot whose token carries `token_label`. Tokens pad their label field
        // with spaces to 32 bytes, so compare trimmed.
        let mut chosen = None;
        for slot in slots {
            if let Ok(info) = context.get_token_info(slot) {
                if info.label().trim() == token_label {
                    chosen = Some(slot);
                    break;
                }
            }
        }
        let slot = chosen.ok_or_else(|| {
            HrtError::Configuration(format!(
                "no {BACKEND} token with label '{token_label}' is present (checked every slot \
                 reporting a token)"
            ))
        })?;

        // RW session: signing itself needs only RO, but a RW session is what allows an
        // operator to provision a key through the same handle, and costs nothing extra.
        let session = context.open_rw_session(slot).map_err(|e| {
            HrtError::Backend {
                backend: BACKEND,
                detail: format!("could not open a session on token '{token_label}': {e}"),
            }
        })?;

        session
            .login(UserType::User, Some(&AuthPin::new(pin.into())))
            .map_err(|e| {
                // Deliberately does not echo the PIN, or its length.
                HrtError::Configuration(format!(
                    "User login to {BACKEND} token '{token_label}' was refused: {e}"
                ))
            })?;

        Ok(Self {
            session: Mutex::new(session),
            cache: Mutex::new(HashMap::new()),
            _context: context,
        })
    }

    /// Resolve `key_id` (a `CKA_LABEL`) to its private handle and public key, caching
    /// the result. See the module doc on why an ambiguous label is a hard error.
    fn resolve(&self, key_id: &str) -> Result<CachedKey, HrtError> {
        if let Some(hit) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key_id)
            .cloned()
        {
            return Ok(hit);
        }

        let session = self.session.lock().unwrap_or_else(|e| e.into_inner());

        let private_template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Label(key_id.as_bytes().to_vec()),
        ];
        let private_handles = session.find_objects(&private_template).map_err(|e| {
            HrtError::Backend { backend: BACKEND, detail: format!("private key search failed: {e}") }
        })?;

        let private_handle = match private_handles.len() {
            0 => return Err(HrtError::UnknownKey(key_id.to_string())),
            1 => private_handles[0],
            n => {
                return Err(HrtError::Configuration(format!(
                    "{n} Ed25519 private keys on this token share the label '{key_id}' — \
                     refusing to guess which one to sign with; give each key a unique CKA_LABEL"
                )))
            }
        };

        // The matching public key object carries CKA_EC_POINT.
        let public_template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Label(key_id.as_bytes().to_vec()),
        ];
        let public_handles = session.find_objects(&public_template).map_err(|e| {
            HrtError::Backend { backend: BACKEND, detail: format!("public key search failed: {e}") }
        })?;
        let public_handle = match public_handles.len() {
            0 => {
                return Err(HrtError::Configuration(format!(
                    "the token has an Ed25519 private key labelled '{key_id}' but no matching \
                     public key object — a caller cannot obtain the verifying key, so this \
                     key is unusable for issuing verifiable signatures"
                )))
            }
            1 => public_handles[0],
            n => {
                return Err(HrtError::Configuration(format!(
                    "{n} Ed25519 public keys on this token share the label '{key_id}'"
                )))
            }
        };

        let attributes = session
            .get_attributes(public_handle, &[AttributeType::EcPoint])
            .map_err(|e| HrtError::Backend {
                backend: BACKEND,
                detail: format!("could not read CKA_EC_POINT for '{key_id}': {e}"),
            })?;
        let ec_point = attributes
            .into_iter()
            .find_map(|a| match a {
                Attribute::EcPoint(bytes) => Some(bytes),
                _ => None,
            })
            .ok_or_else(|| HrtError::Backend {
                backend: BACKEND,
                detail: format!("the public key '{key_id}' has no CKA_EC_POINT attribute"),
            })?;

        let public_key = ed25519_point_from_cka_ec_point(&ec_point)?;

        let entry = CachedKey { private_handle, public_key };
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key_id.to_string(), entry.clone());
        Ok(entry)
    }
}

/// Normalize a token's `CKA_EC_POINT` into the raw 32-byte Ed25519 public key.
///
/// This is the single most token-specific detail in the module. PKCS#11 v3.0 says
/// `CKA_EC_POINT` for Edwards keys is the raw curve point, but real tokens disagree:
/// SoftHSM2 and several HSM vendors wrap it in a DER `OCTET STRING` (tag `0x04`, then a
/// length byte, then the 32 bytes) because that is what the spec required for
/// *Weierstrass* EC points, and the implementations generalized it.
///
/// Both encodings are therefore accepted. Getting this wrong does not fail loudly — it
/// yields a 34-byte "public key", or a 32-byte window that is offset by two — so every
/// accepted path is length-checked rather than sliced on faith.
fn ed25519_point_from_cka_ec_point(raw: &[u8]) -> Result<Vec<u8>, HrtError> {
    // Bare 32-byte point (PKCS#11 v3.0 reading).
    if raw.len() == ED25519_PUBLIC_KEY_LEN {
        return Ok(raw.to_vec());
    }
    // DER OCTET STRING wrapping: 04 20 <32 bytes>.
    if raw.len() == ED25519_PUBLIC_KEY_LEN + 2
        && raw[0] == 0x04
        && raw[1] == ED25519_PUBLIC_KEY_LEN as u8
    {
        return Ok(raw[2..].to_vec());
    }
    Err(HrtError::MalformedResponse {
        backend: BACKEND,
        expected: ED25519_PUBLIC_KEY_LEN,
        got: raw.len(),
    })
}

impl HardwareKeyStore for Pkcs11KeyStore {
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HrtError> {
        let key = self.resolve(key_id)?;
        // `EddsaSignatureScheme::Ed25519` is pure Ed25519 (RFC 8032): no context, no
        // pre-hash, and `into_params` passes a null parameter pointer, which is what a
        // v2.40-era token expects. Using a prehash variant here would produce Ed25519ph
        // signatures that `ed25519_dalek::verify` correctly rejects.
        let mechanism = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519));
        let signature = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sign(&mechanism, key.private_handle, message)
            .map_err(|e| HrtError::Backend {
                backend: BACKEND,
                detail: format!("signing with '{key_id}' failed: {e}"),
            })?;
        check_signature_len(signature, BACKEND)
    }

    fn public_key(&self, key_id: &str) -> Result<Vec<u8>, HrtError> {
        Ok(self.resolve(key_id)?.public_key)
    }
}

impl std::fmt::Debug for Pkcs11KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never renders the session or any key material.
        f.debug_struct("Pkcs11KeyStore").field("backend", &BACKEND).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The token-facing paths need a real PKCS#11 module and so are not exercised here.
    // What is unit-testable is the encoding normalization — the piece most likely to be
    // wrong, and the piece that fails silently rather than loudly when it is.

    #[test]
    fn a_bare_32_byte_ec_point_is_accepted() {
        let point = vec![7u8; 32];
        assert_eq!(ed25519_point_from_cka_ec_point(&point).unwrap(), point);
    }

    #[test]
    fn a_der_octet_string_wrapped_ec_point_is_unwrapped() {
        // What SoftHSM2 actually returns: 04 20 <32 bytes>.
        let mut wrapped = vec![0x04, 0x20];
        wrapped.extend_from_slice(&[9u8; 32]);
        assert_eq!(
            ed25519_point_from_cka_ec_point(&wrapped).unwrap(),
            vec![9u8; 32],
            "the DER OCTET STRING header must be stripped, not returned as key bytes"
        );
    }

    #[test]
    fn a_wrong_length_ec_point_is_rejected_rather_than_truncated() {
        // A P-256 point (65 bytes, uncompressed) — what an operator pointing at the
        // wrong key type would produce. Must not silently yield 32 of those bytes.
        for bad in [vec![0u8; 65], vec![0u8; 31], vec![0u8; 33], Vec::new()] {
            assert!(
                ed25519_point_from_cka_ec_point(&bad).is_err(),
                "a {}-byte CKA_EC_POINT is not an Ed25519 key and must be refused",
                bad.len()
            );
        }
    }

    #[test]
    fn a_der_wrapper_with_an_inconsistent_length_byte_is_rejected() {
        // Right total length, wrong internal length byte — a malformed wrapper that a
        // naive `raw[2..]` slice would happily accept.
        let mut malformed = vec![0x04, 0x1F];
        malformed.extend_from_slice(&[1u8; 32]);
        assert!(ed25519_point_from_cka_ec_point(&malformed).is_err());
    }
}
