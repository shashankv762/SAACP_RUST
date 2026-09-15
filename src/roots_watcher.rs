//! roots_watcher.rs — Background trusted-root bundle reload (Phase 2.3)
//!
//! Spawns a long-lived background thread that polls a JSON file for an
//! updated [`crate::attestation::TrustedRootBundle`] and calls
//! [`crate::attestation::AttestationVerifier::update_roots`] on change.
//! Change detection uses `std::fs::metadata().modified()` — no `notify`
//! crate (and therefore no inotify/kqueue platform divergence).
//! Polling a ~1 KB file every 60 seconds is negligible I/O.
//!
//! # File format
//!
//! The roots file is a JSON object with the following shape:
//!
//! ```json
//! {
//!   "version": 1,
//!   "measurements": [
//!     { "type": "tpm", "hex": "0102030405..." }
//!   ],
//!   "signing_keys": [
//!     { "type": "tpm", "ed25519_hex": "0a1b2c3d..." }
//!   ],
//!   "signature": "<128 hex digits>"
//! }
//! ```
//! The authority signs the UTF-8 bytes of the compact JSON serialization of
//! `{version,measurements,signing_keys}` in that order, excluding `signature`.
//!
//! Reload is **atomic**: the verifier holds an `arc_swap::ArcSwap` pointer,
//! so in-flight verifications keep using the previous bundle until they
//! complete, while new verifications observe the freshly loaded one.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::attestation::{AttestationType, AttestationVerifier, TrustedRootBundle};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireMeasurement {
    #[serde(rename = "type")]
    att_type: String,
    hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireSigningKey {
    #[serde(rename = "type")]
    att_type: String,
    ed25519_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireRootsUnsigned {
    #[serde(default)]
    version: u64,
    #[serde(default)]
    measurements: Vec<WireMeasurement>,
    #[serde(default)]
    signing_keys: Vec<WireSigningKey>,
}

#[derive(Debug, Deserialize)]
struct WireRootsFile {
    #[serde(flatten)]
    roots: WireRootsUnsigned,
    /// Hex-encoded Ed25519 signature from the out-of-band roots authority.
    signature: String,
}

fn parse_roots_file(
    path: &PathBuf,
    roots_authority: &VerifyingKey,
) -> Result<TrustedRootBundle, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("roots_watcher: read '{}': {}", path.display(), e))?;
    let wire: WireRootsFile = serde_json::from_str(&content)
        .map_err(|e| format!("roots_watcher: JSON parse '{}': {}", path.display(), e))?;
    let signature_bytes = hex::decode(&wire.signature)
        .map_err(|e| format!("roots_watcher: signature hex decode: {}", e))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "roots_watcher: signature must be exactly 64 bytes".to_string())?;
    let signed_payload = serde_json::to_vec(&wire.roots)
        .map_err(|e| format!("roots_watcher: canonicalize roots: {}", e))?;
    roots_authority
        .verify(&signed_payload, &Signature::from_bytes(&signature_array))
        .map_err(|_| "roots_watcher: roots signature verification failed".to_string())?;
    if wire.roots.version == 0 {
        return Err("roots_watcher: roots version must be non-zero".to_string());
    }
    let mut bundle = TrustedRootBundle::new();
    bundle.version = wire.roots.version;
    for entry in &wire.roots.measurements {
        let att_type = AttestationType::from_str(&entry.att_type).ok_or_else(|| {
            format!("roots_watcher: unknown attestation type '{}'", entry.att_type)
        })?;
        let bytes = hex::decode(&entry.hex)
            .map_err(|e| format!("roots_watcher: measurement hex decode: {}", e))?;
        bundle.measurements.push((att_type, bytes));
    }
    for entry in &wire.roots.signing_keys {
        let att_type = AttestationType::from_str(&entry.att_type).ok_or_else(|| {
            format!("roots_watcher: unknown attestation type '{}'", entry.att_type)
        })?;
        let bytes = hex::decode(&entry.ed25519_hex)
            .map_err(|e| format!("roots_watcher: signing key hex decode: {}", e))?;
        let key_bytes: [u8; 32] = bytes.try_into()
            .map_err(|_| "roots_watcher: Ed25519 key must be exactly 32 bytes".to_string())?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| format!("roots_watcher: invalid Ed25519 key: {}", e))?;
        bundle.signing_keys.push((att_type, verifying_key));
    }
    Ok(bundle)
}

/// Start a background thread that polls path every poll_interval and
/// calls [AttestationVerifier::update_roots] on mtime change.
///
/// Returns a JoinHandle the caller may drop; thread runs until process exit.
/// Start the watcher with an explicitly provisioned roots-authority key.
/// This is the preferred API for production deployments.
pub fn start_roots_watcher_with_authority(
    verifier: Arc<AttestationVerifier>,
    path: PathBuf,
    poll_interval: Duration,
    roots_authority: VerifyingKey,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("saacp-roots-watcher".to_owned())
        .spawn(move || {
            let mut last_mtime: Option<SystemTime> = None;
            let mut last_version = 0u64;
            match parse_roots_file(&path, &roots_authority) {
                Ok(bundle) => {
                    tracing::info!(path = %path.display(), version = bundle.version, "roots_watcher: initial load succeeded");
                    last_mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
                    last_version = bundle.version;
                    verifier.update_roots(bundle);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "roots_watcher: initial load failed; using empty bundle");
                }
            }
            loop {
                std::thread::sleep(poll_interval);
                let mtime = match std::fs::metadata(&path).and_then(|m| m.modified()) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "roots_watcher: cannot stat roots file; skipping poll");
                        continue;
                    }
                };
                if last_mtime == Some(mtime) { continue; }
                match parse_roots_file(&path, &roots_authority) {
                    Ok(bundle) => {
                        if bundle.version <= last_version {
                            tracing::warn!(path = %path.display(), version = bundle.version, current_version = last_version, "roots_watcher: refusing non-monotonic roots version");
                            last_mtime = Some(mtime);
                            continue;
                        }
                        tracing::info!(path = %path.display(), version = bundle.version, measurements = bundle.measurements.len(), signing_keys = bundle.signing_keys.len(), "roots_watcher: reloaded roots bundle");
                        last_mtime = Some(mtime);
                        last_version = bundle.version;
                        verifier.update_roots(bundle);
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "roots_watcher: parse failed; keeping current bundle");
                    }
                }
            }
        })
        .expect("saacp-roots-watcher thread spawn failed")
}

/// Start the watcher using `SAACP_ROOTS_AUTHORITY_ED25519_HEX`.
///
/// The legacy three-argument API is retained for source compatibility, but it
/// is fail-closed: if the authority variable is absent or malformed, the
/// watcher thread logs the error and never installs a bundle.
pub fn start_roots_watcher(
    verifier: Arc<AttestationVerifier>,
    path: PathBuf,
    poll_interval: Duration,
) -> std::thread::JoinHandle<()> {
    let authority = std::env::var("SAACP_ROOTS_AUTHORITY_ED25519_HEX")
        .ok()
        .and_then(|hex_key| hex::decode(hex_key).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok());
    match authority {
        Some(key) => start_roots_watcher_with_authority(verifier, path, poll_interval, key),
        None => std::thread::Builder::new()
            .name("saacp-roots-watcher".to_owned())
            .spawn(move || {
                tracing::error!(
                    path = %path.display(),
                    "roots_watcher: SAACP_ROOTS_AUTHORITY_ED25519_HEX is missing or invalid; refusing all root reloads"
                );
            })
            .expect("saacp-roots-watcher thread spawn failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use std::io::Write;

    fn write_temp_roots(path: &PathBuf, content: &str) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    fn signed_file(
        authority: &ed25519_dalek::SigningKey,
        version: u64,
        measurements: Vec<WireMeasurement>,
    ) -> String {
        let roots = WireRootsUnsigned {
            version,
            measurements,
            signing_keys: Vec::new(),
        };
        let bytes = serde_json::to_vec(&roots).unwrap();
        let signature = hex::encode(authority.sign(&bytes).to_bytes());
        format!("{{\"version\":{version},\"measurements\":{},\"signing_keys\":[],\"signature\":\"{signature}\"}}", serde_json::to_string(&roots.measurements).unwrap())
    }

    #[test]
    fn parse_empty_roots_file() {
        let dir = std::env::temp_dir().join("saacp_roots_test_empty.json");
        let authority = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        write_temp_roots(&dir, &signed_file(&authority, 1, Vec::new()));
        let bundle = parse_roots_file(&dir, &authority.verifying_key()).unwrap();
        assert_eq!(bundle.version, 1);
        assert!(bundle.measurements.is_empty());
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn parse_roots_with_measurement() {
        let dir = std::env::temp_dir().join("saacp_roots_test_meas.json");
        let authority = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        write_temp_roots(&dir, &signed_file(&authority, 2, vec![WireMeasurement {
            att_type: "tpm".to_string(),
            hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
        }]));
        let bundle = parse_roots_file(&dir, &authority.verifying_key()).unwrap();
        assert_eq!(bundle.measurements.len(), 1);
        assert_eq!(bundle.measurements[0].0, AttestationType::Tpm);
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn signed_roots_reject_tampering_and_wrong_authority() {
        let dir = std::env::temp_dir().join("saacp_roots_test_tamper.json");
        let signer = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let other = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let valid = signed_file(&signer, 4, Vec::new());
        write_temp_roots(&dir, &valid);
        assert!(parse_roots_file(&dir, &other.verifying_key()).is_err());
        write_temp_roots(&dir, &valid.replace("\"version\":4", "\"version\":5"));
        assert!(parse_roots_file(&dir, &signer.verifying_key()).is_err());
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let dir = std::env::temp_dir().join("saacp_roots_test_bad.json");
        write_temp_roots(&dir, "not json");
        let authority = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        assert!(parse_roots_file(&dir, &authority).is_err());
        let _ = std::fs::remove_file(&dir);
    }
}
