//! hrt/gcp_kms.rs — Google Cloud KMS-backed [`HardwareKeyStore`].
//!
//! The GCP counterpart to [`super::aws_kms`], with the same guarantee: the Ed25519
//! private key is generated inside Cloud KMS and has no exportable representation, so it
//! never enters this process's address space. Access is governed by IAM
//! (`cloudkms.cryptoKeyVersions.useToSign`) and every signing call is recorded in Cloud
//! Audit Logs.
//!
//! ## Key requirements
//!
//! An `ASYMMETRIC_SIGN` key whose version algorithm is `EC_SIGN_ED25519`:
//!
//! ```text
//! gcloud kms keys create saacp-issuer \
//!   --keyring saacp --location global \
//!   --purpose asymmetric-signing --default-algorithm ec-sign-ed25519
//! ```
//!
//! `key_id` is the **fully-qualified CryptoKeyVersion resource name**:
//!
//! ```text
//! projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1
//! ```
//!
//! Cloud KMS signs with a specific *version*, not a key, so the version suffix is
//! mandatory. A resource name that stops at the `cryptoKeys/K` level is rejected locally
//! with a precise message rather than being sent on to produce a less obvious
//! `InvalidArgument` from the service.
//!
//! ## Pure mode: `data`, never `digest`
//!
//! Ed25519 in Cloud KMS is a "pure" scheme, so the request must populate
//! `AsymmetricSignRequest::data` with the raw message and leave `digest` unset. This is
//! the opposite of every `EC_SIGN_P*_SHA*` algorithm, where `digest` is what you send —
//! and it is the mistake this file most invites, because the surrounding API is shaped
//! around the digest case.
//!
//! ## Integrity checksums
//!
//! Cloud KMS accepts an optional CRC32C over the request payload and returns one over
//! the response. This module sends and verifies both. They are optional in the protocol
//! but not optional in spirit: they detect corruption on the wire between this process
//! and the service, and a silently-corrupted signature would otherwise surface much later
//! as an unverifiable credential with no indication of where it went wrong.
//!
//! ## Public key format
//!
//! Unlike AWS (which returns DER bytes), Cloud KMS returns a **PEM-encoded**
//! `SubjectPublicKeyInfo` string, so it is base64-decoded to DER first and then put
//! through the shared [`super::ed25519_public_key_from_spki`] check.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::{AsymmetricSignRequest, GetPublicKeyRequest};
// `tonic` is not a direct dependency of this crate; use the copy `gcloud-sdk` re-exports
// so the version can never drift from the one its generated client was built against.
use gcloud_sdk::tonic;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};

use super::remote::{RemoteSignerRuntime, DEFAULT_REMOTE_TIMEOUT};
use super::{
    check_signature_len, ed25519_public_key_from_spki, HardwareKeyStore, HrtError,
};

const BACKEND: &str = "GCP KMS";
const KMS_ENDPOINT: &str = "https://cloudkms.googleapis.com";

type KmsClient = GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>;

/// A Google Cloud KMS-backed [`HardwareKeyStore`].
pub struct GcpKmsKeyStore {
    client: KmsClient,
    runtime: RemoteSignerRuntime,
    /// Cached `resource name -> raw 32-byte public key`. Immutable per key version, and
    /// `GetPublicKey` is a billed round-trip. Signatures are never cached.
    public_keys: Mutex<HashMap<String, Vec<u8>>>,
}

impl GcpKmsKeyStore {
    /// Build a key store using Application Default Credentials — the
    /// `GOOGLE_APPLICATION_CREDENTIALS` service-account file, `gcloud auth
    /// application-default login`, GKE Workload Identity, or the GCE metadata server, in
    /// that order.
    ///
    /// As with the AWS backend, this crate never handles GCP credentials itself.
    pub fn from_environment() -> Result<Self, HrtError> {
        Self::from_environment_with_timeout(DEFAULT_REMOTE_TIMEOUT)
    }

    /// As [`Self::from_environment`], with an explicit per-call timeout.
    pub fn from_environment_with_timeout(timeout: Duration) -> Result<Self, HrtError> {
        let runtime = RemoteSignerRuntime::new(BACKEND, timeout)?;
        let client = runtime.run(async {
            GoogleApi::from_function(KeyManagementServiceClient::new, KMS_ENDPOINT, None)
                .await
                .map_err(|e| {
                    HrtError::Configuration(format!(
                        "could not build a Cloud KMS client — Application Default Credentials \
                         could not be resolved: {e}"
                    ))
                })
        })?;
        Ok(Self { client, runtime, public_keys: Mutex::new(HashMap::new()) })
    }
}

/// Reject a resource name that is not a CryptoKeyVersion before spending a round-trip.
///
/// The overwhelmingly common operator error is pasting the *key* name (which is what the
/// console shows most prominently) where a *key version* is required.
fn validate_version_name(key_id: &str) -> Result<(), HrtError> {
    if !key_id.contains("/cryptoKeyVersions/") {
        return Err(HrtError::Configuration(format!(
            "'{key_id}' is not a Cloud KMS CryptoKeyVersion resource name — Cloud KMS signs \
             with a specific key version, so the name must end in \
             '/cryptoKeyVersions/<n>' (e.g. \
             projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1)"
        )));
    }
    Ok(())
}

/// CRC32C (Castagnoli) over `data`, as the `*_crc32c` request/response fields require.
///
/// Implemented here rather than pulled in as a dependency: it is ~15 lines, and this
/// crate's standing convention is to avoid adding dependencies for small, well-specified
/// computations. Note this is CRC-32C (polynomial 0x1EDC6F41, reflected as 0x82F63B78),
/// *not* the CRC-32 used by zip/gzip — using the wrong polynomial would make every
/// request fail an integrity check that is supposed to be invisible.
fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLY & mask);
        }
    }
    !crc
}

/// Decode a PEM `SubjectPublicKeyInfo` into DER bytes.
fn der_from_pem(pem: &str) -> Result<Vec<u8>, HrtError> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    BASE64.decode(body.trim()).map_err(|e| HrtError::Backend {
        backend: BACKEND,
        detail: format!("GetPublicKey returned a PEM body that is not valid base64: {e}"),
    })
}

impl HardwareKeyStore for GcpKmsKeyStore {
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HrtError> {
        validate_version_name(key_id)?;

        let mut client = self.client.get().clone();
        let name = key_id.to_string();
        let data = message.to_vec();
        let data_crc = crc32c(&data) as i64;

        let signature = self.runtime.run(async move {
            let request = AsymmetricSignRequest {
                name: name.clone(),
                // `data`, not `digest`: Ed25519 is a pure scheme. See the module doc.
                data,
                data_crc32c: Some(data_crc),
                digest: None,
                digest_crc32c: None,
            };

            let response = client
                .asymmetric_sign(tonic::Request::new(request))
                .await
                .map_err(|status| map_status("AsymmetricSign", &name, status))?
                .into_inner();

            // Verify the service's integrity checksum before trusting the bytes.
            if let Some(expected) = response.signature_crc32c {
                let actual = crc32c(&response.signature) as i64;
                if actual != expected {
                    return Err(HrtError::Backend {
                        backend: BACKEND,
                        detail: format!(
                            "signature CRC32C mismatch for '{name}' (service reported {expected}, \
                             computed {actual}) — the response was corrupted in transit; retry"
                        ),
                    });
                }
            }
            Ok(response.signature)
        })?;

        check_signature_len(signature, BACKEND)
    }

    fn public_key(&self, key_id: &str) -> Result<Vec<u8>, HrtError> {
        validate_version_name(key_id)?;

        if let Some(hit) = self
            .public_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key_id)
            .cloned()
        {
            return Ok(hit);
        }

        let mut client = self.client.get().clone();
        let name = key_id.to_string();

        let pem: String = self.runtime.run(async move {
            let response = client
                .get_public_key(tonic::Request::new(GetPublicKeyRequest {
                    name: name.clone(),
                    // 0 = PUBLIC_KEY_FORMAT_UNSPECIFIED, which Cloud KMS documents as
                    // meaning "the default for this key" — PEM. Set explicitly because
                    // the field is non-optional in the generated struct.
                    public_key_format: 0,
                }))
                .await
                .map_err(|status| map_status("GetPublicKey", &name, status))?
                .into_inner();

            if let Some(expected) = response.pem_crc32c {
                let actual = crc32c(response.pem.as_bytes()) as i64;
                if actual != expected {
                    return Err(HrtError::Backend {
                        backend: BACKEND,
                        detail: format!(
                            "public key CRC32C mismatch for '{name}' — response corrupted in \
                             transit"
                        ),
                    });
                }
            }
            Ok(response.pem)
        })?;

        let der = der_from_pem(&pem)?;
        let public_key = ed25519_public_key_from_spki(&der, BACKEND)?;
        self.public_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key_id.to_string(), public_key.clone());
        Ok(public_key)
    }
}

/// Map a gRPC status onto an [`HrtError`], keeping `NotFound` distinguishable so a
/// missing key reports identically across all three backends.
fn map_status(operation: &str, key_id: &str, status: tonic::Status) -> HrtError {
    if status.code() == tonic::Code::NotFound {
        return HrtError::UnknownKey(key_id.to_string());
    }
    if status.code() == tonic::Code::DeadlineExceeded {
        return HrtError::Timeout { backend: BACKEND };
    }
    HrtError::Backend {
        backend: BACKEND,
        detail: format!(
            "{operation} for '{key_id}' failed: {} ({})",
            status.message(),
            status.code()
        ),
    }
}

impl std::fmt::Debug for GcpKmsKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsKeyStore").field("backend", &BACKEND).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned to published CRC32C reference vectors rather than to self-consistency:
    /// a wrong polynomial would make every signing request fail an integrity check that
    /// is supposed to be invisible, and a self-consistent test would not catch it.
    #[test]
    fn crc32c_matches_the_published_reference_vectors() {
        assert_eq!(crc32c(b""), 0x0000_0000);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
    }

    #[test]
    fn a_key_name_without_a_version_suffix_is_refused_locally() {
        // The most common operator mistake — the console shows the key name, but signing
        // requires a version. Must fail before a network round-trip.
        let err =
            validate_version_name("projects/p/locations/global/keyRings/r/cryptoKeys/k").unwrap_err();
        assert!(matches!(err, HrtError::Configuration(msg) if msg.contains("cryptoKeyVersions")));

        assert!(validate_version_name(
            "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
        )
        .is_ok());
    }

    #[test]
    fn a_pem_public_key_decodes_to_32_raw_bytes() {
        // Exactly the shape Cloud KMS returns for an EC_SIGN_ED25519 key version.
        let mut spki = super::super::ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(&[0x5Au8; 32]);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            BASE64.encode(&spki)
        );
        let der = der_from_pem(&pem).unwrap();
        assert_eq!(der, spki, "the PEM armor must be stripped and the body base64-decoded");
        assert_eq!(ed25519_public_key_from_spki(&der, BACKEND).unwrap(), vec![0x5Au8; 32]);
    }

    #[test]
    fn a_malformed_pem_body_is_rejected() {
        let pem = "-----BEGIN PUBLIC KEY-----\nnot!valid!base64!\n-----END PUBLIC KEY-----";
        assert!(der_from_pem(pem).is_err());
    }
}
