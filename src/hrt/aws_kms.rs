//! hrt/aws_kms.rs — AWS KMS-backed [`HardwareKeyStore`].
//!
//! For deployments whose root of trust is a cloud KMS rather than an on-premise
//! appliance. The security property is the same one `pkcs11.rs` provides — the private
//! key never exists in this process's memory — obtained through a different mechanism:
//! the key material lives in AWS's FIPS 140-3 Level 3 validated HSM fleet and is
//! reachable only through IAM-authorized `kms:Sign` calls, every one of which lands in
//! CloudTrail. That audit trail is a meaningful addition over a bare PKCS#11 token:
//! a compromise of this process yields signing *access*, and every use of that access is
//! recorded somewhere the compromised process cannot reach.
//!
//! ## Key requirements
//!
//! The KMS key must be created with key spec `ECC_NIST_EDWARDS25519` and key usage
//! `SIGN_VERIFY`:
//!
//! ```text
//! aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY
//! ```
//!
//! AWS added Ed25519 (EdDSA) support in November 2025. An older account or an
//! unsupported region will reject key creation, not silently produce a different
//! algorithm.
//!
//! `key_id` accepts anything `kms:Sign` accepts: a key id, a key ARN, an alias name
//! (`alias/saacp-issuer`), or an alias ARN. Aliases are the operationally useful form —
//! they let a key be rotated to a new backing key without redeploying config.
//!
//! ## Signing algorithm
//!
//! `ED25519_SHA_512` with `MessageType::Raw`. Ed25519 is a "pure" signature scheme: the
//! hashing is defined *inside* the algorithm, so KMS must receive the raw message, not a
//! digest. AWS also exposes `ED25519_PH_SHA_512` (prehashed, requiring
//! `MessageType::Digest`); those two are not interchangeable, and using the prehash
//! variant here would emit Ed25519ph signatures that `ed25519_dalek`'s verifier correctly
//! rejects. The message-type/algorithm pairing is the single easiest thing to get wrong
//! in this file.
//!
//! ## Message size
//!
//! `kms:Sign` with `MessageType::Raw` caps the message at 4096 bytes. Every payload this
//! crate signs is far below that — a capability-token claim set, a certificate body, a
//! handshake transcript — but the limit is checked locally anyway so an oversized input
//! produces a precise local error rather than a generic `ValidationException` from the
//! service.
//!
//! ## Concurrency and the runtime bridge
//!
//! The AWS SDK is async-only; [`HardwareKeyStore::sign`] is synchronous. See
//! [`super::remote`] for why this uses a dedicated runtime with a channel handoff rather
//! than `Runtime::block_on` (which panics when called from inside an async context, as
//! `daemon.rs`'s handshakes are).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use aws_sdk_kms::Client;

use super::remote::{RemoteSignerRuntime, DEFAULT_REMOTE_TIMEOUT};
use super::{
    check_signature_len, ed25519_public_key_from_spki, HardwareKeyStore, HrtError,
};

const BACKEND: &str = "AWS KMS";

/// Maximum raw message `kms:Sign` accepts with `MessageType::Raw`.
const KMS_MAX_RAW_MESSAGE: usize = 4096;

/// Reject an oversized message before spending a network round-trip on a request the
/// service will refuse anyway.
fn check_message_size(len: usize) -> Result<(), HrtError> {
    if len > KMS_MAX_RAW_MESSAGE {
        return Err(HrtError::Backend {
            backend: BACKEND,
            detail: format!(
                "message is {len} bytes; kms:Sign accepts at most {KMS_MAX_RAW_MESSAGE} with \
                 MessageType::Raw"
            ),
        });
    }
    Ok(())
}

/// An AWS KMS-backed [`HardwareKeyStore`].
pub struct AwsKmsKeyStore {
    client: Client,
    runtime: RemoteSignerRuntime,
    /// Cached `key_id -> raw 32-byte public key`.
    ///
    /// A KMS public key is immutable for the life of the key, so this is cached
    /// aggressively: `GetPublicKey` is a billed network round-trip, and the issuance
    /// paths call `public_key()` to build an issuer fingerprint. Signatures are of course
    /// never cached.
    public_keys: Mutex<HashMap<String, Vec<u8>>>,
}

impl AwsKmsKeyStore {
    /// Build a key store using the standard AWS credential chain (environment,
    /// `~/.aws/credentials` profile, ECS/EKS task role, EC2 instance metadata).
    ///
    /// This crate deliberately never handles AWS credentials itself — delegating to
    /// `aws_config` means an operator's existing IAM posture (IRSA, instance roles,
    /// SSO) works unchanged, and no long-lived secret needs to enter SAACP's config.
    pub fn from_environment() -> Result<Self, HrtError> {
        Self::from_environment_with_timeout(DEFAULT_REMOTE_TIMEOUT)
    }

    /// As [`Self::from_environment`], with an explicit per-call timeout.
    pub fn from_environment_with_timeout(timeout: Duration) -> Result<Self, HrtError> {
        let runtime = RemoteSignerRuntime::new(BACKEND, timeout)?;
        // Credential resolution is itself async (it may hit IMDS), so it runs on the
        // dedicated runtime like every other call.
        let config = runtime.run(async {
            Ok(aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await)
        })?;
        Ok(Self {
            client: Client::new(&config),
            runtime,
            public_keys: Mutex::new(HashMap::new()),
        })
    }

    /// Build from an already-configured client, for callers that need custom endpoint,
    /// region, or retry configuration (LocalStack, FIPS endpoints, a pinned region).
    pub fn from_client(client: Client) -> Result<Self, HrtError> {
        Ok(Self {
            client,
            runtime: RemoteSignerRuntime::new(BACKEND, DEFAULT_REMOTE_TIMEOUT)?,
            public_keys: Mutex::new(HashMap::new()),
        })
    }
}

impl HardwareKeyStore for AwsKmsKeyStore {
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HrtError> {
        check_message_size(message.len())?;

        let client = self.client.clone();
        let key_id_owned = key_id.to_string();
        let message = message.to_vec();

        let signature = self.runtime.run(async move {
            let response = client
                .sign()
                .key_id(&key_id_owned)
                .message(Blob::new(message))
                // Raw + ED25519_SHA_512: pure Ed25519. See the module doc — pairing this
                // with Digest/ED25519_PH_SHA_512 would silently produce Ed25519ph
                // signatures that every verifier in this crate rejects.
                .message_type(MessageType::Raw)
                .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
                .send()
                .await
                .map_err(|e| map_sdk_error("kms:Sign", &key_id_owned, e))?;

            response
                .signature()
                .map(|blob| blob.as_ref().to_vec())
                .ok_or_else(|| HrtError::Backend {
                    backend: BACKEND,
                    detail: "kms:Sign succeeded but returned no signature".to_string(),
                })
        })?;

        check_signature_len(signature, BACKEND)
    }

    fn public_key(&self, key_id: &str) -> Result<Vec<u8>, HrtError> {
        if let Some(hit) = self
            .public_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key_id)
            .cloned()
        {
            return Ok(hit);
        }

        let client = self.client.clone();
        let key_id_owned = key_id.to_string();

        let der = self.runtime.run(async move {
            let response = client
                .get_public_key()
                .key_id(&key_id_owned)
                .send()
                .await
                .map_err(|e| map_sdk_error("kms:GetPublicKey", &key_id_owned, e))?;

            response
                .public_key()
                .map(|blob| blob.as_ref().to_vec())
                .ok_or_else(|| HrtError::Backend {
                    backend: BACKEND,
                    detail: "kms:GetPublicKey succeeded but returned no key".to_string(),
                })
        })?;

        // KMS returns DER SubjectPublicKeyInfo, not the bare point.
        let public_key = ed25519_public_key_from_spki(&der, BACKEND)?;
        self.public_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key_id.to_string(), public_key.clone());
        Ok(public_key)
    }
}

/// Turn an SDK error into an [`HrtError`], preserving the service's own message.
///
/// `NotFoundException` maps to [`HrtError::UnknownKey`] so a missing key is reported
/// identically across all three backends — a caller handling "this key id does not
/// exist" should not need to know whether the store is PKCS#11 or KMS.
fn map_sdk_error<E: std::fmt::Debug, R: std::fmt::Debug>(
    operation: &str,
    key_id: &str,
    err: aws_sdk_kms::error::SdkError<E, R>,
) -> HrtError {
    let detail = format!("{operation} for '{key_id}' failed: {err:?}");
    if detail.contains("NotFoundException") {
        return HrtError::UnknownKey(key_id.to_string());
    }
    HrtError::Backend { backend: BACKEND, detail }
}

impl std::fmt::Debug for AwsKmsKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsKeyStore").field("backend", &BACKEND).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Calls against the real service need credentials and a provisioned Ed25519 key, so
    // they are not exercised here. What is worth asserting is the local pre-flight and
    // the SPKI decode, since those are the parts that would otherwise fail late and
    // confusingly.

    #[test]
    fn an_oversized_message_is_refused_locally() {
        // Constructing a store requires credentials, so the size check is exercised
        // directly: it must reject before any network call is attempted.
        assert!(check_message_size(KMS_MAX_RAW_MESSAGE).is_ok());
        assert!(
            matches!(check_message_size(KMS_MAX_RAW_MESSAGE + 1), Err(HrtError::Backend { .. })),
            "an over-limit message must be caught before it reaches kms:Sign"
        );
    }

    #[test]
    fn a_kms_spki_public_key_decodes_to_32_raw_bytes() {
        // Exactly what kms:GetPublicKey returns for an ECC_NIST_EDWARDS25519 key.
        let mut spki = super::super::ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(&[0xABu8; 32]);
        assert_eq!(ed25519_public_key_from_spki(&spki, BACKEND).unwrap(), vec![0xABu8; 32]);
    }

    #[test]
    fn a_non_ed25519_spki_is_rejected_rather_than_tail_sliced() {
        // An operator pointing at an ECC_NIST_P256 key by mistake. The last 32 bytes
        // would look like a plausible key; it must be refused instead.
        let mut wrong = vec![0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2A, 0x86, 0x48, 0x03, 0x21, 0x00];
        wrong.extend_from_slice(&[0xCDu8; 32]);
        assert!(ed25519_public_key_from_spki(&wrong, BACKEND).is_err());
    }
}
