//! easi.rs — Encrypted Agent State Information (EASI)
//!
//! Implements the EASI encryption wrapper for the 32-byte Context Ref ID
//! field in MEASC transport frames (GAP-9 / M-2 fix, SAACP/0.1-beta2).
//!
//! # Security design
//!
//! The Context Ref ID is a session identifier carried in the authenticated
//! MEASC header. Without EASI, it travels as plaintext, allowing a passive
//! observer to correlate packets across sessions. EASI adds per-packet
//! confidentiality using HKDF-SHA256 to derive a unique 32-byte keystream
//! from the session traffic key, epoch ID, and packet sequence number (PSN).
//!
//! ## Construction
//!
//! ```text
//! pad = HKDF-SHA256(
//!     IKM  = traffic_key,          // 32-byte epoch traffic key
//!     salt = epoch_id_BE4 || psn_BE8,  // 12 bytes: unique per packet
//!     info = b"SAACP-EASI-context-ref-v1",
//!     len  = 32,
//! )
//! wire_ctx_ref_id = plaintext_ctx_ref_id XOR pad
//! ```
//!
//! ## Properties
//!
//! - **No length expansion**: XOR cipher, 32 bytes in → 32 bytes out.
//! - **Integrity via outer frame**: The MEASC header (containing the encrypted
//!   context_ref_id) is authenticated by the outer AES-256-GCM tag. EASI
//!   adds confidentiality only; integrity is provided by the MEASC layer.
//! - **Self-inverse**: `decrypt == encrypt` for XOR ciphers.
//! - **Per-packet uniqueness**: The 12-byte salt (epoch_id || psn) is unique
//!   for every packet in a session, preventing keystream reuse.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

// ─── EasiEncryptor ────────────────────────────────────────────────────────────

/// EASI keystream derivation and XOR cipher for 32-byte Context Ref IDs.
pub struct EasiEncryptor;

impl EasiEncryptor {
    /// HKDF info string — version-tagged for future algorithm agility.
    pub const HKDF_INFO: &'static [u8] = b"SAACP-EASI-context-ref-v1";

    /// Derive a 32-byte keystream pad unique to this (traffic_key, epoch_id, psn) triple.
    ///
    /// The 12-byte salt `epoch_id_BE4 || psn_BE8` ensures that even when the
    /// same context_ref_id appears across multiple packets in a session, each
    /// wire encoding is distinct. Reuse of the same salt across different
    /// traffic_keys (epochs) is prevented by HKDF binding to the IKM.
    pub fn derive_pad(traffic_key: &[u8; 32], epoch_id: u32, psn: u64) -> [u8; 32] {
        // Salt = epoch_id (4 bytes BE) || psn (8 bytes BE) = 12 bytes
        let mut salt = [0u8; 12];
        salt[0..4].copy_from_slice(&epoch_id.to_be_bytes());
        salt[4..12].copy_from_slice(&psn.to_be_bytes());

        let hk = Hkdf::<Sha256>::new(Some(&salt), traffic_key);
        let mut pad = [0u8; 32];
        hk.expand(Self::HKDF_INFO, &mut pad)
            .expect("EASI HKDF-SHA256 expand: output length 32 is always valid");
        pad
    }

    /// Encrypt a 32-byte context_ref_id for wire transmission.
    ///
    /// Returns the 32-byte EASI-encrypted form that goes into the MEASC header
    /// at `MEASC_CONTEXT_REF_ID_OFFSET` (offset 44).
    ///
    /// M-6 fix: the keystream `pad` is derived from `traffic_key` (a session
    /// secret) — it is explicitly zeroized after the XOR so it doesn't linger
    /// in stack memory (which can be paged to swap or captured in a core
    /// dump) past its single use here.
    pub fn encrypt(
        ctx_ref_id: &[u8; 32],
        traffic_key: &[u8; 32],
        epoch_id: u32,
        psn: u64,
    ) -> [u8; 32] {
        let mut pad = Self::derive_pad(traffic_key, epoch_id, psn);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = ctx_ref_id[i] ^ pad[i];
        }
        pad.zeroize();
        out
    }

    /// Decrypt a 32-byte EASI-encrypted context_ref_id received from the wire.
    ///
    /// XOR-based construction means decryption is identical to encryption.
    /// Calling this with the same arguments as `encrypt` recovers the plaintext.
    pub fn decrypt(
        encrypted: &[u8; 32],
        traffic_key: &[u8; 32],
        epoch_id: u32,
        psn: u64,
    ) -> [u8; 32] {
        // XOR cipher is self-inverse: encrypt == decrypt
        Self::encrypt(encrypted, traffic_key, epoch_id, psn)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] { [0xABu8; 32] }
    fn test_ctx_ref_id() -> [u8; 32] { [0x42u8; 32] }

    // ── Basic encrypt/decrypt roundtrip ───────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = test_ctx_ref_id();

        let encrypted = EasiEncryptor::encrypt(&plaintext, &key, 1, 100);
        let decrypted = EasiEncryptor::decrypt(&encrypted, &key, 1, 100);

        assert_eq!(decrypted, plaintext, "roundtrip must recover plaintext exactly");
    }

    #[test]
    fn encrypt_changes_plaintext() {
        let key = test_key();
        let plaintext = test_ctx_ref_id();
        let encrypted = EasiEncryptor::encrypt(&plaintext, &key, 1, 1);
        // Encrypted form must differ from plaintext (the key is non-zero)
        assert_ne!(encrypted, plaintext, "encryption must change the bytes");
    }

    #[test]
    fn encrypt_all_zeros_plaintext() {
        let key = test_key();
        let plaintext = [0u8; 32];
        let encrypted = EasiEncryptor::encrypt(&plaintext, &key, 1, 1);
        // With all-zero plaintext, encrypted == pad
        let pad = EasiEncryptor::derive_pad(&key, 1, 1);
        assert_eq!(encrypted, pad);

        let decrypted = EasiEncryptor::decrypt(&encrypted, &key, 1, 1);
        assert_eq!(decrypted, plaintext);
    }

    // ── Per-packet uniqueness (different PSNs produce different pads) ─────────

    #[test]
    fn different_psn_produces_different_pad() {
        let key = test_key();
        let pad1 = EasiEncryptor::derive_pad(&key, 1, 1);
        let pad2 = EasiEncryptor::derive_pad(&key, 1, 2);
        assert_ne!(pad1, pad2, "different PSN must produce different pad");
    }

    #[test]
    fn different_epoch_produces_different_pad() {
        let key = test_key();
        let pad1 = EasiEncryptor::derive_pad(&key, 0, 1);
        let pad2 = EasiEncryptor::derive_pad(&key, 1, 1);
        assert_ne!(pad1, pad2, "different epoch_id must produce different pad");
    }

    #[test]
    fn different_key_produces_different_pad() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let pad1 = EasiEncryptor::derive_pad(&key1, 1, 1);
        let pad2 = EasiEncryptor::derive_pad(&key2, 1, 1);
        assert_ne!(pad1, pad2, "different traffic_key must produce different pad");
    }

    #[test]
    fn derive_pad_deterministic() {
        let key = test_key();
        let pad_a = EasiEncryptor::derive_pad(&key, 42, 9999);
        let pad_b = EasiEncryptor::derive_pad(&key, 42, 9999);
        assert_eq!(pad_a, pad_b, "pad derivation must be deterministic");
    }

    // ── Decryption with wrong key/epoch/psn fails to recover plaintext ────────

    #[test]
    fn wrong_key_does_not_decrypt() {
        let key = test_key();
        let plaintext = test_ctx_ref_id();
        let encrypted = EasiEncryptor::encrypt(&plaintext, &key, 1, 1);

        let wrong_key = [0xFFu8; 32];
        let wrong_decrypted = EasiEncryptor::decrypt(&encrypted, &wrong_key, 1, 1);
        assert_ne!(wrong_decrypted, plaintext,
            "decryption with wrong key must not recover plaintext");
    }

    #[test]
    fn wrong_psn_does_not_decrypt() {
        let key = test_key();
        let plaintext = test_ctx_ref_id();
        let encrypted = EasiEncryptor::encrypt(&plaintext, &key, 1, 100);

        let wrong_dec = EasiEncryptor::decrypt(&encrypted, &key, 1, 101);
        assert_ne!(wrong_dec, plaintext,
            "decryption with wrong PSN must not recover plaintext");
    }

    #[test]
    fn wrong_epoch_does_not_decrypt() {
        let key = test_key();
        let plaintext = test_ctx_ref_id();
        let encrypted = EasiEncryptor::encrypt(&plaintext, &key, 5, 1);

        let wrong_dec = EasiEncryptor::decrypt(&encrypted, &key, 6, 1);
        assert_ne!(wrong_dec, plaintext,
            "decryption with wrong epoch_id must not recover plaintext");
    }

    // ── XOR self-inverse property ─────────────────────────────────────────────

    #[test]
    fn encrypt_twice_recovers_plaintext() {
        let key = test_key();
        let plaintext = test_ctx_ref_id();
        let encrypted = EasiEncryptor::encrypt(&plaintext, &key, 7, 42);
        // Encrypting the ciphertext again == decrypting
        let recovered = EasiEncryptor::encrypt(&encrypted, &key, 7, 42);
        assert_eq!(recovered, plaintext,
            "XOR cipher: double-encrypt must recover plaintext");
    }

    // ── Boundary conditions ───────────────────────────────────────────────────

    #[test]
    fn max_psn_roundtrip() {
        let key = test_key();
        let plaintext = [0xFFu8; 32];
        let psn = u64::MAX;
        let encrypted = EasiEncryptor::encrypt(&plaintext, &key, u32::MAX, psn);
        let decrypted = EasiEncryptor::decrypt(&encrypted, &key, u32::MAX, psn);
        assert_eq!(decrypted, plaintext, "must work with maximum epoch/psn values");
    }

    #[test]
    fn zero_epoch_zero_psn_roundtrip() {
        let key = [0u8; 32];
        let plaintext = [1u8; 32];
        let encrypted = EasiEncryptor::encrypt(&plaintext, &key, 0, 0);
        let decrypted = EasiEncryptor::decrypt(&encrypted, &key, 0, 0);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn unique_context_ids_encrypt_to_unique_wire_values() {
        let key = test_key();
        let epoch_id = 1u32;
        let psn = 50u64;

        let ctx_a = [0xAAu8; 32];
        let ctx_b = [0xBBu8; 32];

        let enc_a = EasiEncryptor::encrypt(&ctx_a, &key, epoch_id, psn);
        let enc_b = EasiEncryptor::encrypt(&ctx_b, &key, epoch_id, psn);

        assert_ne!(enc_a, enc_b,
            "distinct plaintext context_ref_ids must produce distinct encrypted values");
    }

    // ── HKDF_INFO constant ────────────────────────────────────────────────────

    #[test]
    fn hkdf_info_has_version_tag() {
        let info = std::str::from_utf8(EasiEncryptor::HKDF_INFO).unwrap();
        assert!(info.contains("SAACP-EASI"), "info must contain protocol prefix");
        assert!(info.contains("v1"), "info must contain version tag for algorithm agility");
    }

    // ── Large-scale uniqueness: 1000 distinct PSNs produce distinct pads ──────

    #[test]
    fn thousand_distinct_psns_produce_distinct_pads() {
        let key = test_key();
        let epoch_id = 0u32;
        let pads: Vec<[u8; 32]> = (1..=1000)
            .map(|psn| EasiEncryptor::derive_pad(&key, epoch_id, psn))
            .collect();

        // No two pads should be identical
        for i in 0..pads.len() {
            for j in (i + 1)..pads.len() {
                assert_ne!(pads[i], pads[j],
                    "PSN {} and PSN {} must produce different pads", i + 1, j + 1);
            }
        }
    }
}
