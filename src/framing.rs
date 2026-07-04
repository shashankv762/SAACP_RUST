//! framing.rs — SAACP Wire Format Implementation
//!
//! Implements the full wire protocol for SAACP v4.0:
//! - SAACPFrame: 101-byte application-layer header (matching Python PREFIX_FORMAT)
//! - MEASCFrame: 128-byte transport-layer header
//!
//! Wire format (SAACPFrame):
//!   [101-byte prefix] + [16-byte AES-GCM auth tag] + [4-byte Adler32] + [ciphertext]
//!
//! Python reference: src/saacp/framing.py
//! PREFIX_FORMAT = ">4s H B B B I I 16s 24s 32s I Q"

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

/// Maximum decompressed payload size (prevents zip-bomb attacks).
/// Compressed payload MUST decompress to ≤ MAX_PAYLOAD_SIZE bytes.
pub const MAX_DECOMPRESSED_SIZE: usize = MAX_PAYLOAD_SIZE; // 10 MB

// ── Magic bytes ───────────────────────────────────────────────────────────────
pub const MEASC_MAGIC: &[u8; 4] = b"SACP";
pub const MEASC_HEADER_SIZE: usize = 128;
pub const MAX_PAYLOAD_SIZE: usize = 10_000_000; // 10 MB MTU

// ── SAACPFrame application-layer header sizes ─────────────────────────────────
/// 101-byte prefix matching Python's struct.calcsize(">4s H B B B I I 16s 24s 32s I Q")
pub const SAACPFRAME_PREFIX_SIZE: usize = 101;
/// Full wire overhead without ciphertext: 101 + 16 (auth tag) + 4 (Adler32) = 121
pub const SAACPFRAME_FIXED_OVERHEAD: usize = 121;

// ── Flag-bit constants (authenticated header byte 7) ─────────────────────────
/// M-8 fix: cover traffic; also aliases FLAG_EXTERNAL_INPUT (same bit, context-dependent)
pub const FLAG_COVER_TRAFFIC: u8  = 0x80;
/// Forces FULL gate tier when action_class != 0xFF
pub const FLAG_EXTERNAL_INPUT: u8 = 0x80;
/// Payload carries a capability token
pub const FLAG_HAS_TOKEN: u8      = 0x01;
/// C-2 fix: non-text binary stream — skip Gate 4.0 injection scan
pub const FLAG_BINARY_STREAM: u8  = 0x02;
/// Frame payload is AES-256-GCM encrypted (always set post-handshake)
pub const FLAG_ENCRYPTED: u8      = 0x10;
/// Payload is zlib-compressed (before encryption)
pub const FLAG_COMPRESSED: u8     = 0x20;
/// Packet belongs to a StreamSession
pub const FLAG_STREAMING: u8      = 0x40;

// ── Action class constants ────────────────────────────────────────────────────
pub const ACTION_CLASS_READ_ONLY: u8    = 0x00;
pub const ACTION_CLASS_REVERSIBLE: u8   = 0x01;
pub const ACTION_CLASS_IRREVERSIBLE: u8 = 0x02;

// ── Compile-time frame size invariants (spec §3.1 / §3.2) ────────────────────
// "The struct.Struct computed size MUST be asserted equal to N at module load time."
const _: () = assert!(MEASC_HEADER_SIZE == 128,
    "MEASC header MUST be exactly 128 bytes");
const _: () = assert!(SAACPFRAME_PREFIX_SIZE == 101,
    "SAACPFrame prefix MUST be exactly 101 bytes (matching Python PREFIX_FORMAT)");
const _: () = assert!(SAACPFRAME_FIXED_OVERHEAD == SAACPFRAME_PREFIX_SIZE + 16 + 4,
    "SAACPFrame fixed overhead = prefix(101) + auth_tag(16) + adler32(4) = 121");

// ── Status codes for schema-exempt stream frames ──────────────────────────────
/// STREAM_CONTINUATION (0x18) — binary stream chunk; exempt from JSON schema validation
pub const STATUS_STREAM_CONTINUATION: u8 = 0x18;
/// STREAM_END (0x19) — binary stream terminator; exempt from JSON schema validation
pub const STATUS_STREAM_END: u8          = 0x19;

/// Returns true iff this status code carries a non-JSON binary payload.
/// Authorization Invariance: exemption determined solely by the authenticated
/// status_code field — callers cannot opt out.
pub fn is_schema_exempt(status_code: u8) -> bool {
    status_code == STATUS_STREAM_CONTINUATION || status_code == STATUS_STREAM_END
}

// ═════════════════════════════════════════════════════════════════════════════
// SAACPFrame — 101-byte application-layer header
// ═════════════════════════════════════════════════════════════════════════════

/// The Rigid 101-Byte Binary Header for SAACP v4.0.
///
/// Wire format (all big-endian, matching Python ">4s H B B B I I 16s 24s 32s I Q"):
///
/// | Offset | Size | Type    | Field            |
/// |--------|------|---------|------------------|
/// |      0 |    4 | bytes   | Magic (b"SACP")  |
/// |      4 |    2 | uint16  | Schema ID        |
/// |      6 |    1 | uint8   | Status Code      |
/// |      7 |    1 | uint8   | Flags            |
/// |      8 |    1 | uint8   | Action Class     |
/// |      9 |    4 | uint32  | Payload Length   |
/// |     13 |    4 | uint32  | Sequence ID      |
/// |     17 |   16 | bytes   | Session UUID     |
/// |     33 |   24 | bytes   | W3C Traceparent  |
/// |     57 |   32 | bytes   | Context-State-ID |
/// |     89 |    4 | uint32  | Context Version  |
/// |     93 |    8 | uint64  | Nonce            |
/// |    101 |   -- | --      | End of prefix    |
///
/// Full wire packet after prefix:
///   [16 bytes] AES-256-GCM auth tag
///   [4 bytes]  Adler-32 checksum over (prefix + auth_tag + ciphertext)
///   [payload_length bytes] AES-256-GCM ciphertext
#[derive(Debug, Clone)]
pub struct SAACPFrame {
    pub schema_id: u16,
    pub status_code: u8,
    pub flags: u8,
    pub action_class: u8,
    pub payload_length: u32,
    pub sequence_id: u32,
    pub session_uuid: [u8; 16],
    pub traceparent: [u8; 24],
    pub context_state_id: [u8; 32],
    pub context_version: u32,
    pub nonce: u64,
}

impl SAACPFrame {
    pub const MAX_PAYLOAD_SIZE: usize = MAX_PAYLOAD_SIZE;

    /// Encode the 101-byte prefix (without auth tag, checksum, or ciphertext).
    pub fn encode_prefix(&self) -> [u8; SAACPFRAME_PREFIX_SIZE] {
        let mut buf = [0u8; SAACPFRAME_PREFIX_SIZE];
        // Offset 0: magic
        buf[0..4].copy_from_slice(MEASC_MAGIC);
        // Offset 4: schema_id (uint16 BE)
        buf[4..6].copy_from_slice(&self.schema_id.to_be_bytes());
        // Offset 6: status_code
        buf[6] = self.status_code;
        // Offset 7: flags
        buf[7] = self.flags;
        // Offset 8: action_class
        buf[8] = self.action_class;
        // Offset 9: payload_length (uint32 BE)
        buf[9..13].copy_from_slice(&self.payload_length.to_be_bytes());
        // Offset 13: sequence_id (uint32 BE)
        buf[13..17].copy_from_slice(&self.sequence_id.to_be_bytes());
        // Offset 17: session_uuid (16 bytes)
        buf[17..33].copy_from_slice(&self.session_uuid);
        // Offset 33: traceparent (24 bytes)
        buf[33..57].copy_from_slice(&self.traceparent);
        // Offset 57: context_state_id (32 bytes)
        buf[57..89].copy_from_slice(&self.context_state_id);
        // Offset 89: context_version (uint32 BE)
        buf[89..93].copy_from_slice(&self.context_version.to_be_bytes());
        // Offset 93: nonce (uint64 BE)
        buf[93..101].copy_from_slice(&self.nonce.to_be_bytes());
        buf
    }

    /// Decode only the 101-byte prefix (no decryption).
    pub fn decode_prefix(data: &[u8]) -> Result<Self, SAACPHardDrop> {
        if data.len() < SAACPFRAME_PREFIX_SIZE {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                format!(
                    "SAACPFrame prefix too short: need {} bytes, got {}",
                    SAACPFRAME_PREFIX_SIZE,
                    data.len()
                ),
            ));
        }
        if &data[0..4] != MEASC_MAGIC {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                "SAACPFrame: invalid magic bytes",
            ));
        }
        let schema_id       = u16::from_be_bytes([data[4], data[5]]);
        let status_code     = data[6];
        let flags           = data[7];
        let action_class    = data[8];
        let payload_length  = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
        let sequence_id     = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);
        let mut session_uuid = [0u8; 16];
        session_uuid.copy_from_slice(&data[17..33]);
        let mut traceparent = [0u8; 24];
        traceparent.copy_from_slice(&data[33..57]);
        let mut context_state_id = [0u8; 32];
        context_state_id.copy_from_slice(&data[57..89]);
        let context_version = u32::from_be_bytes([data[89], data[90], data[91], data[92]]);
        let nonce = u64::from_be_bytes([
            data[93], data[94], data[95], data[96],
            data[97], data[98], data[99], data[100],
        ]);
        Ok(Self {
            schema_id, status_code, flags, action_class, payload_length,
            sequence_id, session_uuid, traceparent, context_state_id,
            context_version, nonce,
        })
    }

    /// Derive 96-bit AES-GCM IV: SHA-256(nonce_be8 || session_uuid)[:12]
    /// Matches Python: hashlib.sha256(nonce.to_bytes(8,"big") + session_uuid).digest()[:12]
    pub fn derive_iv(nonce: u64, session_uuid: &[u8; 16]) -> [u8; 12] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(nonce.to_be_bytes());
        hasher.update(session_uuid);
        let digest = hasher.finalize();
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&digest[..12]);
        iv
    }

    /// AES-256-GCM encrypt with AAD. Returns (ciphertext_without_tag, auth_tag).
    fn aes_gcm_encrypt(
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), SAACPHardDrop> {
        use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit, Payload}};
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce_obj = Nonce::from_slice(iv);
        let payload_obj = Payload { msg: plaintext, aad };
        let encrypted = cipher.encrypt(nonce_obj, payload_obj).map_err(|e| {
            SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                format!("AES-256-GCM encryption failed: {}", e),
            )
        })?;
        // aes_gcm appends the 16-byte tag at the end
        let (ciphertext, tag_slice) = encrypted.split_at(encrypted.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_slice);
        Ok((ciphertext.to_vec(), tag))
    }

    /// AES-256-GCM decrypt + authenticate. Returns decrypted plaintext.
    fn aes_gcm_decrypt(
        key: &[u8; 32],
        iv: &[u8; 12],
        auth_tag: &[u8; 16],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SAACPHardDrop> {
        use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit, Payload}};
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce_obj = Nonce::from_slice(iv);
        // Reconstruct ciphertext+tag blob that aes_gcm expects
        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + 16);
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(auth_tag);
        let payload_obj = Payload { msg: &ct_with_tag, aad };
        cipher.decrypt(nonce_obj, payload_obj).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "AES-GCM Authentication Failed. Tampering Detected.",
            )
        })
    }

    /// Build a complete SAACPFrame wire packet.
    ///
    /// Output: [101-byte prefix] [16-byte auth_tag] [4-byte adler32] [ciphertext]
    ///
    /// The payload is AES-256-GCM encrypted with the 101-byte prefix as AAD.
    /// The IV is derived as SHA-256(nonce_be8 || session_uuid)[:12].
    #[allow(clippy::too_many_arguments)]
    pub fn build_frame(
        schema_id: u16,
        status_code: u8,
        flags: u8,
        action_class: u8,
        payload: &[u8],
        sequence_id: u32,
        session_uuid: [u8; 16],
        traceparent: [u8; 24],
        context_state_id: [u8; 32],
        secret_key: &[u8; 32],
        context_version: u32,
    ) -> Result<Vec<u8>, SAACPHardDrop> {
        if payload.len() > Self::MAX_PAYLOAD_SIZE {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::PayloadTooLarge,
                "SAACPFrame: payload exceeds 10MB MTU limit",
            ));
        }

        // COMPRESS-IMPL: compress payload BEFORE encryption when FLAG_COMPRESSED is set.
        // The compressed form is what AES-GCM authenticates and the wire carries.
        let payload_to_encrypt: std::borrow::Cow<[u8]> = if flags & FLAG_COMPRESSED != 0 {
            let compressed = compress_zlib(payload)?;
            std::borrow::Cow::Owned(compressed)
        } else {
            std::borrow::Cow::Borrowed(payload)
        };

        // Cryptographically secure random 64-bit nonce
        let nonce_val: u64 = {
            use rand::RngCore;
            rand::thread_rng().next_u64()
        };

        let frame = Self {
            schema_id, status_code, flags, action_class,
            // payload_to_encrypt.len() <= MAX_PAYLOAD_SIZE (10 MB) — fits in u32.
            payload_length: payload_to_encrypt.len() as u32,
            sequence_id, session_uuid, traceparent, context_state_id,
            context_version, nonce: nonce_val,
        };
        let prefix_bytes = frame.encode_prefix();

        // Derive IV from nonce + session_uuid
        let iv = Self::derive_iv(nonce_val, &session_uuid);

        // Encrypt: AAD = prefix_bytes
        let (ciphertext, auth_tag) = Self::aes_gcm_encrypt(secret_key, &iv, &prefix_bytes, &payload_to_encrypt)?;

        // Adler-32 over (prefix || auth_tag || ciphertext)
        let checksum = {
            let mut buf = Vec::with_capacity(SAACPFRAME_PREFIX_SIZE + 16 + ciphertext.len());
            buf.extend_from_slice(&prefix_bytes);
            buf.extend_from_slice(&auth_tag);
            buf.extend_from_slice(&ciphertext);
            adler32_checksum(&buf)
        };

        // Assemble wire packet
        let mut wire = Vec::with_capacity(SAACPFRAME_FIXED_OVERHEAD + ciphertext.len());
        wire.extend_from_slice(&prefix_bytes);
        wire.extend_from_slice(&auth_tag);
        wire.extend_from_slice(&checksum.to_be_bytes());
        wire.extend_from_slice(&ciphertext);
        Ok(wire)
    }

    /// Parse a complete SAACPFrame wire packet.
    ///
    /// Security gate ordering (MUST NOT be reordered):
    ///   1. Minimum length check
    ///   2. Magic bytes validation
    ///   3. Payload length limit (RGC Gate 1 pre-decryption)
    ///   4. Nonce tracking — C-2 fix: BEFORE decryption
    ///   5. Adler-32 fast corruption filter
    ///   6. AES-256-GCM decryption + authentication tag verification
    ///   7. Schema validation (skipped for STREAM_CONTINUATION/END binary frames)
    pub fn parse_header(
        buffer: &[u8],
        secret_key: &[u8; 32],
        nonce_tracker: &crate::security::NonceTracker,
        rgc_policy: &crate::rgc::RGCPolicy,
    ) -> Result<ParsedSAACPFrame, SAACPHardDrop> {
        // 1. Minimum buffer length: 101 prefix + 16 tag + 4 checksum = 121
        if buffer.len() < SAACPFRAME_FIXED_OVERHEAD {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                format!(
                    "SAACPFrame buffer too short: need at least {} bytes, got {}",
                    SAACPFRAME_FIXED_OVERHEAD, buffer.len()
                ),
            ));
        }

        let prefix_bytes    = &buffer[0..SAACPFRAME_PREFIX_SIZE];
        let auth_tag_slice  = &buffer[SAACPFRAME_PREFIX_SIZE..SAACPFRAME_PREFIX_SIZE + 16];
        let checksum_slice  = &buffer[SAACPFRAME_PREFIX_SIZE + 16..SAACPFRAME_PREFIX_SIZE + 20];

        // 2. Decode + magic check
        let frame = Self::decode_prefix(prefix_bytes)?;

        // 3. Payload length limits (pre-decryption RGC Gate 1)
        if frame.payload_length as usize > Self::MAX_PAYLOAD_SIZE {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::PayloadTooLarge,
                format!(
                    "SAACPFrame: payload_length {} exceeds 10MB MTU",
                    frame.payload_length
                ),
            ));
        }
        if frame.payload_length as usize > rgc_policy.max_total_size {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::RgcResourceLimitExceeded,
                format!(
                    "RGC Gate 1: payload_length {} exceeds governance limit {}",
                    frame.payload_length, rgc_policy.max_total_size
                ),
            ));
        }

        // 4. C-2 FIX: Nonce tracking BEFORE decryption.
        // The nonce is in the plaintext header. Checking after decrypt allows
        // an attacker to force the same AES-GCM IV twice before the check fires.
        nonce_tracker.track(frame.nonce)?;

        // Locate ciphertext
        let ciphertext_end = SAACPFRAME_PREFIX_SIZE + 20 + frame.payload_length as usize;
        if buffer.len() < ciphertext_end {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                "SAACPFrame: buffer shorter than declared payload_length",
            ));
        }
        let ciphertext = &buffer[SAACPFRAME_PREFIX_SIZE + 20..ciphertext_end];

        // 5. Adler-32 fast corruption filter (NOT cryptographic — AES-GCM handles that)
        let expected_checksum = {
            let mut buf = Vec::with_capacity(SAACPFRAME_PREFIX_SIZE + 16 + ciphertext.len());
            buf.extend_from_slice(prefix_bytes);
            buf.extend_from_slice(auth_tag_slice);
            buf.extend_from_slice(ciphertext);
            adler32_checksum(&buf)
        };
        let actual_checksum = u32::from_be_bytes([
            checksum_slice[0], checksum_slice[1], checksum_slice[2], checksum_slice[3],
        ]);
        // Constant-time comparison
        if !constant_time_eq_u32(expected_checksum, actual_checksum) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                "SAACPFrame: Adler32 checksum mismatch — packet corrupted in transit",
            ));
        }

        // 6. AES-256-GCM decryption + authentication
        let iv = Self::derive_iv(frame.nonce, &frame.session_uuid);
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(auth_tag_slice);
        let decrypted_payload = Self::aes_gcm_decrypt(
            secret_key, &iv, &auth_tag, prefix_bytes, ciphertext,
        )?;

        // 6.5. Decompression (COMPRESS-IMPL): if FLAG_COMPRESSED is set, decompress
        //      the plaintext AFTER AES-GCM authentication but BEFORE schema validation.
        //      Security: decompression is bounded by MAX_DECOMPRESSED_SIZE to prevent
        //      zip-bomb attacks. The compressed form was authenticated by AES-GCM, so
        //      we only decompress legitimate frames.
        let decrypted_payload = if frame.flags & FLAG_COMPRESSED != 0 {
            decompress_zlib(&decrypted_payload)?
        } else {
            decrypted_payload
        };

        // 7. Schema validation (skipped for binary stream continuation/end frames)
        if !is_schema_exempt(frame.status_code) {
            crate::rgc::ResourceGovernanceParser::check(&decrypted_payload, Some(rgc_policy))?;
            // Parse JSON for schema validation
            let json_val: serde_json::Value = serde_json::from_slice(&decrypted_payload)
                .map_err(|e| SAACPHardDrop::new(
                    SAACPBytecodes::MalformedHeader,
                    format!("SAACPFrame: payload is not valid JSON: {}", e),
                ))?;
            crate::schemas::PreCompiledSchemas::validate_payload(frame.schema_id, &json_val)?;
        }

        Ok(ParsedSAACPFrame {
            schema_id:        frame.schema_id,
            status_code:      frame.status_code,
            flags:            frame.flags,
            action_class:     frame.action_class,
            sequence_id:      frame.sequence_id,
            session_uuid:     frame.session_uuid,
            traceparent:      frame.traceparent,
            context_state_id: frame.context_state_id,
            context_version:  frame.context_version,
            nonce:            frame.nonce,
            payload:          decrypted_payload,
        })
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ParsedSAACPFrame — result of a successful SAACPFrame::parse_header()
// ═════════════════════════════════════════════════════════════════════════════

/// Fully-parsed and decrypted application-layer packet.
#[derive(Debug, Clone)]
pub struct ParsedSAACPFrame {
    pub schema_id:        u16,
    pub status_code:      u8,
    pub flags:            u8,
    pub action_class:     u8,
    pub sequence_id:      u32,
    pub session_uuid:     [u8; 16],
    pub traceparent:      [u8; 24],
    pub context_state_id: [u8; 32],
    pub context_version:  u32,
    pub nonce:            u64,
    /// Decrypted plaintext payload bytes.
    pub payload:          Vec<u8>,
}

impl ParsedSAACPFrame {
    /// True if this packet is cover traffic (M-8: authenticate only, discard silently).
    pub fn is_cover_traffic(&self) -> bool {
        self.flags & FLAG_COVER_TRAFFIC != 0
    }

    /// True if this packet is a binary stream (C-2 fix: Gate 4.0 injection scan exemption).
    pub fn is_binary_stream(&self) -> bool {
        self.flags & FLAG_BINARY_STREAM != 0
    }

    /// True iff this frame is exempt from JSON schema validation (stream binary frames).
    pub fn is_schema_exempt(&self) -> bool {
        is_schema_exempt(self.status_code)
    }

    /// Session UUID as a 32-char lowercase hex string.
    pub fn session_uuid_hex(&self) -> String {
        hex::encode(self.session_uuid)
    }

    /// Context-State-ID as a 64-char lowercase hex string.
    pub fn context_state_id_hex(&self) -> String {
        hex::encode(self.context_state_id)
    }

    /// W3C traceparent as a hex string.
    pub fn traceparent_hex(&self) -> String {
        hex::encode(self.traceparent)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// MEASCFrame — 128-byte transport-layer header
// ═════════════════════════════════════════════════════════════════════════════

/// MEASC 128-byte transport-layer frame header.
///
/// Wire layout (big-endian):
/// | Offset | Size | Field           |
/// |--------|------|-----------------|
/// |      0 |    4 | magic (b"SACP") |
/// |      4 |    2 | schema_id       |
/// |      6 |    1 | status_code     |
/// |      7 |    1 | flags           |
/// |      8 |    1 | action_class    |
/// |      9 |    3 | padding1        |
/// |     12 |    4 | payload_length  |
/// |     16 |   16 | session_id      |
/// |     32 |    4 | epoch_id        |
/// |     36 |    8 | psn             |
/// |     44 |   32 | context_ref_id  | ← MEASC_CONTEXT_REF_ID_OFFSET
/// |     76 |    4 | context_version |
/// |     80 |   24 | w3c_traceparent |
/// |    104 |    4 | reserved        |
/// |    108 |   20 | padding2        |
/// |    128 |   -- | end             |
#[derive(Debug, Clone)]
pub struct MEASCFrame {
    pub schema_id: u16,
    pub status_code: u8,
    pub flags: u8,
    pub action_class: u8,
    pub payload_length: u32,
    pub session_id: [u8; 16],
    pub epoch_id: u32,
    pub psn: u64,
    pub context_ref_id: [u8; 32],
    pub context_version: u32,
    pub w3c_traceparent: [u8; 24],
}

impl MEASCFrame {
    /// Default constructor with all fields zeroed.
    pub fn new() -> Self {
        Self {
            schema_id: 0,
            status_code: 0,
            flags: 0,
            action_class: 0,
            payload_length: 0,
            session_id: [0u8; 16],
            epoch_id: 0,
            psn: 0,
            context_ref_id: [0u8; 32],
            context_version: 0,
            w3c_traceparent: [0u8; 24],
        }
    }
}

impl Default for MEASCFrame {
    fn default() -> Self {
        Self::new()
    }
}

impl MEASCFrame {

    /// Serialize to exactly 128 bytes (big-endian).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; MEASC_HEADER_SIZE];
        // Offset 0: magic (4 bytes)
        buf[0..4].copy_from_slice(MEASC_MAGIC);
        // Offset 4: schema_id (2 bytes BE)
        buf[4..6].copy_from_slice(&self.schema_id.to_be_bytes());
        // Offset 6: status_code
        buf[6] = self.status_code;
        // Offset 7: flags
        buf[7] = self.flags;
        // Offset 8: action_class
        buf[8] = self.action_class;
        // Offset 9-11: padding1 (3 bytes) — already zero
        // Offset 12: payload_length (4 bytes BE)
        buf[12..16].copy_from_slice(&self.payload_length.to_be_bytes());
        // Offset 16: session_id (16 bytes)
        buf[16..32].copy_from_slice(&self.session_id);
        // Offset 32: epoch_id (4 bytes BE)
        buf[32..36].copy_from_slice(&self.epoch_id.to_be_bytes());
        // Offset 36: psn (8 bytes BE)
        buf[36..44].copy_from_slice(&self.psn.to_be_bytes());
        // Offset 44: context_ref_id (32 bytes) — MEASC_CONTEXT_REF_ID_OFFSET=44
        buf[44..76].copy_from_slice(&self.context_ref_id);
        // Offset 76: context_version (4 bytes BE)
        buf[76..80].copy_from_slice(&self.context_version.to_be_bytes());
        // Offset 80: w3c_traceparent (24 bytes)
        buf[80..104].copy_from_slice(&self.w3c_traceparent);
        // Offset 104-127: reserved/padding2 — already zero
        buf
    }

    /// Deserialize from 128 bytes.
    pub fn decode(data: &[u8]) -> Result<Self, SAACPHardDrop> {
        if data.len() < MEASC_HEADER_SIZE {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                format!(
                    "MEASCFrame too short: expected {} bytes, got {}",
                    MEASC_HEADER_SIZE, data.len()
                ),
            ));
        }
        if &data[0..4] != MEASC_MAGIC {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                format!(
                    "MEASCFrame: invalid magic bytes: expected {:?}, got {:?}",
                    MEASC_MAGIC, &data[0..4]
                ),
            ));
        }
        let schema_id      = u16::from_be_bytes([data[4], data[5]]);
        let status_code    = data[6];
        let flags          = data[7];
        let action_class   = data[8];
        // Skip padding1 at offset 9..12
        let payload_length = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[16..32]);
        let epoch_id = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let psn = u64::from_be_bytes([
            data[36], data[37], data[38], data[39],
            data[40], data[41], data[42], data[43],
        ]);
        let mut context_ref_id = [0u8; 32];
        context_ref_id.copy_from_slice(&data[44..76]);
        let context_version = u32::from_be_bytes([data[76], data[77], data[78], data[79]]);
        let mut w3c_traceparent = [0u8; 24];
        w3c_traceparent.copy_from_slice(&data[80..104]);
        Ok(Self {
            schema_id, status_code, flags, action_class, payload_length,
            session_id, epoch_id, psn, context_ref_id, context_version, w3c_traceparent,
        })
    }

    /// Parse a raw packet: decode transport header, extract payload (after MEASC header).
    /// Note: For full security, AES-GCM decryption is handled by the SAACPFrame layer.
    pub fn parse_header(packet: &[u8], _secret_key: &[u8]) -> Result<ParsedFrame, SAACPHardDrop> {
        let frame = Self::decode(packet)?;
        // SECURITY FIX (BUFFER-SAFETY): `payload_length` is an attacker-controlled
        // u32 read directly from the wire header, and this function (unlike its
        // siblings `SAACPFrame::parse_header` and `measc::MEASCFrame::parse_frame`,
        // which both cap it against MAX_PAYLOAD_SIZE before using it as an offset)
        // previously used it unchecked. On a 64-bit target that's "only" an
        // unbounded-allocation/DoS risk once `packet.len() >= payload_end`; on a
        // 32-bit target (this crate explicitly targets OpenWrt/Raspberry-Pi-class
        // deployments — see CLAUDE.md) `MEASC_HEADER_SIZE + payload_length` can
        // overflow `usize`, wrap to a value smaller than `payload_start`, pass the
        // `packet.len() < payload_end` check below, and then panic on
        // `packet[payload_start..payload_end]` ("slice index starts at higher than
        // ends"). Reject oversized claims up front, exactly like every other
        // wire-parsing entry point in this crate does.
        if frame.payload_length as usize > MAX_PAYLOAD_SIZE {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::PayloadTooLarge,
                format!(
                    "MEASCFrame: payload_length {} exceeds {} byte MTU",
                    frame.payload_length, MAX_PAYLOAD_SIZE
                ),
            ));
        }
        let payload_start = MEASC_HEADER_SIZE;
        let payload_end   = payload_start + frame.payload_length as usize;
        if packet.len() < payload_end {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                format!(
                    "MEASCFrame: packet too short for payload: need {} bytes, got {}",
                    payload_end, packet.len()
                ),
            ));
        }
        let payload          = packet[payload_start..payload_end].to_vec();
        let session_uuid     = hex::encode(frame.session_id);
        let context_state_id = hex::encode(frame.context_ref_id);
        let traceparent      = frame.w3c_traceparent.to_vec();
        Ok(ParsedFrame {
            schema_id:        frame.schema_id,
            status_code:      frame.status_code,
            flags:            frame.flags,
            action_class:     frame.action_class,
            session_uuid,
            sequence_id:      frame.psn,
            context_state_id,
            context_version:  frame.context_version as u64,
            traceparent,
            payload,
        })
    }
}

/// Parsed transport-layer packet.
#[derive(Debug, Clone)]
pub struct ParsedFrame {
    pub schema_id:        u16,
    pub status_code:      u8,
    pub flags:            u8,
    pub action_class:     u8,
    pub session_uuid:     String,
    pub sequence_id:      u64,
    pub context_state_id: String,
    pub context_version:  u64,
    pub traceparent:      Vec<u8>,
    pub payload:          Vec<u8>,
}

// ── Pre-decryption payload size gate ─────────────────────────────────────────

/// RGC Gate 1 pre-decryption payload size check.
pub fn check_payload_size(size: usize) -> Result<(), SAACPHardDrop> {
    if size > MAX_PAYLOAD_SIZE {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::PayloadTooLarge,
            format!("Payload size {} exceeds maximum {}", size, MAX_PAYLOAD_SIZE),
        ));
    }
    Ok(())
}

// ── Compression helpers (COMPRESS-IMPL) ──────────────────────────────────────

/// zlib-compress a byte slice (deflate level 6 — balanced speed/ratio).
///
/// Used by build_frame when FLAG_COMPRESSED is set.
pub fn compress_zlib(data: &[u8]) -> Result<Vec<u8>, SAACPHardDrop> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(6));
    enc.write_all(data).map_err(|e| SAACPHardDrop::new(
        SAACPBytecodes::MalformedHeader,
        format!("Compression failed: {e}"),
    ))?;
    enc.finish().map_err(|e| SAACPHardDrop::new(
        SAACPBytecodes::MalformedHeader,
        format!("Compression finish failed: {e}"),
    ))
}

/// zlib-decompress a byte slice.
///
/// Bounded by MAX_DECOMPRESSED_SIZE (10 MB) to prevent zip-bomb attacks.
/// Called by parse_header when FLAG_COMPRESSED is set in the authenticated header.
pub fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>, SAACPHardDrop> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::with_capacity(data.len() * 3);

    // Read in chunks with a size cap to detect zip-bombs early.
    let mut buf = [0u8; 65536];
    loop {
        match dec.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > MAX_DECOMPRESSED_SIZE {
                    return Err(SAACPHardDrop::new(
                        SAACPBytecodes::PayloadTooLarge,
                        format!(
                            "Decompressed payload exceeds {} byte limit (zip-bomb protection)",
                            MAX_DECOMPRESSED_SIZE
                        ),
                    ));
                }
            }
            Err(e) => {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::MalformedHeader,
                    format!("Decompression failed: {e}"),
                ));
            }
        }
    }
    Ok(out)
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Adler-32 checksum matching Python's `zlib.adler32()`.
pub fn adler32_checksum(data: &[u8]) -> u32 {
    use adler2::Adler32;
    let mut a = Adler32::new();
    a.write_slice(data);
    a.checksum()
}

/// Constant-time comparison of two u32 values.
///
/// Converts to bytes and uses a byte-accumulation XOR loop so the comparison
/// time is independent of the values — a compiler cannot short-circuit this
/// into a branch the way it might `(a ^ b) == 0`.
#[inline]
fn constant_time_eq_u32(a: u32, b: u32) -> bool {
    let ab = a.to_ne_bytes();
    let bb = b.to_ne_bytes();
    let mut diff = 0u8;
    for i in 0..4 {
        diff |= ab[i] ^ bb[i];
    }
    // Widen to u32 to avoid the compiler reducing `diff == 0` to a branch.
    // Subtracting 1 from 0 wraps to 0xFF…, setting the high bit.
    // Any non-zero diff produces a high bit via the OR with negation.
    let d = diff as u32;
    ((d | d.wrapping_neg()) >> 31) == 0
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::NonceTracker;
    use crate::rgc::RGCPolicy;

    fn test_key() -> [u8; 32] { [0xABu8; 32] }

    #[test]
    fn test_prefix_size_is_101() {
        let frame = SAACPFrame {
            schema_id: 1, status_code: 0, flags: FLAG_HAS_TOKEN,
            action_class: 0, payload_length: 42, sequence_id: 1,
            session_uuid: [0u8; 16], traceparent: [0u8; 24],
            context_state_id: [0u8; 32], context_version: 1,
            nonce: 0x123456789ABCDEF0,
        };
        let prefix = frame.encode_prefix();
        assert_eq!(prefix.len(), 101, "SAACPFrame prefix MUST be exactly 101 bytes");
        assert_eq!(SAACPFRAME_PREFIX_SIZE, 101);
    }

    #[test]
    fn test_prefix_magic() {
        let frame = SAACPFrame {
            schema_id: 1, status_code: 0, flags: 0, action_class: 0,
            payload_length: 0, sequence_id: 0, session_uuid: [0u8; 16],
            traceparent: [0u8; 24], context_state_id: [0u8; 32],
            context_version: 0, nonce: 0,
        };
        assert_eq!(&frame.encode_prefix()[0..4], b"SACP");
    }

    #[test]
    fn test_prefix_field_offsets() {
        let session_uuid     = [0x11u8; 16];
        let traceparent      = [0x22u8; 24];
        let context_state_id = [0x33u8; 32];
        let frame = SAACPFrame {
            schema_id: 0xABCD, status_code: 0x05,
            flags: FLAG_HAS_TOKEN | FLAG_ENCRYPTED,
            action_class: ACTION_CLASS_REVERSIBLE,
            payload_length: 0x00001234, sequence_id: 0x00000099,
            session_uuid, traceparent, context_state_id,
            context_version: 0x00000007, nonce: 0x0102030405060708,
        };
        let p = frame.encode_prefix();
        // Offsets per Python PREFIX_FORMAT = ">4s H B B B I I 16s 24s 32s I Q"
        assert_eq!(&p[0..4], b"SACP",                            "offset 0: magic");
        assert_eq!(u16::from_be_bytes([p[4],p[5]]),    0xABCD,   "offset 4: schema_id");
        assert_eq!(p[6],                               0x05,      "offset 6: status_code");
        assert_eq!(p[7],  FLAG_HAS_TOKEN|FLAG_ENCRYPTED,          "offset 7: flags");
        assert_eq!(p[8],  ACTION_CLASS_REVERSIBLE,                "offset 8: action_class");
        assert_eq!(u32::from_be_bytes([p[9],p[10],p[11],p[12]]),  0x00001234, "offset 9: payload_length");
        assert_eq!(u32::from_be_bytes([p[13],p[14],p[15],p[16]]), 0x00000099, "offset 13: sequence_id");
        assert_eq!(&p[17..33], &session_uuid,                     "offset 17: session_uuid");
        assert_eq!(&p[33..57], &traceparent,                      "offset 33: traceparent");
        assert_eq!(&p[57..89], &context_state_id,                 "offset 57: context_state_id");
        assert_eq!(u32::from_be_bytes([p[89],p[90],p[91],p[92]]), 0x00000007, "offset 89: context_version");
        assert_eq!(u64::from_be_bytes([p[93],p[94],p[95],p[96],p[97],p[98],p[99],p[100]]),
                   0x0102030405060708, "offset 93: nonce");
    }

    #[test]
    fn test_build_and_parse_roundtrip() {
        let key          = test_key();
        let nonce_t      = NonceTracker::new();
        let rgc          = RGCPolicy::default();
        // Use schema_id=0 (Raw Binary) — no JSON schema field validation.
        // Framing tests exercise crypto/wire correctness, not schema policy.
        let payload      = b"{\"task\": \"hello world\"}";
        let session_uuid = [0x01u8; 16];
        let traceparent  = [0x02u8; 24];
        let ctx_id       = [0x03u8; 32];

        let wire = SAACPFrame::build_frame(
            0, 0x00, FLAG_HAS_TOKEN | FLAG_ENCRYPTED,
            ACTION_CLASS_READ_ONLY, payload, 1,
            session_uuid, traceparent, ctx_id, &key, 1,
        ).expect("build_frame should succeed");

        assert!(wire.len() >= SAACPFRAME_FIXED_OVERHEAD + payload.len());

        let parsed = SAACPFrame::parse_header(&wire, &key, &nonce_t, &rgc)
            .expect("parse_header should succeed");

        assert_eq!(parsed.schema_id, 0);
        assert_eq!(parsed.action_class, ACTION_CLASS_READ_ONLY);
        assert_eq!(parsed.session_uuid, session_uuid);
        assert_eq!(parsed.context_state_id, ctx_id);
        assert_eq!(parsed.payload, payload.as_ref());
    }

    #[test]
    fn test_nonce_replay_rejected() {
        let key     = test_key();
        let nonce_t = NonceTracker::new();
        let rgc     = RGCPolicy::default();

        // schema_id=0: Raw Binary, no JSON schema validation
        let wire = SAACPFrame::build_frame(
            0, 0x00, FLAG_ENCRYPTED, ACTION_CLASS_READ_ONLY,
            b"{\"task\":\"x\"}", 1, [0x10u8; 16], [0u8; 24], [0u8; 32], &key, 1,
        ).unwrap();

        // First parse: OK
        SAACPFrame::parse_header(&wire, &key, &nonce_t, &rgc).unwrap();
        // Second parse: replay must be rejected (C-2 fix: nonce tracked BEFORE decryption)
        let result = SAACPFrame::parse_header(&wire, &key, &nonce_t, &rgc);
        assert!(result.is_err(), "C-2 fix: second nonce use must be rejected");
    }

    #[test]
    fn test_tamper_rejected() {
        let key     = test_key();
        let nonce_t = NonceTracker::new();
        let rgc     = RGCPolicy::default();

        // schema_id=0: bypass JSON schema validation to focus on AES-GCM tamper detection
        let mut wire = SAACPFrame::build_frame(
            0, 0x00, FLAG_ENCRYPTED, ACTION_CLASS_READ_ONLY,
            b"{\"task\":\"tamper\"}", 1, [0x20u8; 16], [0u8; 24], [0u8; 32], &key, 1,
        ).unwrap();

        // Flip a ciphertext byte (after prefix+tag+checksum)
        let off = SAACPFRAME_FIXED_OVERHEAD + 3;
        if wire.len() > off { wire[off] ^= 0xFF; }

        let result = SAACPFrame::parse_header(&wire, &key, &nonce_t, &rgc);
        assert!(result.is_err(), "Tampered ciphertext must fail AES-GCM auth");
    }

    #[test]
    fn test_measc_parse_header_rejects_oversized_payload_length_claim() {
        // BUFFER-SAFETY regression: a header claiming a payload_length far
        // beyond MAX_PAYLOAD_SIZE must be rejected before it's ever used to
        // compute a slice offset, not just "happen to fail later" once a
        // length check on the (much shorter) real buffer kicks in.
        let mut f = MEASCFrame::new();
        f.payload_length = u32::MAX; // would overflow usize on a 32-bit target
        let enc = f.encode();
        let err = MEASCFrame::parse_header(&enc, &[0u8; 32]).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::PayloadTooLarge);
    }

    #[test]
    fn test_measc_parse_header_rejects_truncated_buffer_within_mtu() {
        // A payload_length within MAX_PAYLOAD_SIZE but larger than what the
        // actual buffer carries must still be rejected cleanly (not panic).
        let mut f = MEASCFrame::new();
        f.payload_length = 1000;
        let enc = f.encode(); // header only, no payload bytes appended
        let err = MEASCFrame::parse_header(&enc, &[0u8; 32]).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::MalformedHeader);
    }

    #[test]
    fn test_measc_encode_decode() {
        let mut f = MEASCFrame::new();
        f.schema_id     = 42;
        f.epoch_id      = 7;
        f.psn           = 12345678;
        f.context_ref_id = [0xAAu8; 32];

        let enc = f.encode();
        assert_eq!(enc.len(), MEASC_HEADER_SIZE);
        assert_eq!(&enc[0..4], b"SACP");
        // Context Ref ID is at offset 44 (MEASC_CONTEXT_REF_ID_OFFSET)
        assert_eq!(&enc[44..76], &[0xAAu8; 32]);

        let dec = MEASCFrame::decode(&enc).unwrap();
        assert_eq!(dec.schema_id, 42);
        assert_eq!(dec.epoch_id, 7);
        assert_eq!(dec.psn, 12345678);
        assert_eq!(dec.context_ref_id, [0xAAu8; 32]);
    }

    #[test]
    fn test_schema_exempt_codes() {
        assert!(is_schema_exempt(0x18), "STREAM_CONTINUATION=0x18 must be exempt");
        assert!(is_schema_exempt(0x19), "STREAM_END=0x19 must be exempt");
        assert!(!is_schema_exempt(0x00), "Normal success frames must not be exempt");
        assert!(!is_schema_exempt(0x17), "STREAM_START must not be exempt — it carries JSON");
    }

    #[test]
    fn test_flag_binary_stream_gate4_exemption() {
        let p = ParsedSAACPFrame {
            schema_id: 1, status_code: STATUS_STREAM_CONTINUATION,
            flags: FLAG_STREAMING | FLAG_BINARY_STREAM,
            action_class: 0, sequence_id: 0,
            session_uuid: [0u8; 16], traceparent: [0u8; 24],
            context_state_id: [0u8; 32], context_version: 0,
            nonce: 0, payload: vec![],
        };
        assert!(p.is_binary_stream(), "FLAG_BINARY_STREAM must be detected");
        assert!(p.is_schema_exempt(), "STREAM_CONTINUATION must be schema-exempt");

        // LLM text stream: FLAG_STREAMING set, FLAG_BINARY_STREAM NOT set
        let text = ParsedSAACPFrame { flags: FLAG_STREAMING, ..p.clone() };
        assert!(!text.is_binary_stream(), "LLM text stream MUST NOT set FLAG_BINARY_STREAM");
    }

    #[test]
    fn test_adler32_empty() {
        assert_eq!(adler32_checksum(&[]), 1, "Adler-32 of empty input is 1");
    }

    #[test]
    fn test_iv_derivation_deterministic() {
        let nonce = 0xDEADBEEFCAFEBABEu64;
        let session_uuid = [0xFFu8; 16];
        let iv1 = SAACPFrame::derive_iv(nonce, &session_uuid);
        let iv2 = SAACPFrame::derive_iv(nonce, &session_uuid);
        assert_eq!(iv1, iv2, "IV derivation must be deterministic");
        assert_eq!(iv1.len(), 12, "IV must be 12 bytes (96 bits) for AES-GCM");
    }
}
