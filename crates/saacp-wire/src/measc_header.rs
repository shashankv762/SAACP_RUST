//! MeascHeader — zero-copy parser for MEASC v1 and v2 headers.
//!
//! Parses the first 128 (v1) or 160 (v2) bytes of a SAACP packet.
//! No AEAD cryptography. No async. No std I/O.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String};

use sha3::{Digest, Sha3_256};

use crate::constants::*;
use crate::frame::WireError;

/// The MEASC wire format version detected from the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeascVersion {
    /// v1: 128-byte header (Python-parity wire format).
    V1,
    /// v2: 160-byte header (cryptographic packet chaining + epoch beacon).
    V2,
}

impl MeascVersion {
    /// Returns the expected header size in bytes.
    pub fn header_size(self) -> usize {
        match self {
            MeascVersion::V1 => MEASC_V1_HEADER_SIZE,
            MeascVersion::V2 => MEASC_V2_HEADER_SIZE,
        }
    }
}

/// Parsed MEASC header fields (common to both v1 and v2).
///
/// AEAD tag and payload are NOT parsed here — this crate has no crypto.
#[derive(Debug, Clone)]
pub struct MeascHeader {
    /// Detected wire format version.
    pub version: MeascVersion,
    /// Session ID (16 bytes at header offset 16).
    pub session_id: [u8; MEASC_SESSION_ID_SIZE],
    /// Packet Sequence Number (u64 big-endian at offset 8).
    pub psn: u64,
    /// Epoch ID (u32 big-endian at offset 0).
    pub epoch_id: u32,
    /// Context reference ID (32 bytes at offset 44).
    pub context_ref_id: [u8; MEASC_CONTEXT_REF_ID_SIZE],

    // v2-only fields (present only when version == V2)
    /// Previous packet hash (24 bytes at v2 offset 128). None for v1 packets.
    pub prev_packet_hash: Option<[u8; MEASC_V2_PREV_HASH_SIZE]>,
    /// Epoch beacon (u64 at v2 offset 152). None for v1 packets.
    pub epoch_beacon: Option<u64>,
}

impl MeascHeader {
    /// Parse a MEASC header from a byte slice.
    ///
    /// Detects v1 vs v2 from the format-version discriminator byte at offset 5.
    /// Validates magic bytes. Does NOT verify AEAD or replay window.
    ///
    /// Returns `(header, consumed_bytes)` where `consumed_bytes` is 128 (v1) or 160 (v2).
    pub fn parse(data: &[u8]) -> Result<(Self, usize), WireError> {
        if data.len() < 6 {
            return Err(WireError("MEASC header too short for version detection".into()));
        }
        if &data[0..4] != MEASC_MAGIC {
            return Err(WireError("MEASC: invalid magic bytes".into()));
        }

        let version_byte = data[MEASC_FORMAT_VERSION_BYTE_OFFSET];
        let version = match version_byte {
            MEASC_FORMAT_VERSION_V1 => MeascVersion::V1,
            MEASC_FORMAT_VERSION_V2 => MeascVersion::V2,
            other => return Err(WireError(format!(
                "MEASC: unknown format version 0x{:02x}", other
            ))),
        };

        let required = version.header_size();
        if data.len() < required {
            return Err(WireError(format!(
                "MEASC {} header too short: need {} bytes, got {}",
                if version == MeascVersion::V1 { "v1" } else { "v2" },
                required,
                data.len()
            )));
        }

        let epoch_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let psn = u64::from_be_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);
        let mut session_id = [0u8; MEASC_SESSION_ID_SIZE];
        session_id.copy_from_slice(&data[MEASC_SESSION_ID_OFFSET..MEASC_SESSION_ID_OFFSET + MEASC_SESSION_ID_SIZE]);
        let mut context_ref_id = [0u8; MEASC_CONTEXT_REF_ID_SIZE];
        context_ref_id.copy_from_slice(&data[MEASC_CONTEXT_REF_ID_OFFSET..MEASC_CONTEXT_REF_ID_OFFSET + MEASC_CONTEXT_REF_ID_SIZE]);

        let (prev_packet_hash, epoch_beacon) = if version == MeascVersion::V2 {
            let mut prev_hash = [0u8; MEASC_V2_PREV_HASH_SIZE];
            prev_hash.copy_from_slice(&data[MEASC_V2_PREV_HASH_OFFSET..MEASC_V2_PREV_HASH_OFFSET + MEASC_V2_PREV_HASH_SIZE]);
            let beacon = u64::from_be_bytes([
                data[MEASC_V2_EPOCH_BEACON_OFFSET],
                data[MEASC_V2_EPOCH_BEACON_OFFSET + 1],
                data[MEASC_V2_EPOCH_BEACON_OFFSET + 2],
                data[MEASC_V2_EPOCH_BEACON_OFFSET + 3],
                data[MEASC_V2_EPOCH_BEACON_OFFSET + 4],
                data[MEASC_V2_EPOCH_BEACON_OFFSET + 5],
                data[MEASC_V2_EPOCH_BEACON_OFFSET + 6],
                data[MEASC_V2_EPOCH_BEACON_OFFSET + 7],
            ]);
            (Some(prev_hash), Some(beacon))
        } else {
            (None, None)
        };

        Ok((
            MeascHeader { version, session_id, psn, epoch_id, context_ref_id, prev_packet_hash, epoch_beacon },
            required,
        ))
    }

    /// Compute the v2 prev_packet_hash for this header (SHA-3-256 truncated to 24 bytes).
    ///
    /// Call this ONLY after the full header + AEAD tag has been successfully verified.
    /// Pass the 128-byte v1-layout portion of the authenticated header.
    pub fn compute_chain_hash(authenticated_header_128: &[u8; 128]) -> [u8; MEASC_V2_PREV_HASH_SIZE] {
        let digest = Sha3_256::digest(authenticated_header_128);
        let mut out = [0u8; MEASC_V2_PREV_HASH_SIZE];
        out.copy_from_slice(&digest[..MEASC_V2_PREV_HASH_SIZE]);
        out
    }
}
