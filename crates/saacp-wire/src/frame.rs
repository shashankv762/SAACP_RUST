//! SaacpFrame — zero-copy parser and builder for the 101-byte SAACPFrame prefix.
//!
//! No cryptography. No async. No std I/O. Pure byte manipulation.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String};

use crate::constants::*;

/// Error type for wire-format parsing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub String);

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SAACP wire error: {}", self.0)
    }
}

/// Parsed SAACPFrame application-layer header (101-byte prefix).
///
/// All fields are decoded from big-endian wire format.
/// No encryption or decryption is performed here.
#[derive(Debug, Clone)]
pub struct SaacpFrame {
    pub schema_id: u16,
    pub status_code: u8,
    pub flags: u8,
    pub action_class: u8,
    pub payload_length: u32,
    pub sequence_id: u32,
    pub session_uuid: [u8; SAACPFRAME_SESSION_UUID_SIZE],
    pub traceparent: [u8; SAACPFRAME_TRACEPARENT_SIZE],
    pub context_state_id: [u8; SAACPFRAME_CONTEXT_STATE_ID_SIZE],
    pub context_version: u32,
    pub nonce: u64,
}

impl SaacpFrame {
    /// Decode the 101-byte prefix from a byte slice.
    ///
    /// Validates magic bytes and minimum length. No AEAD verification.
    /// Returns `Err(WireError)` if the slice is too short or magic is wrong.
    pub fn decode_prefix(data: &[u8]) -> Result<Self, WireError> {
        if data.len() < SAACPFRAME_PREFIX_SIZE {
            return Err(WireError(format!(
                "SAACPFrame prefix too short: need {} bytes, got {}",
                SAACPFRAME_PREFIX_SIZE,
                data.len()
            )));
        }
        if &data[0..4] != MEASC_MAGIC {
            return Err(WireError("SAACPFrame: invalid magic bytes".into()));
        }
        let schema_id = u16::from_be_bytes([data[SAACPFRAME_SCHEMA_ID_OFFSET], data[SAACPFRAME_SCHEMA_ID_OFFSET + 1]]);
        let status_code = data[SAACPFRAME_STATUS_CODE_OFFSET];
        let flags = data[SAACPFRAME_FLAGS_OFFSET];
        let action_class = data[SAACPFRAME_ACTION_CLASS_OFFSET];
        let payload_length = u32::from_be_bytes([
            data[SAACPFRAME_PAYLOAD_LEN_OFFSET],
            data[SAACPFRAME_PAYLOAD_LEN_OFFSET + 1],
            data[SAACPFRAME_PAYLOAD_LEN_OFFSET + 2],
            data[SAACPFRAME_PAYLOAD_LEN_OFFSET + 3],
        ]);
        let sequence_id = u32::from_be_bytes([
            data[SAACPFRAME_SEQUENCE_ID_OFFSET],
            data[SAACPFRAME_SEQUENCE_ID_OFFSET + 1],
            data[SAACPFRAME_SEQUENCE_ID_OFFSET + 2],
            data[SAACPFRAME_SEQUENCE_ID_OFFSET + 3],
        ]);
        let mut session_uuid = [0u8; SAACPFRAME_SESSION_UUID_SIZE];
        session_uuid.copy_from_slice(&data[SAACPFRAME_SESSION_UUID_OFFSET..SAACPFRAME_SESSION_UUID_OFFSET + SAACPFRAME_SESSION_UUID_SIZE]);
        let mut traceparent = [0u8; SAACPFRAME_TRACEPARENT_SIZE];
        traceparent.copy_from_slice(&data[SAACPFRAME_TRACEPARENT_OFFSET..SAACPFRAME_TRACEPARENT_OFFSET + SAACPFRAME_TRACEPARENT_SIZE]);
        let mut context_state_id = [0u8; SAACPFRAME_CONTEXT_STATE_ID_SIZE];
        context_state_id.copy_from_slice(&data[SAACPFRAME_CONTEXT_STATE_ID_OFFSET..SAACPFRAME_CONTEXT_STATE_ID_OFFSET + SAACPFRAME_CONTEXT_STATE_ID_SIZE]);
        let context_version = u32::from_be_bytes([
            data[SAACPFRAME_CONTEXT_VERSION_OFFSET],
            data[SAACPFRAME_CONTEXT_VERSION_OFFSET + 1],
            data[SAACPFRAME_CONTEXT_VERSION_OFFSET + 2],
            data[SAACPFRAME_CONTEXT_VERSION_OFFSET + 3],
        ]);
        let nonce = u64::from_be_bytes([
            data[SAACPFRAME_NONCE_OFFSET],
            data[SAACPFRAME_NONCE_OFFSET + 1],
            data[SAACPFRAME_NONCE_OFFSET + 2],
            data[SAACPFRAME_NONCE_OFFSET + 3],
            data[SAACPFRAME_NONCE_OFFSET + 4],
            data[SAACPFRAME_NONCE_OFFSET + 5],
            data[SAACPFRAME_NONCE_OFFSET + 6],
            data[SAACPFRAME_NONCE_OFFSET + 7],
        ]);
        Ok(Self {
            schema_id, status_code, flags, action_class, payload_length,
            sequence_id, session_uuid, traceparent, context_state_id,
            context_version, nonce,
        })
    }

    /// Encode the 101-byte prefix to a fixed-size array.
    pub fn encode_prefix(&self) -> [u8; SAACPFRAME_PREFIX_SIZE] {
        let mut buf = [0u8; SAACPFRAME_PREFIX_SIZE];
        buf[0..4].copy_from_slice(MEASC_MAGIC);
        buf[SAACPFRAME_SCHEMA_ID_OFFSET..SAACPFRAME_SCHEMA_ID_OFFSET + 2]
            .copy_from_slice(&self.schema_id.to_be_bytes());
        buf[SAACPFRAME_STATUS_CODE_OFFSET] = self.status_code;
        buf[SAACPFRAME_FLAGS_OFFSET] = self.flags;
        buf[SAACPFRAME_ACTION_CLASS_OFFSET] = self.action_class;
        buf[SAACPFRAME_PAYLOAD_LEN_OFFSET..SAACPFRAME_PAYLOAD_LEN_OFFSET + 4]
            .copy_from_slice(&self.payload_length.to_be_bytes());
        buf[SAACPFRAME_SEQUENCE_ID_OFFSET..SAACPFRAME_SEQUENCE_ID_OFFSET + 4]
            .copy_from_slice(&self.sequence_id.to_be_bytes());
        buf[SAACPFRAME_SESSION_UUID_OFFSET..SAACPFRAME_SESSION_UUID_OFFSET + SAACPFRAME_SESSION_UUID_SIZE]
            .copy_from_slice(&self.session_uuid);
        buf[SAACPFRAME_TRACEPARENT_OFFSET..SAACPFRAME_TRACEPARENT_OFFSET + SAACPFRAME_TRACEPARENT_SIZE]
            .copy_from_slice(&self.traceparent);
        buf[SAACPFRAME_CONTEXT_STATE_ID_OFFSET..SAACPFRAME_CONTEXT_STATE_ID_OFFSET + SAACPFRAME_CONTEXT_STATE_ID_SIZE]
            .copy_from_slice(&self.context_state_id);
        buf[SAACPFRAME_CONTEXT_VERSION_OFFSET..SAACPFRAME_CONTEXT_VERSION_OFFSET + 4]
            .copy_from_slice(&self.context_version.to_be_bytes());
        buf[SAACPFRAME_NONCE_OFFSET..SAACPFRAME_NONCE_OFFSET + SAACPFRAME_NONCE_SIZE]
            .copy_from_slice(&self.nonce.to_be_bytes());
        buf
    }
}
