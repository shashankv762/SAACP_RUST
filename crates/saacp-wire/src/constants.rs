//! Wire format constants for SAACP.
//!
//! These are the source-of-truth values for all MEASC and SAACPFrame field
//! offsets, sizes, and magic bytes. They are identical to the constants in
//! `saacp::measc` and `saacp::framing`, but isolated here so no_std/Wasm
//! consumers do not need the full crypto stack.

/// Magic bytes at offset 0 of every SAACP frame (both MEASC header and SAACPFrame prefix).
pub const MEASC_MAGIC: &[u8; 4] = b"SACP";

// ── MEASC v1 header (128 bytes, Python-parity) ────────────────────────────────
pub const MEASC_V1_HEADER_SIZE: usize = 128;
pub const MEASC_FORMAT_VERSION_V1: u8 = 0x00;

// ── MEASC v2 header (160 bytes, packet chaining) ──────────────────────────────
pub const MEASC_V2_HEADER_SIZE: usize = 160;
pub const MEASC_FORMAT_VERSION_V2: u8 = 0x02;

/// Byte offset of the format-version discriminator within the MEASC header.
/// Was a reserved/zero byte in v1; set to MEASC_FORMAT_VERSION_V2 (0x02) in v2.
pub const MEASC_FORMAT_VERSION_BYTE_OFFSET: usize = 5;

// v2 extension fields
pub const MEASC_V2_PREV_HASH_OFFSET: usize = 128;
pub const MEASC_V2_PREV_HASH_SIZE: usize = 24;
pub const MEASC_V2_EPOCH_BEACON_OFFSET: usize = 152;
pub const MEASC_V2_EPOCH_BEACON_SIZE: usize = 8;
pub const MEASC_V2_CHAIN_GENESIS: [u8; MEASC_V2_PREV_HASH_SIZE] = [0u8; MEASC_V2_PREV_HASH_SIZE];

// ── MEASC header field offsets (v1 layout, shared with v2 bytes 0..128) ───────
pub const MEASC_SESSION_ID_OFFSET: usize = 16;
pub const MEASC_SESSION_ID_SIZE: usize = 16;
pub const MEASC_EPOCH_ID_OFFSET: usize = 0;    // first 4 bytes
pub const MEASC_PSN_OFFSET: usize = 8;
pub const MEASC_PSN_SIZE: usize = 8;
pub const MEASC_CONTEXT_REF_ID_OFFSET: usize = 44;
pub const MEASC_CONTEXT_REF_ID_SIZE: usize = 32;

// ── MEASC auth tag ────────────────────────────────────────────────────────────
pub const MEASC_AUTH_TAG_SIZE: usize = 16;

// ── SAACPFrame application header (101-byte prefix) ──────────────────────────
pub const SAACPFRAME_PREFIX_SIZE: usize = 101;

/// SAACPFrame field offsets (within the 101-byte prefix).
pub const SAACPFRAME_SCHEMA_ID_OFFSET: usize = 4;
pub const SAACPFRAME_STATUS_CODE_OFFSET: usize = 6;
pub const SAACPFRAME_FLAGS_OFFSET: usize = 7;
pub const SAACPFRAME_ACTION_CLASS_OFFSET: usize = 8;
pub const SAACPFRAME_PAYLOAD_LEN_OFFSET: usize = 9;
pub const SAACPFRAME_SEQUENCE_ID_OFFSET: usize = 13;
pub const SAACPFRAME_SESSION_UUID_OFFSET: usize = 17;
pub const SAACPFRAME_SESSION_UUID_SIZE: usize = 16;
pub const SAACPFRAME_TRACEPARENT_OFFSET: usize = 33;
pub const SAACPFRAME_TRACEPARENT_SIZE: usize = 24;
pub const SAACPFRAME_CONTEXT_STATE_ID_OFFSET: usize = 57;
pub const SAACPFRAME_CONTEXT_STATE_ID_SIZE: usize = 32;
pub const SAACPFRAME_CONTEXT_VERSION_OFFSET: usize = 89;
pub const SAACPFRAME_NONCE_OFFSET: usize = 93;
pub const SAACPFRAME_NONCE_SIZE: usize = 8;

// Full wire overhead = prefix(101) + auth_tag(16) + adler32(4) = 121 bytes.
pub const SAACPFRAME_FIXED_OVERHEAD: usize = SAACPFRAME_PREFIX_SIZE + MEASC_AUTH_TAG_SIZE + 4;

/// Maximum payload size (10 MB). Matches `saacp::daemon::MAX_PAYLOAD_SIZE`.
pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024;

// ── Action class constants ────────────────────────────────────────────────────
pub const ACTION_CLASS_READ_ONLY: u8 = 0x00;
pub const ACTION_CLASS_REVERSIBLE: u8 = 0x01;
pub const ACTION_CLASS_IRREVERSIBLE: u8 = 0x02;

// ── Status codes for schema-exempt stream frames ──────────────────────────────
pub const STATUS_STREAM_CONTINUATION: u8 = 0x18;
pub const STATUS_STREAM_END: u8 = 0x19;

/// Returns true iff this status code carries a non-JSON binary payload.
pub fn is_schema_exempt(status_code: u8) -> bool {
    status_code == STATUS_STREAM_CONTINUATION || status_code == STATUS_STREAM_END
}

// ── Compile-time layout invariants ───────────────────────────────────────────
const _: () = assert!(MEASC_V1_HEADER_SIZE == 128, "MEASC v1 header must be 128 bytes");
const _: () = assert!(MEASC_V2_HEADER_SIZE == 160, "MEASC v2 header must be 160 bytes");
const _: () = assert!(
    MEASC_V2_PREV_HASH_OFFSET + MEASC_V2_PREV_HASH_SIZE + MEASC_V2_EPOCH_BEACON_SIZE
        == MEASC_V2_HEADER_SIZE,
    "v2 header layout: 128 + 24 + 8 == 160"
);
const _: () = assert!(SAACPFRAME_PREFIX_SIZE == 101, "SAACPFrame prefix must be 101 bytes");
const _: () = assert!(
    SAACPFRAME_FIXED_OVERHEAD == 121,
    "SAACPFrame fixed overhead must be 121 bytes"
);
