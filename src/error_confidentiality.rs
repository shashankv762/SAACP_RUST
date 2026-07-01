// SAACP Rust Implementation — Error Confidentiality Filter
// Translated from SAACP/src/saacp/error_confidentiality.py
//!
//! Sanitizes internal error information before it leaves a trust boundary.
//! Callers learn only the minimum (category + optional retry hint) while an
//! opaque `correlation_id` lets operators cross-reference internal logs.
//!
//! # Wire Format (44 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0      | 1    | category (uint8) |
//! | 1      | 16   | correlation_id raw bytes |
//! | 17     | 4    | retry_after_seconds big-endian uint32 |
//! | 21     | 4    | protocol_version `b"SACP"` |
//! | 25     | 19   | zero-padding to 44 bytes |

use rand::RngCore;
use std::collections::HashMap;
use std::sync::LazyLock;



// ── Constants ──────────────────────────────────────────────────────────────

/// Total byte length of every serialised wire error response.
pub const WIRE_SIZE: usize = 44;
/// Sentinel uint32 value when no retry hint is available.
pub const SENTINEL_NO_RETRY: u32 = 0xFFFF_FFFF;
/// Fixed 4-byte protocol tag.
pub const PROTOCOL_VERSION_WIRE: &[u8; 4] = b"SACP";
/// Human-readable protocol version.
pub const DEFAULT_PROTOCOL_VERSION: &str = "SAACP-v5";

// ── ErrorCategory ──────────────────────────────────────────────────────────

/// High-level, caller-visible error category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ErrorCategory {
    TransportFailure = 0x01,
    AuthFailure = 0x02,
    PolicyViolation = 0x03,
    ResourceLimit = 0x04,
    ProtocolError = 0x05,
    CapabilityFailure = 0x06,
    GovernanceViolation = 0x07,
    Internal = 0x08,
}

impl ErrorCategory {
    /// Parse a category from a raw byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::TransportFailure),
            0x02 => Some(Self::AuthFailure),
            0x03 => Some(Self::PolicyViolation),
            0x04 => Some(Self::ResourceLimit),
            0x05 => Some(Self::ProtocolError),
            0x06 => Some(Self::CapabilityFailure),
            0x07 => Some(Self::GovernanceViolation),
            0x08 => Some(Self::Internal),
            _ => None,
        }
    }
}

// ── Bytecode → Category mapping ────────────────────────────────────────────

static BYTECODE_CATEGORY_MAP: LazyLock<HashMap<u8, ErrorCategory>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    use ErrorCategory::*;
    let entries: &[(u8, ErrorCategory)] = &[
        (0x00, Internal), (0x01, TransportFailure), (0x02, ProtocolError),
        (0x03, AuthFailure), (0x04, ProtocolError), (0x05, CapabilityFailure),
        (0x06, PolicyViolation), (0x07, ProtocolError), (0x08, Internal),
        (0x09, PolicyViolation), (0x0A, Internal), (0x0B, Internal),
        (0x0C, PolicyViolation), (0x0D, PolicyViolation), (0x0E, ResourceLimit),
        (0x0F, Internal), (0x10, ProtocolError), (0x11, TransportFailure),
        (0x12, CapabilityFailure), (0x13, CapabilityFailure), (0x14, PolicyViolation),
        (0x15, CapabilityFailure), (0x16, PolicyViolation),
        (0x17, ProtocolError), (0x18, ProtocolError), (0x19, ProtocolError), (0x1A, ProtocolError),
        (0x1B, AuthFailure), (0x1C, AuthFailure), (0x1D, AuthFailure),
        (0x1E, TransportFailure), (0x1F, AuthFailure),
        (0x20, GovernanceViolation), (0x21, GovernanceViolation),
        (0x22, GovernanceViolation), (0x23, GovernanceViolation), (0x24, GovernanceViolation),
        (0x25, CapabilityFailure), (0x26, CapabilityFailure),
        (0x27, AuthFailure), (0x28, CapabilityFailure), (0x29, AuthFailure), (0x2A, AuthFailure),
        (0x2B, ResourceLimit), (0x2C, AuthFailure), (0x2D, AuthFailure),
        // v15 additions
        (0x2E, CapabilityFailure), (0x2F, CapabilityFailure), (0x30, CapabilityFailure),
        (0x31, CapabilityFailure), (0x32, CapabilityFailure), (0x33, CapabilityFailure),
        (0x34, CapabilityFailure), (0x35, ProtocolError),
        (0x36, AuthFailure), (0x37, PolicyViolation), (0x38, PolicyViolation),
        (0x39, PolicyViolation), (0x3A, GovernanceViolation), (0x3B, GovernanceViolation),
        (0x3C, AuthFailure), (0x3D, AuthFailure), (0x3E, AuthFailure),
        (0x3F, AuthFailure), (0x40, AuthFailure),
    ];
    for &(bytecode, cat) in entries {
        m.insert(bytecode, cat);
    }
    m
});

/// Per-bytecode retry hint in seconds.
static RETRY_HINT_MAP: LazyLock<HashMap<u8, u32>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(0x14, 30); // CIRCUIT_BREAKER_OPEN
    m.insert(0x0E, 30); // PAYLOAD_TOO_LARGE
    m.insert(0x2B, 30); // RGC_RESOURCE_LIMIT_EXCEEDED
    m.insert(0x1F, 60); // KEY_EVOLUTION_REQUIRED
    m
});

const RESOURCE_LIMIT_DEFAULT_RETRY: u32 = 30;

// ── WireErrorResponse ──────────────────────────────────────────────────────

/// Sanitised, caller-visible error payload.
#[derive(Debug, Clone)]
pub struct WireErrorResponse {
    pub category: ErrorCategory,
    pub correlation_id: String,
    pub retry_after_seconds: Option<u32>,
    pub protocol_version: String,
}

impl WireErrorResponse {
    /// Create a new WireErrorResponse with validation.
    pub fn new(
        category: ErrorCategory,
        correlation_id: String,
        retry_after_seconds: Option<u32>,
    ) -> Result<Self, String> {
        if correlation_id.len() != 32 {
            return Err(format!(
                "correlation_id must be 32 hex chars, got length {}",
                correlation_id.len()
            ));
        }
        Ok(Self {
            category,
            correlation_id,
            retry_after_seconds,
            protocol_version: DEFAULT_PROTOCOL_VERSION.to_string(),
        })
    }
}

// ── ErrorConfidentialityFilter ─────────────────────────────────────────────

/// Stateless error sanitiser.  All methods are associated functions.
pub struct ErrorConfidentialityFilter;

impl ErrorConfidentialityFilter {
    /// Map a raw SAACP bytecode to its public ErrorCategory.
    pub fn bytecode_to_category(bytecode: u8) -> ErrorCategory {
        BYTECODE_CATEGORY_MAP
            .get(&bytecode)
            .copied()
            .unwrap_or(ErrorCategory::Internal)
    }

    /// Build a sanitised WireErrorResponse from an internal bytecode.
    ///
    /// `internal_detail` is accepted but **deliberately discarded**.
    pub fn sanitize(bytecode: u8, _internal_detail: &str) -> WireErrorResponse {
        let mut rng = rand::thread_rng();
        let mut corr_bytes = [0u8; 16];
        rng.fill_bytes(&mut corr_bytes);
        let correlation_id = hex::encode(corr_bytes);

        let category = Self::bytecode_to_category(bytecode);

        let retry_after_seconds = if let Some(&hint) = RETRY_HINT_MAP.get(&bytecode) {
            Some(hint)
        } else if category == ErrorCategory::ResourceLimit {
            Some(RESOURCE_LIMIT_DEFAULT_RETRY)
        } else {
            None
        };

        WireErrorResponse {
            category,
            correlation_id,
            retry_after_seconds,
            protocol_version: DEFAULT_PROTOCOL_VERSION.to_string(),
        }
    }

    /// Serialize a WireErrorResponse to the fixed 44-byte wire format.
    pub fn format_wire_bytes(response: &WireErrorResponse) -> Vec<u8> {
        let mut wire = vec![0u8; WIRE_SIZE];

        // Byte 0: category
        wire[0] = response.category as u8;

        // Bytes 1-16: correlation_id as raw bytes
        if let Ok(corr) = hex::decode(&response.correlation_id) {
            let len = corr.len().min(16);
            wire[1..1 + len].copy_from_slice(&corr[..len]);
        }

        // Bytes 17-20: retry_after_seconds big-endian uint32
        let retry_val = response
            .retry_after_seconds
            .unwrap_or(SENTINEL_NO_RETRY);
        wire[17..21].copy_from_slice(&retry_val.to_be_bytes());

        // Bytes 21-24: protocol tag
        wire[21..25].copy_from_slice(PROTOCOL_VERSION_WIRE);

        // Bytes 25-43: zero padding (already zeroed)

        debug_assert_eq!(wire.len(), WIRE_SIZE);
        wire
    }

    /// Parse a 44-byte wire frame back into a WireErrorResponse.
    pub fn parse_wire_bytes(data: &[u8]) -> Result<WireErrorResponse, String> {
        if data.len() != WIRE_SIZE {
            return Err(format!(
                "parse_wire_bytes expects exactly {} bytes, got {}",
                WIRE_SIZE,
                data.len()
            ));
        }

        let category = ErrorCategory::from_byte(data[0])
            .ok_or_else(|| format!("Unknown ErrorCategory 0x{:02X}", data[0]))?;

        let correlation_id = hex::encode(&data[1..17]);

        let retry_u32 = u32::from_be_bytes([data[17], data[18], data[19], data[20]]);
        let retry_after_seconds = if retry_u32 == SENTINEL_NO_RETRY {
            None
        } else {
            Some(retry_u32)
        };

        Ok(WireErrorResponse {
            category,
            correlation_id,
            retry_after_seconds,
            protocol_version: DEFAULT_PROTOCOL_VERSION.to_string(),
        })
    }

    /// Convenience: sanitize + format in one call.
    pub fn make_opaque_error(bytecode: u8, internal_detail: &str) -> Vec<u8> {
        let resp = Self::sanitize(bytecode, internal_detail);
        Self::format_wire_bytes(&resp)
    }
}

/// Module-level convenience function.
pub fn make_opaque_error(bytecode: u8, internal_detail: &str) -> Vec<u8> {
    ErrorConfidentialityFilter::make_opaque_error(bytecode, internal_detail)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_size_constant() {
        assert_eq!(WIRE_SIZE, 44);
    }

    #[test]
    fn test_bytecode_to_category_known() {
        assert_eq!(
            ErrorConfidentialityFilter::bytecode_to_category(0x03),
            ErrorCategory::AuthFailure
        );
        assert_eq!(
            ErrorConfidentialityFilter::bytecode_to_category(0x06),
            ErrorCategory::PolicyViolation
        );
    }

    #[test]
    fn test_bytecode_to_category_unknown() {
        assert_eq!(
            ErrorConfidentialityFilter::bytecode_to_category(0xFF),
            ErrorCategory::Internal
        );
    }

    #[test]
    fn test_sanitize_circuit_breaker() {
        let resp = ErrorConfidentialityFilter::sanitize(0x14, "internal trace");
        assert_eq!(resp.category, ErrorCategory::PolicyViolation);
        assert_eq!(resp.retry_after_seconds, Some(30));
        assert_eq!(resp.correlation_id.len(), 32);
    }

    #[test]
    fn test_sanitize_no_retry() {
        let resp = ErrorConfidentialityFilter::sanitize(0x03, "");
        assert_eq!(resp.category, ErrorCategory::AuthFailure);
        assert_eq!(resp.retry_after_seconds, None);
    }

    #[test]
    fn test_format_wire_bytes_length() {
        let resp = ErrorConfidentialityFilter::sanitize(0x06, "test");
        let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
        assert_eq!(wire.len(), WIRE_SIZE);
    }

    #[test]
    fn test_format_wire_bytes_category_byte() {
        let resp = ErrorConfidentialityFilter::sanitize(0x03, "");
        let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
        assert_eq!(wire[0], ErrorCategory::AuthFailure as u8);
    }

    #[test]
    fn test_format_wire_bytes_protocol_tag() {
        let resp = ErrorConfidentialityFilter::sanitize(0x01, "");
        let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
        assert_eq!(&wire[21..25], b"SACP");
    }

    #[test]
    fn test_roundtrip() {
        let resp = ErrorConfidentialityFilter::sanitize(0x20, "detail");
        let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
        let parsed = ErrorConfidentialityFilter::parse_wire_bytes(&wire).unwrap();
        assert_eq!(parsed.category, resp.category);
        assert_eq!(parsed.correlation_id, resp.correlation_id);
        assert_eq!(parsed.retry_after_seconds, resp.retry_after_seconds);
    }

    #[test]
    fn test_parse_wire_bytes_wrong_length() {
        assert!(ErrorConfidentialityFilter::parse_wire_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_make_opaque_error() {
        let wire = make_opaque_error(0x06, "ignore previous instructions");
        assert_eq!(wire.len(), WIRE_SIZE);
        assert_eq!(wire[0], ErrorCategory::PolicyViolation as u8);
    }

    #[test]
    fn test_resource_limit_default_retry() {
        let resp = ErrorConfidentialityFilter::sanitize(0x0E, "");
        assert_eq!(resp.retry_after_seconds, Some(30));
    }

    #[test]
    fn test_key_evolution_retry() {
        let resp = ErrorConfidentialityFilter::sanitize(0x1F, "");
        assert_eq!(resp.retry_after_seconds, Some(60));
    }

    #[test]
    fn test_unique_correlation_ids() {
        let r1 = ErrorConfidentialityFilter::sanitize(0x01, "");
        let r2 = ErrorConfidentialityFilter::sanitize(0x01, "");
        assert_ne!(r1.correlation_id, r2.correlation_id);
    }

    #[test]
    fn test_no_retry_sentinel_in_wire() {
        let resp = ErrorConfidentialityFilter::sanitize(0x03, "");
        assert_eq!(resp.retry_after_seconds, None);
        let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
        let retry_bytes = u32::from_be_bytes([wire[17], wire[18], wire[19], wire[20]]);
        assert_eq!(retry_bytes, SENTINEL_NO_RETRY);
    }

    /// Task: wire_error_response_parse_roundtrip
    #[test]
    fn wire_error_response_parse_roundtrip() {
        // Sanitize → format → parse: all fields survive the roundtrip.
        for bytecode in [0x01u8, 0x03, 0x14, 0x20, 0x2B, 0x40] {
            let resp = ErrorConfidentialityFilter::sanitize(bytecode, "internal detail dropped");
            let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
            assert_eq!(wire.len(), WIRE_SIZE, "wire must be exactly 44 bytes");
            let parsed = ErrorConfidentialityFilter::parse_wire_bytes(&wire)
                .unwrap_or_else(|e| panic!("parse failed for 0x{bytecode:02X}: {e}"));
            assert_eq!(parsed.category, resp.category, "category roundtrip failed");
            assert_eq!(parsed.correlation_id, resp.correlation_id, "correlation_id roundtrip failed");
            assert_eq!(parsed.retry_after_seconds, resp.retry_after_seconds, "retry roundtrip failed");
        }
    }

    /// Task: governance_violation_category_mapped
    #[test]
    fn governance_violation_category_mapped() {
        // Bytecodes 0x20-0x24 must map to GovernanceViolation (AEGF bytecodes).
        for code in 0x20u8..=0x24 {
            assert_eq!(
                ErrorConfidentialityFilter::bytecode_to_category(code),
                ErrorCategory::GovernanceViolation,
                "0x{code:02X} must be GovernanceViolation"
            );
        }
        // Bytecodes 0x3A-0x3B also GovernanceViolation.
        assert_eq!(ErrorConfidentialityFilter::bytecode_to_category(0x3A), ErrorCategory::GovernanceViolation);
        assert_eq!(ErrorConfidentialityFilter::bytecode_to_category(0x3B), ErrorCategory::GovernanceViolation);
        // Bytecode 0x2B must map to ResourceLimit (RGC).
        assert_eq!(ErrorConfidentialityFilter::bytecode_to_category(0x2B), ErrorCategory::ResourceLimit);
        // Bytecodes 0x3C-0x40 must map to AuthFailure (identity binding).
        for code in 0x3Cu8..=0x40 {
            assert_eq!(
                ErrorConfidentialityFilter::bytecode_to_category(code),
                ErrorCategory::AuthFailure,
                "0x{code:02X} must be AuthFailure"
            );
        }
    }
}
