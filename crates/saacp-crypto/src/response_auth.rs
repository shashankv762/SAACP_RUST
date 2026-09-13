//! Response authentication (M3 / R1 — opusreview.md).
//!
//! The plaintext ack (`b"SUCCESS"`, `b"STREAM_ACK"`, etc.) is forgeable by an
//! active MITM because it is neither encrypted nor authenticated. This module
//! provides HMAC-SHA256 response authentication: the daemon computes a MAC tag
//! over the response using the session root key, and the sidecar verifies it.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// MAC tag size in bytes (SHA256 output).
pub const RESPONSE_MAC_LEN: usize = 32;

/// Compute the MAC tag for a response under the session root key.
///
/// M3 (R1 / opusreview.md): authenticates the plaintext ack so an active
/// MITM cannot forge a SUCCESS response. The session root key is the only
/// secret shared between the daemon and the sidecar at this point in the
/// protocol (derived from the ECDH handshake).
pub fn compute_response_mac(session_key: &[u8; 32], response: &[u8]) -> [u8; RESPONSE_MAC_LEN] {
    let mut mac =
        HmacSha256::new_from_slice(session_key).expect("HMAC key length is always 32 bytes");
    mac.update(response);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut tag = [0u8; RESPONSE_MAC_LEN];
    tag.copy_from_slice(&bytes[..RESPONSE_MAC_LEN]);
    tag
}

/// Verify the MAC tag for a response under the session root key.
/// Returns `true` if the tag is valid.
pub fn verify_response_mac(
    session_key: &[u8; 32],
    response: &[u8],
    tag: &[u8; RESPONSE_MAC_LEN],
) -> bool {
    let mut mac =
        HmacSha256::new_from_slice(session_key).expect("HMAC key length is always 32 bytes");
    mac.update(response);
    mac.verify_slice(tag).is_ok()
}
