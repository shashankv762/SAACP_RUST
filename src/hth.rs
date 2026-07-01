//! hth.rs — Handshake Transcript Hash (HTH) for SAACP
//!
//! The Handshake Transcript Hash (HTH) is a cryptographic commitment over the
//! ordered sequence of security-critical messages exchanged during a SAACP
//! handshake. Once finalized the HTH is a 32-byte SHA-256 digest that
//! authenticates every element that was appended to the transcript.
//!
//! Capability tokens can subsequently be *bound* to a specific HTH value via
//! HMAC-SHA-256, preventing cross-session replay of capabilities.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;

use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// TranscriptElementType
// ---------------------------------------------------------------------------

/// Identifies the role of a single entry in the handshake transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TranscriptElementType {
    /// The client opening handshake message.
    ClientHello,
    /// The server response to a ClientHello.
    ServerHello,
    /// A cryptographic proof of peer identity.
    IdentityProof,
    /// An ephemeral public-key share for key agreement.
    KeyExchangeShare,
    /// Epoch initialisation data (session epoch number and nonce).
    EpochInit,
    /// A binding commitment to a capability or access policy.
    PolicyCommitment,
    /// A token that binds a capability to the session context.
    CapabilityBinding,
    /// Final negotiated session parameters.
    SessionParams,
}

impl TranscriptElementType {
    /// Return the wire tag string for this element type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientHello => "client_hello",
            Self::ServerHello => "server_hello",
            Self::IdentityProof => "identity_proof",
            Self::KeyExchangeShare => "key_exchange_share",
            Self::EpochInit => "epoch_init",
            Self::PolicyCommitment => "policy_commitment",
            Self::CapabilityBinding => "capability_binding",
            Self::SessionParams => "session_params",
        }
    }

    /// Return the tag as UTF-8 bytes.
    pub fn as_bytes(&self) -> &'static [u8] {
        self.as_str().as_bytes()
    }
}

// ---------------------------------------------------------------------------
// TranscriptElement
// ---------------------------------------------------------------------------

/// An immutable record of a single security-critical handshake message.
#[derive(Debug, Clone)]
pub struct TranscriptElement {
    /// The semantic role of this element within the handshake.
    pub element_type: TranscriptElementType,
    /// The raw bytes of the message or value being recorded.
    pub data: Vec<u8>,
    /// Zero-based ordinal position within the transcript.
    pub sequence: u64,
    /// Wall-clock time at which the element was recorded (seconds since UNIX epoch).
    /// Used for audit logging only — not included in HTH digest.
    pub timestamp: f64,
}

// ---------------------------------------------------------------------------
// HandshakeTranscript
// ---------------------------------------------------------------------------

/// Thread-safe, append-only transcript of security-critical handshake elements.
///
/// The transcript collects `TranscriptElement` objects in strict append order
/// and, once `finalize()` is called, produces a 32-byte SHA-256 Handshake
/// Transcript Hash (HTH) that cryptographically commits to every element.
///
/// After finalization no further elements may be appended.
pub struct HandshakeTranscript {
    session_id: Vec<u8>,
    inner: Mutex<TranscriptInner>,
}

struct TranscriptInner {
    elements: Vec<TranscriptElement>,
    finalized: bool,
    hth: Option<Vec<u8>>,
}

impl HandshakeTranscript {
    /// Create a new transcript with the given 16-byte session identifier.
    ///
    /// # Errors
    /// Returns `Err` if `session_id` is not exactly 16 bytes.
    pub fn new(session_id: &[u8]) -> Result<Self, String> {
        if session_id.len() != 16 {
            return Err(format!(
                "session_id must be exactly 16 bytes, got {}",
                session_id.len()
            ));
        }
        Ok(Self {
            session_id: session_id.to_vec(),
            inner: Mutex::new(TranscriptInner {
                elements: Vec::new(),
                finalized: false,
                hth: None,
            }),
        })
    }

    /// Append a new element to the transcript.
    ///
    /// # Errors
    /// Returns `Err` if the transcript has already been finalized.
    pub fn append(&self, element_type: TranscriptElementType, data: &[u8]) -> Result<(), String> {
        let mut inner = self.inner.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        if inner.finalized {
            return Err("Cannot append to a finalized HandshakeTranscript".into());
        }
        let sequence = inner.elements.len() as u64;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        inner.elements.push(TranscriptElement {
            element_type,
            data: data.to_vec(),
            sequence,
            timestamp,
        });
        Ok(())
    }

    /// Seal the transcript and compute the 32-byte Handshake Transcript Hash.
    ///
    /// Digest input layout:
    /// ```text
    /// b'\x09session_id'                          // 9-byte literal tag
    /// + uint32_le(len(session_id))               // 4-byte length prefix
    /// + session_id                               // 16 bytes
    /// for each element in append order:
    ///     uint32_le(len(type_tag)) + type_tag
    ///     uint32_le(len(data))     + data
    /// ```
    ///
    /// # Errors
    /// Returns `Err` if the transcript has already been finalized.
    pub fn finalize(&self) -> Result<Vec<u8>, String> {
        let mut inner = self.inner.lock().map_err(|e| format!("lock poisoned: {e}"))?;
        if inner.finalized {
            return Err("HandshakeTranscript has already been finalized".into());
        }

        let mut buf: Vec<u8> = Vec::new();

        // Session-ID prefix
        let session_tag: &[u8] = b"\x09session_id";
        buf.extend_from_slice(session_tag);
        buf.extend_from_slice(&(self.session_id.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.session_id);

        // Transcript elements
        for element in &inner.elements {
            let type_tag = element.element_type.as_bytes();
            buf.extend_from_slice(&(type_tag.len() as u32).to_le_bytes());
            buf.extend_from_slice(type_tag);
            buf.extend_from_slice(&(element.data.len() as u32).to_le_bytes());
            buf.extend_from_slice(&element.data);
        }

        let digest = Sha256::digest(&buf).to_vec();
        inner.finalized = true;
        inner.hth = Some(digest.clone());

        Ok(digest)
    }

    /// The 32-byte HTH digest, or `None` if not yet finalized.
    pub fn hth(&self) -> Option<Vec<u8>> {
        let inner = self.inner.lock().ok()?;
        inner.hth.clone()
    }

    /// Hex-encoded HTH digest string, or `None` if not yet finalized.
    pub fn hth_hex(&self) -> Option<String> {
        let inner = self.inner.lock().ok()?;
        inner.hth.as_ref().map(hex::encode)
    }

    /// Return the number of elements currently in the transcript.
    pub fn element_count(&self) -> u64 {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.elements.len() as u64
    }

    /// Return `true` if `finalize()` has been successfully called.
    pub fn is_finalized(&self) -> bool {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.finalized
    }

    /// Return a reference to the session ID bytes.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
}

impl std::fmt::Debug for HandshakeTranscript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().expect("lock poisoned");
        f.debug_struct("HandshakeTranscript")
            .field("session_id", &hex::encode(&self.session_id))
            .field("elements", &inner.elements.len())
            .field("finalized", &inner.finalized)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// TranscriptSession
// ---------------------------------------------------------------------------

/// Associates a finalized HTH with all session-level protocol state.
pub struct TranscriptSession {
    /// The 16-byte opaque session identifier.
    pub session_id: Vec<u8>,
    /// The protocol epoch number at session establishment.
    pub epoch_id: u64,
    /// The AEGF Conversation ID (CID) string scoping this session.
    pub conversation_id: String,
    /// The `HandshakeTranscript` finalized to produce `hth`.
    pub transcript: HandshakeTranscript,
    /// Wall-clock time (seconds since UNIX epoch) at creation.
    pub established_at: f64,
    /// The 32-byte SHA-256 Handshake Transcript Hash at establishment.
    pub hth: Vec<u8>,
}

impl TranscriptSession {
    /// Create a `TranscriptSession` from a (possibly open) transcript.
    ///
    /// If `transcript` has not yet been finalized this method calls `finalize()` first.
    pub fn create(
        session_id: &[u8],
        epoch_id: u64,
        conversation_id: &str,
        transcript: HandshakeTranscript,
    ) -> Result<Self, String> {
        if !transcript.is_finalized() {
            transcript.finalize()?;
        }
        let hth = transcript.hth().ok_or("transcript finalized but hth is None")?;
        let established_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Ok(Self {
            session_id: session_id.to_vec(),
            epoch_id,
            conversation_id: conversation_id.to_string(),
            transcript,
            established_at,
            hth,
        })
    }
}

impl std::fmt::Debug for TranscriptSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranscriptSession")
            .field("session_id", &hex::encode(&self.session_id))
            .field("epoch_id", &self.epoch_id)
            .field("conversation_id", &self.conversation_id)
            .field("hth", &hex::encode(&self.hth))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Capability binding helpers
// ---------------------------------------------------------------------------

/// Produce an HMAC-SHA-256 binding of a capability token to an HTH.
///
/// `msg = hth + capability_token_bytes`
/// `mac = HMAC-SHA256(key=secret, msg=msg)`
///
/// # Errors
/// Returns `Err` if `hth` is not exactly 32 bytes.
pub fn bind_capability(hth: &[u8], capability_token_bytes: &[u8], secret: &[u8]) -> Result<Vec<u8>, String> {
    if hth.len() != 32 {
        return Err(format!("hth must be exactly 32 bytes, got {}", hth.len()));
    }
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| format!("HMAC key error: {e}"))?;
    mac.update(hth);
    mac.update(capability_token_bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify an HMAC-SHA-256 capability binding in constant time.
///
/// Returns `true` if the MAC is valid, `false` otherwise.
/// A `ValueError` from `bind_capability` (malformed hth) is propagated.
pub fn verify_capability_binding(
    hth: &[u8],
    capability_token_bytes: &[u8],
    secret: &[u8],
    mac: &[u8],
) -> Result<bool, String> {
    let expected = bind_capability(hth, capability_token_bytes, secret)?;
    // Constant-time comparison
    if expected.len() != mac.len() {
        return Ok(false);
    }
    let mut acc: u8 = 0;
    for (a, b) in expected.iter().zip(mac.iter()) {
        acc |= a ^ b;
    }
    Ok(acc == 0)
}

// ---------------------------------------------------------------------------
// TranscriptRegistry
// ---------------------------------------------------------------------------

/// Thread-safe global registry mapping session IDs to TranscriptSessions.
pub struct TranscriptRegistry {
    sessions: Mutex<HashMap<Vec<u8>, TranscriptSession>>,
}

impl TranscriptRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Add a `TranscriptSession` to the registry.
    /// Silently replaces any existing session with the same ID.
    pub fn register(&self, session: TranscriptSession) {
        let mut sessions = self.sessions.lock().expect("lock poisoned");
        sessions.insert(session.session_id.clone(), session);
    }

    /// Look up a session by its identifier.
    /// Returns `None` if not found.
    pub fn get<F, R>(&self, session_id: &[u8], f: F) -> Option<R>
    where
        F: FnOnce(&TranscriptSession) -> R,
    {
        let sessions = self.sessions.lock().ok()?;
        sessions.get(session_id).map(f)
    }

    /// Check if a session exists.
    pub fn contains(&self, session_id: &[u8]) -> bool {
        let sessions = self.sessions.lock().expect("lock poisoned");
        sessions.contains_key(session_id)
    }

    /// Remove a session from the registry. No-op if not present.
    pub fn remove(&self, session_id: &[u8]) {
        let mut sessions = self.sessions.lock().expect("lock poisoned");
        sessions.remove(session_id);
    }

    /// Return the number of currently registered sessions.
    pub fn count(&self) -> usize {
        let sessions = self.sessions.lock().expect("lock poisoned");
        sessions.len()
    }
}

impl Default for TranscriptRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TranscriptRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sessions = self.sessions.lock().expect("lock poisoned");
        write!(f, "TranscriptRegistry(sessions={})", sessions.len())
    }
}

/// Process-wide default `TranscriptRegistry`.
pub static DEFAULT_REGISTRY: LazyLock<TranscriptRegistry> = LazyLock::new(TranscriptRegistry::new);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session_id() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
    }

    #[test]
    fn test_session_id_validation() {
        assert!(HandshakeTranscript::new(&[0u8; 16]).is_ok());
        assert!(HandshakeTranscript::new(&[0u8; 15]).is_err());
        assert!(HandshakeTranscript::new(&[0u8; 17]).is_err());
        assert!(HandshakeTranscript::new(&[]).is_err());
    }

    #[test]
    fn test_append_and_count() {
        let ht = HandshakeTranscript::new(&test_session_id()).unwrap();
        assert_eq!(ht.element_count(), 0);
        ht.append(TranscriptElementType::ClientHello, b"hello").unwrap();
        assert_eq!(ht.element_count(), 1);
        ht.append(TranscriptElementType::ServerHello, b"world").unwrap();
        assert_eq!(ht.element_count(), 2);
    }

    #[test]
    fn test_finalize_produces_32_bytes() {
        let ht = HandshakeTranscript::new(&test_session_id()).unwrap();
        ht.append(TranscriptElementType::ClientHello, b"client").unwrap();
        ht.append(TranscriptElementType::ServerHello, b"server").unwrap();
        let hth = ht.finalize().unwrap();
        assert_eq!(hth.len(), 32);
        assert!(ht.is_finalized());
        assert!(ht.hth().is_some());
        assert!(ht.hth_hex().is_some());
    }

    #[test]
    fn test_finalize_deterministic() {
        let sid = test_session_id();
        let ht1 = HandshakeTranscript::new(&sid).unwrap();
        ht1.append(TranscriptElementType::ClientHello, b"data").unwrap();
        let hth1 = ht1.finalize().unwrap();

        let ht2 = HandshakeTranscript::new(&sid).unwrap();
        ht2.append(TranscriptElementType::ClientHello, b"data").unwrap();
        let hth2 = ht2.finalize().unwrap();

        assert_eq!(hth1, hth2);
    }

    #[test]
    fn test_different_data_different_hth() {
        let sid = test_session_id();
        let ht1 = HandshakeTranscript::new(&sid).unwrap();
        ht1.append(TranscriptElementType::ClientHello, b"data_a").unwrap();
        let hth1 = ht1.finalize().unwrap();

        let ht2 = HandshakeTranscript::new(&sid).unwrap();
        ht2.append(TranscriptElementType::ClientHello, b"data_b").unwrap();
        let hth2 = ht2.finalize().unwrap();

        assert_ne!(hth1, hth2);
    }

    #[test]
    fn test_cannot_append_after_finalize() {
        let ht = HandshakeTranscript::new(&test_session_id()).unwrap();
        ht.finalize().unwrap();
        assert!(ht.append(TranscriptElementType::ClientHello, b"x").is_err());
    }

    #[test]
    fn test_cannot_finalize_twice() {
        let ht = HandshakeTranscript::new(&test_session_id()).unwrap();
        ht.finalize().unwrap();
        assert!(ht.finalize().is_err());
    }

    #[test]
    fn test_transcript_session_create() {
        let sid = test_session_id();
        let ht = HandshakeTranscript::new(&sid).unwrap();
        ht.append(TranscriptElementType::SessionParams, b"params").unwrap();
        let session = TranscriptSession::create(&sid, 1, "cid-001", ht).unwrap();
        assert_eq!(session.hth.len(), 32);
        assert_eq!(session.epoch_id, 1);
        assert_eq!(session.conversation_id, "cid-001");
    }

    #[test]
    fn test_transcript_session_create_already_finalized() {
        let sid = test_session_id();
        let ht = HandshakeTranscript::new(&sid).unwrap();
        ht.append(TranscriptElementType::EpochInit, b"epoch").unwrap();
        ht.finalize().unwrap();
        let session = TranscriptSession::create(&sid, 2, "cid-002", ht).unwrap();
        assert_eq!(session.hth.len(), 32);
    }

    #[test]
    fn test_bind_capability() {
        let hth = vec![0xAB; 32];
        let token = b"capability_token_data";
        let secret = b"shared_secret_key";
        let mac = bind_capability(&hth, token, secret).unwrap();
        assert_eq!(mac.len(), 32);
        assert!(verify_capability_binding(&hth, token, secret, &mac).unwrap());
    }

    #[test]
    fn test_bind_capability_invalid_hth() {
        let hth = vec![0xAB; 31]; // wrong length
        assert!(bind_capability(&hth, b"token", b"secret").is_err());
    }

    #[test]
    fn test_verify_bad_mac() {
        let hth = vec![0xAB; 32];
        let token = b"capability_token_data";
        let secret = b"shared_secret_key";
        let mac = bind_capability(&hth, token, secret).unwrap();
        let mut bad_mac = mac.clone();
        bad_mac[0] ^= 0xFF;
        assert!(!verify_capability_binding(&hth, token, secret, &bad_mac).unwrap());
    }

    #[test]
    fn test_verify_wrong_secret() {
        let hth = vec![0xAB; 32];
        let token = b"capability_token_data";
        let mac = bind_capability(&hth, token, b"secret1").unwrap();
        assert!(!verify_capability_binding(&hth, token, b"secret2", &mac).unwrap());
    }

    #[test]
    fn test_registry_basic_operations() {
        let reg = TranscriptRegistry::new();
        assert_eq!(reg.count(), 0);

        let sid = test_session_id();
        let ht = HandshakeTranscript::new(&sid).unwrap();
        ht.append(TranscriptElementType::ClientHello, b"hello").unwrap();
        let session = TranscriptSession::create(&sid, 1, "cid", ht).unwrap();
        let hth_val = session.hth.clone();

        reg.register(session);
        assert_eq!(reg.count(), 1);
        assert!(reg.contains(&sid));

        let found = reg.get(&sid, |s| s.hth.clone());
        assert_eq!(found, Some(hth_val));

        reg.remove(&sid);
        assert_eq!(reg.count(), 0);
        assert!(!reg.contains(&sid));
    }

    #[test]
    fn test_registry_remove_nonexistent() {
        let reg = TranscriptRegistry::new();
        reg.remove(&[0u8; 16]); // should not panic
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn test_default_registry() {
        // Just verify the static exists and is accessible
        let _count = DEFAULT_REGISTRY.count();
    }
}
