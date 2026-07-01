/// Cross-language interoperability test vectors.
///
/// PURPOSE
/// -------
/// Verify that Rust and Python agree on every wire-format primitive. Fixed,
/// deterministic inputs are used throughout. Each test prints its vector in
/// a format that the companion `tests/cross_lang_verify.py` script can
/// replicate with Python's `cryptography` library.
///
/// KNOWN DIVERGENCES (remaining)
/// ─────────────────────────────
/// 1. EASI context_ref_id: Python build_frame writes plaintext at header[44..76].
///    Rust encrypts it with HKDF-XOR (GAP-9). Python must gain EASI support.
///    Full MEASC frame bytes therefore differ at bytes 44..76.
///
/// HOW TO UPDATE EXPECTED VALUES
/// ─────────────────────────────
/// Run `python3 tests/cross_lang_verify.py` and replace the `expected` strings
/// below with the printed Python hex values.

use saacp::{
    KeyEvolutionEngine, SessionEpochManager,
    MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD, MEASC_DEFAULT_EPOCH_TIME_SECONDS,
    MEASCFrame,
};

fn hex(b: &[u8]) -> String { hex::encode(b) }

// ── Vector 1: HKDF initial epoch key (epoch 0, no prev_key) ──────────────────
// Python: HKDF-SHA256(ikm=session_secret, salt=session_id,
//          info=b"SAACP-MEASC-epoch-key-v1"\x00\x00\x00\x00)
// BOTH implementations must produce the same 32-byte key.

#[test]
fn vector_hkdf_epoch_key_initial() {
    let session_secret = [0xAAu8; 32];
    let session_id     = [0x01u8; 16];

    let engine = KeyEvolutionEngine::new(session_secret);
    let key = engine.derive_epoch_key(&session_id, 0, None);
    let output = hex(&key);
    eprintln!("[VECTOR] hkdf_epoch_key_initial = {}", output);

    // Rust-computed value — run `python3 tests/cross_lang_verify.py` to confirm
    // Python's HKDF(ikm=[0xAA]*32, salt=[0x01]*16, info=b"SAACP-MEASC-epoch-key-v1\x00\x00\x00\x00")
    // produces the same 32 bytes. Any mismatch is a cross-language bug.
    assert_eq!(
        output, "65b32ae4912b806927dfd2d9357e380caa229afb951fbd26745ae1f727acddeb",
        "HKDF initial epoch key changed or diverges from Python"
    );
}

// ── Vector 2: HKDF chained epoch key — Rust now matches Python normative ────
// Algorithm: IKM = session_secret XOR prev_key; info = b"SAACP-MEASC-epoch-key-v1" + epoch_id_BE4
// Python-verified expected value: 62f34873a678aa43b916fc1ae6acd3df49cd73af250f723cdec0568d12c1e304

#[test]
fn vector_hkdf_epoch_key_chained() {
    let session_secret = [0xAAu8; 32];
    let session_id     = [0x01u8; 16];
    let prev_key       = [0xBBu8; 32];

    let engine = KeyEvolutionEngine::new(session_secret);
    let key = engine.derive_epoch_key(&session_id, 1, Some(&prev_key));
    let output = hex(&key);

    // Verified against Python cross_lang_verify.py — both must produce this value.
    assert_eq!(
        output, "62f34873a678aa43b916fc1ae6acd3df49cd73af250f723cdec0568d12c1e304",
        "Chained epoch key diverges from Python normative value"
    );
}

// ── Vector 3: MEASC frame build+parse round-trip ─────────────────────────────
// Builds a frame with fixed inputs and parses it back. Verifies:
//   - AES-256-GCM encrypt/decrypt is internally consistent in Rust
//   - PSN is assigned to 1 (first packet in the epoch)
//   - Payload bytes are recovered identically
//
// The printed frame_hex can be cross-checked with Python's build_frame output
// for bytes 0..16 (magic + header fields) and the plaintext after decryption,
// noting that bytes 44..76 differ due to the EASI divergence.

#[test]
fn vector_measc_build_parse_roundtrip() {
    let session_secret = [0xCCu8; 32];
    let session_id     = [0x02u8; 16];
    let context_ref_id = [0x03u8; 32];
    let traceparent    = [0x04u8; 24];
    let payload        = b"hello saacp cross-language";

    let mgr = SessionEpochManager::new();
    mgr.create_session(
        session_id, session_secret,
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
        None,
    ).expect("create_session");

    let (frame_bytes, psn) = mgr
        .with_epoch_mut(&session_id, 0, |ep| {
            MEASCFrame::build_frame(
                ep, 1u16, 0x00, 0x00, 0, payload, &context_ref_id, &traceparent, 1,
            )
        })
        .expect("epoch 0 exists")
        .expect("build_frame");

    // PSN 1 is the first packet (sequencer starts at 1)
    assert_eq!(psn, 1, "first packet must use PSN=1");
    eprintln!("[VECTOR] measc_frame psn={} frame_hex={}", psn, hex(&frame_bytes));

    let parsed = MEASCFrame::parse_frame(&frame_bytes, &mgr, true)
        .expect("parse_frame must succeed on a freshly-built frame");
    assert_eq!(parsed.payload, payload, "payload round-trip mismatch");
    assert_eq!(parsed.psn, psn, "PSN round-trip mismatch");
}

// ── Vector 4: SignedCapabilityToken wire round-trip ───────────────────────────
// Wire format: base64(4-byte-BE-json-len || sorted-claims-json || 64-byte-Ed25519-sig)
// Both Python and Rust must produce the same bytes for the same key seed and claims.

#[test]
fn vector_token_wire_roundtrip() {
    use saacp::acsvaf::SignedCapabilityToken;
    use ed25519_dalek::{SigningKey, Signer};
    use serde_json::{json, Map, Value};

    // Fixed Ed25519 private key seed (32 deterministic bytes)
    let seed = [0xDDu8; 32];
    let signing_key = SigningKey::from_bytes(&seed);

    let mut claims: Map<String, Value> = Map::new();
    claims.insert("exp".into(), json!(1700003600_u64));
    claims.insert("iat".into(), json!(1700000000_u64));
    claims.insert("iss".into(), json!("test-issuer"));
    claims.insert("scopes".into(), json!(["read"]));
    claims.insert("sub".into(), json!("test-agent"));

    // Produce the signature the same way acsvaf.rs does: sign the
    // 4-byte-len-prefixed sorted-JSON bytes.
    let json_bytes: Vec<u8> = {
        // Use BTreeMap for deterministic ordering (same as serialize_sorted_json)
        let ordered: std::collections::BTreeMap<_, _> = claims.iter().collect();
        serde_json::to_vec(&ordered).unwrap()
    };
    let mut to_sign = Vec::with_capacity(4 + json_bytes.len());
    to_sign.extend_from_slice(&(json_bytes.len() as u32).to_be_bytes());
    to_sign.extend_from_slice(&json_bytes);
    let sig = signing_key.sign(&to_sign);

    let token = SignedCapabilityToken {
        claims: claims.clone(),
        signature: sig.to_bytes(),
    };

    let wire = token.to_wire();
    eprintln!("[VECTOR] token_wire wire_hex={}", hex(&wire));

    // Verify round-trip
    let recovered = SignedCapabilityToken::from_wire(&wire)
        .expect("from_wire must succeed on valid token");
    assert_eq!(recovered.signature, token.signature, "signature round-trip");
    assert_eq!(recovered.claims, token.claims, "claims round-trip");
}

// ── Vector 5: AES-256-GCM NIST known-answer test ─────────────────────────────
// Standard NIST SP 800-38D empty-plaintext test vector.
// Verifies the `aes-gcm` crate produces the correct auth tag.
// Key=00*32, IV=00*12, AAD=[], plaintext=[] → tag = 530f8afbc74536b9a963b4f1c4cb738b

#[test]
fn vector_aes256gcm_nist_empty_plaintext() {
    use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
    let key = [0u8; 32];
    let iv  = [0u8; 12];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce  = Nonce::from_slice(&iv);
    let output = cipher.encrypt(nonce, b"".as_ref()).expect("encrypt empty");
    // 0 bytes ciphertext + 16-byte auth tag
    assert_eq!(output.len(), 16, "empty plaintext → 16-byte tag only");
    assert_eq!(
        hex(&output),
        "530f8afbc74536b9a963b4f1c4cb738b",
        "AES-256-GCM NIST tag mismatch"
    );
}
