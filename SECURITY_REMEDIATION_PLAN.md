# SAACP-rs Quantum-Resistant Security Remediation Plan

## Executive Summary

This plan transforms SAACP-rs from a classically-secure protocol into a quantum-resistant standard suitable for healthcare and banking. The implementation follows a 7-phase approach, each independently shippable, with zero regressions to existing functionality.

## Current Architecture Analysis

### Existing Strengths (Preserved)
- ✅ 12-gate zero-trust pipeline with Authorization Invariance
- ✅ AES-256-GCM per-frame AEAD with HKDF-SHA256 key evolution
- ✅ Ed25519 capability tokens with HMAC-PSK fallback
- ✅ 4096-entry sliding PSN replay window with anomaly detection
- ✅ Immutable hash-chained audit log with WAL
- ✅ Fail-closed token validation (already fixed)
- ✅ Depth-limited JSON parsing (already fixed)
- ✅ Constant-time comparisons via `subtle` crate
- ✅ `zeroize` for key material scrubbing

### Critical Vulnerabilities (Addressed)
- ❌ Ed25519 signatures forgeable by Shor's algorithm (quantum)
- ❌ X25519 key exchange breakable by Shor's algorithm (quantum)
- ❌ No crypto-agility — algorithms hard-wired
- ❌ No forward secrecy in key exchange
- ❌ No channel binding (session hijacking risk)
- ❌ No signed transcript (downgrade attack risk)
- ❌ No hardware attestation implementation
- ❌ No PQC message size limits (DoS risk)

## Implementation Phases

### Phase 1: Crypto-Agility Foundation
**Goal:** Extend `CryptoSuite` trait to support multiple signature algorithms

**Files Modified:**
- `Cargo.toml` — Add `ml-dsa`, `ml-kem`, `sha3` dependencies
- `src/cryptosuite.rs` — Add `MlDsa65Suite`, `HybridEd25519MlDsa65Suite`
- `src/crypto_governance.rs` — Add PQC suites to approved policies

**Key Types:**
```rust
pub enum SignatureAlgorithm {
    Ed25519,
    MlDsa65,
    SlhDsa,
    HybridEd25519MlDsa65,
}

pub trait SignatureSuite: Send + Sync {
    fn algorithm(&self) -> SignatureAlgorithm;
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, String>;
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool;
}
```

### Phase 2: Hybrid KEM (Key Exchange)
**Goal:** Implement X25519+ML-KEM-768 hybrid key exchange

**Files Modified:**
- `src/measc.rs` — Add `HybridKem` module
- New: `src/pqc/kem.rs` — KEM trait + implementations

**Key Types:**
```rust
pub trait Kem: Send + Sync {
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);
    fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String>;
    fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, String>;
}

pub struct HybridKem {
    classical: X25519Kem,
    pqc: MlKem768,
}

impl Kem for HybridKem {
    // Combines X25519 ECDH + ML-KEM-768 decapsulation
    // session_key = HKDF-SHA384(ss_classical || ss_pqc)
}
```

### Phase 3: Hybrid Signatures
**Goal:** Implement Ed25519+ML-DSA-65 hybrid signature composition

**Files Modified:**
- `src/cryptosuite.rs` — Add `HybridEd25519MlDsa65Suite`
- `src/gateway.rs` — Update token validation for hybrid sigs

**Key Types:**
```rust
pub struct HybridEd25519MlDsa65Suite;

impl SignatureSuite for HybridEd25519MlDsa65Suite {
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        // Sign with both Ed25519 and ML-DSA-65
        // Concatenate: classical_sig || pqc_sig
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        // Verify BOTH signatures — both must pass
    }
}
```

### Phase 4: Governance & Policy Updates
**Goal:** Extend `ApprovedSuitePolicy` to support PQC suites

**Files Modified:**
- `src/crypto_governance.rs` — Add PQC suite identifiers and policies

**Key Changes:**
```rust
pub const APPROVED_SIGNATURE_SUITES: &[&str] = &[
    "ed25519",
    "ml-dsa-65",
    "slh-dsa",
    "hybrid-ed25519-ml-dsa-65",
];

pub const APPROVED_KEM_SUITES: &[&str] = &[
    "x25519",
    "ml-kem-768",
    "ml-kem-1024",
    "hybrid-x25519-ml-kem-768",
];
```

### Phase 5: Channel Binding & Downgrade Prevention
**Goal:** Bind tokens to handshake transcript; sign negotiation transcript

**Files Modified:**
- `src/handler.rs` — Add channel binding to Gate 1.0
- `src/crypto_governance.rs` — Add signature to `NegotiationTranscript`

**Key Changes:**
- Session tokens embed `transcript_hash` from handshake
- `NegotiationTranscript` includes Ed25519+ML-DSA signature
- Downgrade attempts detected via transcript verification

### Phase 6: Hardware Attestation
**Goal:** Implement TPM/HSM attestation verification

**Files Modified:**
- `src/faitf.rs` — Implement `HardwareAttestation` trait
- New: `src/attestation.rs` — Attestation verification module

### Phase 7: Structural Hardening
**Goal:** Add PQC-specific size limits and DoS protection

**Files Modified:**
- `src/handler.rs` — Add handshake size limits
- `src/measc.rs` — Add PQC message bounds

## Dependency Additions

```toml
[dependencies]
# Post-Quantum Cryptography
ml-dsa = "0.2"       # FIPS 204 (Dilithium)
ml-kem = "0.2"       # FIPS 203 (Kyber)
sha3 = "0.10"        # SHA-3 for PQC hashing
```

## Testing Strategy

1. **Unit tests** for each new PQC primitive
2. **Integration tests** for hybrid KEM handshake
3. **Compatibility tests** ensuring classical-only peers still work
4. **Regression tests** verifying all 1708 existing tests pass
5. **Red-team tests** for quantum attack scenarios

## Migration Path

1. **Phase 1-2:** Deploy crypto-agility + hybrid KEM (backward compatible)
2. **Phase 3-4:** Enable hybrid signatures (graceful degradation for classical peers)
3. **Phase 5-7:** Full quantum-resistant deployment

## Success Criteria

- ✅ All existing tests pass (zero regressions)
- ✅ Hybrid KEM handshake completes successfully
- ✅ Hybrid signatures verify correctly
- ✅ Channel binding prevents token replay across sessions
- ✅ Downgrade attacks detected and rejected
- ✅ PQC message size limits enforced
- ✅ Hardware attestation verified
