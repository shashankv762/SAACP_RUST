
```
SAACP Working Group                                         S. Verma, Ed.
Internet-Draft                                              September 2026
Intended Status: Experimental
Expires: March 2027

             Secure Autonomous Agent Communication Protocol
                              SAACP/0.2

                        RFC Draft — SAACP-0001

Abstract

   This document defines the Secure Autonomous Agent Communication
   Protocol (SAACP), a zero-trust wire protocol and security gate
   pipeline for autonomous AI-agent-to-AI-agent communication.  Every
   inter-agent frame is individually encrypted with per-epoch AEAD,
   authenticated, then subjected to a non-reorderable pipeline of
   security gates enforcing capability authorization, action-class
   escalation limits, intent binding, prompt-injection resistance,
   epistemic sanity, and an immutable audit trail — before the payload
   is delivered to the receiving agent's business logic.

   SAACP/0.2 defines two wire format versions: the original 128-byte
   MEASC v1 header (Python-parity) and the new 160-byte MEASC v2 header
   (cryptographic packet chaining for stateless cross-node replay
   protection).

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.  This document is an Internet-Draft
   and is subject to all provisions of Section 10 of RFC 2026.

Copyright Notice

   Copyright (c) 2026 The SAACP Authors. All rights reserved.

Table of Contents

   1.  Introduction
   2.  Conventions and Terminology
   3.  Design Thesis
   4.  Wire Format
       4.1  MEASC Header (v1, 128 bytes)
       4.2  MEASC Header (v2, 160 bytes)
       4.3  SAACPFrame Application Header (101 bytes)
       4.4  Full Packet Layout
   5.  Cryptography
       5.1  Session Key Derivation (HKDF-SHA256)
       5.2  Epoch Rotation and Forward Secrecy
       5.3  IV Derivation
       5.4  Replay Protection (PSN Bitmap)
       5.5  MEASC v2 Packet Chaining
       5.6  Post-Quantum Hybrid Handshake
   6.  The Security Gate Pipeline (Authorization Invariance)
       6.1  Gate 0   — Cryptographic Integrity
       6.2  Gate 1.0 — Capability Token Validation
       6.3  Gate 2.5 — Kinetic Firewall
       6.4  Gate 1.5 — Intent Envelope
       6.5  Gate 0.5 — Financial Circuit Breaker
       6.6  Gate 3.0 — Lateral-Movement Guard
       6.7  Gate 4.0 — Prompt-Injection Scanner
       6.8  Gate 5.0 — Epistemic Circuit Breaker
       6.9  Gate 5.0b— Scope-Consistency Reinforcement
       6.10 Gate 6.0 — Immutable Audit Checkpoint
       6.11 Gate 9.0 — Schema Validation + Resource Governance
       6.12 Gate 11.0— AEGF Hop-Limit + Causal-Graph Governance
       6.13 Gate 12.0— CSCS Oscillation / Loop Detection
   7.  Identity and Trust
       7.1  Agent Credentials (FAITF)
       7.2  Capability Tokens (ACSVAF)
       7.3  W3C DIDs (Phase 2)
   8.  Streaming Continuation
   9.  Error Confidentiality (PECF)
   10. Multi-Tenant Contexts
   11. Security Considerations
   12. IANA Considerations
   13. References

1. Introduction

   Classical service-mesh security answers "is this connection from a
   trusted host?"  That is necessary but not sufficient for LLM-driven
   agents, where the threat is often a legitimately authenticated agent
   that has been prompt-injected, confused-deputized, or driven into a
   runaway loop.

   SAACP adds the agent-specific layer on top of transport security:
   authorization invariance, intent envelopes, injection scanning,
   epistemic circuit breakers, and causal-graph governance.  It is
   designed to run from cloud-scale Kubernetes meshes to edge/IoT
   microcontrollers, with a feature-gated dependency model that keeps
   the binary size minimal for resource-constrained deployments.

2. Conventions and Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in
   BCP 14 [RFC2119] [RFC8174].

   Terms:
   - Agent: An autonomous AI system (LLM-driven or otherwise) that
     sends or receives SAACP frames.
   - Session: A keyed, stateful connection between two agents.
   - Epoch: A time- or packet-threshold-bounded key rotation window.
   - PSN: Packet Sequence Number; monotonically increasing per session.
   - MEASC: Mandatory Encryption & Authenticated Sequence Control.
   - Gate: A mandatory security check in the pipeline.
   - Authorization Invariance: The property that ALL mandatory gates
     execute on EVERY packet, in a fixed order, regardless of tier,
     agent identity, or operator configuration.

3. Design Thesis

   SAACP's core invariant is Authorization Invariance:

      INVARIANT: The set of mandatory security gates, and their
      execution order, is a protocol constant.  Tiers and operator
      configuration affect ONLY telemetry verbosity and optional
      additional checks — NEVER which mandatory gates run.

   Any implementation that allows a gate to be skipped for ANY packet
   (including "trusted" or "internal" ones) is non-conformant.

4. Wire Format

4.1 MEASC Header (v1, 128 bytes)

   The v1 MEASC header is a 128-byte binary structure preceding the
   SAACPFrame application header.  Field offsets are in bytes; all
   integer fields are big-endian unless noted.

   | Offset | Size | Type    | Field                              |
   |--------|------|---------|------------------------------------|
   |  0     |  4   | bytes   | Epoch ID (u32 BE)                  |
   |  4     |  1   | uint8   | Reserved / version discriminator*  |
   |  5     |  1   | uint8   | Reserved (MUST be 0x00 in v1)      |
   |  6     |  2   | uint16  | Reserved                           |
   |  8     |  8   | uint64  | PSN (Packet Sequence Number, BE)   |
   | 16     | 16   | bytes   | Session ID (128-bit UUID)           |
   | 32     | 12   | bytes   | Reserved                           |
   | 44     | 32   | bytes   | Context Reference ID               |
   | 76     | 52   | bytes   | Reserved (MUST be zeroed in v1)    |

   * Byte 4 is the format-version discriminator:
     - 0x00: v1 (this table); 128-byte header.
     - 0x02: v2 (section 4.2); 160-byte header.
     Implementations MUST check byte 4 BEFORE reading any other field
     to determine the correct header length.

   Magic bytes b"SACP" are NOT in the MEASC header; they are in the
   SAACPFrame application header at offset 0 (section 4.3).

4.2 MEASC Header (v2, 160 bytes)

   The v2 header extends v1 with 32 bytes of packet-chaining state.
   Bytes 0..127 are identical to v1.  Byte 4 is set to 0x02.

   | Offset | Size | Type    | Field                              |
   |--------|------|---------|------------------------------------|
   | 0..127 | 128  | —       | v1 header fields (unchanged)       |
   | 128    | 24   | bytes   | prev_packet_hash (SHA-3-256[0:24]) |
   | 152    |  8   | uint64  | epoch_beacon (cluster floor, BE)   |

   prev_packet_hash:
      Truncated SHA-3-256 of the previous packet's 128-byte
      authenticated MEASC header (bytes 0..128, AFTER AEAD
      verification).  Senders set this to MEASC_V2_CHAIN_GENESIS
      (all-zero 24 bytes) for the first packet in a session.

   epoch_beacon:
      The sender's current cluster-wide revocation epoch floor
      counter.  Receivers MUST reject packets whose epoch_beacon
      is below the cluster's known floor (retrieved from the
      distributed StateBackend, cached locally with a 1-second TTL).

   Both fields are part of the AAD for the AEAD — any tampering is
   detected before the chain is consulted.

4.3 SAACPFrame Application Header (101 bytes)

   The SAACPFrame is a 101-byte binary application-layer header
   carrying per-packet metadata.  It follows immediately after the
   MEASC header.

   | Offset | Size | Type    | Field                              |
   |--------|------|---------|------------------------------------|
   |  0     |  4   | bytes   | Magic (b"SACP")                    |
   |  4     |  2   | uint16  | Schema ID                          |
   |  6     |  1   | uint8   | Status Code                        |
   |  7     |  1   | uint8   | Flags                              |
   |  8     |  1   | uint8   | Action Class                       |
   |  9     |  4   | uint32  | Payload Length                     |
   | 13     |  4   | uint32  | Sequence ID                        |
   | 17     | 16   | bytes   | Session UUID                       |
   | 33     | 24   | bytes   | W3C Traceparent                    |
   | 57     | 32   | bytes   | Context-State-ID                   |
   | 89     |  4   | uint32  | Context Version                    |
   | 93     |  8   | uint64  | Nonce                              |

   Action Class values:
   - 0x00: READ_ONLY  — idempotent, no side effects.
   - 0x01: REVERSIBLE — side effects that can be undone.
   - 0x02: IRREVERSIBLE — permanent or high-impact action.

4.4 Full Packet Layout

   A complete SAACP packet on the wire:

   [MEASC header: 128 or 160 bytes]
   [SAACPFrame prefix: 101 bytes]
   [AES-256-GCM auth tag: 16 bytes]
   [Adler-32 checksum: 4 bytes]      (over prefix + tag + ciphertext)
   [Ciphertext: payload_length bytes]

   Total minimum size (v1, zero payload):
     128 + 101 + 16 + 4 + 0 = 249 bytes.

   Total minimum size (v2, zero payload):
     160 + 101 + 16 + 4 + 0 = 281 bytes.

   Maximum payload size: 10,485,760 bytes (10 MiB).

5. Cryptography

5.1 Session Key Derivation

   Each session derives an AES-256-GCM traffic key per epoch using
   HKDF-SHA256 [RFC5869]:

      epoch_key = HKDF-SHA256(
          IKM  = session_secret XOR prev_epoch_key,
          salt = session_id,
          info = "SAACP-MEASC-epoch-key-v1" || epoch_id_BE4
      )

   For the initial epoch (no prev_epoch_key):
      IKM = session_secret.

5.2 Epoch Rotation and Forward Secrecy

   Epochs rotate when either:
   - MEASC_DEFAULT_EPOCH_TIME_SECONDS (600s) has elapsed, OR
   - MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD (1,048,576) packets sent.

   A MEASC_EPOCH_GRACE_PERIOD_SECONDS (60s) overlap allows in-flight
   packets from the old epoch to be accepted after rotation.  After
   the grace period, the old epoch key MUST be zeroized.

   The optional root-ratchet mixes the current epoch key into the root
   before deriving the next, ensuring that compromise of only the
   long-term root does not expose future epoch keys.

5.3 IV Derivation

   96-bit IV: SHA-256(nonce_BE8 || session_uuid || sequence_id_BE4)[0:12]

   Including sequence_id prevents IV collision at high packet rates
   (F4 fix; raises the varying-input space from 64 to 96 bits).

5.4 Replay Protection (PSN Bitmap)

   Each session maintains a 4096-entry sliding bitmap keyed on PSN.
   The bitmap check and mark operation MUST be atomic (held under the
   same Mutex lock) to prevent TOCTOU replay (C-1 fix).

   Pre-authentication peek: a read-only pre-check runs BEFORE AEAD
   decryption to reject obvious out-of-window PSNs without consuming
   bitmap state or budget (F1 fix).

   Invariants:
   - MEASC_MAX_PSN_ADVANCE (2048) MUST be < MEASC_REPLAY_WINDOW_SIZE
     (4096).  Violation would allow an attacker to skip the entire
     window in one packet, clearing all replay records.

5.5 MEASC v2 Packet Chaining

   The packet chain verifier supplements (NOT replaces) the PSN bitmap.
   It maintains a single 24-byte hash (vs. the bitmap's 512 bytes) per
   session:

      prev_packet_hash = SHA-3-256(authenticated_header_128)[0:24]

   The chain verifier catches cross-session splicing and roaming attacks
   where a session migrates to a new node that has no bitmap state.

   Genesis rule: a packet claiming prev_packet_hash = GENESIS (all
   zeros) is accepted on the first packet.  A genesis claim on a
   session that has already advanced MUST be rejected with
   PsnOutOfWindow.

5.6 Post-Quantum Hybrid Handshake

   SAACP uses hybrid PQC:
   - Key exchange:  ML-KEM-768 (FIPS 203) + X25519
   - Signatures:    ML-DSA-65 (FIPS 204) + Ed25519

   Both classical and PQC components MUST succeed; the combined shared
   secret is XOR-mixed (same as the epoch key mix) before being used
   as IKM for session_secret derivation.

6. The Security Gate Pipeline (Authorization Invariance)

   The following gates execute in the stated order on EVERY packet.
   Implementations MUST NOT skip, reorder, or merge gates.

6.1 Gate 0 — Cryptographic Integrity

   MUST verify: MEASC header fields, Adler-32 checksum, PSN peek
   (pre-auth, non-state-mutating), AES-256-GCM decryption with AAD =
   full SAACPFrame prefix.  MUST atomically check-and-accept the PSN
   in the bitmap AFTER AEAD verification.  MUST verify MEASC v2 packet
   chain and epoch_beacon floor (if v2).

6.2 Gate 1.0 — Capability Token Validation

   MUST verify: token signature (Ed25519 or HMAC-PSK), token expiry,
   token revocation status, action class ceiling, delegation depth
   (MUST NOT exceed 3 hops).

6.3 Gate 2.5 — Kinetic Firewall

   MUST verify: action class does not escalate beyond the session's
   established action class ceiling.

6.4 Gate 1.5 — Intent Envelope

   MUST verify: signed root-intent hash binding, intent drift (declared
   task text vs. root intent), dangerous verb detection.

6.5 Gate 0.5 — Financial Circuit Breaker

   MUST verify: declared token cost does not exceed the session's
   remaining budget cap.

6.6 Gate 3.0 — Lateral-Movement Guard

   MUST require a secondary IRREVERSIBLE-class token for cross-agent
   mutation operations.

6.7 Gate 4.0 — Prompt-Injection Scanner

   MUST: normalize Unicode (NFKC + homoglyph mapping + zero-width
   stripping), scan normalized payload with the compiled Aho-Corasick
   automaton of injection signatures, recurse up to 3 decode layers
   (base64/hex/percent-encoding).

6.8 Gate 5.0 — Epistemic Circuit Breaker

   MUST reject packets whose epistemic confidence claims violate
   Schema 3 constraints or fall below the declared minimum threshold.

6.9 Gate 5.0b — Scope-Consistency Reinforcement

   MUST verify that the payload's declared scope does not contradict
   the session's established context scope.

6.10 Gate 6.0 — Immutable Audit Checkpoint

   MUST append an HMAC-SHA256 hash-chained entry to the write-ahead
   log BEFORE delivering the payload to the receiving agent.  The
   audit chain MUST be verifiable offline from the WAL files alone.

6.11 Gate 9.0 — Schema Validation + Resource Governance

   MUST validate the payload against the declared Schema ID's compiled
   JSON schema.  MUST enforce RGC resource governance limits.

6.12 Gate 11.0 — AEGF Hop-Limit + Causal-Graph Governance

   MUST enforce the AEGF hop count (HC) limit.  MUST verify no cycle
   in the distributed execution graph rooted at this conversation ID.

6.13 Gate 12.0 — CSCS Oscillation / Loop Detection

   MUST detect and terminate oscillating/looping agent behaviors using
   the CSCS sliding window detector.

7. Identity and Trust

7.1 Agent Credentials (FAITF)

   Each agent is identified by an Ed25519 key pair + optional ML-DSA-65
   post-quantum key pair.  The FAITF subsystem manages:
   - AgentIdentity: (agent_id, public_key, trust_level, valid_from/until).
   - Delegation chains: max 3 hops; each hop reduces trust level by 1.
   - TrustStore: revocation-aware, with gossip propagation.

7.2 Capability Tokens (ACSVAF)

   Ed25519-signed or HMAC-PSK-authenticated capability tokens carry:
   - Issuer identity (iss), subject (sub), action class ceiling.
   - Expiry (exp), issued-at (iat), token ID (jti).
   - Optional: financial limit, tool access list, delegation parent JTI.

   Revoked JTIs MUST be rejected after revocation propagates via the
   gossip network (fanout=3, max_hops=5).

7.3 W3C Decentralized Identifiers (Phase 2)

   Phase 2 adds DID Method did:saacp:<network>:<fingerprint> where
   fingerprint = SHA-256(agent_public_key)[0:20] hex-encoded (40 chars).
   DID Document resolution is via DNS (TXT record or .well-known/did.json)
   with a DHT-based fallback.  No blockchain dependency.

8. Streaming Continuation

   Multi-frame payloads use status codes:
   - 0x17 STREAM_START:        first frame, establishes stream session ID.
   - 0x18 STREAM_CONTINUATION: subsequent frames.
   - 0x19 STREAM_END:          final frame; closes the stream.

   Limits:
   - Max total bytes: 5 MiB per stream.
   - Max duration: 120 seconds.
   - Max inter-frame gap: 10 seconds.
   - Max concurrent streams: 1000 global, 10 per agent.

9. Error Confidentiality (PECF)

   External error responses (to the network) MUST be opaque error codes
   only — no internal reason strings, no stack traces, no gate names.
   Internal error details are logged only to the immutable audit log
   (accessible only to authorized operators).  This prevents gate-timing
   side channels and information leakage to attackers.

10. Multi-Tenant Contexts

    A SaacpContext isolates all per-tenant state:
    - Trust engine, telemetry counters, audit chain, stream state,
      rate limits, revocations, loop/governor state.
    - N contexts per process with zero cross-talk.
    - Injection via handler entry points; legacy globals remain as
      deprecated shims.

11. Security Considerations

    Replay attacks: addressed by PSN bitmap (per-node) and v2 packet
    chain (cross-node).  Both MUST be enforced.

    Prompt injection: Gate 4.0's multi-layer Unicode normalization and
    Aho-Corasick scan addresses known LLM injection vectors.  New
    injection patterns MUST be propagated to all nodes via the rulepack
    distribution mechanism.

    Key compromise: KLMS manages key lifecycle.  Compromised keys MUST
    be revoked via the FAITF revocation system and propagated via gossip.
    Revoked JTIs MUST be rejected at Gate 1.0 after propagation.

    Side-channel attacks: PECF (section 9) prevents timing/error oracle
    attacks.  AES-256-GCM + HKDF epoch keys limit the blast radius of
    any single key compromise to one epoch.

    Memory exhaustion: all bounded structures (SessionEpochManager,
    replay window, affinity tracker, revocation set) have documented
    capacity caps and eviction policies.

12. IANA Considerations

    This document requests no IANA actions at this time.  A future
    revision will request registration of:
    - TCP/UDP port XXXX for SAACP.
    - ALPN protocol identifier "saacp/0.2" for TLS and QUIC transports.

13. References

    [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
               Requirement Levels", BCP 14, RFC 2119, March 1997.

    [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in
               RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.

    [RFC5869]  Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-
               Expand Key Derivation Function (HKDF)", RFC 5869, May 2010.

    [FIPS203]  National Institute of Standards and Technology,
               "Module-Lattice-Based Key-Encapsulation Mechanism
               Standard", FIPS 203, August 2024.

    [FIPS204]  National Institute of Standards and Technology,
               "Module-Lattice-Based Digital Signature Standard",
               FIPS 204, August 2024.

    [SP800-185] National Institute of Standards and Technology,
                "SHA-3 Derived Functions", NIST SP 800-185, December 2016.

Author's Address

   SAACP Working Group
   <https://github.com/shashankv762/SAACP_RUST>
```
