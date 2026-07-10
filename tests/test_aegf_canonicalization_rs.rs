//! test_aegf_canonicalization_rs.rs — AEGF binary pack/unpack tests
//!
//! Ports tests from Python tests/test_aegf_canonicalization.py
//!
//! Verifies:
//!   - AEGFMetadata::pack() produces exactly 120 bytes
//!   - Field byte offsets match the documented layout (README §4.2)
//!   - Format version constant matches Python
//!   - Pack/unpack roundtrip preserves all fields

use std::sync::Arc;

use saacp::{
    AEGFMetadata,
    AEGF_META_SIZE, AEGF_META_FORMAT_VERSION,
};

// ─── Size and Version ─────────────────────────────────────────────────────────

#[test]
fn test_format_version_assertion() {
    // Python parity: AEGF_META_FORMAT_VERSION == 1
    assert_eq!(AEGF_META_FORMAT_VERSION, 1,
        "AEGF_META_FORMAT_VERSION must be 1");
}

#[test]
fn test_aegf_meta_size_is_120() {
    assert_eq!(AEGF_META_SIZE, 120,
        "AEGF_META_SIZE must be 120 bytes (README §4.2)");
}

#[test]
fn test_pack_produces_120_bytes() {
    let meta = AEGFMetadata::new(
        "agent-alpha", "session-1", None, None, 300.0, 0, 0,
    );
    let packed = meta.pack();
    assert_eq!(packed.len(), 120,
        "pack() must produce exactly 120 bytes");
}

// ─── Field Offsets (README §4.2) ─────────────────────────────────────────────
//
//  Offset | Size | Field
//  -------|------|-------
//       0 |   16 | CID
//      16 |   16 | RID
//      32 |   16 | PRID
//      48 |   16 | SID
//      64 |   32 | OAID
//      96 |    2 | HC (hop count, big-endian u16)
//      98 |    2 | ED (execution depth, big-endian u16)
//     100 |    8 | TTL (f64 big-endian)
//     108 |   12 | Reserved (zeros)

#[test]
fn test_field_offsets_cid_at_0() {
    let meta = AEGFMetadata {
        cid: Arc::from("aabbccdd00112233aabbccdd00112233"),
        rid: "0".repeat(32),
        prid: "0".repeat(32),
        sid: Arc::from("0".repeat(32)),
        oaid: String::new(),
        hc: 0,
        ed: 0,
        ttl: 9999999999.0,
    };
    let packed = meta.pack();
    // CID is at bytes [0..16] — must not be all-zero
    let cid_bytes = &packed[0..16];
    assert!(!cid_bytes.iter().all(|&b| b == 0),
        "CID at offset 0 must be non-zero for non-empty CID");
}

#[test]
fn test_field_offset_hc_at_96() {
    let meta = AEGFMetadata {
        cid: Arc::from("0".repeat(32)),
        rid: "0".repeat(32),
        prid: "0".repeat(32),
        sid: Arc::from("0".repeat(32)),
        oaid: String::new(),
        hc: 0x0042,  // 66 decimal
        ed: 0,
        ttl: 9999999999.0,
    };
    let packed = meta.pack();
    let hc = u16::from_be_bytes([packed[96], packed[97]]);
    assert_eq!(hc, 0x0042, "HC at offset 96 must be 0x0042");
}

#[test]
fn test_field_offset_ed_at_98() {
    let meta = AEGFMetadata {
        cid: Arc::from("0".repeat(32)),
        rid: "0".repeat(32),
        prid: "0".repeat(32),
        sid: Arc::from("0".repeat(32)),
        oaid: String::new(),
        hc: 0,
        ed: 0x0007,
        ttl: 9999999999.0,
    };
    let packed = meta.pack();
    let ed = u16::from_be_bytes([packed[98], packed[99]]);
    assert_eq!(ed, 0x0007, "ED at offset 98 must be 0x0007");
}

#[test]
fn test_field_offset_ttl_at_100() {
    let ttl_val: f64 = 1_700_000_000.0;
    let meta = AEGFMetadata {
        cid: Arc::from("0".repeat(32)),
        rid: "0".repeat(32),
        prid: "0".repeat(32),
        sid: Arc::from("0".repeat(32)),
        oaid: String::new(),
        hc: 0,
        ed: 0,
        ttl: ttl_val,
    };
    let packed = meta.pack();
    let ttl_bytes: [u8; 8] = packed[100..108].try_into().unwrap();
    let roundtrip = f64::from_be_bytes(ttl_bytes);
    assert_eq!(roundtrip, ttl_val,
        "TTL at offset 100 must round-trip exactly");
}

#[test]
fn test_reserved_bytes_108_to_120_are_zero() {
    let meta = AEGFMetadata::new("agent", "session", None, None, 300.0, 5, 3);
    let packed = meta.pack();
    let reserved = &packed[108..120];
    assert!(reserved.iter().all(|&b| b == 0),
        "Reserved bytes [108..120] must be zero");
}

// ─── Pack / Unpack Roundtrip ──────────────────────────────────────────────────

#[test]
fn test_pack_unpack_roundtrip_preserves_hc_ed() {
    let meta = AEGFMetadata::new("agent-beta", "session-2", None, None, 600.0, 3, 2);
    let packed = meta.pack();
    let unpacked = AEGFMetadata::unpack(&packed)
        .expect("unpack must succeed for valid packed bytes");
    assert_eq!(unpacked.hc, meta.hc, "HC must survive pack/unpack");
    assert_eq!(unpacked.ed, meta.ed, "ED must survive pack/unpack");
}

#[test]
fn test_pack_unpack_roundtrip_preserves_oaid() {
    let meta = AEGFMetadata::new("agent-oaid-test", "session-3", None, None, 60.0, 0, 0);
    let packed = meta.pack();
    let unpacked = AEGFMetadata::unpack(&packed)
        .expect("unpack must succeed");
    assert_eq!(unpacked.oaid, meta.oaid, "OAID must survive pack/unpack");
}

#[test]
fn test_unpack_rejects_short_buffer() {
    let short = vec![0u8; 50]; // Less than 120 bytes
    let result = AEGFMetadata::unpack(&short);
    assert!(result.is_err(),
        "unpack of short buffer must return error");
}

#[test]
fn test_pack_deterministic_for_same_fields() {
    // Same struct fields → same bytes (deterministic serialization)
    let meta = AEGFMetadata {
        cid: Arc::from("aabbccdd00112233aabbccdd00112233"),
        rid: "1122334455667788aabbccdd00112233".to_string(),
        prid: "0".repeat(32),
        sid: Arc::from("fedcba9876543210fedcba9876543210"),
        oaid: "deterministic-agent".to_string(),
        hc: 7,
        ed: 3,
        ttl: 1_700_000_000.0,
    };
    let packed1 = meta.pack();
    let packed2 = meta.pack();
    assert_eq!(packed1, packed2, "pack() must be deterministic");
}

// ─── Derive (parent → child) ─────────────────────────────────────────────────

#[test]
fn test_derive_increments_hc_and_ed() {
    let parent = AEGFMetadata::new("parent-agent", "session-4", None, None, 300.0, 1, 2);
    let child = AEGFMetadata::derive(&parent, None).expect("derive must succeed");
    assert_eq!(child.hc, parent.hc + 1, "HC must increment on derive");
    assert_eq!(child.ed, parent.ed + 1, "ED must increment on derive");
    assert_eq!(child.cid, parent.cid, "CID must be inherited from parent");
    assert_eq!(child.prid, parent.rid, "Child PRID must equal parent RID");
}

#[test]
fn test_derive_new_oaid_overrides_parent() {
    let parent = AEGFMetadata::new("parent-agent", "session-5", None, None, 300.0, 0, 0);
    let child = AEGFMetadata::derive(&parent, Some("child-agent"))
        .expect("derive must succeed");
    assert_eq!(child.oaid, "child-agent", "New OAID must override parent's OAID");
}

#[test]
fn test_max_hc_prevents_derive() {
    let mut meta = AEGFMetadata::new("agent", "session", None, None, 300.0, 0, 0);
    meta.hc = 65535; // MAX_HC
    let result = AEGFMetadata::derive(&meta, None);
    assert!(result.is_err(), "Derive at MAX_HC must return error");
}
