//! test_klms_rs.rs — KLMS key lifecycle tests
//!
//! Ports Python: tests/test_klms.py
//! Key registration, rotation, revocation, expiry, audit.

use saacp::{
    KeyRegistry, KeyLifecycleManager, KeyAlgorithm, KeyCategory, KeyStatus,
    make_kid, make_descriptor,
    KLMS_DEFAULT_REGISTRY, KLMS_DEFAULT_POLICY,
};

fn register_fresh(registry: &KeyRegistry) -> String {
    let kid = make_kid();
    let desc = make_descriptor(
        &kid,
        KeyAlgorithm::Ed25519,
        KeyCategory::TokenSigning,
        vec![0xAAu8; 32],
        None, None, None,
    ).unwrap();
    registry.register(desc).unwrap();
    kid
}

// ─── KeyRegistry ──────────────────────────────────────────────────────────────

#[test]
fn test_register_and_get() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    let desc = reg.get_active(&kid);
    assert!(desc.is_ok());
    assert_eq!(desc.unwrap().kid, kid);
}

#[test]
fn test_list_active_kids_contains_registered() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    assert!(reg.list_active_kids().contains(&kid));
}

#[test]
fn test_register_multiple_keys() {
    let reg = KeyRegistry::new();
    let mut kids = Vec::new();
    for _ in 0..5 {
        kids.push(register_fresh(&reg));
    }
    let active = reg.list_active_kids();
    for kid in &kids {
        assert!(active.contains(kid));
    }
}

#[test]
fn test_duplicate_registration_rejected() {
    let reg = KeyRegistry::new();
    let kid = make_kid();
    let desc = make_descriptor(&kid, KeyAlgorithm::Ed25519, KeyCategory::TokenSigning, vec![0u8; 32], None, None, None).unwrap();
    reg.register(desc).unwrap();
    let desc2 = make_descriptor(&kid, KeyAlgorithm::Ed25519, KeyCategory::TokenSigning, vec![1u8; 32], None, None, None).unwrap();
    let res = reg.register(desc2);
    assert!(res.is_err(), "Duplicate kid must be rejected");
}

#[test]
fn test_get_unknown_kid_returns_err() {
    let reg = KeyRegistry::new();
    assert!(reg.get_active(&"0".repeat(32)).is_err());
}

// ─── KeyLifecycleManager ──────────────────────────────────────────────────────

#[test]
fn test_rotate_key_increments_version() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    let mgr = KeyLifecycleManager::new(reg, None);
    let rotated = mgr.rotate_key(&kid, vec![0xBBu8; 32], KeyAlgorithm::Ed25519).unwrap();
    assert_eq!(rotated.version, 2);
}

#[test]
fn test_rotate_key_changes_bytes() {
    let reg = KeyRegistry::new();
    let kid = make_kid();
    let original_bytes = vec![0x11u8; 32];
    let desc = make_descriptor(&kid, KeyAlgorithm::Ed25519, KeyCategory::TokenSigning, original_bytes.clone(), None, None, None).unwrap();
    reg.register(desc).unwrap();
    let mgr = KeyLifecycleManager::new(reg, None);
    let new_bytes = vec![0x22u8; 32];
    let rotated = mgr.rotate_key(&kid, new_bytes.clone(), KeyAlgorithm::Ed25519).unwrap();
    assert_eq!(rotated.key_material, new_bytes);
}

#[test]
fn test_rotate_unknown_key_fails() {
    let reg = KeyRegistry::new();
    let mgr = KeyLifecycleManager::new(reg, None);
    let res = mgr.rotate_key(&"a".repeat(32), vec![0u8; 32], KeyAlgorithm::Ed25519);
    assert!(res.is_err());
}

// ─── Revocation ───────────────────────────────────────────────────────────────

#[test]
fn test_revoke_key_returns_record() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    let mgr = KeyLifecycleManager::new(reg, None);
    let record = mgr.revoke_key(&kid, "end-of-life").unwrap();
    assert_eq!(record.kid, kid);
    assert_eq!(record.reason, "end-of-life");
}

#[test]
fn test_revocation_log_not_empty_after_revoke() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    let mgr = KeyLifecycleManager::new(reg, None);
    mgr.revoke_key(&kid, "compromised").unwrap();
    assert!(!mgr.get_revocation_log().is_empty());
}

#[test]
fn test_revoke_unknown_key_fails() {
    let reg = KeyRegistry::new();
    let mgr = KeyLifecycleManager::new(reg, None);
    let res = mgr.revoke_key("nonexistent-kid", "reason");
    assert!(res.is_err());
}

#[test]
fn test_revocation_log_grows_with_multiple_revocations() {
    let reg = KeyRegistry::new();
    let kid1 = register_fresh(&reg);
    let kid2 = register_fresh(&reg);
    let mgr = KeyLifecycleManager::new(reg, None);
    mgr.revoke_key(&kid1, "reason-1").unwrap();
    mgr.revoke_key(&kid2, "reason-2").unwrap();
    assert_eq!(mgr.get_revocation_log().len(), 2);
}

// ─── Key Algorithms / Categories ─────────────────────────────────────────────

#[test]
fn test_aes256gcm_key_category_memory() {
    let reg = KeyRegistry::new();
    let kid = make_kid();
    let desc = make_descriptor(&kid, KeyAlgorithm::Aes256Gcm, KeyCategory::MemoryProtection, vec![0u8; 32], None, None, None).unwrap();
    reg.register(desc).unwrap();
    let active = reg.get_active(&kid).unwrap();
    assert!(matches!(active.algorithm, KeyAlgorithm::Aes256Gcm));
}

#[test]
fn test_hkdf_key_category_epoch_traffic() {
    let reg = KeyRegistry::new();
    let kid = make_kid();
    let desc = make_descriptor(&kid, KeyAlgorithm::HkdfSha256, KeyCategory::EpochTraffic, vec![0u8; 32], None, None, None).unwrap();
    reg.register(desc).unwrap();
    let active = reg.get_active(&kid).unwrap();
    assert!(matches!(active.algorithm, KeyAlgorithm::HkdfSha256));
}

#[test]
fn test_hmac_key_category_psk() {
    let reg = KeyRegistry::new();
    let kid = make_kid();
    let desc = make_descriptor(&kid, KeyAlgorithm::HmacSha256, KeyCategory::Psk, vec![0u8; 32], None, None, None).unwrap();
    reg.register(desc).unwrap();
    let active = reg.get_active(&kid).unwrap();
    assert!(matches!(active.category, KeyCategory::Psk));
}

// ─── Status transitions ───────────────────────────────────────────────────────

#[test]
fn test_active_after_register() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    let desc = reg.get_active(&kid).unwrap();
    assert!(matches!(desc.status, KeyStatus::Active));
}

#[test]
fn test_rotated_descriptor_version_2() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    let mgr = KeyLifecycleManager::new(reg, None);
    let new_desc = mgr.rotate_key(&kid, vec![0xFFu8; 32], KeyAlgorithm::Aes256Gcm).unwrap();
    assert!(matches!(new_desc.status, KeyStatus::Active));
    assert_eq!(new_desc.version, 2);
}

#[test]
fn test_revoke_all_versions_marks_compromised() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    let mgr = KeyLifecycleManager::new(reg, None);
    mgr.revoke_key(&kid, "compromised").unwrap();
    let audit = mgr.audit_key_lifecycle(&kid);
    assert!(!audit.is_empty());
    assert!(audit.iter().all(|e| e.status == "COMPROMISED"));
}

// ─── make_kid / make_descriptor ───────────────────────────────────────────────

#[test]
fn test_make_kid_not_empty() {
    let kid = make_kid();
    assert!(!kid.is_empty());
}

#[test]
fn test_make_kid_32_chars() {
    let kid = make_kid();
    assert_eq!(kid.len(), 32);
}

#[test]
fn test_make_kid_unique() {
    let k1 = make_kid();
    let k2 = make_kid();
    assert_ne!(k1, k2);
}

#[test]
fn test_make_descriptor_valid() {
    let kid = make_kid();
    let res = make_descriptor(&kid, KeyAlgorithm::Ed25519, KeyCategory::TokenSigning, vec![1u8; 32], None, None, None);
    assert!(res.is_ok());
}

#[test]
fn test_make_descriptor_bad_kid_fails() {
    let res = make_descriptor("INVALID", KeyAlgorithm::Ed25519, KeyCategory::TokenSigning, vec![0u8; 32], None, None, None);
    assert!(res.is_err(), "Non-hex kid must fail validation");
}

// ─── Audit ────────────────────────────────────────────────────────────────────

#[test]
fn test_audit_key_lifecycle_has_one_entry() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    let mgr = KeyLifecycleManager::new(reg, None);
    let audit = mgr.audit_key_lifecycle(&kid);
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].status, "ACTIVE");
}

#[test]
fn test_audit_after_rotation_has_two_entries() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    let mgr = KeyLifecycleManager::new(reg, None);
    mgr.rotate_key(&kid, vec![0xCCu8; 32], KeyAlgorithm::Ed25519).unwrap();
    let audit = mgr.audit_key_lifecycle(&kid);
    assert_eq!(audit.len(), 2);
}

// ─── Propagation ─────────────────────────────────────────────────────────────

#[test]
fn test_propagate_revocations_count() {
    let reg = KeyRegistry::new();
    let kid = register_fresh(&reg);
    let mgr = KeyLifecycleManager::new(reg, None);
    mgr.revoke_key(&kid, "superseded").unwrap();
    let mut propagated_kids = Vec::new();
    let count = mgr.propagate_revocations(Some(|r: &saacp::KeyRevocationRecord| {
        propagated_kids.push(r.kid.clone());
    }));
    assert_eq!(count, 1);
    assert!(propagated_kids.contains(&kid));
}

// ─── Default statics ─────────────────────────────────────────────────────────

#[test]
fn test_klms_default_registry_exists() {
    let _ = KLMS_DEFAULT_REGISTRY.list_active_kids();
}

#[test]
fn test_klms_default_policy_exists() {
    let _ = KLMS_DEFAULT_POLICY.max_age_seconds;
}
