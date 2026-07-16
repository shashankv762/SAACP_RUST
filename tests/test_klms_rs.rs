//! test_klms_rs.rs — KLMS key lifecycle tests
//!
//! Ports Python: tests/test_klms.py
//! Key registration, rotation, revocation, expiry, audit.

use saacp::{
    KeyRegistry, KeyLifecycleManager, KeyAlgorithm, KeyCategory, KeyStatus,
    KeyRotationPolicy,
    make_kid, make_descriptor, default_key_generator,
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
    assert_eq!(rotated.key_material.as_slice(), new_bytes.as_slice());
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

// ─── Automatic key rotation (Phase 5, item 4) ────────────────────────────────

fn register_with_expiry(registry: &KeyRegistry, expires_at: f64, created_at: f64) -> String {
    let kid = make_kid();
    let desc = saacp::KeyDescriptor::new(
        kid.clone(),
        1,
        KeyAlgorithm::Ed25519,
        KeyCategory::TokenSigning,
        vec![0xABu8; 32],
        created_at,
        expires_at,
        None,
        KeyStatus::Active,
        std::collections::HashMap::new(),
    ).unwrap();
    registry.register(desc).unwrap();
    kid
}

#[test]
fn test_list_expiring_returns_keys_within_lead_window() {
    let reg = KeyRegistry::new();
    let now = 1_000_000.0;
    // Expires in 100s — well within a 200s lead window.
    let due_kid = register_with_expiry(&reg, now + 100.0, now - 1000.0);
    // Expires in 10,000s — far outside a 200s lead window.
    let far_kid = register_with_expiry(&reg, now + 10_000.0, now - 1000.0);

    let expiring = reg.list_expiring(200.0, now);
    let expiring_kids: Vec<&String> = expiring.iter().map(|(k, _)| k).collect();

    assert!(expiring_kids.contains(&&due_kid), "key within the lead window must be listed");
    assert!(!expiring_kids.contains(&&far_kid), "key far from expiry must not be listed");
}

#[test]
fn test_list_expiring_excludes_non_active_keys() {
    let reg = KeyRegistry::new();
    let now = 1_000_000.0;

    // A Revoked descriptor whose expires_at would otherwise put it well within the lead
    // window — registered directly with Revoked status (not via rotate_key/revoke_key,
    // which live on KeyLifecycleManager and take the registry by value) so this test
    // isolates `KeyRegistry::list_expiring`'s own status filter.
    let revoked_kid = make_kid();
    let revoked_desc = saacp::KeyDescriptor::new(
        revoked_kid.clone(),
        1,
        KeyAlgorithm::Ed25519,
        KeyCategory::TokenSigning,
        vec![0xCDu8; 32],
        now - 1000.0,
        now + 100.0,
        None,
        KeyStatus::Revoked,
        std::collections::HashMap::new(),
    ).unwrap();
    reg.register(revoked_desc).unwrap();

    // A genuinely Active descriptor within the same window, for contrast.
    let active_kid = register_with_expiry(&reg, now + 100.0, now - 1000.0);

    let expiring = reg.list_expiring(200.0, now);
    let expiring_kids: Vec<&String> = expiring.iter().map(|(k, _)| k).collect();

    assert!(!expiring_kids.contains(&&revoked_kid), "a Revoked key must never appear in list_expiring");
    assert!(expiring_kids.contains(&&active_kid), "sanity: the Active key in the same window IS listed");
}

#[test]
fn test_sweep_and_rotate_noop_when_auto_rotate_disabled() {
    let reg = KeyRegistry::new();
    let now = 1_000_000.0;
    let kid = register_with_expiry(&reg, now + 10.0, now - 1000.0);

    let policy = KeyRotationPolicy {
        auto_rotate: false,
        renewal_lead_seconds: 1000.0,
        ..Default::default()
    };
    let mgr = KeyLifecycleManager::new(reg, Some(policy));

    let rotated = mgr.sweep_and_rotate(now, default_key_generator);
    assert!(rotated.is_empty(), "sweep_and_rotate must be a no-op when auto_rotate is false");

    // The key must still be Active version 1 — untouched.
    let audit = mgr.audit_key_lifecycle(&kid);
    assert_eq!(audit.len(), 1, "no rotation should have created a second version");
    assert_eq!(audit[0].version, 1);
    assert_eq!(audit[0].status, "ACTIVE");
}

#[test]
fn test_sweep_and_rotate_full_cycle_with_injectable_clock() {
    let reg = KeyRegistry::new();
    let now = 1_000_000.0;
    // Simulate a key issued long ago whose 24h TTL has almost elapsed (23.9 hours in).
    let created_at = now - 23.9 * 3600.0;
    let expires_at = created_at + 24.0 * 3600.0;
    let kid = register_with_expiry(&reg, expires_at, created_at);

    let policy = KeyRotationPolicy {
        auto_rotate: true,
        max_age_seconds: 86_400.0,
        renewal_lead_seconds: 86_400.0 * 0.1, // default 10% lead (2.4h)
        ..Default::default()
    };
    let mgr = KeyLifecycleManager::new(reg, Some(policy));

    let rotated = mgr.sweep_and_rotate(now, default_key_generator);
    assert_eq!(rotated, vec![kid.clone()], "the near-expiry key must be rotated");

    let audit = mgr.audit_key_lifecycle(&kid);
    assert_eq!(audit.len(), 2, "rotation must produce a ROTATED v1 and an ACTIVE v2");
    assert_eq!(audit[0].status, "ROTATED");
    assert_eq!(audit[1].status, "ACTIVE");
    assert_eq!(audit[1].version, 2);
}

#[test]
fn test_sweep_and_rotate_never_touches_non_active_keys() {
    let reg = KeyRegistry::new();
    let now = 1_000_000.0;
    let kid = register_with_expiry(&reg, now + 10.0, now - 1000.0);

    let policy = KeyRotationPolicy {
        auto_rotate: true,
        renewal_lead_seconds: 1000.0,
        ..Default::default()
    };
    let mgr = KeyLifecycleManager::new(reg, Some(policy));

    // Revoke it first — it's now Compromised, not Active, even though it's within the
    // renewal lead window by expires_at alone.
    mgr.revoke_key(&kid, "compromised").unwrap();

    let rotated = mgr.sweep_and_rotate(now, default_key_generator);
    assert!(
        rotated.is_empty(),
        "sweep_and_rotate must never rotate a Revoked/Compromised key back to Active"
    );

    let audit = mgr.audit_key_lifecycle(&kid);
    assert_eq!(audit.len(), 1, "no new version should have been created");
    assert_eq!(audit[0].status, "COMPROMISED");
}

#[test]
fn test_concurrent_sweep_and_rotate_does_not_double_rotate() {
    use std::sync::Arc;
    use std::thread;

    let reg = KeyRegistry::new();
    let now = 1_000_000.0;
    let created_at = now - 23.9 * 3600.0;
    let expires_at = created_at + 24.0 * 3600.0;
    let kid = register_with_expiry(&reg, expires_at, created_at);

    let policy = KeyRotationPolicy {
        auto_rotate: true,
        max_age_seconds: 86_400.0,
        renewal_lead_seconds: 86_400.0 * 0.1,
        ..Default::default()
    };
    let mgr = Arc::new(KeyLifecycleManager::new(reg, Some(policy)));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let mgr = Arc::clone(&mgr);
        handles.push(thread::spawn(move || mgr.sweep_and_rotate(now, default_key_generator)));
    }
    let results: Vec<Vec<String>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let total_rotations: usize = results.iter().map(|r| r.len()).sum();
    assert_eq!(
        total_rotations, 1,
        "exactly one of the concurrent sweep_and_rotate calls must win the (kid, version+1) \
         registration race — KeyRegistry::register already rejects a duplicate (kid, version) \
         pair, which this asserts rather than assumes"
    );

    let audit = mgr.audit_key_lifecycle(&kid);
    assert_eq!(audit.len(), 2, "only one rotation must have taken effect, not one per thread");
}
