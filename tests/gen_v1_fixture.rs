//! One-shot generator for the pinned v1 audit-log fixture (Phase 6 regression guard).
//!
//! Run ONCE against the pre-Phase-6 (v1-only) code to mint
//! `tests/fixtures/audit_v1_pinned.jsonl` + its sentinel. The fixture is then
//! checked in, and `test_audit_v1_fixture_rs.rs` asserts that every later
//! version of `verify_chain_disk` still accepts it byte-for-byte.
//!
//! `#[ignore]` on purpose: regenerating the fixture from post-change code would
//! defeat the entire point of pinning it. Run explicitly with
//! `cargo test --test gen_v1_fixture -- --ignored`.

use std::time::Duration;

#[test]
#[ignore = "one-shot fixture generator; run explicitly against v1 code only"]
fn generate_pinned_v1_fixture() {
    // The generator must write the real fixture path, not a redirected test dir.
    std::env::remove_var("SAACP_TEST_LOG_DIR");

    let dir = std::path::Path::new("tests/fixtures");
    std::fs::create_dir_all(dir).unwrap();
    let log = dir.join("audit_v1_pinned.jsonl");
    let sentinel = dir.join("audit_v1_pinned.sentinel");
    let _ = std::fs::remove_file(&log);
    let _ = std::fs::remove_file(&sentinel);

    let audit = saacp::security::ImmutableAuditLog::with_paths(
        log.to_str().unwrap(),
        sentinel.to_str().unwrap(),
    );
    let secret = b"pinned-v1-fixture-issuer-secret!";
    for i in 0..50u32 {
        audit.append_event(
            secret,
            &format!("agent-src-{i:03}"),
            &format!("agent-dst-{i:03}"),
            &format!("sig{i:03}"),
            &format!("intent-number-{i}"),
            &format!("{:032x}-{:016x}-01", i, i),
        );
    }
    assert!(audit.flush(Duration::from_secs(5)), "WAL flush must ack");
    assert!(
        audit.verify_chain_disk(secret),
        "generator must emit a chain that verifies under the code that wrote it",
    );
    println!("wrote {} ({} events)", log.display(), audit.event_count());
}
