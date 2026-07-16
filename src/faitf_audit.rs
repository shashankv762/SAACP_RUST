// SAACP Rust Implementation — FAITF Audit Log Extension
// Translated from SAACP/src/saacp/faitf_audit.py
//!
//! Extends ImmutableAuditLog with structured event types for:
//! - Credential issuance (including key fingerprints)
//! - Authentication events (trust anchor used, session binding)
//! - Revocation events (agent, credential, trust anchor)
//! - Key rotation / credential renewal
//! - Federation events (agreement registration, cross-domain auth)
//! - Delegation events (chain issuance, depth, constraint summary)



use std::borrow::Cow;
use std::sync::LazyLock;

use crate::security::ImmutableAuditLog;

/// L-14/L-24 fix: fallback HMAC key used when no PSK is available in FAITF-only
/// deployments (every `log_*` function below accepts an optional `session_key`; this is
/// only ever used when the caller passes `None`). Previously a fixed compile-time
/// constant shared byte-for-byte by every deployment of this crate — a real weakness,
/// since anyone who has read this source (it's open source) could forge/verify
/// sentinel-keyed audit entries for any deployment that never configures an explicit
/// session key. Resolution order, computed once and cached for this process's lifetime:
/// 1. `SAACP_FAITF_AUDIT_KEY` env var, hex-encoded, if present and decodes to >= 32
///    bytes — lets an operator pin a real deployment-specific secret (L-24).
/// 2. Otherwise, a securely-random 32-byte value generated via `OsRng` at first use
///    (L-14) — unpredictable and unique per process, so two instances (or the same
///    instance across restarts without an explicit secret configured) never share a
///    guessable key.
///
/// Cached in a `LazyLock` (not regenerated per call) because every event logged within
/// one process's lifetime must use the same fallback key for the audit chain's HMAC to
/// be internally self-consistent.
static FAITF_AUDIT_KEY: LazyLock<Vec<u8>> = LazyLock::new(|| {
    if let Ok(hex_key) = std::env::var("SAACP_FAITF_AUDIT_KEY") {
        if let Ok(bytes) = hex::decode(hex_key.trim()) {
            if bytes.len() >= 32 {
                return bytes;
            }
        }
    }
    use rand::RngCore;
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
});

/// L-27 fix: strip ASCII control characters (C0 range `0x00-0x1F` plus `0x7F`) from a
/// caller-supplied string before it is interpolated into an `intent` line that becomes
/// an audit log entry. Every `log_*` function below formats free-form,
/// potentially-attacker-influenced strings (agent IDs, domains, reasons, ...) directly
/// into a line of a line-oriented JSONL log; an embedded newline/carriage-return could
/// otherwise inject fake-looking extra "log lines" or corrupt downstream log
/// parsing/SIEM ingestion. Only allocates (`Cow::Owned`) when a control character is
/// actually present, so the common clean-input path stays zero-copy.
fn sanitize_for_audit(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_control()) {
        Cow::Owned(s.chars().filter(|c| !c.is_ascii_control()).collect())
    } else {
        Cow::Borrowed(s)
    }
}

/// Structured FAITF event logger that writes to ImmutableAuditLog.
pub struct FAITFAuditLog;

impl FAITFAuditLog {
    /// Record a credential issuance event.
    #[allow(clippy::too_many_arguments)]
    pub fn log_credential_issuance(
        audit_log: &ImmutableAuditLog,
        agent_id: &str,
        issuer_id: &str,
        credential_version: u64,
        key_fingerprint: &str,
        valid_until: f64,
        trust_model: &str,
        session_key: Option<&[u8]>,
        traceparent: &str,
    ) {
        let agent_id_s = sanitize_for_audit(agent_id);
        let issuer_id_s = sanitize_for_audit(issuer_id);
        let trust_model_s = sanitize_for_audit(trust_model);
        let intent = format!(
            "[FAITF:ISSUANCE] agent={} issuer={} version={} key={}... valid_until={:.0} model={}",
            agent_id_s,
            issuer_id_s,
            credential_version,
            &key_fingerprint[..16.min(key_fingerprint.len())],
            valid_until,
            trust_model_s
        );
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY.as_slice());
        audit_log.append_signed(
            key,
            issuer_id,
            agent_id,
            key_fingerprint,
            &intent,
            traceparent,
        );
    }

    /// Record a successful FAITF authentication event.
    #[allow(clippy::too_many_arguments)]
    pub fn log_authentication(
        audit_log: &ImmutableAuditLog,
        agent_id: &str,
        session_id: &str,
        trust_anchor_used: &str,
        trust_model: &str,
        cross_domain: bool,
        source_domain: &str,
        target_domain: &str,
        session_key: Option<&[u8]>,
        traceparent: &str,
    ) {
        let agent_id_s = sanitize_for_audit(agent_id);
        let trust_anchor_used_s = sanitize_for_audit(trust_anchor_used);
        let trust_model_s = sanitize_for_audit(trust_model);
        let domain_info = if cross_domain {
            format!(
                " cross_domain={}->{}",
                sanitize_for_audit(source_domain),
                sanitize_for_audit(target_domain)
            )
        } else {
            String::new()
        };
        let intent = format!(
            "[FAITF:AUTH] agent={} session={}... anchor={} model={}{}",
            agent_id_s,
            &session_id[..16.min(session_id.len())],
            trust_anchor_used_s,
            trust_model_s,
            domain_info
        );
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY.as_slice());
        audit_log.append_signed(
            key,
            agent_id,
            trust_anchor_used,
            session_id,
            &intent,
            traceparent,
        );
    }

    /// Record a revocation event.
    pub fn log_revocation(
        audit_log: &ImmutableAuditLog,
        agent_id: &str,
        revoker_id: &str,
        reason: &str,
        credential_fingerprint: &str,
        session_key: Option<&[u8]>,
        traceparent: &str,
    ) {
        let agent_id_s = sanitize_for_audit(agent_id);
        let revoker_id_s = sanitize_for_audit(revoker_id);
        let reason_s = sanitize_for_audit(reason);
        let scope = if !credential_fingerprint.is_empty() {
            format!("cred={}...", &credential_fingerprint[..16.min(credential_fingerprint.len())])
        } else {
            "agent-wide".to_string()
        };
        let intent = format!(
            "[FAITF:REVOCATION] agent={} revoker={} scope={} reason={}",
            agent_id_s, revoker_id_s, scope, reason_s
        );
        let token_sig = if !credential_fingerprint.is_empty() {
            credential_fingerprint
        } else {
            "agent-wide"
        };
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY.as_slice());
        audit_log.append_signed(
            key,
            revoker_id,
            agent_id,
            token_sig,
            &intent,
            traceparent,
        );
    }

    /// Record a key rotation / credential renewal event.
    #[allow(clippy::too_many_arguments)]
    pub fn log_rotation(
        audit_log: &ImmutableAuditLog,
        agent_id: &str,
        old_key_fingerprint: &str,
        new_key_fingerprint: &str,
        old_version: u64,
        new_version: u64,
        issuer_id: &str,
        emergency: bool,
        session_key: Option<&[u8]>,
        traceparent: &str,
    ) {
        let agent_id_s = sanitize_for_audit(agent_id);
        let issuer_id_s = sanitize_for_audit(issuer_id);
        let mode = if emergency { "EMERGENCY" } else { "SCHEDULED" };
        let intent = format!(
            "[FAITF:ROTATION:{}] agent={} issuer={} old_key={}... new_key={}... v{}->v{}",
            mode,
            agent_id_s,
            issuer_id_s,
            &old_key_fingerprint[..16.min(old_key_fingerprint.len())],
            &new_key_fingerprint[..16.min(new_key_fingerprint.len())],
            old_version,
            new_version
        );
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY.as_slice());
        audit_log.append_signed(
            key,
            issuer_id,
            agent_id,
            new_key_fingerprint,
            &intent,
            traceparent,
        );
    }

    /// Record a federation trust mesh event.
    #[allow(clippy::too_many_arguments)]
    pub fn log_federation_event(
        audit_log: &ImmutableAuditLog,
        event_type: &str,
        source_domain: &str,
        target_domain: &str,
        agreement_id: &str,
        result: &str,
        session_key: Option<&[u8]>,
        traceparent: &str,
    ) {
        let event_type_s = sanitize_for_audit(event_type);
        let source_domain_s = sanitize_for_audit(source_domain);
        let target_domain_s = sanitize_for_audit(target_domain);
        let result_s = sanitize_for_audit(result);
        let agreement_id_s = sanitize_for_audit(agreement_id);
        let intent = format!(
            "[FAITF:FEDERATION:{}] {}->{} agreement={} result={}",
            event_type_s,
            source_domain_s,
            target_domain_s,
            if agreement_id.is_empty() { "no_agreement" } else { agreement_id_s.as_ref() },
            result_s
        );
        let token_sig = if agreement_id.is_empty() {
            "no_agreement"
        } else {
            agreement_id
        };
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY.as_slice());
        audit_log.append_signed(
            key,
            source_domain,
            target_domain,
            token_sig,
            &intent,
            traceparent,
        );
    }

    /// Record a credential delegation event.
    pub fn log_delegation(
        audit_log: &ImmutableAuditLog,
        parent_agent_id: &str,
        child_agent_id: &str,
        depth: u32,
        constraints_summary: &str,
        session_key: Option<&[u8]>,
        traceparent: &str,
    ) {
        let parent_agent_id_s = sanitize_for_audit(parent_agent_id);
        let child_agent_id_s = sanitize_for_audit(child_agent_id);
        let constraints_summary_s = sanitize_for_audit(constraints_summary);
        let intent = format!(
            "[FAITF:DELEGATION] parent={} child={} depth={} constraints={}",
            parent_agent_id_s, child_agent_id_s, depth, constraints_summary_s
        );
        let token_sig = format!("depth:{}", depth);
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY.as_slice());
        audit_log.append_signed(
            key,
            parent_agent_id,
            child_agent_id,
            &token_sig,
            &intent,
            traceparent,
        );
    }

    /// Record a trust anchor registration or removal.
    pub fn log_trust_anchor_change(
        audit_log: &ImmutableAuditLog,
        event_type: &str,
        anchor_id: &str,
        key_fingerprint: &str,
        trust_model: &str,
        session_key: Option<&[u8]>,
        traceparent: &str,
    ) {
        let event_type_s = sanitize_for_audit(event_type);
        let anchor_id_s = sanitize_for_audit(anchor_id);
        let trust_model_s = sanitize_for_audit(trust_model);
        let intent = format!(
            "[FAITF:ANCHOR:{}] anchor={} key={}... model={}",
            event_type_s,
            anchor_id_s,
            &key_fingerprint[..16.min(key_fingerprint.len())],
            trust_model_s
        );
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY.as_slice());
        audit_log.append_signed(
            key,
            "TrustStore",
            anchor_id,
            key_fingerprint,
            &intent,
            traceparent,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_log() -> ImmutableAuditLog {
        ImmutableAuditLog::new("test-faitf-audit.log")
    }

    #[test]
    fn test_log_credential_issuance() {
        let log = test_log();
        FAITFAuditLog::log_credential_issuance(
            &log,
            "agent-1",
            "issuer-1",
            1,
            "abcdef1234567890abcdef",
            1_700_000_000.0,
            "direct",
            None,
            &"0".repeat(48),
        );
        assert!(log.entry_count() > 0);
    }

    #[test]
    fn test_log_authentication() {
        let log = test_log();
        FAITFAuditLog::log_authentication(
            &log,
            "agent-1",
            "session-1234567890abcdef",
            "anchor-1",
            "direct",
            false,
            "",
            "",
            None,
            &"0".repeat(48),
        );
        assert!(log.entry_count() > 0);
    }

    #[test]
    fn test_log_authentication_cross_domain() {
        let log = test_log();
        FAITFAuditLog::log_authentication(
            &log,
            "agent-1",
            "session-1234567890abcdef",
            "anchor-1",
            "federation",
            true,
            "domain-a",
            "domain-b",
            None,
            &"0".repeat(48),
        );
        assert!(log.entry_count() > 0);
    }

    #[test]
    fn test_log_revocation() {
        let log = test_log();
        FAITFAuditLog::log_revocation(
            &log,
            "agent-1",
            "revoker-1",
            "compromised",
            "fingerprint-abcdef12",
            None,
            &"0".repeat(48),
        );
        assert!(log.entry_count() > 0);
    }

    #[test]
    fn test_log_revocation_agent_wide() {
        let log = test_log();
        FAITFAuditLog::log_revocation(
            &log, "agent-1", "revoker-1", "policy-violation", "", None, &"0".repeat(48),
        );
        assert!(log.entry_count() > 0);
    }

    #[test]
    fn test_log_rotation() {
        let log = test_log();
        FAITFAuditLog::log_rotation(
            &log,
            "agent-1",
            "old-key-fingerprint-abc",
            "new-key-fingerprint-xyz",
            1,
            2,
            "issuer-1",
            false,
            None,
            &"0".repeat(48),
        );
        assert!(log.entry_count() > 0);
    }

    #[test]
    fn test_log_rotation_emergency() {
        let log = test_log();
        FAITFAuditLog::log_rotation(
            &log,
            "agent-1",
            "old-key-fingerprint-abc",
            "new-key-fingerprint-xyz",
            1,
            2,
            "issuer-1",
            true,
            None,
            &"0".repeat(48),
        );
        assert!(log.entry_count() > 0);
    }

    #[test]
    fn test_log_federation_event() {
        let log = test_log();
        FAITFAuditLog::log_federation_event(
            &log,
            "REGISTER",
            "domain-a",
            "domain-b",
            "agreement-123",
            "success",
            None,
            &"0".repeat(48),
        );
        assert!(log.entry_count() > 0);
    }

    #[test]
    fn test_log_delegation() {
        let log = test_log();
        FAITFAuditLog::log_delegation(
            &log,
            "parent-agent",
            "child-agent",
            2,
            "read-only",
            None,
            &"0".repeat(48),
        );
        assert!(log.entry_count() > 0);
    }

    #[test]
    fn test_log_trust_anchor_change() {
        let log = test_log();
        FAITFAuditLog::log_trust_anchor_change(
            &log,
            "REGISTERED",
            "anchor-1",
            "key-fingerprint-1234",
            "direct",
            None,
            &"0".repeat(48),
        );
        assert!(log.entry_count() > 0);
    }

    #[test]
    fn test_sanitize_for_audit_strips_control_chars() {
        assert_eq!(sanitize_for_audit("clean"), "clean");
        assert_eq!(sanitize_for_audit("line1\nline2\r\nline3"), "line1line2line3");
        assert_eq!(sanitize_for_audit("tab\tbell\x07end"), "tabbellend");
    }

    #[test]
    fn test_faitf_audit_key_is_at_least_32_bytes() {
        assert!(FAITF_AUDIT_KEY.len() >= 32);
    }
}
