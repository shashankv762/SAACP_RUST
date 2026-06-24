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

use std::sync::Arc;

use crate::security::ImmutableAuditLog;

/// Sentinel key used when no PSK is available in FAITF-only deployments.
const FAITF_AUDIT_KEY: &[u8] = b"FAITF_AUDIT_LOG_SENTINEL_KEY_v1";

/// Structured FAITF event logger that writes to ImmutableAuditLog.
pub struct FAITFAuditLog;

impl FAITFAuditLog {
    /// Record a credential issuance event.
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
        let intent = format!(
            "[FAITF:ISSUANCE] agent={} issuer={} version={} key={}... valid_until={:.0} model={}",
            agent_id,
            issuer_id,
            credential_version,
            &key_fingerprint[..16.min(key_fingerprint.len())],
            valid_until,
            trust_model
        );
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY);
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
        let domain_info = if cross_domain {
            format!(" cross_domain={}->{}", source_domain, target_domain)
        } else {
            String::new()
        };
        let intent = format!(
            "[FAITF:AUTH] agent={} session={}... anchor={} model={}{}",
            agent_id,
            &session_id[..16.min(session_id.len())],
            trust_anchor_used,
            trust_model,
            domain_info
        );
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY);
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
        let scope = if !credential_fingerprint.is_empty() {
            format!("cred={}...", &credential_fingerprint[..16.min(credential_fingerprint.len())])
        } else {
            "agent-wide".to_string()
        };
        let intent = format!(
            "[FAITF:REVOCATION] agent={} revoker={} scope={} reason={}",
            agent_id, revoker_id, scope, reason
        );
        let token_sig = if !credential_fingerprint.is_empty() {
            credential_fingerprint
        } else {
            "agent-wide"
        };
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY);
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
        let mode = if emergency { "EMERGENCY" } else { "SCHEDULED" };
        let intent = format!(
            "[FAITF:ROTATION:{}] agent={} issuer={} old_key={}... new_key={}... v{}->v{}",
            mode,
            agent_id,
            issuer_id,
            &old_key_fingerprint[..16.min(old_key_fingerprint.len())],
            &new_key_fingerprint[..16.min(new_key_fingerprint.len())],
            old_version,
            new_version
        );
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY);
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
        let intent = format!(
            "[FAITF:FEDERATION:{}] {}->{} agreement={} result={}",
            event_type,
            source_domain,
            target_domain,
            if agreement_id.is_empty() { "no_agreement" } else { agreement_id },
            result
        );
        let token_sig = if agreement_id.is_empty() {
            "no_agreement"
        } else {
            agreement_id
        };
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY);
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
        let intent = format!(
            "[FAITF:DELEGATION] parent={} child={} depth={} constraints={}",
            parent_agent_id, child_agent_id, depth, constraints_summary
        );
        let token_sig = format!("depth:{}", depth);
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY);
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
        let intent = format!(
            "[FAITF:ANCHOR:{}] anchor={} key={}... model={}",
            event_type,
            anchor_id,
            &key_fingerprint[..16.min(key_fingerprint.len())],
            trust_model
        );
        let key = session_key.unwrap_or(FAITF_AUDIT_KEY);
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
}
