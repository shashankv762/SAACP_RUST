// SAACP Rust Implementation — ACSVAF/FACTF Audit Facade
// Translated from SAACP/src/saacp/acsvaf_audit.py
//!
//! Routes capability lifecycle events to the CapabilityTransparencyLog
//! and the ImmutableAuditLog.  Centralises all capability audit calls so
//! the rest of the protocol never writes directly to the log.
//!
//! The `ImmutableAuditLog::append()` calls here are intentionally diagnostic
//! (human-readable event descriptions), not cryptographically-verified chain
//! entries.  `#[allow(deprecated)]` is applied at module level so future
//! security-critical callers still receive the deprecation warning while
//! these legitimate diagnostic uses remain clean.
#![allow(deprecated)]

use std::sync::{Arc, Mutex};

use crate::security::ImmutableAuditLog;

// ── Audit Event Types ──────────────────────────────────────────────────────

/// Supported capability lifecycle event types.
pub const EVENT_ISSUED: &str = "ISSUED";
pub const EVENT_VERIFIED: &str = "VERIFIED";
pub const EVENT_REJECTED: &str = "REJECTED";
pub const EVENT_DELEGATED: &str = "DELEGATED";
pub const EVENT_REVOKED: &str = "REVOKED";
pub const EVENT_KEY_ROTATED: &str = "KEY_ROTATED";
pub const EVENT_KEY_COMPROMISED: &str = "KEY_COMPROMISED";

// ── Audit Entry ────────────────────────────────────────────────────────────

/// A single capability audit event.
#[derive(Debug, Clone)]
pub struct CapabilityAuditEntry {
    pub event_type: String,
    pub issuer_id: String,
    pub jti: Option<String>,
    pub kid: Option<String>,
    pub sub: Option<String>,
    pub aud: Vec<String>,
    pub actions: Vec<String>,
    pub delegation_depth: Option<u32>,
    pub parent_jti: Option<String>,
    pub reason: Option<String>,
}

// ── TransparencyLog (inline, lightweight) ──────────────────────────────────

/// Lightweight transparency log for capability events.
/// In production this would be the full CapabilityTransparencyLog from factf;
/// here we provide a simplified thread-safe version for audit purposes.
pub struct CapabilityTransparencyLog {
    entries: Mutex<Vec<CapabilityAuditEntry>>,
}

impl CapabilityTransparencyLog {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn append(&self, entry: CapabilityAuditEntry) {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.entries.lock().unwrap().push(entry);
    }

    pub fn entry_count(&self) -> usize {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.entries.lock().unwrap().len()
    }

    pub fn entries(&self) -> Vec<CapabilityAuditEntry> {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.entries.lock().unwrap().clone()
    }
}

impl Default for CapabilityTransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

// ── ACSVAFAuditLog ─────────────────────────────────────────────────────────

/// Thin facade that writes capability lifecycle events to both
/// CapabilityTransparencyLog and ImmutableAuditLog.
pub struct ACSVAFAuditLog {
    tlog: Arc<CapabilityTransparencyLog>,
    alog: Option<Arc<ImmutableAuditLog>>,
}

impl ACSVAFAuditLog {
    /// Create a new audit log backed by a transparency log and optional audit log.
    pub fn new(
        transparency_log: Arc<CapabilityTransparencyLog>,
        audit_log: Option<Arc<ImmutableAuditLog>>,
    ) -> Self {
        Self {
            tlog: transparency_log,
            alog: audit_log,
        }
    }

    /// Log a capability issuance event.
    #[allow(clippy::too_many_arguments)]
    pub fn log_issuance(
        &self,
        jti: &str,
        kid: &str,
        iss: &str,
        sub: &str,
        aud: &[String],
        actions: &[String],
        delegation_depth: u32,
        parent_jti: Option<&str>,
    ) {
        self.tlog.append(CapabilityAuditEntry {
            event_type: EVENT_ISSUED.into(),
            issuer_id: iss.into(),
            jti: Some(jti.into()),
            kid: Some(kid.into()),
            sub: Some(sub.into()),
            aud: aud.to_vec(),
            actions: actions.to_vec(),
            delegation_depth: Some(delegation_depth),
            parent_jti: parent_jti.map(String::from),
            reason: None,
        });
        if let Some(ref alog) = self.alog {
            alog.append(format!(
                "ACSVAF ISSUED jti={} kid={} iss={} depth={}",
                &jti[..8.min(jti.len())],
                kid,
                iss,
                delegation_depth
            ));
        }
    }

    /// Log a capability verification event.
    #[allow(clippy::too_many_arguments)]
    pub fn log_verification(
        &self,
        issuer_id: &str,
        jti: &str,
        sub: &str,
        audience: &[String],
        actions: &[String],
        delegation_depth: u32,
        parent_jti: Option<&str>,
    ) {
        self.tlog.append(CapabilityAuditEntry {
            event_type: EVENT_VERIFIED.into(),
            issuer_id: issuer_id.into(),
            jti: Some(jti.into()),
            kid: None,
            sub: Some(sub.into()),
            aud: audience.to_vec(),
            actions: actions.to_vec(),
            delegation_depth: Some(delegation_depth),
            parent_jti: parent_jti.map(String::from),
            reason: None,
        });
        if let Some(ref alog) = self.alog {
            alog.append(format!(
                "ACSVAF VERIFIED jti={} sub={}",
                &jti[..8.min(jti.len())],
                sub
            ));
        }
    }

    /// Log a rejection event.
    pub fn log_rejection(&self, reason: &str, kid: Option<&str>, issuer_id: &str) {
        self.tlog.append(CapabilityAuditEntry {
            event_type: EVENT_REJECTED.into(),
            issuer_id: issuer_id.into(),
            jti: None,
            kid: kid.map(String::from),
            sub: None,
            aud: vec![],
            actions: vec![],
            delegation_depth: None,
            parent_jti: None,
            reason: Some(reason.into()),
        });
        if let Some(ref alog) = self.alog {
            alog.append(format!(
                "ACSVAF REJECTED kid={} reason={}",
                kid.unwrap_or("none"),
                reason
            ));
        }
    }

    /// Log a delegation event.
    #[allow(clippy::too_many_arguments)]
    pub fn log_delegation(
        &self,
        parent_jti: &str,
        child_jti: &str,
        child_iss: &str,
        child_kid: &str,
        child_sub: &str,
        child_aud: &[String],
        child_actions: &[String],
        child_delegation_depth: u32,
    ) {
        self.tlog.append(CapabilityAuditEntry {
            event_type: EVENT_DELEGATED.into(),
            issuer_id: child_iss.into(),
            jti: Some(child_jti.into()),
            kid: Some(child_kid.into()),
            sub: Some(child_sub.into()),
            aud: child_aud.to_vec(),
            actions: child_actions.to_vec(),
            delegation_depth: Some(child_delegation_depth),
            parent_jti: Some(parent_jti.into()),
            reason: None,
        });
        if let Some(ref alog) = self.alog {
            alog.append(format!(
                "ACSVAF DELEGATED parent_jti={} child_jti={} depth={}",
                &parent_jti[..8.min(parent_jti.len())],
                &child_jti[..8.min(child_jti.len())],
                child_delegation_depth
            ));
        }
    }

    /// Log a revocation event.
    pub fn log_revocation(&self, jti: &str, kid: &str, issuer_id: &str) {
        self.tlog.append(CapabilityAuditEntry {
            event_type: EVENT_REVOKED.into(),
            issuer_id: issuer_id.into(),
            jti: Some(jti.into()),
            kid: Some(kid.into()),
            sub: None,
            aud: vec![],
            actions: vec![],
            delegation_depth: None,
            parent_jti: None,
            reason: None,
        });
        if let Some(ref alog) = self.alog {
            alog.append(format!(
                "ACSVAF REVOKED jti={} kid={}",
                &jti[..8.min(jti.len())],
                kid
            ));
        }
    }

    /// Log a key rotation event.
    pub fn log_key_rotation(&self, old_kid: &str, new_kid: &str, issuer_id: &str) {
        self.tlog.append(CapabilityAuditEntry {
            event_type: EVENT_KEY_ROTATED.into(),
            issuer_id: issuer_id.into(),
            jti: None,
            kid: Some(old_kid.into()),
            sub: None,
            aud: vec![],
            actions: vec![],
            delegation_depth: None,
            parent_jti: None,
            reason: None,
        });
        self.tlog.append(CapabilityAuditEntry {
            event_type: EVENT_KEY_ROTATED.into(),
            issuer_id: issuer_id.into(),
            jti: None,
            kid: Some(new_kid.into()),
            sub: None,
            aud: vec![],
            actions: vec![],
            delegation_depth: None,
            parent_jti: None,
            reason: None,
        });
        if let Some(ref alog) = self.alog {
            alog.append(format!(
                "ACSVAF KEY_ROTATED old={} new={} iss={}",
                old_kid, new_kid, issuer_id
            ));
        }
    }

    /// Log a key compromise event.
    pub fn log_compromise(&self, compromised_kid: &str, affected_token_count: usize, replacement_kid: &str) {
        self.tlog.append(CapabilityAuditEntry {
            event_type: EVENT_KEY_COMPROMISED.into(),
            issuer_id: "recovery".into(),
            jti: None,
            kid: Some(compromised_kid.into()),
            sub: None,
            aud: vec![],
            actions: vec![],
            delegation_depth: None,
            parent_jti: None,
            reason: None,
        });
        if let Some(ref alog) = self.alog {
            alog.append(format!(
                "ACSVAF KEY_COMPROMISED kid={} affected={} replacement={}",
                compromised_kid, affected_token_count, replacement_kid
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transparency_log_append() {
        let tlog = CapabilityTransparencyLog::new();
        tlog.append(CapabilityAuditEntry {
            event_type: EVENT_ISSUED.into(),
            issuer_id: "agent-1".into(),
            jti: Some("jti-001".into()),
            kid: Some("kid-001".into()),
            sub: None,
            aud: vec![],
            actions: vec![],
            delegation_depth: None,
            parent_jti: None,
            reason: None,
        });
        assert_eq!(tlog.entry_count(), 1);
    }

    #[test]
    fn test_audit_log_issuance() {
        let tlog = Arc::new(CapabilityTransparencyLog::new());
        let audit = ACSVAFAuditLog::new(tlog.clone(), None);
        audit.log_issuance(
            "jti-12345678", "kid-abc", "issuer-1", "sub-1",
            &["aud-1".into()], &["read".into()], 0, None,
        );
        assert_eq!(tlog.entry_count(), 1);
        let entries = tlog.entries();
        assert_eq!(entries[0].event_type, EVENT_ISSUED);
    }

    #[test]
    fn test_audit_log_verification() {
        let tlog = Arc::new(CapabilityTransparencyLog::new());
        let audit = ACSVAFAuditLog::new(tlog.clone(), None);
        audit.log_verification(
            "issuer-1", "jti-12345678", "sub-1",
            &["aud-1".into()], &["read".into()], 0, None,
        );
        assert_eq!(tlog.entry_count(), 1);
    }

    #[test]
    fn test_audit_log_rejection() {
        let tlog = Arc::new(CapabilityTransparencyLog::new());
        let audit = ACSVAFAuditLog::new(tlog.clone(), None);
        audit.log_rejection("invalid signature", Some("kid-abc"), "issuer-1");
        assert_eq!(tlog.entry_count(), 1);
        let entries = tlog.entries();
        assert_eq!(entries[0].event_type, EVENT_REJECTED);
    }

    #[test]
    fn test_audit_log_delegation() {
        let tlog = Arc::new(CapabilityTransparencyLog::new());
        let audit = ACSVAFAuditLog::new(tlog.clone(), None);
        audit.log_delegation(
            "parent-jti-12345", "child-jti-12345",
            "child-iss", "child-kid", "child-sub",
            &["aud".into()], &["write".into()], 1,
        );
        assert_eq!(tlog.entry_count(), 1);
    }

    #[test]
    fn test_audit_log_revocation() {
        let tlog = Arc::new(CapabilityTransparencyLog::new());
        let audit = ACSVAFAuditLog::new(tlog.clone(), None);
        audit.log_revocation("jti-12345678", "kid-abc", "issuer-1");
        assert_eq!(tlog.entry_count(), 1);
    }

    #[test]
    fn test_audit_log_key_rotation() {
        let tlog = Arc::new(CapabilityTransparencyLog::new());
        let audit = ACSVAFAuditLog::new(tlog.clone(), None);
        audit.log_key_rotation("old-kid", "new-kid", "issuer-1");
        // Two entries: one for old key, one for new
        assert_eq!(tlog.entry_count(), 2);
    }

    #[test]
    fn test_audit_log_compromise() {
        let tlog = Arc::new(CapabilityTransparencyLog::new());
        let audit = ACSVAFAuditLog::new(tlog.clone(), None);
        audit.log_compromise("compromised-kid", 5, "replacement-kid");
        assert_eq!(tlog.entry_count(), 1);
        let entries = tlog.entries();
        assert_eq!(entries[0].event_type, EVENT_KEY_COMPROMISED);
    }
}
