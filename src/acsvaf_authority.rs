//! acsvaf_authority.rs — Delegation Integrity and Authority Separation (C-2)
//!
//! Implements the six authority classes defined by the protocol and enforces
//! strict separation between issuers and subjects.
//!
//! ## Authority Hierarchy
//! - `RootAuthority` — May issue to any class; only class allowed to be federation root.
//! - `FederationAuthority` — May issue to all classes except RootAuthority.
//! - `AdministrativeAuthority` — Issues to Service, Delegated, Execution.
//! - `ServiceAuthority` — Issues to Delegated and Execution agents only.
//! - `DelegatedAuthority` — Issues only to Execution agents (limited scope).
//! - `ExecutionAgent` — May NOT issue capability tokens (terminal class).

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// ---------------------------------------------------------------------------
// AuthorityClass
// ---------------------------------------------------------------------------

/// Formal authority class hierarchy for SAACP agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityClass {
    RootAuthority,
    FederationAuthority,
    AdministrativeAuthority,
    ServiceAuthority,
    DelegatedAuthority,
    ExecutionAgent,
}

impl AuthorityClass {
    /// Return the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RootAuthority => "root_authority",
            Self::FederationAuthority => "federation_authority",
            Self::AdministrativeAuthority => "administrative_authority",
            Self::ServiceAuthority => "service_authority",
            Self::DelegatedAuthority => "delegated_authority",
            Self::ExecutionAgent => "execution_agent",
        }
    }
}

/// Classes that may NEVER produce capability tokens regardless of key status.
fn terminal_classes() -> HashSet<AuthorityClass> {
    let mut s = HashSet::new();
    s.insert(AuthorityClass::ExecutionAgent);
    s
}

/// Permitted issuee classes per issuer class.
fn issuance_permissions(issuer: AuthorityClass) -> HashSet<AuthorityClass> {
    use AuthorityClass::*;
    match issuer {
        RootAuthority => {
            let mut s = HashSet::new();
            s.insert(RootAuthority);
            s.insert(FederationAuthority);
            s.insert(AdministrativeAuthority);
            s.insert(ServiceAuthority);
            s.insert(DelegatedAuthority);
            s.insert(ExecutionAgent);
            s
        }
        FederationAuthority => {
            let mut s = HashSet::new();
            s.insert(FederationAuthority);
            s.insert(AdministrativeAuthority);
            s.insert(ServiceAuthority);
            s.insert(DelegatedAuthority);
            s.insert(ExecutionAgent);
            s
        }
        AdministrativeAuthority => {
            let mut s = HashSet::new();
            s.insert(ServiceAuthority);
            s.insert(DelegatedAuthority);
            s.insert(ExecutionAgent);
            s
        }
        ServiceAuthority => {
            let mut s = HashSet::new();
            s.insert(DelegatedAuthority);
            s.insert(ExecutionAgent);
            s
        }
        DelegatedAuthority => {
            let mut s = HashSet::new();
            s.insert(ExecutionAgent);
            s
        }
        ExecutionAgent => HashSet::new(),
    }
}

// ---------------------------------------------------------------------------
// AuthorityPolicy
// ---------------------------------------------------------------------------

/// Per-issuer policy record stored in the AuthorityRegistry.
pub struct AuthorityPolicy {
    /// Globally unique issuer identifier.
    pub issuer_id: String,
    /// The authority class assigned to this issuer.
    pub authority_class: AuthorityClass,
    /// True only for ROOT_AUTHORITY issuers that may legitimately self-issue.
    pub is_federation_root: bool,
    /// Explicit whitelist of action strings. Empty = unrestricted.
    pub allowed_actions: HashSet<String>,
    /// Override for max delegation depth (defaults to 8).
    pub max_delegation_depth: u32,
    /// Arbitrary protocol-level annotations.
    pub metadata: HashMap<String, String>,
}

impl AuthorityPolicy {
    /// Create a new AuthorityPolicy.
    pub fn new(issuer_id: &str, authority_class: AuthorityClass) -> Self {
        Self {
            issuer_id: issuer_id.to_string(),
            authority_class,
            is_federation_root: false,
            allowed_actions: HashSet::new(),
            max_delegation_depth: 8,
            metadata: HashMap::new(),
        }
    }

    /// Return true if this issuer class may grant capabilities to `sub_class`.
    pub fn may_issue_to(&self, sub_class: AuthorityClass) -> bool {
        issuance_permissions(self.authority_class).contains(&sub_class)
    }

    /// Root authority with federation-root flag is the only self-issuance exemption.
    pub fn may_self_issue(&self) -> bool {
        self.authority_class == AuthorityClass::RootAuthority && self.is_federation_root
    }
}

// ---------------------------------------------------------------------------
// AuthorityRegistry
// ---------------------------------------------------------------------------

/// Thread-safe registry mapping issuer_id → AuthorityPolicy.
pub struct AuthorityRegistry {
    inner: Mutex<RegistryInner>,
}

struct RegistryInner {
    policies: HashMap<String, AuthorityPolicy>,
}

impl AuthorityRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                policies: HashMap::new(),
            }),
        }
    }

    /// Register or replace an authority policy for issuer_id.
    pub fn register(&self, policy: AuthorityPolicy) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.policies.insert(policy.issuer_id.clone(), policy);
    }

    /// Remove a policy. Returns true if it existed.
    pub fn deregister(&self, issuer_id: &str) -> bool {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.policies.remove(issuer_id).is_some()
    }

    /// Check if an issuer is registered.
    pub fn contains(&self, issuer_id: &str) -> bool {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.policies.contains_key(issuer_id)
    }

    /// Get the authority class for an issuer, if registered.
    pub fn get_authority_class(&self, issuer_id: &str) -> Option<AuthorityClass> {
        let inner = self.inner.lock().ok()?;
        inner.policies.get(issuer_id).map(|p| p.authority_class)
    }

    /// Get whether an issuer may self-issue.
    pub fn may_self_issue(&self, issuer_id: &str) -> bool {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.policies.get(issuer_id).map_or(false, |p| p.may_self_issue())
    }

    /// Check if an issuer may issue to a given subject class.
    pub fn may_issue_to(&self, issuer_id: &str, sub_class: AuthorityClass) -> bool {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.policies.get(issuer_id).map_or(false, |p| p.may_issue_to(sub_class))
    }

    /// Check if an issuer is a terminal class.
    pub fn is_terminal(&self, issuer_id: &str) -> bool {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.policies.get(issuer_id).map_or(false, |p| terminal_classes().contains(&p.authority_class))
    }

    /// List all registered issuer IDs.
    pub fn list_issuers(&self) -> Vec<String> {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.policies.keys().cloned().collect()
    }

    /// Return the number of registered policies.
    pub fn count(&self) -> usize {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.policies.len()
    }

    /// Promote or demote a ROOT_AUTHORITY issuer's federation-root flag.
    pub fn set_federation_root(&self, issuer_id: &str, is_root: bool) -> Result<(), SAACPHardDrop> {
        let mut inner = self.inner.lock().expect("lock poisoned");
        let policy = inner.policies.get_mut(issuer_id).ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::FederationRootRequired,
                format!("Issuer '{}' not registered in AuthorityRegistry.", issuer_id),
            )
        })?;
        if policy.authority_class != AuthorityClass::RootAuthority {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::FederationRootRequired,
                format!("Only ROOT_AUTHORITY issuers may hold federation-root status; \
                    '{}' is {}.", issuer_id, policy.authority_class.as_str()),
            ));
        }
        policy.is_federation_root = is_root;
        Ok(())
    }
}

impl Default for AuthorityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Enforcement helpers
// ---------------------------------------------------------------------------

/// Validate C-2 invariants at issuance time.
///
/// Checks:
/// 1. Issuer registered and not a terminal class.
/// 2. Self-issuance prohibition (iss == sub) unless federation root.
/// 3. Issuer may issue to sub's authority class (if sub class is known).
/// 4. Delegated tokens (depth > 0) must carry parent_jti AND parent_iss.
pub fn enforce_issuance_policy(
    issuer_id: &str,
    sub: &str,
    delegation_depth: u32,
    parent_jti: Option<&str>,
    parent_iss: Option<&str>,
    sub_authority_class: Option<AuthorityClass>,
    registry: &AuthorityRegistry,
) -> Result<(), SAACPHardDrop> {
    // 1. Terminal class check
    if registry.is_terminal(issuer_id) {
        let cls = registry.get_authority_class(issuer_id).unwrap();
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::UnauthorizedIssuerClass,
            format!("C-2: Authority class '{}' for issuer '{}' is terminal and may never issue capability tokens.",
                cls.as_str(), issuer_id),
        ));
    }

    // 2. Self-issuance prohibition
    if issuer_id == sub {
        if !registry.may_self_issue(issuer_id) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SelfIssuedCapability,
                format!("C-2: Self-issued capability rejected — iss == sub == '{}'. \
                    Only federation-root authorities may self-issue.", issuer_id),
            ));
        }
    }

    // 3. Authority class scope (if sub class is known)
    if let Some(sub_class) = sub_authority_class {
        if !registry.may_issue_to(issuer_id, sub_class) {
            let issuer_class = registry.get_authority_class(issuer_id)
                .map(|c| c.as_str().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::AuthorityClassViolation,
                format!("C-2: Issuer class '{}' may not grant capabilities to subject class '{}'.",
                    issuer_class, sub_class.as_str()),
            ));
        }
    }

    // 4. Delegated token metadata completeness
    if delegation_depth > 0 {
        if parent_jti.is_none() || parent_iss.is_none() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::DelegationMetadataIncomplete,
                format!("C-2: Delegated capability (depth={}) must carry both parent_jti and parent_iss. \
                    One or both are missing.", delegation_depth),
            ));
        }
    }

    Ok(())
}

/// Validate C-2 invariants at verification time.
///
/// This catches tokens that were issued without going through
/// `enforce_issuance_policy` (e.g. crafted externally or via legacy path).
pub fn enforce_verification_policy(
    issuer_id: &str,
    sub: &str,
    delegation_depth: u32,
    parent_jti: Option<&str>,
    parent_iss: Option<&str>,
    registry: &AuthorityRegistry,
) -> Result<(), SAACPHardDrop> {
    // Terminal class cannot be an issuer
    if registry.is_terminal(issuer_id) {
        let cls = registry.get_authority_class(issuer_id).unwrap();
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::UnauthorizedIssuerClass,
            format!("C-2: Token issuer '{}' has terminal authority class '{}' and may not issue tokens.",
                issuer_id, cls.as_str()),
        ));
    }

    // Self-issuance prohibition
    if issuer_id == sub {
        if !registry.may_self_issue(issuer_id) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SelfIssuedCapability,
                format!("C-2: Self-issued token rejected at verification — iss == sub == '{}'.", issuer_id),
            ));
        }
    }

    // Delegation metadata completeness
    if delegation_depth > 0 {
        if parent_jti.is_none() || parent_iss.is_none() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::DelegationMetadataIncomplete,
                format!("C-2: Delegated token (depth={}) is missing parent_jti or parent_iss delegation metadata.",
                    delegation_depth),
            ));
        }
    }

    Ok(())
}

/// Process-wide default authority registry.
pub static DEFAULT_AUTHORITY_REGISTRY: LazyLock<AuthorityRegistry> = LazyLock::new(AuthorityRegistry::new);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authority_class_str() {
        assert_eq!(AuthorityClass::RootAuthority.as_str(), "root_authority");
        assert_eq!(AuthorityClass::ExecutionAgent.as_str(), "execution_agent");
    }

    #[test]
    fn test_policy_may_issue_to() {
        let root_policy = AuthorityPolicy::new("root", AuthorityClass::RootAuthority);
        assert!(root_policy.may_issue_to(AuthorityClass::ExecutionAgent));
        assert!(root_policy.may_issue_to(AuthorityClass::RootAuthority));

        let svc_policy = AuthorityPolicy::new("svc", AuthorityClass::ServiceAuthority);
        assert!(svc_policy.may_issue_to(AuthorityClass::DelegatedAuthority));
        assert!(svc_policy.may_issue_to(AuthorityClass::ExecutionAgent));
        assert!(!svc_policy.may_issue_to(AuthorityClass::RootAuthority));
        assert!(!svc_policy.may_issue_to(AuthorityClass::ServiceAuthority));
    }

    #[test]
    fn test_policy_may_self_issue() {
        let mut root_policy = AuthorityPolicy::new("root", AuthorityClass::RootAuthority);
        assert!(!root_policy.may_self_issue()); // not federation root yet
        root_policy.is_federation_root = true;
        assert!(root_policy.may_self_issue());

        let fed_policy = AuthorityPolicy::new("fed", AuthorityClass::FederationAuthority);
        assert!(!fed_policy.may_self_issue());
    }

    #[test]
    fn test_registry_register_and_query() {
        let reg = AuthorityRegistry::new();
        assert_eq!(reg.count(), 0);

        let policy = AuthorityPolicy::new("issuer-1", AuthorityClass::ServiceAuthority);
        reg.register(policy);
        assert_eq!(reg.count(), 1);
        assert!(reg.contains("issuer-1"));
        assert_eq!(reg.get_authority_class("issuer-1"), Some(AuthorityClass::ServiceAuthority));

        assert!(reg.deregister("issuer-1"));
        assert_eq!(reg.count(), 0);
        assert!(!reg.deregister("issuer-1")); // already gone
    }

    #[test]
    fn test_registry_set_federation_root() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority);
        reg.register(policy);

        assert!(reg.set_federation_root("root-1", true).is_ok());
        assert!(reg.may_self_issue("root-1"));

        assert!(reg.set_federation_root("root-1", false).is_ok());
        assert!(!reg.may_self_issue("root-1"));
    }

    #[test]
    fn test_registry_set_federation_root_wrong_class() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("svc-1", AuthorityClass::ServiceAuthority);
        reg.register(policy);

        let err = reg.set_federation_root("svc-1", true).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::FederationRootRequired);
    }

    #[test]
    fn test_enforce_issuance_terminal_blocked() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("exec-1", AuthorityClass::ExecutionAgent);
        reg.register(policy);

        let err = enforce_issuance_policy(
            "exec-1", "someone", 0, None, None, None, &reg,
        ).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::UnauthorizedIssuerClass);
    }

    #[test]
    fn test_enforce_issuance_self_issue_blocked() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("svc-1", AuthorityClass::ServiceAuthority);
        reg.register(policy);

        let err = enforce_issuance_policy(
            "svc-1", "svc-1", 0, None, None, None, &reg,
        ).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::SelfIssuedCapability);
    }

    #[test]
    fn test_enforce_issuance_self_issue_allowed_for_fed_root() {
        let reg = AuthorityRegistry::new();
        let mut policy = AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority);
        policy.is_federation_root = true;
        reg.register(policy);

        assert!(enforce_issuance_policy(
            "root-1", "root-1", 0, None, None, None, &reg,
        ).is_ok());
    }

    #[test]
    fn test_enforce_issuance_class_violation() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("del-1", AuthorityClass::DelegatedAuthority);
        reg.register(policy);

        let err = enforce_issuance_policy(
            "del-1", "svc-1", 0, None, None,
            Some(AuthorityClass::ServiceAuthority), &reg,
        ).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::AuthorityClassViolation);
    }

    #[test]
    fn test_enforce_issuance_delegation_metadata_ok() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority);
        reg.register(policy);

        assert!(enforce_issuance_policy(
            "root-1", "agent-1", 1, Some("parent-jti"), Some("parent-iss"), None, &reg,
        ).is_ok());
    }

    #[test]
    fn test_enforce_issuance_delegation_metadata_missing() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority);
        reg.register(policy);

        let err = enforce_issuance_policy(
            "root-1", "agent-1", 1, None, None, None, &reg,
        ).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::DelegationMetadataIncomplete);
    }

    #[test]
    fn test_enforce_verification_policy_terminal() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("exec-1", AuthorityClass::ExecutionAgent);
        reg.register(policy);

        let err = enforce_verification_policy(
            "exec-1", "someone", 0, None, None, &reg,
        ).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::UnauthorizedIssuerClass);
    }

    #[test]
    fn test_enforce_verification_policy_self_issue() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("svc-1", AuthorityClass::ServiceAuthority);
        reg.register(policy);

        let err = enforce_verification_policy(
            "svc-1", "svc-1", 0, None, None, &reg,
        ).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::SelfIssuedCapability);
    }

    #[test]
    fn test_enforce_verification_policy_delegation_missing() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority);
        reg.register(policy);

        let err = enforce_verification_policy(
            "root-1", "agent-1", 2, None, None, &reg,
        ).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::DelegationMetadataIncomplete);
    }

    #[test]
    fn test_enforce_verification_policy_ok() {
        let reg = AuthorityRegistry::new();
        let policy = AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority);
        reg.register(policy);

        assert!(enforce_verification_policy(
            "root-1", "agent-1", 0, None, None, &reg,
        ).is_ok());
    }

    #[test]
    fn test_default_registry_static() {
        assert_eq!(DEFAULT_AUTHORITY_REGISTRY.count(), 0);
    }
}
