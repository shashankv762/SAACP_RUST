//! test_c2_authority_separation_rs.rs — C-2 Authority Separation tests
//!
//! Ports Python: tests/test_c2_authority_separation.py
//! AuthorityClass hierarchy, AuthorityPolicy, AuthorityRegistry,
//! enforce_issuance_policy, enforce_verification_policy.

use saacp::{
    AuthorityClass, AuthorityPolicy, AuthorityRegistry,
    enforce_issuance_policy, enforce_verification_policy,
    SAACPBytecodes,
};

// ─── AuthorityClass ───────────────────────────────────────────────────────────

#[test]
fn test_authority_class_variants_exist() {
    let _ = AuthorityClass::RootAuthority;
    let _ = AuthorityClass::FederationAuthority;
    let _ = AuthorityClass::AdministrativeAuthority;
    let _ = AuthorityClass::ServiceAuthority;
    let _ = AuthorityClass::DelegatedAuthority;
    let _ = AuthorityClass::ExecutionAgent;
}

#[test]
fn test_authority_class_as_str() {
    assert_eq!(AuthorityClass::RootAuthority.as_str(), "root_authority");
    assert_eq!(AuthorityClass::FederationAuthority.as_str(), "federation_authority");
    assert_eq!(AuthorityClass::AdministrativeAuthority.as_str(), "administrative_authority");
    assert_eq!(AuthorityClass::ServiceAuthority.as_str(), "service_authority");
    assert_eq!(AuthorityClass::DelegatedAuthority.as_str(), "delegated_authority");
    assert_eq!(AuthorityClass::ExecutionAgent.as_str(), "execution_agent");
}

// ─── AuthorityPolicy ──────────────────────────────────────────────────────────

#[test]
fn test_policy_new_root_may_issue_to_all() {
    let p = AuthorityPolicy::new("root", AuthorityClass::RootAuthority);
    assert!(p.may_issue_to(AuthorityClass::ExecutionAgent));
    assert!(p.may_issue_to(AuthorityClass::ServiceAuthority));
    assert!(p.may_issue_to(AuthorityClass::RootAuthority));
    assert!(p.may_issue_to(AuthorityClass::FederationAuthority));
    assert!(p.may_issue_to(AuthorityClass::AdministrativeAuthority));
    assert!(p.may_issue_to(AuthorityClass::DelegatedAuthority));
}

#[test]
fn test_policy_execution_agent_may_not_issue_to_anyone() {
    let p = AuthorityPolicy::new("exec", AuthorityClass::ExecutionAgent);
    assert!(!p.may_issue_to(AuthorityClass::ExecutionAgent));
    assert!(!p.may_issue_to(AuthorityClass::ServiceAuthority));
    assert!(!p.may_issue_to(AuthorityClass::DelegatedAuthority));
}

#[test]
fn test_policy_service_authority_may_issue_to_delegated_and_execution() {
    let p = AuthorityPolicy::new("svc", AuthorityClass::ServiceAuthority);
    assert!(p.may_issue_to(AuthorityClass::DelegatedAuthority));
    assert!(p.may_issue_to(AuthorityClass::ExecutionAgent));
    assert!(!p.may_issue_to(AuthorityClass::ServiceAuthority));
    assert!(!p.may_issue_to(AuthorityClass::RootAuthority));
    assert!(!p.may_issue_to(AuthorityClass::FederationAuthority));
}

#[test]
fn test_policy_delegated_authority_may_issue_only_to_execution() {
    let p = AuthorityPolicy::new("del", AuthorityClass::DelegatedAuthority);
    assert!(p.may_issue_to(AuthorityClass::ExecutionAgent));
    assert!(!p.may_issue_to(AuthorityClass::DelegatedAuthority));
    assert!(!p.may_issue_to(AuthorityClass::ServiceAuthority));
}

#[test]
fn test_policy_administrative_may_issue_to_service_delegated_execution() {
    let p = AuthorityPolicy::new("admin", AuthorityClass::AdministrativeAuthority);
    assert!(p.may_issue_to(AuthorityClass::ServiceAuthority));
    assert!(p.may_issue_to(AuthorityClass::DelegatedAuthority));
    assert!(p.may_issue_to(AuthorityClass::ExecutionAgent));
    assert!(!p.may_issue_to(AuthorityClass::RootAuthority));
    assert!(!p.may_issue_to(AuthorityClass::AdministrativeAuthority));
}

#[test]
fn test_policy_may_self_issue_only_for_fed_root() {
    let p = AuthorityPolicy::new("root", AuthorityClass::RootAuthority);
    assert!(!p.may_self_issue()); // not federation root yet

    let mut p2 = AuthorityPolicy::new("root2", AuthorityClass::RootAuthority);
    p2.is_federation_root = true;
    assert!(p2.may_self_issue());
}

#[test]
fn test_policy_service_authority_may_not_self_issue() {
    let p = AuthorityPolicy::new("svc", AuthorityClass::ServiceAuthority);
    assert!(!p.may_self_issue());
}

// ─── AuthorityRegistry ────────────────────────────────────────────────────────

#[test]
fn test_registry_empty_on_creation() {
    let reg = AuthorityRegistry::new();
    assert_eq!(reg.count(), 0);
}

#[test]
fn test_registry_register_and_contains() {
    let reg = AuthorityRegistry::new();
    let p = AuthorityPolicy::new("issuer-1", AuthorityClass::ServiceAuthority);
    reg.register(p);
    assert!(reg.contains("issuer-1"));
    assert_eq!(reg.count(), 1);
}

#[test]
fn test_registry_deregister() {
    let reg = AuthorityRegistry::new();
    let p = AuthorityPolicy::new("issuer-2", AuthorityClass::ServiceAuthority);
    reg.register(p);
    assert!(reg.deregister("issuer-2"));
    assert!(!reg.contains("issuer-2"));
    assert_eq!(reg.count(), 0);
}

#[test]
fn test_registry_deregister_nonexistent_returns_false() {
    let reg = AuthorityRegistry::new();
    assert!(!reg.deregister("nobody"));
}

#[test]
fn test_registry_get_authority_class() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("root", AuthorityClass::RootAuthority));
    assert_eq!(reg.get_authority_class("root"), Some(AuthorityClass::RootAuthority));
    assert_eq!(reg.get_authority_class("unknown"), None);
}

#[test]
fn test_registry_set_federation_root_ok() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority));
    assert!(reg.set_federation_root("root-1", true).is_ok());
    assert!(reg.may_self_issue("root-1"));
    assert!(reg.set_federation_root("root-1", false).is_ok());
    assert!(!reg.may_self_issue("root-1"));
}

#[test]
fn test_registry_set_federation_root_wrong_class_fails() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("svc-1", AuthorityClass::ServiceAuthority));
    let err = reg.set_federation_root("svc-1", true).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::FederationRootRequired);
}

#[test]
fn test_registry_is_terminal_for_execution_agent() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("exec-1", AuthorityClass::ExecutionAgent));
    assert!(reg.is_terminal("exec-1"));
}

#[test]
fn test_registry_is_not_terminal_for_root() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority));
    assert!(!reg.is_terminal("root-1"));
}

#[test]
fn test_registry_list_issuers() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("a", AuthorityClass::RootAuthority));
    reg.register(AuthorityPolicy::new("b", AuthorityClass::ServiceAuthority));
    let issuers = reg.list_issuers();
    assert!(issuers.contains(&"a".to_string()));
    assert!(issuers.contains(&"b".to_string()));
}

// ─── enforce_issuance_policy ──────────────────────────────────────────────────

#[test]
fn test_enforce_issuance_terminal_class_blocked() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("exec-1", AuthorityClass::ExecutionAgent));
    let err = enforce_issuance_policy("exec-1", "someone", 0, None, None, None, &reg).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::UnauthorizedIssuerClass);
}

#[test]
fn test_enforce_issuance_self_issue_blocked_for_non_root() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("svc-1", AuthorityClass::ServiceAuthority));
    let err = enforce_issuance_policy("svc-1", "svc-1", 0, None, None, None, &reg).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::SelfIssuedCapability);
}

#[test]
fn test_enforce_issuance_self_issue_allowed_for_federation_root() {
    let reg = AuthorityRegistry::new();
    let mut p = AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority);
    p.is_federation_root = true;
    reg.register(p);
    assert!(enforce_issuance_policy("root-1", "root-1", 0, None, None, None, &reg).is_ok());
}

#[test]
fn test_enforce_issuance_class_violation_delegated_to_service() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("del-1", AuthorityClass::DelegatedAuthority));
    let err = enforce_issuance_policy(
        "del-1", "svc-1", 0, None, None,
        Some(AuthorityClass::ServiceAuthority), &reg,
    ).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::AuthorityClassViolation);
}

#[test]
fn test_enforce_issuance_class_ok_root_to_execution() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority));
    assert!(enforce_issuance_policy(
        "root-1", "agent-1", 0, None, None,
        Some(AuthorityClass::ExecutionAgent), &reg,
    ).is_ok());
}

#[test]
fn test_enforce_issuance_delegation_metadata_required_at_depth_1() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority));
    let err = enforce_issuance_policy("root-1", "agent-1", 1, None, None, None, &reg).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::DelegationMetadataIncomplete);
}

#[test]
fn test_enforce_issuance_delegation_metadata_ok() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority));
    assert!(enforce_issuance_policy(
        "root-1", "agent-1", 1,
        Some("parent-jti-abc"), Some("parent-iss-xyz"),
        None, &reg,
    ).is_ok());
}

#[test]
fn test_enforce_issuance_depth_0_no_metadata_ok() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("svc-1", AuthorityClass::ServiceAuthority));
    assert!(enforce_issuance_policy("svc-1", "agent-1", 0, None, None, None, &reg).is_ok());
}

// ─── enforce_verification_policy ─────────────────────────────────────────────

#[test]
fn test_enforce_verification_terminal_blocked() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("exec-1", AuthorityClass::ExecutionAgent));
    let err = enforce_verification_policy("exec-1", "someone", 0, None, None, &reg).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::UnauthorizedIssuerClass);
}

#[test]
fn test_enforce_verification_self_issue_blocked() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("svc-1", AuthorityClass::ServiceAuthority));
    let err = enforce_verification_policy("svc-1", "svc-1", 0, None, None, &reg).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::SelfIssuedCapability);
}

#[test]
fn test_enforce_verification_delegation_missing_at_depth_2() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority));
    let err = enforce_verification_policy("root-1", "agent-1", 2, None, None, &reg).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::DelegationMetadataIncomplete);
}

#[test]
fn test_enforce_verification_ok_root_to_agent() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority));
    assert!(enforce_verification_policy("root-1", "agent-1", 0, None, None, &reg).is_ok());
}

#[test]
fn test_enforce_verification_ok_with_delegation_metadata() {
    let reg = AuthorityRegistry::new();
    reg.register(AuthorityPolicy::new("root-1", AuthorityClass::RootAuthority));
    assert!(enforce_verification_policy(
        "root-1", "agent-1", 1,
        Some("pjti"), Some("piss"), &reg,
    ).is_ok());
}
