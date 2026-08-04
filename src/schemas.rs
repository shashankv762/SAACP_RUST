use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use serde_json::Value;

/// Allowed meta keys that pass through validation without being counted as extra fields.
const ALLOWED_META_KEYS: &[&str] = &["_capability_token", "_cognitive_constraint", "_secondary_token"];

/// Schema definition holding an ID, human-readable name, required keys, and
/// an explicit extensibility allowlist.
///
/// M-14 fix: `additional_fields` (empty for every schema below — zero
/// behavior change from before this fix) names extra fields a future
/// protocol extension may add to a specific schema without those fields
/// being rejected as "Unexpected field". Unlike `ALLOWED_META_KEYS` (which
/// applies uniformly to every schema, e.g. `_capability_token`),
/// `additional_fields` is per-schema — extending schema 6's Heartbeat with a
/// new optional field, say, does not implicitly loosen schema 1's Task
/// validation.
struct SchemaDefinition {
    id: u16,
    #[allow(dead_code)]
    name: &'static str,
    required_keys: &'static [&'static str],
    additional_fields: &'static [&'static str],
}

/// Static schema registry (IDs 0-12).
const SCHEMAS: &[SchemaDefinition] = &[
    SchemaDefinition { id: 0, name: "Raw Binary", required_keys: &[], additional_fields: &[] },
    SchemaDefinition { id: 1, name: "Task", required_keys: &["task", "priority"], additional_fields: &[] },
    SchemaDefinition { id: 2, name: "Action", required_keys: &["action", "target", "parameters"], additional_fields: &[] },
    SchemaDefinition { id: 3, name: "Epistemic", required_keys: &["epistemic_metadata", "data"], additional_fields: &[] },
    SchemaDefinition { id: 4, name: "Budget Request", required_keys: &["max_token_budget", "task_schema"], additional_fields: &[] },
    SchemaDefinition { id: 5, name: "Cost Estimate", required_keys: &["estimated_cost", "max_token_budget"], additional_fields: &[] },
    SchemaDefinition { id: 6, name: "Heartbeat", required_keys: &["agent_id", "heartbeat_seq", "status"], additional_fields: &[] },
    SchemaDefinition { id: 7, name: "Error", required_keys: &["error_code", "error_detail", "retry_after"], additional_fields: &[] },
    SchemaDefinition { id: 8, name: "Delegation", required_keys: &["delegation_request", "scope", "ttl"], additional_fields: &[] },
    SchemaDefinition { id: 9, name: "Audit Query", required_keys: &["audit_query", "from_timestamp", "to_timestamp"], additional_fields: &[] },
    // Execution receipt (Phase 6, item 3 — IEVL, Part 8.1): a signed, after-the-fact
    // report of what an agent actually did, matched against the `IntentDeclaration`
    // `ievl.rs` captured at Gate 1.5 time. `receipt_signature`'s own Ed25519 signature
    // is verified by `ievl::verify_receipt_signature`, not here.
    SchemaDefinition { id: 10, name: "Execution Receipt", required_keys: &["declaration_ref", "actual_action", "actual_targets", "receipt_signature"], additional_fields: &[] },
    // Gossip envelope (Phase 5, item 3 — revocation gossip protocol, Part 8.6):
    // carries a pre-signed `SignedRevocationRecord` wire blob rather than free-form
    // JSON, so only the envelope wrapper fields are schema-validated here — the
    // `gossip_record` payload's own signature is verified by `gossip::GossipEngine`.
    SchemaDefinition { id: 11, name: "Gossip Envelope", required_keys: &["gossip_record", "hop_count", "origin_id", "revocation_id"], additional_fields: &[] },
    // Cluster envelope (Active-Active Clustering & Failover, `cluster.rs`): carries a
    // pre-signed `ClusterMessage` wire blob. Only the envelope wrapper is validated
    // here — the `cluster_message` payload's own Ed25519 signature is verified by
    // `cluster::ClusterEngine::receive_envelope`, which additionally cross-checks that
    // `sender_id`/`leader_epoch`/`message_kind` (duplicated outside the signature so the
    // daemon can route without parsing the blob) agree with the signed body, and rejects
    // the message if they disagree. Mirrors schema 11's signed-blob-in-a-string design.
    SchemaDefinition { id: 12, name: "Cluster Envelope", required_keys: &["cluster_message", "sender_id", "leader_epoch", "message_kind"], additional_fields: &[] },
];

/// Pre-compiled JSON schema validation registry.
pub struct PreCompiledSchemas;

impl PreCompiledSchemas {
    /// Validate a payload against a schema identified by `schema_id`.
    ///
    /// - Schema 0 ("Raw Binary"): no validation, always Ok(())
    /// - Schemas 1-9: payload must be a JSON object with exactly the required keys
    ///   (plus any allowed meta keys).
    /// - Unknown schema IDs produce a hard drop.
    pub fn validate_payload(schema_id: u16, payload: &Value) -> Result<(), SAACPHardDrop> {
        // Schema 0: no validation
        if schema_id == 0 {
            return Ok(());
        }

        // Find the schema definition
        let schema = SCHEMAS.iter().find(|s| s.id == schema_id).ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                format!("Unknown schema ID: {}", schema_id),
            )
        })?;

        // Payload must be a JSON object for schemas 1-9
        let obj = payload.as_object().ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                "Payload must be a JSON object".to_string(),
            )
        })?;

        // Check for missing required fields
        for &key in schema.required_keys {
            if !obj.contains_key(key) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::SchemaMismatch,
                    format!("Missing required field: {}", key),
                ));
            }
        }

        // Check for unexpected extra fields
        for key in obj.keys() {
            let key_str = key.as_str();
            let is_required = schema.required_keys.contains(&key_str);
            let is_meta = ALLOWED_META_KEYS.contains(&key_str);
            // M-14 fix: a field explicitly allowlisted for this schema via
            // `additional_fields` is also accepted — see `SchemaDefinition`'s
            // doc comment. Every current schema's `additional_fields` is
            // empty, so this check is a no-op today; it exists so a future
            // protocol extension can opt a specific schema into a specific
            // new field without touching this validation loop.
            let is_additional = schema.additional_fields.contains(&key_str);
            if !is_required && !is_meta && !is_additional {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::SchemaMismatch,
                    format!("Unexpected field: {}", key),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_0_always_passes() {
        assert!(PreCompiledSchemas::validate_payload(0, &json!(null)).is_ok());
        assert!(PreCompiledSchemas::validate_payload(0, &json!("anything")).is_ok());
        assert!(PreCompiledSchemas::validate_payload(0, &json!(42)).is_ok());
    }

    #[test]
    fn schema_1_task_valid() {
        let payload = json!({"task": "do something", "priority": 1});
        assert!(PreCompiledSchemas::validate_payload(1, &payload).is_ok());
    }

    #[test]
    fn schema_1_missing_field() {
        let payload = json!({"task": "do something"});
        let err = PreCompiledSchemas::validate_payload(1, &payload).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::SchemaMismatch);
        assert!(err.message.contains("Missing required field: priority"));
    }

    #[test]
    fn schema_1_extra_field() {
        let payload = json!({"task": "x", "priority": 1, "rogue": true});
        let err = PreCompiledSchemas::validate_payload(1, &payload).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::SchemaMismatch);
        assert!(err.message.contains("Unexpected field: rogue"));
    }

    #[test]
    fn meta_keys_allowed() {
        let payload = json!({
            "task": "x",
            "priority": 1,
            "_capability_token": "tok",
            "_cognitive_constraint": "cc",
            "_secondary_token": "st"
        });
        assert!(PreCompiledSchemas::validate_payload(1, &payload).is_ok());
    }

    #[test]
    fn unknown_schema_id() {
        let err = PreCompiledSchemas::validate_payload(99, &json!({})).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::SchemaMismatch);
        assert!(err.message.contains("Unknown schema ID: 99"));
    }

    #[test]
    fn non_object_payload_rejected() {
        let err = PreCompiledSchemas::validate_payload(1, &json!("string")).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::SchemaMismatch);
        assert!(err.message.contains("Payload must be a JSON object"));
    }

    #[test]
    fn schema_11_gossip_envelope_valid() {
        let payload = json!({
            "gossip_record": "base64blob==",
            "hop_count": 0,
            "origin_id": "node-a",
            "revocation_id": "rev-1234",
        });
        assert!(PreCompiledSchemas::validate_payload(11, &payload).is_ok());
    }

    #[test]
    fn schema_11_missing_field() {
        let payload = json!({"gossip_record": "x", "hop_count": 0, "origin_id": "node-a"});
        let err = PreCompiledSchemas::validate_payload(11, &payload).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::SchemaMismatch);
        assert!(err.message.contains("Missing required field: revocation_id"));
    }

    #[test]
    fn schema_10_execution_receipt_valid() {
        let payload = json!({
            "declaration_ref": "abc123",
            "actual_action": "delete stale records",
            "actual_targets": ["table-x"],
            "receipt_signature": "base64sig==",
        });
        assert!(PreCompiledSchemas::validate_payload(10, &payload).is_ok());
    }

    #[test]
    fn schema_10_missing_field() {
        let payload = json!({"declaration_ref": "abc123", "actual_action": "x", "actual_targets": []});
        let err = PreCompiledSchemas::validate_payload(10, &payload).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::SchemaMismatch);
        assert!(err.message.contains("Missing required field: receipt_signature"));
    }

    // -- M-14: additional_fields extensibility hook --

    #[test]
    fn additional_fields_is_empty_for_every_schema_today() {
        // Every schema's `additional_fields` must currently be empty — this
        // is the "zero behavior change" guarantee the M-14 fix relies on.
        // If a future edit populates one, this test documents the change is
        // intentional (it will start failing and must be updated, not just
        // silently pass).
        for schema in SCHEMAS {
            assert!(
                schema.additional_fields.is_empty(),
                "schema id {} has non-empty additional_fields — update this test \
                 if that's an intentional extension",
                schema.id
            );
        }
    }

    #[test]
    fn schema_1_extra_field_still_rejected_with_empty_additional_fields() {
        // Unchanged behavior: an unlisted field is still rejected when
        // `additional_fields` is empty (today's state for every schema).
        let payload = json!({"task": "x", "priority": 1, "future_field": "v"});
        let err = PreCompiledSchemas::validate_payload(1, &payload).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::SchemaMismatch);
        assert!(err.message.contains("Unexpected field: future_field"));
    }
}
