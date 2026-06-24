use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use serde_json::Value;

/// Allowed meta keys that pass through validation without being counted as extra fields.
const ALLOWED_META_KEYS: &[&str] = &["_capability_token", "_cognitive_constraint", "_secondary_token"];

/// Schema definition holding an ID, human-readable name, and required keys.
struct SchemaDefinition {
    id: u16,
    #[allow(dead_code)]
    name: &'static str,
    required_keys: &'static [&'static str],
}

/// Static schema registry (IDs 0-9).
const SCHEMAS: &[SchemaDefinition] = &[
    SchemaDefinition { id: 0, name: "Raw Binary", required_keys: &[] },
    SchemaDefinition { id: 1, name: "Task", required_keys: &["task", "priority"] },
    SchemaDefinition { id: 2, name: "Action", required_keys: &["action", "target", "parameters"] },
    SchemaDefinition { id: 3, name: "Epistemic", required_keys: &["epistemic_metadata", "data"] },
    SchemaDefinition { id: 4, name: "Budget Request", required_keys: &["max_token_budget", "task_schema"] },
    SchemaDefinition { id: 5, name: "Cost Estimate", required_keys: &["estimated_cost", "max_token_budget"] },
    SchemaDefinition { id: 6, name: "Heartbeat", required_keys: &["agent_id", "heartbeat_seq", "status"] },
    SchemaDefinition { id: 7, name: "Error", required_keys: &["error_code", "error_detail", "retry_after"] },
    SchemaDefinition { id: 8, name: "Delegation", required_keys: &["delegation_request", "scope", "ttl"] },
    SchemaDefinition { id: 9, name: "Audit Query", required_keys: &["audit_query", "from_timestamp", "to_timestamp"] },
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
            if !is_required && !is_meta {
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
}
