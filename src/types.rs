//! Shared packet types — re-exported from `handler` for a stable public path.
//!
//! G3/M7: This module provides a stable import path for types that were
//! previously only accessible via `crate::handler::*`. All callers can now
//! use `crate::types::*` instead of `crate::handler::*`, breaking the
//! circular dependency chain handler↔rulepack, handler↔sid, etc.
//!
//! The canonical definitions remain in `handler.rs` for now. A future phase
//! will physically move them here when the handler is further decomposed.

// Re-export all shared types from handler
pub use crate::handler::{
    JsonValue, ParsedPacket, CachedTokenResult,
    DANGEROUS_ACTION_TERMS,
    serde_value_to_json_value, serde_value_to_json_value_bounded,
    json_value_depth_exceeded,
};
