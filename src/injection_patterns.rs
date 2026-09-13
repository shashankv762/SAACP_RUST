//! Prompt injection scanning — re-exported from `handler` for a stable public path.
//!
//! G3/M7: This module provides a stable import path for scanner items that were
//! previously only accessible via `crate::handler::*`. Breaking the
//! `handler ↔ rulepack` and `handler ↔ type_state` circular dependencies.
//!
//! The canonical definitions remain in `handler.rs` for now. A future phase
//! will physically move them here when the handler is further decomposed.

// Re-export scanner items from handler
pub use crate::handler::{
    builtin_injection_patterns, normalize_scan_window, PromptInjectionScanner,
};
