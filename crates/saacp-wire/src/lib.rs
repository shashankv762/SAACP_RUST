//! saacp-wire — SAACP wire format types.
//!
//! A `no_std + alloc` crate containing ONLY the structural parsing and building
//! of SAACP wire frames (MEASC headers + SAACPFrame application headers). No AEAD
//! cryptography, no async runtime, no OS dependencies.
//!
//! This crate compiles to:
//! - Native targets (via the `std` feature, enabled by default)
//! - `wasm32-wasi` and `wasm32-unknown-unknown` (disable the `std` feature)
//! - Embedded `no_std` targets with `alloc`
//!
//! # Relationship to the main `saacp` crate
//!
//! The `saacp` crate's `framing.rs` and `measc.rs` contain both structural
//! (parsing/building) logic AND cryptographic (AES-GCM, HKDF) logic in the same
//! file. `saacp-wire` extracts ONLY the structural half — the wire constants,
//! header layouts, and zero-copy parsers — for use by:
//! - Browser-based agents (Wasm)
//! - IoT microcontroller agents (`no_std` + `alloc`)
//! - Third-party SAACP implementations in other languages (via C FFI or Wasm)
//!
//! # Feature flags
//! - `std` (default): enables `std::io::Error` and standard I/O traits.
//!   Disable for `no_std` targets.
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod constants;
pub mod frame;
pub mod measc_header;

pub use constants::*;
pub use frame::SaacpFrame;
pub use measc_header::{MeascHeader, MeascVersion};
