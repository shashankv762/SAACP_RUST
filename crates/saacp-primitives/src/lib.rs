// SAACP Layer 0: Zero-dependency primitive types.
// These are the foundation every other workspace crate builds upon.
// No intra-workspace dependencies, no tokio, no observability libraries.
//
// FIPS note: this crate is part of the trusted base — every type here is
// subject to the same `forbid(unsafe_code)` guarantee as the rest of SAACP.
#![forbid(unsafe_code)]

pub mod errors;
pub mod clock;
pub mod shard;
pub mod estimator;
