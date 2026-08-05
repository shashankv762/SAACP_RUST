//! shard.rs — shared shard-index hashing for the crate's sharded lock tables.
//!
//! Several hot-path structures replace one global mutex with an array of
//! per-shard mutexes (`gateway::AgentRateLimiter`, `trust_decay::TrustDecayEngine`,
//! `streaming::StreamRegistry`, `ievl::IevlEngine`, `cscs::OscillationFingerprinter`,
//! and the gateway token cache). Each needs to map a string key to a shard, and
//! the quality of that mapping decides whether sharding buys anything at all: if
//! a realistic workload concentrates on one shard, the remaining mutexes sit idle
//! and the structure behaves exactly as it did before it was sharded.
//!
//! ## Why the first byte is not enough
//!
//! The original convention was `key.as_bytes().first().unwrap_or(0) % N`. Hashing
//! a single byte fails on both key spaces this crate actually uses:
//!
//! * **Prefixed agent ids** — `agent-0001`, `agent-0002`, … all begin with `'a'`,
//!   so every one of them maps to the same shard. Measured: 16,000 such ids
//!   distribute as `[0, 16000, 0, …]` across 16 shards. This is the naming
//!   convention used throughout this crate's own tests, benchmarks, and docs.
//! * **Hex-encoded ids** — fingerprints, session uuids, and SHA-256 digests begin
//!   with a character from `[0-9a-f]`, whose ASCII codes (`0x30..=0x39` and
//!   `0x61..=0x66`) produce only ten distinct residues mod 16. Shards 10–15 are
//!   therefore **unreachable by construction**, no matter how much entropy the
//!   rest of the key carries.
//!
//! The second case is the instructive one: "the keys are random" does not rescue
//! a single-byte hash, because the entropy has to live in the byte being hashed.
//! `cscs.rs` diagnosed this for its own key space and fixed it locally; this
//! module generalizes that fix so every sharded structure shares one
//! implementation instead of each re-deriving (or re-breaking) it.
//!
//! ## Not a security primitive
//!
//! FNV-1a is a non-cryptographic hash, which is the right choice here: this
//! selects a *lock*, never a security decision, and no output is exposed on the
//! wire or used for authentication. A hostile key can at worst concentrate load
//! on one shard — precisely what the unsharded code did for every key already, so
//! this cannot be worse than the structure it replaced.
//!
//! Per-shard entry caps (`RATE_LIMITER_PER_SHARD_MAX_ENTRIES` and friends) remain
//! the memory bound against an attacker minting unlimited distinct ids; spreading
//! keys evenly is what lets those caps apply as intended rather than one shard
//! hitting its cap while fifteen sit empty.

/// FNV-1a 64-bit offset basis.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Map `key` to a shard index in `0..n_shards`, mixing **every** byte.
///
/// `n_shards` must be non-zero; callers pass a module-level constant.
#[inline]
pub fn fnv1a_shard(key: &str, n_shards: usize) -> usize {
    debug_assert!(n_shards > 0, "n_shards must be non-zero");
    let mut hash = FNV_OFFSET_BASIS;
    for b in key.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    (hash % n_shards as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chi-squared-ish evenness check over the three key shapes this crate
    /// actually produces. Each must land within ±10% of the ideal `n / shards`.
    #[test]
    fn distributes_every_real_key_shape_evenly() {
        const SHARDS: usize = 16;
        const N: usize = 16_000;

        let corpora: [(&str, Vec<String>); 4] = [
            // The shape that fully collapsed under a single-byte hash.
            ("prefixed agent ids", (0..N).map(|i| format!("agent-{i:04}")).collect()),
            // Hex ids: shards 10-15 were unreachable under a single-byte hash.
            ("hex session ids", (0..N).map(|i| format!("{:016x}", (i as u64).wrapping_mul(2_654_435_761))).collect()),
            // Namespaced trust keys (`trust_decay`), where the prefix is constant.
            ("namespaced pk: keys", (0..N).map(|i| format!("pk:{i:08x}")).collect()),
            // Long shared prefix, differing only in the final characters.
            ("long common prefix", (0..N).map(|i| format!("saacp-production-tenant-alpha-worker-{i}")).collect()),
        ];

        for (label, keys) in corpora {
            let mut counts = vec![0usize; SHARDS];
            for k in &keys {
                counts[fnv1a_shard(k, SHARDS)] += 1;
            }
            let ideal = N as f64 / SHARDS as f64;
            let (lo, hi) = (ideal * 0.9, ideal * 1.1);
            assert!(
                counts.iter().all(|&c| (c as f64) >= lo && (c as f64) <= hi),
                "{label}: uneven distribution {counts:?} \
                 (ideal {ideal:.0} per shard, tolerance {lo:.0}..={hi:.0})",
            );
        }
    }

    /// Same key, same shard — the lock table depends on this.
    #[test]
    fn is_deterministic() {
        for k in ["agent-1", "", "pk:deadbeef", "a"] {
            assert_eq!(fnv1a_shard(k, 16), fnv1a_shard(k, 16));
        }
    }

    /// Never indexes out of bounds, including on the empty key and non-power-of-two
    /// shard counts (`streaming::STREAM_SHARDS` is 8, but callers may pass others).
    #[test]
    fn stays_in_range_for_any_shard_count() {
        for shards in [1usize, 2, 3, 7, 8, 16, 64] {
            for k in ["", "a", "agent-0001", "\u{1F512}multibyte"] {
                assert!(fnv1a_shard(k, shards) < shards);
            }
        }
    }
}
