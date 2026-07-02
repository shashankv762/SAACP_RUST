//! MEASC — Mandatory Encryption & Authenticated Sequence Control
//!
//! Full feature-parity with Python SAACP measc.py (1476 lines).
//! Security ordering in parse_frame() MUST NOT be reordered.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::schemas::PreCompiledSchemas;

// ─── Protocol constants ───────────────────────────────────────────────────────

pub const MEASC_REPLAY_WINDOW_SIZE: usize            = 4096;
pub const MEASC_MAX_PSN_ADVANCE: u64                 = 2048;
pub const MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD: u64   = 512;
pub const MEASC_REPLAY_RATE_LIMIT_WINDOW_SEC: f64    = 1.0;
pub const MEASC_REPLAY_MAX_LARGE_ADVANCES: u32       = 3;
pub const MEASC_REPLAY_MAX_ANOMALIES_QUARANTINE: u32 = 5;
pub const MEASC_DEFAULT_EPOCH_TIME_SECONDS: u64      = 600;
pub const MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD: u64  = 1_048_576;
pub const MEASC_EPOCH_GRACE_PERIOD_SECONDS: u64      = 60;
pub const MEASC_PSN_MAX: u64                         = i64::MAX as u64;
pub const MEASC_AUTH_TAG_SIZE: usize                 = 16;
pub const MEASC_HEADER_SIZE: usize                   = 128;
pub const MEASC_MAGIC: &[u8; 4]                      = b"SACP";
pub const MEASC_CONTEXT_REF_ID_OFFSET: usize         = 44;
pub const MEASC_CONTEXT_REF_ID_SIZE: usize           = 32;

// INVARIANT (spec §4.1): MEASC_MAX_PSN_ADVANCE MUST be < MEASC_REPLAY_WINDOW_SIZE.
// A larger advance would allow an attacker to skip beyond the entire bitmap,
// clearing all replay-protection records in a single packet.
const _: () = assert!(
    MEASC_MAX_PSN_ADVANCE < MEASC_REPLAY_WINDOW_SIZE as u64,
    "INVARIANT VIOLATED: MEASC_MAX_PSN_ADVANCE must be strictly less than MEASC_REPLAY_WINDOW_SIZE"
);

// INVARIANT: MEASC header sizes must match the wire layout.
const _: () = assert!(MEASC_HEADER_SIZE == 128, "MEASC_HEADER_SIZE must be 128");
const _: () = assert!(MEASC_AUTH_TAG_SIZE == 16, "MEASC_AUTH_TAG_SIZE must be 16");
const _: () = assert!(MEASC_CONTEXT_REF_ID_OFFSET == 44, "context_ref_id must be at offset 44");
const _: () = assert!(MEASC_CONTEXT_REF_ID_SIZE == 32, "context_ref_id field must be 32 bytes");

// HKDF info prefixes — MUST match Python measc.py exactly.
const HKDF_EPOCH_KEY_INFO_PREFIX: &[u8] = b"SAACP-MEASC-epoch-key-v1";
const HKDF_IV_INFO_PREFIX:        &[u8] = b"SAACP-MEASC-iv-v1";

// ─── AnomalyPolicy ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnomalyPolicy {
    Allow,
    #[default]
    Audit,
    RateLimit,
    Quarantine,
}

// ─── ReplayWindowPolicy ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ReplayWindowPolicy {
    pub window_size: usize,
    pub max_advance: u64,
    pub anomaly_jump_threshold: u64,
    pub anomaly_policy: AnomalyPolicy,
    pub max_anomalies_before_quarantine: u32,
    pub rate_limit_window_seconds: f64,
    pub max_large_advances_per_window: u32,
}

impl Default for ReplayWindowPolicy {
    fn default() -> Self {
        let mut p = Self {
            window_size: MEASC_REPLAY_WINDOW_SIZE,
            max_advance: MEASC_MAX_PSN_ADVANCE,
            anomaly_jump_threshold: MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD,
            anomaly_policy: AnomalyPolicy::Audit,
            max_anomalies_before_quarantine: MEASC_REPLAY_MAX_ANOMALIES_QUARANTINE,
            rate_limit_window_seconds: MEASC_REPLAY_RATE_LIMIT_WINDOW_SEC,
            max_large_advances_per_window: MEASC_REPLAY_MAX_LARGE_ADVANCES,
        };
        p.clamp();
        p
    }
}

impl ReplayWindowPolicy {
    pub fn clamp(&mut self) {
        if self.window_size < 1 { self.window_size = 1; }
        if self.max_advance >= self.window_size as u64 {
            self.max_advance = (self.window_size as u64).saturating_sub(1);
        }
        if self.anomaly_jump_threshold == 0 { self.anomaly_jump_threshold = 1; }
        if self.anomaly_jump_threshold >= self.max_advance {
            self.anomaly_jump_threshold = (self.max_advance / 2).max(1);
        }
    }
}

// ─── ReplayWindowStats ───────────────────────────────────────────────────────
// Matches the dict returned by Python ReplayWindow.statistics()

#[derive(Debug, Clone)]
pub struct ReplayWindowStats {
    pub highest: i64,
    pub window_size: usize,
    pub max_advance: u64,
    pub initialized: bool,
    pub grace_period_locked: bool,
    pub anomaly_count: u32,
    pub quarantined: bool,
    pub anomaly_policy: AnomalyPolicy,
    pub anomaly_jump_threshold: u64,
    pub rate_window_advances: u32,
}

// ─── EpochSnapshot ───────────────────────────────────────────────────────────
// Safe, Send-able snapshot of epoch state — returned by get_epoch() / get_current_epoch().

#[derive(Debug, Clone)]
pub struct EpochSnapshot {
    pub session_id: [u8; 16],
    pub epoch_id: u32,
    pub is_destroyed: bool,
    pub is_in_grace_period: bool,
    pub should_rotate: bool,
}

// ─── ReplayWindow ────────────────────────────────────────────────────────────

pub struct ReplayWindow {
    policy: ReplayWindowPolicy,
    bitmap: Vec<u8>,
    highest_psn: i64,
    initialized: bool,
    grace_period_locked: bool,
    anomaly_count: u32,
    quarantined: bool,
    rate_window_start: Instant,
    rate_window_advances: u32,
}

impl ReplayWindow {
    pub fn new(policy: ReplayWindowPolicy) -> Self {
        let bitmap_bytes = policy.window_size.div_ceil(8);
        Self {
            bitmap: vec![0u8; bitmap_bytes],
            highest_psn: -1,
            initialized: false,
            grace_period_locked: false,
            anomaly_count: 0,
            quarantined: false,
            rate_window_start: Instant::now(),
            rate_window_advances: 0,
            policy,
        }
    }

    pub fn with_default_policy() -> Self { Self::new(ReplayWindowPolicy::default()) }

    pub fn highest(&self) -> i64 { self.highest_psn }
    pub fn anomaly_count(&self) -> u32 { self.anomaly_count }
    pub fn is_quarantined(&self) -> bool { self.quarantined }
    pub fn is_grace_period_locked(&self) -> bool { self.grace_period_locked }
    pub fn anomaly_policy(&self) -> AnomalyPolicy { self.policy.anomaly_policy }
    /// Return a rich snapshot of replay-window state for monitoring/telemetry.
    /// Matches Python `ReplayWindow.statistics()` return dict exactly.
    pub fn statistics(&self) -> ReplayWindowStats {
        ReplayWindowStats {
            highest:                self.highest_psn,
            window_size:            self.policy.window_size,
            max_advance:            self.policy.max_advance,
            initialized:            self.initialized,
            grace_period_locked:    self.grace_period_locked,
            anomaly_count:          self.anomaly_count,
            quarantined:            self.quarantined,
            anomaly_policy:         self.policy.anomaly_policy,
            anomaly_jump_threshold: self.policy.anomaly_jump_threshold,
            rate_window_advances:   self.rate_window_advances,
        }
    }

    /// Legacy tuple accessor for internal tests that compare (highest, anomaly_count,
    /// quarantined, grace_period_locked). Python parity: use statistics() for rich access.
    #[allow(dead_code)]
    pub fn statistics_tuple(&self) -> (i64, u32, bool, bool) {
        (self.highest_psn, self.anomaly_count, self.quarantined, self.grace_period_locked)
    }

    pub fn lock_for_grace_period(&mut self) { self.grace_period_locked = true; }

    /// Atomic check-and-accept: verify PSN is not a duplicate/out-of-window AND
    /// immediately mark it as seen in one operation while the Mutex is held.
    ///
    /// SECURITY FIX (C-1 REPLAY-TOCTOU): Previously, `check()` and `accept()` were
    /// separate method calls separated by AES-GCM decryption. Under concurrent load,
    /// two threads for the same session+PSN could both pass `check()` before either
    /// called `accept()`, allowing a replay to succeed. Now the bitmap is marked
    /// atomically inside the same method, closing the window.
    ///
    /// Returns `(ok: bool, reason: &'static str)`. On `ok == true` the PSN is
    /// already recorded; the caller MUST NOT call `accept()` separately.
    pub fn check_and_accept(&mut self, psn: u64) -> (bool, &'static str) {
        // Run the check logic
        let (ok, reason) = self.check(psn);
        if ok {
            // Immediately mark as seen — same lock hold, no TOCTOU gap.
            let _ = self.accept(psn);
        }
        (ok, reason)
    }

    pub fn check(&mut self, psn: u64) -> (bool, &'static str) {
        if psn == 0 { return (false, "negative_psn"); }
        if self.quarantined { return (false, "quarantined"); }

        let highest = self.highest_psn;

        if highest >= 0 {
            // highest is i64 and checked >= 0; cast to u64 is safe.
            #[allow(clippy::cast_sign_loss)]
            let h = highest as u64;
            if psn > h.saturating_add(self.policy.max_advance) {
                return (false, "advance_too_large");
            }
            if psn <= h.saturating_sub(self.policy.window_size as u64) {
                return (false, "out_of_window");
            }
            if psn <= h {
                // psn % window_size <= window_size <= 4096 — always fits in usize.
                #[allow(clippy::cast_possible_truncation)]
                let bit_idx  = (psn as usize) % self.policy.window_size;
                let byte_idx = bit_idx / 8;
                let bit_off  = bit_idx % 8;
                if self.bitmap[byte_idx] & (1 << bit_off) != 0 {
                    return (false, "duplicate");
                }
            }
        }

        // highest checked >= 0 above; cast to u64 is safe.
        #[allow(clippy::cast_sign_loss)]
        let highest_u64 = if highest >= 0 { highest as u64 } else { 0u64 };
        let is_anomalous = highest >= 0
            && psn > highest_u64.saturating_add(self.policy.anomaly_jump_threshold);

        if is_anomalous {
            match self.policy.anomaly_policy {
                AnomalyPolicy::Allow => {}
                AnomalyPolicy::Audit => {
                    self.anomaly_count += 1;
                    return (true, "ok_anomaly_recorded");
                }
                AnomalyPolicy::RateLimit => {
                    let elapsed = self.rate_window_start.elapsed().as_secs_f64();
                    if elapsed > self.policy.rate_limit_window_seconds {
                        self.rate_window_advances = 0;
                        self.rate_window_start = Instant::now();
                    }
                    self.rate_window_advances += 1;
                    if self.rate_window_advances > self.policy.max_large_advances_per_window {
                        return (false, "rate_limit_exceeded");
                    }
                    self.anomaly_count += 1;
                    return (true, "ok_anomaly_recorded");
                }
                AnomalyPolicy::Quarantine => {
                    self.anomaly_count += 1;
                    if self.anomaly_count >= self.policy.max_anomalies_before_quarantine {
                        self.quarantined = true;
                        return (false, "quarantined");
                    }
                    return (true, "ok_anomaly_recorded");
                }
            }
        }

        (true, "ok")
    }

    pub fn accept(&mut self, psn: u64) -> Result<(), SAACPHardDrop> {
        if psn == 0 {
            return Err(SAACPHardDrop::new(SAACPBytecodes::PsnOutOfWindow, "PSN must be > 0"));
        }

        // highest_psn is i64; checked < 0 then cast to u64 is safe.
        #[allow(clippy::cast_sign_loss)]
        let h = if self.highest_psn < 0 { 0u64 } else { self.highest_psn as u64 };

        if psn > h || !self.initialized {
            let old_h     = h;
            let new_h     = psn;
            let new_start = new_h.saturating_sub(self.policy.window_size as u64);
            let old_start = old_h.saturating_sub(self.policy.window_size as u64);

            if new_start > old_start || !self.initialized {
                let clear_start = if self.initialized { old_start + 1 } else { 0 };
                let clear_end   = new_start;
                let clear_count = if clear_end >= clear_start {
                    (clear_end - clear_start + 1).min(self.policy.window_size as u64)
                } else { 0 };

                if clear_count >= self.policy.window_size as u64 {
                    self.bitmap.iter_mut().for_each(|b| *b = 0);
                } else {
                    for i in 0..clear_count {
                        let seq      = clear_start + i;
                        // seq % window_size <= window_size <= 4096 — fits in usize.
                        #[allow(clippy::cast_possible_truncation)]
                        let bit_idx  = (seq as usize) % self.policy.window_size;
                        let byte_idx = bit_idx / 8;
                        let bit_off  = bit_idx % 8;
                        self.bitmap[byte_idx] &= !(1 << bit_off);
                    }
                }
            }

            // psn <= MEASC_PSN_MAX = i64::MAX as u64, so fits in i64.
            #[allow(clippy::cast_possible_wrap)]
            { self.highest_psn = psn as i64; }
            self.initialized = true;
        }

        // psn % window_size <= window_size <= 4096 — fits in usize.
        #[allow(clippy::cast_possible_truncation)]
        let bit_idx  = (psn as usize) % self.policy.window_size;
        let byte_idx = bit_idx / 8;
        let bit_off  = bit_idx % 8;
        self.bitmap[byte_idx] |= 1 << bit_off;
        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), SAACPHardDrop> {
        if self.grace_period_locked {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                "Cannot reset a grace-period-locked replay window",
            ));
        }
        self.bitmap.iter_mut().for_each(|b| *b = 0);
        self.highest_psn = -1;
        self.initialized = false;
        self.anomaly_count = 0;
        self.quarantined = false;
        Ok(())
    }
}

// ─── PacketSequencer ─────────────────────────────────────────────────────────

pub struct PacketSequencer {
    next_psn: AtomicU64,
}

impl PacketSequencer {
    pub fn new(start: u64) -> Self { Self { next_psn: AtomicU64::new(start) } }

    pub fn next_psn(&self) -> Result<u64, SAACPHardDrop> {
        let psn = self.next_psn.fetch_add(1, Ordering::SeqCst);
        if psn >= MEASC_PSN_MAX {
            self.next_psn.fetch_sub(1, Ordering::SeqCst);
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SequenceOverflow, "PSN would exceed MEASC_PSN_MAX",
            ));
        }
        Ok(psn)
    }

    pub fn next(&self) -> Result<u64, SAACPHardDrop> { self.next_psn() }

    pub fn current(&self) -> u64 { self.next_psn.load(Ordering::SeqCst) }
}

// ─── KeyEvolutionEngine ──────────────────────────────────────────────────────

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyEvolutionEngine {
    session_secret: [u8; 32],
}

impl KeyEvolutionEngine {
    pub fn new(session_secret: [u8; 32]) -> Self { Self { session_secret } }

    pub fn derive_epoch_key(
        &self,
        session_id: &[u8; 16],
        epoch_id: u32,
        prev_key: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        if let Some(pk) = prev_key {
            // Chained epoch key derivation — matches Python normative reference (measc.py:226–228).
            //   IKM  = session_secret XOR prev_key   (XOR-mixed, not prev_key alone)
            //   salt = session_id
            //   info = b"SAACP-MEASC-epoch-key-v1" || epoch_id_BE4
            //
            // Using prev_key directly as IKM (the old approach) breaks forward secrecy:
            // an attacker who recovers epoch N's traffic key can derive all future epoch
            // keys without ever knowing session_secret.  The XOR mix forces session_secret
            // to be part of every chained derivation.
            let mut ikm = [0u8; 32];
            for i in 0..32 { ikm[i] = self.session_secret[i] ^ pk[i]; }

            let mut info = Vec::with_capacity(HKDF_EPOCH_KEY_INFO_PREFIX.len() + 4);
            info.extend_from_slice(HKDF_EPOCH_KEY_INFO_PREFIX);
            info.extend_from_slice(&epoch_id.to_be_bytes());

            let hk = Hkdf::<Sha256>::new(Some(session_id), &ikm);
            let mut okm = [0u8; 32];
            hk.expand(&info, &mut okm).expect("HKDF expand failed for epoch evolution");
            okm
        } else {
            // Initial epoch key derivation: IKM = session_secret.
            let mut info = Vec::with_capacity(HKDF_EPOCH_KEY_INFO_PREFIX.len() + 4);
            info.extend_from_slice(HKDF_EPOCH_KEY_INFO_PREFIX);
            info.extend_from_slice(&epoch_id.to_be_bytes());

            let hk  = Hkdf::<Sha256>::new(Some(session_id), &self.session_secret);
            let mut okm = [0u8; 32];
            hk.expand(&info, &mut okm).expect("HKDF expand failed");
            okm
        }
    }
}

// ─── IV Derivation ───────────────────────────────────────────────────────────

fn derive_iv(traffic_key: &[u8; 32], epoch_id: u32, psn: u64) -> [u8; 12] {
    let mut info = Vec::with_capacity(HKDF_IV_INFO_PREFIX.len() + 12);
    info.extend_from_slice(HKDF_IV_INFO_PREFIX);
    info.extend_from_slice(&epoch_id.to_be_bytes());
    info.extend_from_slice(&psn.to_be_bytes());

    let hk  = Hkdf::<Sha256>::from_prk(traffic_key).expect("PRK length valid");
    let mut iv = [0u8; 12];
    hk.expand(&info, &mut iv).expect("IV HKDF expand failed");
    iv
}

// ─── SessionEpoch ────────────────────────────────────────────────────────────

pub struct SessionEpoch {
    pub session_id: [u8; 16],
    pub epoch_id: u32,
    traffic_key: [u8; 32],
    pub created_at: Instant,
    pub packet_threshold: u64,
    pub time_threshold: Duration,
    pub replay_window: ReplayWindow,
    pub sequencer: PacketSequencer,
    destroyed: bool,
    in_grace_period: bool,
}

impl SessionEpoch {
    pub fn new(
        session_id: [u8; 16],
        epoch_id: u32,
        traffic_key: [u8; 32],
        packet_threshold: u64,
        time_threshold_secs: f64,
    ) -> Self {
        Self {
            session_id,
            epoch_id,
            traffic_key,
            created_at: Instant::now(),
            packet_threshold,
            time_threshold: Duration::from_secs_f64(time_threshold_secs),
            replay_window: ReplayWindow::with_default_policy(),
            sequencer: PacketSequencer::new(1),
            destroyed: false,
            in_grace_period: false,
        }
    }

    pub fn traffic_key(&self) -> Result<&[u8; 32], SAACPHardDrop> {
        if self.destroyed {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::EpochExpired, "Attempted to access destroyed epoch key material",
            ));
        }
        Ok(&self.traffic_key)
    }

    pub fn is_destroyed(&self) -> bool { self.destroyed }
    pub fn is_in_grace_period(&self) -> bool { self.in_grace_period }

    pub fn should_rotate(&self) -> bool {
        if self.destroyed { return false; }
        self.sequencer.current() >= self.packet_threshold
            || self.created_at.elapsed() >= self.time_threshold
    }

    pub fn enter_grace_period(&mut self) {
        self.in_grace_period = true;
        self.replay_window.lock_for_grace_period();
    }

    pub fn destroy(&mut self) {
        if !self.destroyed {
            self.traffic_key.zeroize();
            self.destroyed = true;
        }
    }
}

/// SECURITY FIX (FINDING-2b): `destroy()` was previously the only path that
/// zeroized `traffic_key`; a panic unwinding through a scope holding a live
/// `SessionEpoch` (e.g. before `rotate_epoch()`/`destroy_session()` call
/// `destroy()`) skipped zeroization entirely. Drop guarantees it always runs.
impl Drop for SessionEpoch {
    fn drop(&mut self) {
        self.destroy();
    }
}

// ─── SessionEpochManager ─────────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Zeroize, ZeroizeOnDrop)]
struct SessionMeta {
    secret: [u8; 32],
    current_epoch: u32,
    packet_threshold: u64,
    time_threshold_secs: f64,
    suite_transcript_hash_hex: String,
}

pub struct SessionEpochManager {
    pub(crate) sessions: Mutex<HashMap<[u8; 16], HashMap<u32, SessionEpoch>>>,
    meta: Mutex<HashMap<[u8; 16], SessionMeta>>,
    grace: Mutex<HashMap<[u8; 16], HashMap<u32, Instant>>>,
}

impl Default for SessionEpochManager {
    fn default() -> Self { Self::new() }
}

impl SessionEpochManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            meta: Mutex::new(HashMap::new()),
            grace: Mutex::new(HashMap::new()),
        }
    }

    pub fn create_session(
        &self,
        session_id: [u8; 16],
        session_secret: [u8; 32],
        packet_threshold: u64,
        time_threshold_secs: f64,
        suite_transcript_hash: Option<[u8; 32]>,
    ) -> Result<u32, SAACPHardDrop> {
        let (bound_secret, suite_hex) = if let Some(tx_hash) = suite_transcript_hash {
            let hk = Hkdf::<Sha256>::new(Some(&tx_hash), &session_secret);
            let mut bound = [0u8; 32];
            hk.expand(b"SAACP-suite-binding", &mut bound).expect("HKDF expand");
            (bound, hex::encode(tx_hash))
        } else {
            (session_secret, String::new())
        };

        let engine = KeyEvolutionEngine::new(bound_secret);
        let initial_key = engine.derive_epoch_key(&session_id, 0, None);
        let epoch = SessionEpoch::new(session_id, 0, initial_key, packet_threshold, time_threshold_secs);

        {
            let mut sessions = self.sessions.lock().unwrap();
            if sessions.contains_key(&session_id) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::SchemaMismatch,
                    format!("Session {} already exists", hex::encode(session_id)),
                ));
            }
            let mut ep_map = HashMap::new();
            ep_map.insert(0u32, epoch);
            sessions.insert(session_id, ep_map);
        }

        self.meta.lock().unwrap().insert(session_id, SessionMeta {
            secret: bound_secret,
            current_epoch: 0,
            packet_threshold,
            time_threshold_secs,
            suite_transcript_hash_hex: suite_hex,
        });
        self.grace.lock().unwrap().insert(session_id, HashMap::new());
        Ok(0)
    }

    pub fn with_epoch<F, R>(&self, session_id: &[u8; 16], epoch_id: u32, f: F) -> Option<R>
    where F: FnOnce(&SessionEpoch) -> R {
        self.sessions.lock().unwrap().get(session_id)?.get(&epoch_id).map(f)
    }

    pub fn with_epoch_mut<F, R>(&self, session_id: &[u8; 16], epoch_id: u32, f: F) -> Option<R>
    where F: FnOnce(&mut SessionEpoch) -> R {
        self.sessions.lock().unwrap().get_mut(session_id)?.get_mut(&epoch_id).map(f)
    }

    pub fn get_current_epoch_id(&self, session_id: &[u8; 16]) -> Option<u32> {
        self.meta.lock().unwrap().get(session_id).map(|m| m.current_epoch)
    }

    pub fn list_epoch_ids(&self, session_id: &[u8; 16]) -> Vec<u32> {
        match self.sessions.lock().unwrap().get(session_id) {
            Some(m) => { let mut v: Vec<u32> = m.keys().copied().collect(); v.sort(); v }
            None => vec![],
        }
    }

    pub fn rotate_epoch(&self, session_id: &[u8; 16]) -> Result<u32, SAACPHardDrop> {
        let (current_id, secret, packet_threshold, time_threshold_secs) = {
            let meta = self.meta.lock().unwrap();
            let m = meta.get(session_id).ok_or_else(|| SAACPHardDrop::new(
                SAACPBytecodes::EpochExpired,
                format!("Cannot rotate: session {} not found", hex::encode(session_id)),
            ))?;
            (m.current_epoch, m.secret, m.packet_threshold, m.time_threshold_secs)
        };

        let prev_key = {
            let sessions = self.sessions.lock().unwrap();
            let ep_map = sessions.get(session_id).ok_or_else(|| SAACPHardDrop::new(
                SAACPBytecodes::EpochExpired, "Session not found",
            ))?;
            let epoch = ep_map.get(&current_id).ok_or_else(|| SAACPHardDrop::new(
                SAACPBytecodes::EpochExpired, format!("Current epoch {} not found", current_id),
            ))?;
            *epoch.traffic_key()?
        };

        let new_epoch_id = current_id.checked_add(1).ok_or_else(|| SAACPHardDrop::new(
            SAACPBytecodes::SequenceOverflow, "Epoch ID exhausted — u32 overflow",
        ))?;
        let engine   = KeyEvolutionEngine::new(secret);
        let new_key  = engine.derive_epoch_key(session_id, new_epoch_id, Some(&prev_key));
        let new_epoch = SessionEpoch::new(
            *session_id, new_epoch_id, new_key, packet_threshold, time_threshold_secs,
        );

        {
            let mut sessions = self.sessions.lock().unwrap();
            let ep_map = sessions.get_mut(session_id).ok_or_else(|| SAACPHardDrop::new(
                SAACPBytecodes::EpochExpired, "Session disappeared during rotation",
            ))?;
            ep_map.insert(new_epoch_id, new_epoch);
        }

        if let Some(m) = self.meta.lock().unwrap().get_mut(session_id) {
            m.current_epoch = new_epoch_id;
        }
        self.grace.lock().unwrap()
            .entry(*session_id).or_default()
            .insert(current_id, Instant::now());

        {
            let mut sessions = self.sessions.lock().unwrap();
            if let Some(ep_map) = sessions.get_mut(session_id) {
                if let Some(old) = ep_map.get_mut(&current_id) {
                    old.enter_grace_period();
                    old.destroy();
                }
            }
        }

        Ok(new_epoch_id)
    }

    pub fn check_and_rotate(&self, session_id: &[u8; 16]) -> Option<u32> {
        let current_id = self.get_current_epoch_id(session_id)?;
        let should = self.with_epoch(session_id, current_id, |e| e.should_rotate())?;
        if should { self.rotate_epoch(session_id).ok() } else { None }
    }

    pub fn destroy_session(&self, session_id: &[u8; 16]) {
        let epochs = self.sessions.lock().unwrap().remove(session_id);
        self.meta.lock().unwrap().remove(session_id);
        self.grace.lock().unwrap().remove(session_id);
        if let Some(mut ep_map) = epochs {
            for e in ep_map.values_mut() { e.destroy(); }
        }
    }

    pub fn expire_old_epochs(&self, grace_seconds: Option<f64>) -> usize {
        let grace = Duration::from_secs_f64(
            grace_seconds.unwrap_or(MEASC_EPOCH_GRACE_PERIOD_SECONDS as f64)
        );
        let to_remove: Vec<([u8; 16], u32)> = {
            let g = self.grace.lock().unwrap();
            g.iter().flat_map(|(sid, eid_map)| {
                eid_map.iter()
                    .filter(|(_, &t)| t.elapsed() >= grace)
                    .map(|(&eid, _)| (*sid, eid))
                    .collect::<Vec<_>>()
            }).collect()
        };
        let mut collected = 0;
        for (sid, eid) in to_remove {
            let ep = self.sessions.lock().unwrap().get_mut(&sid).and_then(|m| m.remove(&eid));
            self.grace.lock().unwrap().get_mut(&sid).map(|m| m.remove(&eid));
            if let Some(mut e) = ep { e.destroy(); collected += 1; }
        }
        collected
    }

    pub fn session_count(&self) -> usize { self.sessions.lock().unwrap().len() }

    // ── Python parity: get_epoch() and get_current_epoch() ──────────────────

    /// Return a clone of the SessionEpoch state for the given (session_id, epoch_id).
    /// Python parity: `SessionEpochManager.get_epoch(session_id, epoch_id)`.
    pub fn get_epoch(&self, session_id: &[u8; 16], epoch_id: u32) -> Option<EpochSnapshot> {
        let sessions = self.sessions.lock().unwrap();
        let ep = sessions.get(session_id)?.get(&epoch_id)?;
        Some(EpochSnapshot {
            session_id: *session_id,
            epoch_id,
            is_destroyed: ep.is_destroyed(),
            is_in_grace_period: ep.is_in_grace_period(),
            should_rotate: ep.should_rotate(),
        })
    }

    /// Return a clone of the current-epoch state for a session.
    /// Python parity: `SessionEpochManager.get_current_epoch(session_id)`.
    pub fn get_current_epoch(&self, session_id: &[u8; 16]) -> Option<EpochSnapshot> {
        let current_id = self.get_current_epoch_id(session_id)?;
        self.get_epoch(session_id, current_id)
    }

    /// Negotiate a cipher suite and create a session in one call.
    /// Python parity: `SessionEpochManager.create_session_with_negotiation()`.
    ///
    /// 1. Calls `SuiteNegotiator::negotiate()` to select an approved suite and
    ///    produce a `NegotiationTranscript`.
    /// 2. Derives a 32-byte transcript hash from the transcript's `transcript_hash_hex`.
    /// 3. Passes the transcript hash to `create_session()` for key binding.
    /// 4. Returns `(epoch_id, NegotiationTranscript)` so callers can transmit
    ///    `transcript_hash_hex` to the remote peer for verification.
    #[allow(clippy::too_many_arguments)]
    pub fn create_session_with_negotiation(
        &self,
        session_id: [u8; 16],
        session_secret: [u8; 32],
        local_suites: &[&str],
        remote_suites: &[&str],
        protocol_version: Option<&str>,
        packet_threshold: u64,
        time_threshold_secs: f64,
    ) -> Result<(u32, crate::crypto_governance::NegotiationTranscript), SAACPHardDrop> {
        use crate::crypto_governance::{SuiteNegotiator, CryptoTransparencyLedger};
        // Use a temporary per-call ledger so this convenience method does not
        // require a global ledger reference (callers can pass their own ledger to
        // SuiteNegotiator::negotiate directly if they need persistent audit).
        let tmp_ledger = CryptoTransparencyLedger::new();
        // Step 1: negotiate a common approved suite
        let transcript = SuiteNegotiator::negotiate(
            local_suites,
            remote_suites,
            &session_id,
            protocol_version,
            None,          // use production policy default
            &tmp_ledger,
        ).map_err(|e| SAACPHardDrop::new(
            SAACPBytecodes::SchemaMismatch,
            format!("Suite negotiation failed: {e}"),
        ))?;
        // Step 2: copy transcript.transcript_hash (32-byte SHA-256) into fixed array
        let mut suite_tx_hash = [0u8; 32];
        let src = &transcript.transcript_hash;
        let len = src.len().min(32);
        suite_tx_hash[..len].copy_from_slice(&src[..len]);
        // Step 3: create session with transcript binding
        let epoch_id = self.create_session(
            session_id,
            session_secret,
            packet_threshold,
            time_threshold_secs,
            Some(suite_tx_hash),
        )?;
        Ok((epoch_id, transcript))
    }
}


// ─── ParsedMEASCFrame ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ParsedMEASCFrame {
    pub schema_id: u16,
    pub status_code: u8,
    pub flags: u8,
    pub action_class: u8,
    pub payload_length: u32,
    pub session_id: [u8; 16],
    pub epoch_id: u32,
    pub psn: u64,
    pub context_ref_id: [u8; 32],
    pub context_version: u32,
    pub traceparent: [u8; 24],
    pub payload: Vec<u8>,
}

// ─── MEASCFrame ───────────────────────────────────────────────────────────────

pub struct MEASCFrame;

impl MEASCFrame {
    pub const HEADER_SIZE: usize    = MEASC_HEADER_SIZE;
    pub const AUTH_TAG_SIZE: usize  = MEASC_AUTH_TAG_SIZE;
    pub const MIN_FRAME_SIZE: usize = MEASC_HEADER_SIZE + MEASC_AUTH_TAG_SIZE;

    #[allow(clippy::too_many_arguments)]
    pub fn build_frame(
        epoch: &mut SessionEpoch,
        schema_id: u16,
        status_code: u8,
        flags: u8,
        action_class: u8,
        payload: &[u8],
        context_ref_id: &[u8; 32],
        traceparent: &[u8; 24],
        context_version: u32,
    ) -> Result<(Vec<u8>, u64), SAACPHardDrop> {
        let psn         = epoch.sequencer.next_psn()?;
        let traffic_key = *epoch.traffic_key()?;
        let iv          = derive_iv(&traffic_key, epoch.epoch_id, psn);

        // GAP-9 / M-2 fix: EASI-encrypt the Context Ref ID before placing it in
        // the authenticated header. The outer AES-256-GCM tag covers the encrypted
        // form, providing both integrity and confidentiality for this field.
        let easi_ctx_ref_id = crate::easi::EasiEncryptor::encrypt(
            context_ref_id, &traffic_key, epoch.epoch_id, psn,
        );

        let mut header = vec![0u8; MEASC_HEADER_SIZE];
        header[0..4].copy_from_slice(MEASC_MAGIC);
        header[4..6].copy_from_slice(&schema_id.to_be_bytes());
        header[6]  = status_code;
        header[7]  = flags;
        header[8]  = action_class;
        // payload.len() <= 10 MB (checked before build_frame is called) — fits in u32.
        header[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        header[16..32].copy_from_slice(&epoch.session_id);
        header[32..36].copy_from_slice(&epoch.epoch_id.to_be_bytes());
        header[36..44].copy_from_slice(&psn.to_be_bytes());
        header[44..76].copy_from_slice(&easi_ctx_ref_id);
        header[76..80].copy_from_slice(&context_version.to_be_bytes());
        header[80..104].copy_from_slice(traceparent);

        let key    = Key::<Aes256Gcm>::from_slice(&traffic_key);
        let cipher = Aes256Gcm::new(key);
        let nonce  = Nonce::from_slice(&iv);

        let ct_with_tag = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: payload, aad: &header })
            .map_err(|_| SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature, "AES-GCM encryption failed",
            ))?;

        // Wire format: header || tag (last 16B) || ciphertext (matches Python layout)
        let ct_len = ct_with_tag.len() - MEASC_AUTH_TAG_SIZE;
        let mut frame = Vec::with_capacity(MEASC_HEADER_SIZE + ct_with_tag.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&ct_with_tag[ct_len..]);  // tag
        frame.extend_from_slice(&ct_with_tag[..ct_len]);  // ciphertext

        Ok((frame, psn))
    }

    /// 9-step security pipeline — DO NOT REORDER.
    pub fn parse_frame(
        buffer: &[u8],
        epoch_manager: &SessionEpochManager,
        skip_schema_validation: bool,
    ) -> Result<ParsedMEASCFrame, SAACPHardDrop> {
        // Step 1
        if buffer.len() < Self::MIN_FRAME_SIZE {
            return Err(SAACPHardDrop::new(SAACPBytecodes::MalformedHeader,
                "Buffer too short for MEASC frame"));
        }

        // Step 2
        let header = &buffer[..MEASC_HEADER_SIZE];
        if &header[0..4] != MEASC_MAGIC {
            return Err(SAACPHardDrop::new(SAACPBytecodes::MalformedHeader,
                format!("Invalid MEASC magic: {:?}", &header[0..4])));
        }
        let schema_id       = u16::from_be_bytes(header[4..6].try_into().unwrap());
        let status_code     = header[6];
        let flags           = header[7];
        let action_class    = header[8];
        let payload_length  = u32::from_be_bytes(header[12..16].try_into().unwrap());
        let session_id: [u8; 16] = header[16..32].try_into().unwrap();
        let epoch_id        = u32::from_be_bytes(header[32..36].try_into().unwrap());
        let psn             = u64::from_be_bytes(header[36..44].try_into().unwrap());
        let context_ref_id: [u8; 32] = header[44..76].try_into().unwrap();
        let context_version = u32::from_be_bytes(header[76..80].try_into().unwrap());
        let traceparent: [u8; 24]   = header[80..104].try_into().unwrap();

        // Step 3
        if payload_length > 10_000_000 {
            return Err(SAACPHardDrop::new(SAACPBytecodes::PayloadTooLarge,
                format!("MEASC payload {} > 10MB MTU", payload_length)));
        }
        let expected_total = MEASC_HEADER_SIZE + MEASC_AUTH_TAG_SIZE + payload_length as usize;
        if buffer.len() < expected_total {
            return Err(SAACPHardDrop::new(SAACPBytecodes::MalformedHeader,
                "Buffer too short for declared payload length"));
        }

        // Step 4
        let epoch_ok = epoch_manager.with_epoch(&session_id, epoch_id, |e| !e.is_destroyed());
        if epoch_ok != Some(true) {
            return Err(SAACPHardDrop::new(SAACPBytecodes::EpochExpired,
                format!("Epoch (session={}, epoch_id={}) unknown or destroyed",
                    hex::encode(&session_id[..4]), epoch_id)));
        }

        // Step 5 — SECURITY FIX (C-1 REPLAY-TOCTOU):
        // Use check_and_accept() to atomically verify AND mark the PSN as seen
        // in a single Mutex hold. The old split (check → decrypt → accept) created
        // a TOCTOU window where two concurrent threads could both pass check()
        // for the same PSN before either called accept().
        let (rw_ok, rw_reason) = epoch_manager
            .with_epoch_mut(&session_id, epoch_id, |e| e.replay_window.check_and_accept(psn))
            .unwrap();

        if !rw_ok {
            let (bc, msg) = match rw_reason {
                "duplicate"          => (SAACPBytecodes::PsnReplayDetected,
                    format!("PSN {} already accepted in epoch {}", psn, epoch_id)),
                "advance_too_large"  => (SAACPBytecodes::PsnOutOfWindow,
                    format!("PSN {} advance exceeds max {}", psn, MEASC_MAX_PSN_ADVANCE)),
                "rate_limit_exceeded"=> (SAACPBytecodes::PsnOutOfWindow,
                    format!("PSN {} rate limit exceeded in epoch {}", psn, epoch_id)),
                "quarantined"        => (SAACPBytecodes::PsnReplayDetected,
                    format!("PSN {} rejected — epoch {} window quarantined", psn, epoch_id)),
                _                    => (SAACPBytecodes::PsnOutOfWindow,
                    format!("PSN {} out of window ({})", psn, rw_reason)),
            };
            return Err(SAACPHardDrop::new(bc, msg));
        }

        // Step 6
        let auth_tag   = &buffer[MEASC_HEADER_SIZE..MEASC_HEADER_SIZE + MEASC_AUTH_TAG_SIZE];
        let ciphertext = &buffer[MEASC_HEADER_SIZE + MEASC_AUTH_TAG_SIZE..expected_total];

        let traffic_key = epoch_manager
            .with_epoch(&session_id, epoch_id, |e| e.traffic_key().copied())
            .unwrap()?;

        let iv    = derive_iv(&traffic_key, epoch_id, psn);
        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + MEASC_AUTH_TAG_SIZE);
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(auth_tag);

        let key    = Key::<Aes256Gcm>::from_slice(&traffic_key);
        let cipher = Aes256Gcm::new(key);
        let nonce  = Nonce::from_slice(&iv);

        let plaintext = cipher
            .decrypt(nonce, aes_gcm::aead::Payload { msg: &ct_with_tag, aad: header })
            .map_err(|_| SAACPHardDrop::new(SAACPBytecodes::InvalidSignature,
                "MEASC AES-GCM auth failed — tampering or replay"))?;

        // Step 7: PSN already accepted atomically in Step 5 (check_and_accept).
        // No separate accept() call needed — that would re-mark an already-set bit.

        // GAP-9 / M-2 fix: EASI-decrypt the Context Ref ID.
        // The header was authenticated (Step 6 AES-GCM) with the encrypted form.
        // Now recover the plaintext context_ref_id using the same traffic_key,
        // epoch_id, and psn that were used during build_frame encryption.
        let context_ref_id = crate::easi::EasiEncryptor::decrypt(
            &context_ref_id, &traffic_key, epoch_id, psn,
        );

        // Step 8
        if !skip_schema_validation {
            let json_val: serde_json::Value = serde_json::from_slice(&plaintext)
                .map_err(|_| SAACPHardDrop::new(SAACPBytecodes::SchemaMismatch,
                    "MEASC payload is not valid JSON for schema validation"))?;
            PreCompiledSchemas::validate_payload(schema_id, &json_val)?;
        }

        // Step 9
        let should = epoch_manager.with_epoch(&session_id, epoch_id, |e| e.should_rotate())
            .unwrap_or(false);
        if should { let _ = epoch_manager.check_and_rotate(&session_id); }

        Ok(ParsedMEASCFrame {
            schema_id, status_code, flags, action_class, payload_length,
            session_id, epoch_id, psn, context_ref_id, context_version, traceparent,
            payload: plaintext,
        })
    }
}

// ─── PSKCompromiseRecovery ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PSKCompromiseReport {
    pub sessions_destroyed: usize,
    pub session_ids_hex: Vec<String>,
    pub revocation_epoch: u64,
    pub recovery_complete: bool,
}

pub struct PSKCompromiseRecovery {
    manager: Arc<SessionEpochManager>,
    /// Step 1/2 gateway callback: called to execute `revoke_all_tokens()`.
    gateway_callback: Option<Box<dyn Fn() + Send + Sync>>,
    /// Step 6 callback: revoke all SignedCapabilityTokens via ACSVAF/FACTF.
    /// Caller should close/revoke all active capability tokens.
    capability_revoke_callback: Option<Box<dyn Fn() + Send + Sync>>,
    /// Step 7 callback: rotate all Ed25519 keys via `KeyLifecycleManager`.
    /// Caller should call `KeyLifecycleManager::rotate_key()` for every key.
    key_rotation_callback: Option<Box<dyn Fn() + Send + Sync>>,
    /// Step 8 callback: audit `SecureDiagnosticLedger` (PECF) for anomalies.
    /// Caller should scan SDL for anomalous session records and log/alert.
    audit_callback: Option<Box<dyn Fn() + Send + Sync>>,
}

impl PSKCompromiseRecovery {
    /// Create with only the mandatory gateway callback (steps 1–5 only).
    pub fn new(
        manager: Arc<SessionEpochManager>,
        gateway_callback: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> Self {
        Self {
            manager,
            gateway_callback,
            capability_revoke_callback: None,
            key_rotation_callback: None,
            audit_callback: None,
        }
    }

    /// Builder: register Step 6 callback (ACSVAF/FACTF token revocation).
    ///
    /// # Python parity
    /// Matches README §5.6 Step 6: "Revoke all SignedCapabilityTokens via ACSVAF/FACTF".
    pub fn with_capability_revoke(mut self, cb: Box<dyn Fn() + Send + Sync>) -> Self {
        self.capability_revoke_callback = Some(cb);
        self
    }

    /// Builder: register Step 7 callback (Ed25519 key rotation via KLMS).
    ///
    /// # Python parity
    /// Matches README §5.6 Step 7: "Rotate all Ed25519 signing keys via KeyLifecycleManager".
    pub fn with_key_rotation(mut self, cb: Box<dyn Fn() + Send + Sync>) -> Self {
        self.key_rotation_callback = Some(cb);
        self
    }

    /// Builder: register Step 8 callback (SDL audit via PECF).
    ///
    /// # Python parity
    /// Matches README §5.6 Step 8: "Audit SecureDiagnosticLedger for anomalous sessions".
    pub fn with_audit(mut self, cb: Box<dyn Fn() + Send + Sync>) -> Self {
        self.audit_callback = Some(cb);
        self
    }

    /// Execute the **full 8-step PSK Compromise Recovery** procedure.
    ///
    /// Step ordering (MUST NOT be reordered per SAACP/M-6):
    ///   Step 1: Invoke gateway_callback → `ZeroTrustGateway::revoke_all_tokens()`
    ///   Step 2: Destroy ALL active MEASC sessions via `SessionEpochManager`
    ///   Step 3–5: Rotate PSK / re-register issuer keys / re-issue tokens
    ///             (caller's responsibility after this call returns)
    ///   Step 6: Invoke capability_revoke_callback → revoke all ACSVAF/FACTF tokens
    ///   Step 7: Invoke key_rotation_callback → rotate all Ed25519 keys via KLMS
    ///   Step 8: Invoke audit_callback → scan SDL for anomalous sessions
    ///
    /// # Python parity
    /// Fully implements the 8-step procedure documented in README §5.6 and measc.py.
    pub fn execute(&self, gateway_revocation_epoch: Option<u64>) -> PSKCompromiseReport {
        // ── Step 1: Gateway revoke_all_tokens ──────────────────────────────
        if let Some(cb) = &self.gateway_callback {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cb));
        }

        // ── Step 2: Destroy ALL active MEASC sessions ──────────────────────
        let session_ids: Vec<[u8; 16]> = {
            self.manager.sessions.lock().unwrap().keys().copied().collect()
        };
        let mut destroyed     = 0usize;
        let mut destroyed_hex = Vec::new();
        for sid in &session_ids {
            self.manager.destroy_session(sid);
            destroyed += 1;
            destroyed_hex.push(hex::encode(sid));
        }

        // ── Step 6: Revoke all capability tokens (ACSVAF/FACTF) ────────────
        if let Some(cb) = &self.capability_revoke_callback {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cb));
        }

        // ── Step 7: Rotate all Ed25519 keys (KLMS) ─────────────────────────
        if let Some(cb) = &self.key_rotation_callback {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cb));
        }

        // ── Step 8: Audit SDL (PECF) for anomalous sessions ────────────────
        if let Some(cb) = &self.audit_callback {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cb));
        }

        PSKCompromiseReport {
            sessions_destroyed: destroyed,
            session_ids_hex: destroyed_hex,
            revocation_epoch: gateway_revocation_epoch.unwrap_or(0),
            recovery_complete: true,
        }
    }
}


// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_window_policy_defaults() {
        let p = ReplayWindowPolicy::default();
        assert_eq!(p.window_size, MEASC_REPLAY_WINDOW_SIZE);
        assert!(p.max_advance < p.window_size as u64);
    }

    #[test]
    fn test_replay_window_policy_clamping() {
        let mut p = ReplayWindowPolicy {
            window_size: 10,
            max_advance: MEASC_MAX_PSN_ADVANCE,
            anomaly_jump_threshold: MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD,
            anomaly_policy: AnomalyPolicy::Audit,
            max_anomalies_before_quarantine: 5,
            rate_limit_window_seconds: 1.0,
            max_large_advances_per_window: 3,
        };
        p.clamp();
        assert!(p.max_advance < 10);
        assert!(p.anomaly_jump_threshold < p.max_advance);
    }

    #[test]
    fn test_replay_window_basic() {
        let mut w = ReplayWindow::with_default_policy();
        let (ok, _) = w.check(1);
        assert!(ok);
        w.accept(1).unwrap();
        let (ok2, r) = w.check(1);
        assert!(!ok2);
        assert_eq!(r, "duplicate");
    }

    #[test]
    fn test_replay_window_advance_too_large() {
        let mut w = ReplayWindow::with_default_policy();
        w.accept(1).unwrap();
        let (ok, r) = w.check(1 + MEASC_MAX_PSN_ADVANCE + 1);
        assert!(!ok);
        assert_eq!(r, "advance_too_large");
    }

    #[test]
    fn test_replay_window_grace_period_lock() {
        let mut w = ReplayWindow::with_default_policy();
        w.lock_for_grace_period();
        assert!(w.is_grace_period_locked());
        assert!(w.reset().is_err());
    }

    #[test]
    fn test_replay_window_statistics() {
        let mut w = ReplayWindow::with_default_policy();
        w.accept(5).unwrap();
        // Test new struct API (matches Python statistics() dict)
        let stats = w.statistics();
        assert_eq!(stats.highest, 5);
        assert_eq!(stats.anomaly_count, 0);
        assert!(!stats.quarantined);
        assert!(!stats.grace_period_locked);
        assert!(stats.initialized);
        assert_eq!(stats.window_size, MEASC_REPLAY_WINDOW_SIZE);
        assert_eq!(stats.max_advance, MEASC_MAX_PSN_ADVANCE);
        assert_eq!(stats.anomaly_jump_threshold, MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD);
        // Legacy tuple (for backward compat)
        let (h, anomaly, quarantined, grace) = w.statistics_tuple();
        assert_eq!(h, 5);
        assert_eq!(anomaly, 0);
        assert!(!quarantined);
        assert!(!grace);
    }

    #[test]
    fn test_session_epoch_destroy_guard() {
        let mut e = SessionEpoch::new([0u8;16], 0, [1u8;32],
            MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD, MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64);
        assert!(e.traffic_key().is_ok());
        e.destroy();
        assert!(e.is_destroyed());
        assert!(e.traffic_key().is_err());
    }

    #[test]
    fn test_session_epoch_manager_multi_session() {
        let mgr = SessionEpochManager::new();
        let sid1 = [1u8; 16];
        let sid2 = [2u8; 16];
        mgr.create_session(sid1, [42u8;32], MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
            MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).unwrap();
        mgr.create_session(sid2, [42u8;32], MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
            MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).unwrap();
        assert_eq!(mgr.session_count(), 2);
        mgr.destroy_session(&sid1);
        assert_eq!(mgr.session_count(), 1);
        assert_eq!(mgr.get_current_epoch_id(&sid2), Some(0));
    }

    #[test]
    fn test_session_epoch_manager_duplicate_rejected() {
        let mgr = SessionEpochManager::new();
        let sid = [9u8; 16];
        mgr.create_session(sid, [0u8;32], MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
            MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).unwrap();
        assert!(mgr.create_session(sid, [0u8;32], MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
            MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).is_err());
    }

    #[test]
    fn test_hkdf_info_prefixes_match_python() {
        assert_eq!(HKDF_EPOCH_KEY_INFO_PREFIX, b"SAACP-MEASC-epoch-key-v1");
        assert_eq!(HKDF_IV_INFO_PREFIX, b"SAACP-MEASC-iv-v1");
    }

    #[test]
    fn test_key_evolution_engine_deterministic() {
        let engine = KeyEvolutionEngine::new([1u8;32]);
        let sid = [2u8;16];
        let k1 = engine.derive_epoch_key(&sid, 0, None);
        let k2 = engine.derive_epoch_key(&sid, 0, None);
        assert_eq!(k1, k2);
        let k3 = engine.derive_epoch_key(&sid, 1, Some(&k1));
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_measc_frame_round_trip() {
        let mgr = SessionEpochManager::new();
        let sid = [5u8;16];
        mgr.create_session(sid, [7u8;32], MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
            MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).unwrap();

        let (frame, psn) = {
            let mut sessions = mgr.sessions.lock().unwrap();
            let ep = sessions.get_mut(&sid).unwrap().get_mut(&0u32).unwrap();
            MEASCFrame::build_frame(ep, 1, 0, 0, 0, b"hello SAACP",
                &[0u8;32], &[0u8;24], 1).unwrap()
        };

        assert_eq!(psn, 1);
        let parsed = MEASCFrame::parse_frame(&frame, &mgr, true).unwrap();
        assert_eq!(parsed.payload, b"hello SAACP");
        assert_eq!(parsed.psn, 1);
        assert_eq!(parsed.session_id, sid);
    }

    #[test]
    fn test_psk_compromise_recovery() {
        let mgr = Arc::new(SessionEpochManager::new());
        for i in 0u8..3 {
            mgr.create_session([i;16], [i;32], MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
                MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).unwrap();
        }
        let recovery = PSKCompromiseRecovery::new(Arc::clone(&mgr), None);
        let report = recovery.execute(Some(42));
        assert_eq!(report.sessions_destroyed, 3);
        assert!(report.recovery_complete);
        assert_eq!(report.revocation_epoch, 42);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_psk_compromise_recovery_steps_6_7_8() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc as StdArc;

        let mgr = Arc::new(SessionEpochManager::new());
        mgr.create_session([0u8;16], [1u8;32], MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
            MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).unwrap();

        // Track which callbacks fired
        let step6_fired = StdArc::new(AtomicBool::new(false));
        let step7_fired = StdArc::new(AtomicBool::new(false));
        let step8_fired = StdArc::new(AtomicBool::new(false));

        let s6 = StdArc::clone(&step6_fired);
        let s7 = StdArc::clone(&step7_fired);
        let s8 = StdArc::clone(&step8_fired);

        let recovery = PSKCompromiseRecovery::new(Arc::clone(&mgr), None)
            .with_capability_revoke(Box::new(move || { s6.store(true, Ordering::SeqCst); }))
            .with_key_rotation(Box::new(move || { s7.store(true, Ordering::SeqCst); }))
            .with_audit(Box::new(move || { s8.store(true, Ordering::SeqCst); }));

        let report = recovery.execute(Some(99));
        assert_eq!(report.sessions_destroyed, 1);
        assert!(report.recovery_complete);
        assert_eq!(mgr.session_count(), 0);

        // All three extended steps must have fired
        assert!(step6_fired.load(Ordering::SeqCst), "Step 6 (capability revoke) must fire");
        assert!(step7_fired.load(Ordering::SeqCst), "Step 7 (key rotation) must fire");
        assert!(step8_fired.load(Ordering::SeqCst), "Step 8 (SDL audit) must fire");
    }

    #[test]
    fn test_get_epoch_snapshot() {
        let mgr = SessionEpochManager::new();
        let sid = [0xEEu8; 16];
        mgr.create_session(sid, [0xABu8; 32],
            MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
            MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).unwrap();
        // get_epoch returns a snapshot
        let snap = mgr.get_epoch(&sid, 0).expect("epoch 0 must exist");
        assert_eq!(snap.epoch_id, 0);
        assert!(!snap.is_destroyed);
        assert!(!snap.is_in_grace_period);
        // get_current_epoch matches
        let cur = mgr.get_current_epoch(&sid).expect("current epoch must exist");
        assert_eq!(cur.epoch_id, snap.epoch_id);
        // Missing session returns None
        assert!(mgr.get_epoch(&[0xFFu8; 16], 0).is_none());
    }

    #[test]
    fn test_create_session_with_negotiation() {
        let mgr = SessionEpochManager::new();
        let sid = [0x11u8; 16];
        let secret = [0x22u8; 32];
        // Must include the mandatory baseline "ed25519" and the encryption suite.
        // Python SuiteNegotiator checks that mandatory_baseline is in BOTH peer lists.
        let local = &["ed25519", "AES-256-GCM-HKDF-SHA256"];
        let remote = &["ed25519", "AES-256-GCM-HKDF-SHA256"];
        let result = mgr.create_session_with_negotiation(
            sid, secret, local, remote, None,
            MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
            MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
        );
        assert!(result.is_ok(), "negotiation must succeed for common suite: {:?}", result.err());
        let (epoch_id, transcript) = result.unwrap();
        assert_eq!(epoch_id, 0);
        assert!(!transcript.transcript_hash_hex().is_empty());
        // Session was created
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.get_current_epoch(&sid).is_some());
    }

    #[test]
    fn test_create_session_with_negotiation_no_common_suite() {
        let mgr = SessionEpochManager::new();
        let sid = [0x33u8; 16];
        // Remote peer is missing the mandatory baseline "ed25519" — this is the
        // DOWNGRADE_ATTEMPT rejection path in SuiteNegotiator::negotiate().
        let local = &["ed25519", "AES-256-GCM-HKDF-SHA256"];
        let remote = &["ChaCha20-Poly1305-HKDF-SHA256"]; // no ed25519 baseline
        let result = mgr.create_session_with_negotiation(
            sid, [0u8; 32], local, remote, None, 0, 0.0,
        );
        assert!(result.is_err(), "missing baseline must produce an error");
    }
}
