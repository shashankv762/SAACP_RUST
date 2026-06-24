//! MEASC — Mandatory Encryption & Authenticated Sequence Control
//!
//! Core encryption and replay protection subsystem for SAACP.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// ─── Constants ───────────────────────────────────────────────────────────────

pub const MEASC_REPLAY_WINDOW_SIZE: usize = 4096;
pub const MEASC_MAX_PSN_ADVANCE: u64 = 2048;
pub const MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD: u64 = 512;
pub const MEASC_DEFAULT_EPOCH_TIME_SECONDS: u64 = 600;
pub const MEASC_EPOCH_GRACE_PERIOD_SECONDS: u64 = 60;
pub const MEASC_REPLAY_RATE_LIMIT_WINDOW_SEC: f64 = 1.0;
pub const MEASC_PSN_MAX: u64 = i64::MAX as u64; // 2^63 - 1
pub const MEASC_EPOCH_PACKET_THRESHOLD: u64 = 1_048_576;
pub const MEASC_AUTH_TAG_SIZE: usize = 16;

// ─── AnomalyPolicy ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyPolicy {
    Allow,
    Audit,
    RateLimit,
    Quarantine,
}

// ─── ReplayWindow ────────────────────────────────────────────────────────────

/// Sliding-window bitmap for O(1) replay detection with anomaly detection.
pub struct ReplayWindow {
    bitmap: Vec<u8>,
    highest_psn: u64,
    anomaly_policy: AnomalyPolicy,
    rate_limit_count: u32,
    rate_limit_window_start: Instant,
    quarantined: bool,
    grace_period_active: bool,
    grace_period_start: Option<Instant>,
}

impl ReplayWindow {
    pub fn new(policy: AnomalyPolicy) -> Self {
        Self {
            bitmap: vec![0u8; MEASC_REPLAY_WINDOW_SIZE / 8], // 512 bytes = 4096 bits
            highest_psn: 0,
            anomaly_policy: policy,
            rate_limit_count: 0,
            rate_limit_window_start: Instant::now(),
            quarantined: false,
            grace_period_active: false,
            grace_period_start: None,
        }
    }

    /// Pre-decryption replay check. Returns (accepted, reason).
    pub fn check(&mut self, psn: u64) -> (bool, &'static str) {
        // PSN must be > 0
        if psn == 0 {
            return (false, "negative_psn");
        }

        // Quarantine check
        if self.quarantined {
            return (false, "quarantined");
        }

        // Advance too large
        if psn > self.highest_psn.saturating_add(MEASC_MAX_PSN_ADVANCE) {
            return (false, "advance_too_large");
        }

        // Out of window (too old)
        if self.highest_psn >= MEASC_REPLAY_WINDOW_SIZE as u64
            && psn <= self.highest_psn.saturating_sub(MEASC_REPLAY_WINDOW_SIZE as u64)
        {
            return (false, "out_of_window");
        }

        // Duplicate check (only if psn <= highest_psn, i.e., within established window)
        if psn <= self.highest_psn {
            let bit_idx = (psn as usize) % MEASC_REPLAY_WINDOW_SIZE;
            let byte_idx = bit_idx / 8;
            let bit_offset = bit_idx % 8;
            if self.bitmap[byte_idx] & (1 << bit_offset) != 0 {
                return (false, "duplicate");
            }
        }

        // Rate limit check
        if self.anomaly_policy == AnomalyPolicy::RateLimit {
            let elapsed = self.rate_limit_window_start.elapsed().as_secs_f64();
            if elapsed > MEASC_REPLAY_RATE_LIMIT_WINDOW_SEC {
                // Reset window
                self.rate_limit_count = 0;
                self.rate_limit_window_start = Instant::now();
            }
            self.rate_limit_count += 1;
            // Allow up to MEASC_REPLAY_WINDOW_SIZE packets per window
            if self.rate_limit_count > MEASC_REPLAY_WINDOW_SIZE as u32 {
                return (false, "rate_limit_exceeded");
            }
        }

        // Anomaly jump detection
        if self.highest_psn > 0
            && psn > self.highest_psn + MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD
        {
            if self.anomaly_policy == AnomalyPolicy::Quarantine {
                self.quarantined = true;
                return (false, "quarantined");
            }
            return (true, "ok_anomaly_pending");
        }

        (true, "ok")
    }

    /// Post-decryption commit. Set the bit, advance highest_psn if needed.
    pub fn accept(&mut self, psn: u64) -> Result<(), SAACPHardDrop> {
        if psn == 0 {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::PsnOutOfWindow,
                "PSN must be > 0",
            ));
        }

        // If PSN advances the window, slide forward
        if psn > self.highest_psn {
            let old_highest = self.highest_psn;
            self.highest_psn = psn;

            // Clear bits that fall out of window
            let new_window_start = psn.saturating_sub(MEASC_REPLAY_WINDOW_SIZE as u64);
            let old_window_start = old_highest.saturating_sub(MEASC_REPLAY_WINDOW_SIZE as u64);

            if new_window_start > old_window_start {
                // Clear bits from old_window_start+1 to new_window_start
                let clear_start = old_window_start + 1;
                let clear_end = new_window_start;
                let clear_count = (clear_end - clear_start + 1).min(MEASC_REPLAY_WINDOW_SIZE as u64);

                if clear_count >= MEASC_REPLAY_WINDOW_SIZE as u64 {
                    // Clear entire bitmap
                    self.bitmap.iter_mut().for_each(|b| *b = 0);
                } else {
                    for i in 0..clear_count {
                        let seq = clear_start + i;
                        let bit_idx = (seq as usize) % MEASC_REPLAY_WINDOW_SIZE;
                        let byte_idx = bit_idx / 8;
                        let bit_offset = bit_idx % 8;
                        self.bitmap[byte_idx] &= !(1 << bit_offset);
                    }
                }
            }
        }

        // Set the bit for this PSN
        let bit_idx = (psn as usize) % MEASC_REPLAY_WINDOW_SIZE;
        let byte_idx = bit_idx / 8;
        let bit_offset = bit_idx % 8;
        self.bitmap[byte_idx] |= 1 << bit_offset;

        Ok(())
    }

    /// Activate grace period for epoch transition.
    pub fn activate_grace_period(&mut self) {
        self.grace_period_active = true;
        self.grace_period_start = Some(Instant::now());
    }

    /// Check if grace period (60s) has elapsed.
    pub fn is_grace_period_expired(&self) -> bool {
        if let Some(start) = self.grace_period_start {
            start.elapsed().as_secs() >= MEASC_EPOCH_GRACE_PERIOD_SECONDS
        } else {
            !self.grace_period_active
        }
    }
}

// ─── PacketSequencer ─────────────────────────────────────────────────────────

/// Simple atomic monotonic counter for sending packets.
pub struct PacketSequencer {
    next_psn: AtomicU64,
}

impl PacketSequencer {
    pub fn new(start: u64) -> Self {
        Self {
            next_psn: AtomicU64::new(start),
        }
    }

    /// Increment and return the next PSN. Errors on overflow.
    pub fn next(&self) -> Result<u64, SAACPHardDrop> {
        let psn = self.next_psn.fetch_add(1, Ordering::SeqCst);
        if psn >= MEASC_PSN_MAX {
            // Roll back the increment
            self.next_psn.fetch_sub(1, Ordering::SeqCst);
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SequenceOverflow,
                "PSN would exceed MEASC_PSN_MAX",
            ));
        }
        Ok(psn)
    }

    /// Get the current PSN value (next to be issued).
    pub fn current(&self) -> u64 {
        self.next_psn.load(Ordering::SeqCst)
    }
}

// ─── KeyEvolutionEngine ──────────────────────────────────────────────────────

/// HKDF-SHA256 based forward-secret key derivation.
pub struct KeyEvolutionEngine {
    session_secret: [u8; 32],
}

impl KeyEvolutionEngine {
    pub fn new(session_secret: [u8; 32]) -> Self {
        Self { session_secret }
    }

    /// Derive the next epoch key using HKDF-SHA256.
    pub fn derive_epoch_key(
        &self,
        prev_key: &[u8; 32],
        session_id: &[u8; 16],
        epoch_id: u32,
    ) -> [u8; 32] {
        // IKM = session_secret XOR prev_key
        let mut ikm = [0u8; 32];
        for i in 0..32 {
            ikm[i] = self.session_secret[i] ^ prev_key[i];
        }

        // salt = session_id (16 bytes)
        let hk = Hkdf::<Sha256>::new(Some(session_id), &ikm);

        // info = b"SAACP-EPOCH" || epoch_id.to_be_bytes() (15 bytes total)
        let mut info = Vec::with_capacity(15);
        info.extend_from_slice(b"SAACP-EPOCH");
        info.extend_from_slice(&epoch_id.to_be_bytes());

        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).expect("HKDF expand failed");

        ikm.zeroize();
        okm
    }
}

// ─── SessionEpoch ────────────────────────────────────────────────────────────

/// Represents a single epoch within a session.
pub struct SessionEpoch {
    pub session_id: [u8; 16],
    pub epoch_id: u32,
    pub traffic_key: [u8; 32],
    pub created_at: Instant,
    pub packet_count: u64,
    pub replay_window: ReplayWindow,
    pub sequencer: PacketSequencer,
}

impl SessionEpoch {
    pub fn new(session_id: [u8; 16], epoch_id: u32, traffic_key: [u8; 32]) -> Self {
        Self {
            session_id,
            epoch_id,
            traffic_key,
            created_at: Instant::now(),
            packet_count: 0,
            replay_window: ReplayWindow::new(AnomalyPolicy::Audit),
            sequencer: PacketSequencer::new(1), // PSN starts at 1 (0 is invalid)
        }
    }

    /// Check if this epoch needs rotation.
    pub fn needs_rotation(&self) -> bool {
        self.packet_count >= MEASC_EPOCH_PACKET_THRESHOLD
            || self.created_at.elapsed().as_secs() >= MEASC_DEFAULT_EPOCH_TIME_SECONDS
    }
}

// ─── SessionEpochManager ─────────────────────────────────────────────────────

/// Main orchestrator for encryption, decryption, and epoch rotation.
pub struct SessionEpochManager {
    current_epoch: SessionEpoch,
    previous_epoch: Option<SessionEpoch>,
    key_engine: KeyEvolutionEngine,
}

impl SessionEpochManager {
    pub fn new(session_id: [u8; 16], session_secret: [u8; 32], initial_key: [u8; 32]) -> Self {
        let key_engine = KeyEvolutionEngine::new(session_secret);
        let current_epoch = SessionEpoch::new(session_id, 0, initial_key);
        Self {
            current_epoch,
            previous_epoch: None,
            key_engine,
        }
    }

    /// Derive 12-byte IV from traffic key, PSN, and epoch_id using HKDF-Expand.
    fn derive_iv(traffic_key: &[u8; 32], psn: u64, epoch_id: u32) -> [u8; 12] {
        let hk = Hkdf::<Sha256>::from_prk(traffic_key).expect("PRK length valid");
        let mut iv = [0u8; 12];
        let mut info = [0u8; 12];
        info[..8].copy_from_slice(&psn.to_be_bytes());
        info[8..12].copy_from_slice(&epoch_id.to_be_bytes());
        hk.expand(&info, &mut iv).expect("IV derivation failed");
        iv
    }

    /// Encrypt plaintext payload with AES-256-GCM. AAD = frame header bytes.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, u64), SAACPHardDrop> {
        // 1. Get next PSN from sequencer
        let psn = self.current_epoch.sequencer.next()?;

        // 2. Check if rotation needed, rotate if so
        if self.current_epoch.needs_rotation() {
            self.rotate_epoch();
        }

        // 3. Derive IV from traffic_key, psn, epoch_id
        let iv = Self::derive_iv(
            &self.current_epoch.traffic_key,
            psn,
            self.current_epoch.epoch_id,
        );

        // 4. Encrypt with AES-256-GCM
        let key = Key::<Aes256Gcm>::from_slice(&self.current_epoch.traffic_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&iv);

        let ciphertext = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
            .map_err(|_| {
                SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "AES-GCM encryption failed",
                )
            })?;

        // 5. Increment packet_count
        self.current_epoch.packet_count += 1;

        // 6. Return (ciphertext_with_tag, psn)
        Ok((ciphertext, psn))
    }

    /// Decrypt ciphertext with AES-256-GCM. AAD = frame header bytes.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        psn: u64,
        epoch_id: u32,
    ) -> Result<Vec<u8>, SAACPHardDrop> {
        // 1. Determine which epoch to use
        let epoch = if epoch_id == self.current_epoch.epoch_id {
            &mut self.current_epoch
        } else if let Some(ref mut prev) = self.previous_epoch {
            if epoch_id == prev.epoch_id {
                prev
            } else {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::EpochExpired,
                    format!("Unknown epoch_id: {}", epoch_id),
                ));
            }
        } else {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::EpochExpired,
                format!("No epoch with id: {}", epoch_id),
            ));
        };

        // 2. Check replay window
        let (accepted, reason) = epoch.replay_window.check(psn);
        if !accepted {
            let (bytecode, msg) = match reason {
                "duplicate" | "out_of_window" => (
                    SAACPBytecodes::PsnReplayDetected,
                    format!("Replay detected: {}", reason),
                ),
                "advance_too_large" | "negative_psn" => (
                    SAACPBytecodes::PsnOutOfWindow,
                    format!("PSN out of window: {}", reason),
                ),
                "rate_limit_exceeded" | "quarantined" => (
                    SAACPBytecodes::PsnReplayDetected,
                    format!("Replay protection triggered: {}", reason),
                ),
                _ => (
                    SAACPBytecodes::PsnReplayDetected,
                    format!("Replay check failed: {}", reason),
                ),
            };
            return Err(SAACPHardDrop::new(bytecode, msg));
        }

        // 3. Derive IV
        let iv = Self::derive_iv(&epoch.traffic_key, psn, epoch_id);

        // 4. Decrypt with AES-256-GCM
        let key = Key::<Aes256Gcm>::from_slice(&epoch.traffic_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&iv);

        let plaintext = cipher
            .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
            .map_err(|_| {
                SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "AES-GCM decryption failed: authentication tag mismatch",
                )
            })?;

        // 5. Accept PSN in replay window
        epoch.replay_window.accept(psn)?;

        Ok(plaintext)
    }

    /// Rotate to next epoch.
    pub fn rotate_epoch(&mut self) {
        let new_epoch_id = self.current_epoch.epoch_id + 1;

        // 1. Derive new key from current key
        let new_key = self.key_engine.derive_epoch_key(
            &self.current_epoch.traffic_key,
            &self.current_epoch.session_id,
            new_epoch_id,
        );

        // 2. Create new SessionEpoch with epoch_id + 1
        let session_id = self.current_epoch.session_id;
        let new_epoch = SessionEpoch::new(session_id, new_epoch_id, new_key);

        // 3. Move current to previous_epoch (activate grace period on old one)
        let mut old_epoch = std::mem::replace(&mut self.current_epoch, new_epoch);
        old_epoch.replay_window.activate_grace_period();

        // 4. Zeroize old previous epoch key material if grace period expired
        if let Some(ref mut prev) = self.previous_epoch {
            prev.traffic_key.zeroize();
        }

        self.previous_epoch = Some(old_epoch);
    }

    /// Get current epoch_id.
    pub fn current_epoch_id(&self) -> u32 {
        self.current_epoch.epoch_id
    }

    /// Get current session_id.
    pub fn session_id(&self) -> &[u8; 16] {
        &self.current_epoch.session_id
    }
}
