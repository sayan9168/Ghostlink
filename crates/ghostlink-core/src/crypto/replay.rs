//! Constant-space, zero-allocation 1024-packet anti-replay sliding window (RFC 6479 style).
//!
//! Protects stateless AEAD transport channels (`dc-video` unreliable UDP and `dc-ctrl` SCTP)
//! against duplicate/replayed datagrams while tolerating severe network packet reordering
//! across 4G/5G CGNAT paths.

use crate::crypto::error::CryptoError;

/// Number of 64-bit words in the anti-replay bitmap (`16 * 64 = 1024` packets).
const BITMAP_WORDS: usize = 16;

/// Sliding window span in sequence numbers (`1024` packets ≈ ~1.7 seconds at 600 pkt/s).
pub const REPLAY_WINDOW_SIZE: u64 = (BITMAP_WORDS as u64) * 64;

/// Two-phase sliding replay window preventing both duplicate packet acceptance
/// and unauthenticated replay-window poisoning DoS attacks.
#[derive(Debug, Clone)]
pub struct SlidingReplayWindow {
    initialized: bool,
    highest_seq: u64,
    /// Bit `offset` (`0..1024`) tracks whether `highest_seq - offset` has been authenticated.
    bitmap: [u64; BITMAP_WORDS],
}

impl Default for SlidingReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl SlidingReplayWindow {
    /// Creates an empty, uninitialized 1024-packet sliding replay window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initialized: false,
            highest_seq: 0,
            bitmap: [0u64; BITMAP_WORDS],
        }
    }

    /// Read-only pre-filter invoked **before** expensive AEAD decryption.
    ///
    /// Rejects known duplicates and stale packets without mutating window state, ensuring
    /// forged packets with huge sequence numbers cannot advance the window.
    pub fn check_plausible(&self, seq: u64) -> Result<(), CryptoError> {
        if !self.initialized || seq > self.highest_seq {
            return Ok(());
        }

        let offset = self.highest_seq - seq;
        if offset >= REPLAY_WINDOW_SIZE {
            return Err(CryptoError::ReplayDetected);
        }

        let word_idx = (offset / 64) as usize;
        let bit_idx = (offset % 64) as u32;
        if (self.bitmap[word_idx] & (1u64 << bit_idx)) != 0 {
            return Err(CryptoError::ReplayDetected);
        }

        Ok(())
    }

    /// Atomically re-verifies `seq` and records it as seen **after** AEAD MAC verification succeeds.
    pub fn check_and_commit(&mut self, seq: u64) -> Result<(), CryptoError> {
        if !self.initialized {
            self.initialized = true;
            self.highest_seq = seq;
            self.bitmap = [0u64; BITMAP_WORDS];
            self.bitmap[0] = 1;
            return Ok(());
        }

        if seq > self.highest_seq {
            let delta = seq - self.highest_seq;
            if delta >= REPLAY_WINDOW_SIZE {
                self.bitmap = [0u64; BITMAP_WORDS];
            } else {
                self.shift_left(delta);
            }
            self.bitmap[0] |= 1;
            self.highest_seq = seq;
            return Ok(());
        }

        let offset = self.highest_seq - seq;
        if offset >= REPLAY_WINDOW_SIZE {
            return Err(CryptoError::ReplayDetected);
        }

        let word_idx = (offset / 64) as usize;
        let bit_idx = (offset % 64) as u32;
        let mask = 1u64 << bit_idx;

        if (self.bitmap[word_idx] & mask) != 0 {
            return Err(CryptoError::ReplayDetected);
        }

        self.bitmap[word_idx] |= mask;
        Ok(())
    }

    /// Returns the highest authenticated sequence number observed so far, if any.
    #[must_use]
    pub const fn highest_authenticated_seq(&self) -> Option<u64> {
        if self.initialized {
            Some(self.highest_seq)
        } else {
            None
        }
    }

    /// Shifts the 1024-bit bitmap left by `1 <= delta < 1024` bits without shift overflow.
    fn shift_left(&mut self, delta: u64) {
        let word_shift = (delta / 64) as usize;
        let bit_shift = (delta % 64) as u32;

        for i in (0..BITMAP_WORDS).rev() {
            if i < word_shift {
                self.bitmap[i] = 0;
            } else {
                let src = i - word_shift;
                if bit_shift == 0 {
                    self.bitmap[i] = self.bitmap[src];
                } else {
                    let low = self.bitmap[src] << bit_shift;
                    let carry = if src > 0 {
                        self.bitmap[src - 1] >> (64 - bit_shift)
                    } else {
                        0
                    };
                    self.bitmap[i] = low | carry;
                }
            }
        }
    }
}
