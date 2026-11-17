//! Privacy-preserving, zero-plaintext-IP token-bucket rate limiter.
//!
//! Traditional HTTP/WebSocket rate limiters retain raw client `IpAddr` keys in RAM,
//! creating a forensic IP metadata trail if server memory is snapshotted.
//! [`BlindedIpRateLimiter`] hashes canonical client addresses (`/32` IPv4, `/64` IPv6
//! subscriber prefix) through `HMAC-SHA256` keyed with a rotating, RAM-only CSPRNG salt
//! that is zeroized upon rotation and drop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Maximum blinded IP buckets retained simultaneously in RAM (`~3 MiB` ceiling).
pub const MAX_TRACKED_BUCKETS: usize = 65_536;

/// Interval after which the in-memory `HMAC-SHA256` IP-blinding salt is rotated and wiped.
const SALT_ROTATION_INTERVAL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Copy)]
struct TokenBucket {
    tokens: u32,
    last_refill: Instant,
}

struct LimiterInner {
    hmac_key: [u8; 32],
    salt_created_at: Instant,
    buckets: HashMap<[u8; 16], TokenBucket>,
}

impl Drop for LimiterInner {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
    }
}

/// Thread-safe, zero-log token-bucket rate limiter keyed by ephemeral `HMAC-SHA256` IP digests.
pub struct BlindedIpRateLimiter {
    burst_capacity: u32,
    refill_interval: Duration,
    bucket_idle_ttl: Duration,
    inner: Mutex<LimiterInner>,
}

impl BlindedIpRateLimiter {
    /// Creates a new blinded rate limiter with `burst_capacity` tokens and 1-token `refill_interval`.
    #[must_use]
    pub fn new(burst_capacity: u32, refill_interval: Duration) -> Self {
        let mut hmac_key = [0u8; 32];
        OsRng.fill_bytes(&mut hmac_key);
        let now = Instant::now();
        let bucket_idle_ttl = refill_interval
            .saturating_mul(burst_capacity.max(1))
            .max(Duration::from_secs(30));

        Self {
            burst_capacity: burst_capacity.max(1),
            refill_interval,
            bucket_idle_ttl,
            inner: Mutex::new(LimiterInner {
                hmac_key,
                salt_created_at: now,
                buckets: HashMap::new(),
            }),
        }
    }

    /// Attempts to consume `cost` tokens for `client_ip` at timestamp `now`.
    ///
    /// Returns `true` if permitted, or `false` (`429 Too Many Requests`) if throttled.
    #[must_use]
    pub fn check_and_consume(&self, client_ip: IpAddr, cost: u32, now: Instant) -> bool {
        let cost = cost.max(1);
        if cost > self.burst_capacity {
            return false;
        }

        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if now.saturating_duration_since(guard.salt_created_at) >= SALT_ROTATION_INTERVAL {
            guard.hmac_key.zeroize();
            OsRng.fill_bytes(&mut guard.hmac_key);
            guard.salt_created_at = now;
            guard.buckets.clear();
        }

        let blinded_id = blind_ip(&guard.hmac_key, client_ip);

        if let Some(bucket) = guard.buckets.get_mut(&blinded_id) {
            let elapsed = now.saturating_duration_since(bucket.last_refill);
            let refill_nanos = self.refill_interval.as_nanos().max(1);
            let replenished = (elapsed.as_nanos() / refill_nanos).min(u128::from(self.burst_capacity)) as u32;

            if replenished > 0 {
                bucket.tokens = bucket.tokens.saturating_add(replenished).min(self.burst_capacity);
                let consumed_dur = self
                    .refill_interval
                    .saturating_mul(replenished);
                bucket.last_refill = (bucket.last_refill + consumed_dur).min(now);
            }

            if bucket.tokens >= cost {
                bucket.tokens -= cost;
                return true;
            }
            return false;
        }

        if guard.buckets.len() >= MAX_TRACKED_BUCKETS {
            let idle_ttl = self.bucket_idle_ttl;
            guard
                .buckets
                .retain(|_, b| now.saturating_duration_since(b.last_refill) < idle_ttl);
            if guard.buckets.len() >= MAX_TRACKED_BUCKETS {
                return false;
            }
        }

        guard.buckets.insert(
            blinded_id,
            TokenBucket {
                tokens: self.burst_capacity - cost,
                last_refill: now,
            },
        );
        true
    }

    /// Evicts full/idle buckets during periodic background sweeps.
    pub fn reap_idle(&self, now: Instant) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let idle_ttl = self.bucket_idle_ttl;
        guard
            .buckets
            .retain(|_, b| now.saturating_duration_since(b.last_refill) < idle_ttl);
    }
}

/// Computes a truncated 128-bit `HMAC-SHA256` digest of the canonicalized IP/subnet.
fn blind_ip(hmac_key: &[u8; 32], raw_ip: IpAddr) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts 32-byte key");
    match raw_ip {
        IpAddr::V4(v4) => {
            mac.update(&[0x04]);
            mac.update(&v4.octets());
        }
        IpAddr::V6(v6) => {
            mac.update(&[0x06]);
            if v6.is_loopback() {
                mac.update(&v6.octets());
            } else {
                // Normalize global IPv6 addresses to their /64 subscriber prefix
                mac.update(&v6.octets()[..8]);
            }
        }
    }
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}
