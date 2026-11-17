//! Hardened runtime configuration for the zero-log GhostLink rendezvous server.

use std::env;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use zeroize::Zeroizing;

/// Default WebSocket binary frame ceiling (`36 KiB`, covering `32 KiB` encrypted SDP + AEAD header/tag).
pub const DEFAULT_MAX_WS_FRAME_BYTES: usize = 36 * 1024;

/// Default room expiration TTL (`60` seconds).
pub const DEFAULT_ROOM_TTL_SECS: u64 = 60;

/// Default WebSocket read idle timeout (`45` seconds).
pub const DEFAULT_WS_IDLE_TIMEOUT_SECS: u64 = 45;

/// Default maximum concurrent rendezvous rooms held in RAM (`16,384`).
pub const DEFAULT_MAX_ACTIVE_ROOMS: usize = 16_384;

/// Maximum permitted `coturn` ephemeral credential lifetime (`300` seconds / `5` minutes).
pub const MAX_TURN_CREDENTIAL_TTL_SECS: u64 = 300;

/// Configuration validation failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SignalConfigError {
    /// Failed to parse `GHOSTLINK_SIGNAL_BIND` into a valid `SocketAddr`.
    #[error("invalid GHOSTLINK_SIGNAL_BIND socket address")]
    InvalidBindAddress,

    /// Numeric configuration parameter was zero or outside safe bounds.
    #[error("invalid configuration parameter '{field}'")]
    InvalidParameter {
        /// Offending configuration field name.
        field: &'static str,
    },

    /// `turn_urls` were configured without a non-empty `turn_shared_secret` (`>= 16` bytes).
    #[error("TURN URLs configured without a strong GHOSTLINK_TURN_SECRET (minimum 16 bytes)")]
    WeakOrMissingTurnSecret,
}

/// Validated, zero-log configuration for `ghostlink-signal`.
#[derive(Clone)]
pub struct SignalConfig {
    /// Listening TCP address (`0.0.0.0:8080` by default).
    pub bind_addr: SocketAddr,
    /// Hard expiration lifetime of any rendezvous room slot (`10..=300` seconds).
    pub room_ttl: Duration,
    /// Per-socket inactivity cutoff (`5..=120` seconds).
    pub ws_idle_timeout: Duration,
    /// Upper bound on concurrent rooms stored in memory.
    pub max_active_rooms: usize,
    /// Maximum accepted WebSocket binary message length in bytes.
    pub max_ws_frame_bytes: usize,
    /// Per-blinded-IP token-bucket burst capacity.
    pub rate_limit_burst: u32,
    /// Per-blinded-IP token refill interval (1 token replenished per interval).
    pub rate_limit_refill_interval: Duration,
    /// Ephemeral `coturn` credential validity window (`<= 300` seconds).
    pub turn_credential_ttl_secs: u64,
    /// Public STUN server URIs returned inside `/v1/ice-config`.
    pub stun_urls: Vec<String>,
    /// Public zero-log TURN/TURNS server URIs returned inside `/v1/ice-config`.
    pub turn_urls: Vec<String>,
    /// Shared `coturn` `static-auth-secret` wiped from RAM on drop.
    turn_shared_secret: Option<Zeroizing<String>>,
}

impl Default for SignalConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
            room_ttl: Duration::from_secs(DEFAULT_ROOM_TTL_SECS),
            ws_idle_timeout: Duration::from_secs(DEFAULT_WS_IDLE_TIMEOUT_SECS),
            max_active_rooms: DEFAULT_MAX_ACTIVE_ROOMS,
            max_ws_frame_bytes: DEFAULT_MAX_WS_FRAME_BYTES,
            rate_limit_burst: 12,
            rate_limit_refill_interval: Duration::from_secs(2),
            turn_credential_ttl_secs: MAX_TURN_CREDENTIAL_TTL_SECS,
            stun_urls: Vec::new(),
            turn_urls: Vec::new(),
            turn_shared_secret: None,
        }
    }
}

impl SignalConfig {
    /// Creates a new configuration with an optional `coturn` HMAC shared secret and validates invariants.
    pub fn with_turn_secret(mut self, secret: impl Into<String>) -> Result<Self, SignalConfigError> {
        let s = Zeroizing::new(secret.into());
        if s.len() < 16 {
            return Err(SignalConfigError::WeakOrMissingTurnSecret);
        }
        self.turn_shared_secret = Some(s);
        self.validate()?;
        Ok(self)
    }

    /// Loads configuration from `GHOSTLINK_*` environment variables with safe defaults.
    pub fn from_env() -> Result<Self, SignalConfigError> {
        let mut cfg = Self::default();

        if let Ok(raw_bind) = env::var("GHOSTLINK_SIGNAL_BIND") {
            cfg.bind_addr = raw_bind
                .parse::<SocketAddr>()
                .map_err(|_| SignalConfigError::InvalidBindAddress)?;
        }

        if let Ok(raw_stun) = env::var("GHOSTLINK_STUN_URLS") {
            cfg.stun_urls = split_csv_urls(&raw_stun);
        }

        if let Ok(raw_turn) = env::var("GHOSTLINK_TURN_URLS") {
            cfg.turn_urls = split_csv_urls(&raw_turn);
        }

        if let Ok(raw_secret) = env::var("GHOSTLINK_TURN_SECRET") {
            let trimmed = Zeroizing::new(raw_secret.trim().to_owned());
            if !trimmed.is_empty() {
                cfg.turn_shared_secret = Some(trimmed);
            }
        }

        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates security bounds across all configuration knobs.
    pub fn validate(&self) -> Result<(), SignalConfigError> {
        if self.room_ttl < Duration::from_secs(5) || self.room_ttl > Duration::from_secs(300) {
            return Err(SignalConfigError::InvalidParameter { field: "room_ttl" });
        }
        if self.ws_idle_timeout.is_zero() || self.ws_idle_timeout > Duration::from_secs(300) {
            return Err(SignalConfigError::InvalidParameter {
                field: "ws_idle_timeout",
            });
        }
        if self.max_active_rooms == 0 || self.max_active_rooms > 1_000_000 {
            return Err(SignalConfigError::InvalidParameter {
                field: "max_active_rooms",
            });
        }
        if self.max_ws_frame_bytes < 1024 || self.max_ws_frame_bytes > 128 * 1024 {
            return Err(SignalConfigError::InvalidParameter {
                field: "max_ws_frame_bytes",
            });
        }
        if self.rate_limit_burst == 0 || self.rate_limit_refill_interval.is_zero() {
            return Err(SignalConfigError::InvalidParameter {
                field: "rate_limit",
            });
        }
        if self.turn_credential_ttl_secs == 0
            || self.turn_credential_ttl_secs > MAX_TURN_CREDENTIAL_TTL_SECS
        {
            return Err(SignalConfigError::InvalidParameter {
                field: "turn_credential_ttl_secs",
            });
        }

        if !self.turn_urls.is_empty() {
            match &self.turn_shared_secret {
                Some(sec) if sec.len() >= 16 => {}
                _ => return Err(SignalConfigError::WeakOrMissingTurnSecret),
            }
        }

        Ok(())
    }

    /// Borrows the `coturn` shared secret bytes if TURN credential minting is enabled.
    #[must_use]
    pub fn turn_shared_secret_bytes(&self) -> Option<&[u8]> {
        self.turn_shared_secret.as_ref().map(|s| s.as_bytes())
    }
}

impl fmt::Debug for SignalConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignalConfig")
            .field("bind_addr", &self.bind_addr)
            .field("room_ttl", &self.room_ttl)
            .field("ws_idle_timeout", &self.ws_idle_timeout)
            .field("max_active_rooms", &self.max_active_rooms)
            .field("max_ws_frame_bytes", &self.max_ws_frame_bytes)
            .field("turn_enabled", &self.turn_shared_secret.is_some())
            .field("turn_shared_secret", &"[REDACTED]")
            .finish()
    }
}

fn split_csv_urls(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}
