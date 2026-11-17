//! Stateless ephemeral TURN REST credential minter (`draft-uberti-behave-turn-rest-00`).
//!
//! Generates unlinkable, short-lived (`TTL <= 300s`) `HMAC-SHA1` credentials compatible
//! with hardened zero-log `coturn` (`--use-auth-secret`) deployments.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha1::Sha1;

use crate::config::SignalConfig;

type HmacSha1 = Hmac<Sha1>;

/// Ephemeral TURN server credential bundle returned to connecting WebRTC peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralTurnCredentials {
    /// Configured `turn:` (UDP) and `turns:` (TLS:443) relay URIs.
    pub urls: Vec<String>,
    /// Time-limited, unlinkable username (`"{expiry_unix_secs}:{random_64bit_hex}"`).
    pub username: String,
    /// Standard Base64-encoded `HMAC-SHA1(static_auth_secret, username)`.
    pub credential: String,
    /// Validity window in seconds (`<= 300`).
    pub ttl_secs: u64,
}

/// Complete ICE bootstrap descriptor returned by `POST /v1/ice-config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceBootstrapResponse {
    /// Stateless STUN discovery URIs.
    pub stun_urls: Vec<String>,
    /// Optional short-lived zero-log TURN fallback credentials.
    pub turn: Option<EphemeralTurnCredentials>,
}

/// Mints a fresh [`IceBootstrapResponse`] using `now_unix_secs` and the server's [`SignalConfig`].
#[must_use]
pub fn mint_ice_bootstrap(config: &SignalConfig, now_unix_secs: u64) -> IceBootstrapResponse {
    let turn = match (config.turn_shared_secret_bytes(), config.turn_urls.is_empty()) {
        (Some(secret), false) => {
            let ttl_secs = config.turn_credential_ttl_secs;
            let expires_at = now_unix_secs.saturating_add(ttl_secs);
            let nonce = OsRng.next_u64();
            let username = format!("{expires_at}:{nonce:016x}");

            let mut mac =
                HmacSha1::new_from_slice(secret).expect("HMAC-SHA1 accepts arbitrary key lengths");
            mac.update(username.as_bytes());
            let credential = STANDARD.encode(mac.finalize().into_bytes());

            Some(EphemeralTurnCredentials {
                urls: config.turn_urls.clone(),
                username,
                credential,
                ttl_secs,
            })
        }
        _ => None,
    };

    IceBootstrapResponse {
        stun_urls: config.stun_urls.clone(),
        turn,
    }
}

/// Returns current UTC Unix timestamp in seconds.
#[must_use]
pub fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Reference `coturn` `--use-auth-secret` validator used in tests and health checks.
#[must_use]
pub fn verify_coturn_credential(
    secret: &[u8],
    username: &str,
    credential_b64: &str,
    now_unix_secs: u64,
) -> bool {
    let Some((ts_part, nonce_part)) = username.split_once(':') else {
        return false;
    };
    if nonce_part.len() != 16 || !nonce_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let Ok(expires_at) = ts_part.parse::<u64>() else {
        return false;
    };
    if now_unix_secs > expires_at {
        return false;
    }
    let Ok(decoded_tag) = STANDARD.decode(credential_b64) else {
        return false;
    };

    let mut mac =
        HmacSha1::new_from_slice(secret).expect("HMAC-SHA1 accepts arbitrary key lengths");
    mac.update(username.as_bytes());
    mac.verify_slice(&decoded_tag).is_ok()
}
