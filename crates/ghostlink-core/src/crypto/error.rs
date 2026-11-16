//! Non-leaky cryptographic and session-boundary error definitions.

use thiserror::Error;

/// Unified error boundary for GhostLink identity, rendezvous, and E2EE operations.
///
/// Error messages intentionally omit secret inputs, expected MAC bytes, or partial
/// plaintext states to prevent side-channel and error-oracle leakage.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Ephemeral Session ID failed Crockford Base32 length or alphabet validation.
    #[error("invalid session ID format: expected 16 unambiguous Crockford Base32 characters")]
    InvalidSessionId,

    /// One-time PIN did not consist of exactly 6 ASCII digits (`000000`–`999999`).
    #[error("invalid one-time PIN: expected exactly 6 numeric digits")]
    InvalidPin,

    /// QR pairing URI failed schema, parameter, Base64url, or key-length validation.
    #[error("invalid pairing QR URI: {reason}")]
    InvalidQrUri {
        /// Publicly safe structural parse failure description.
        reason: &'static str,
    },

    /// QR pairing URI has expired or declares a TTL exceeding the protocol maximum.
    #[error("pairing QR payload expired or outside valid TTL window")]
    QrPayloadExpired,

    /// SPAKE2 public share was malformed or rejected as a low-order curve point.
    #[error("SPAKE2 key agreement failed: invalid peer public share")]
    Spake2ProtocolFailure,

    /// AEAD authentication, key-confirmation tag, or Noise MAC verification failed.
    #[error("cryptographic authentication failed")]
    AuthenticationFailed,

    /// Signaling or transport frame violated protocol version, header length, or direction rules.
    #[error("malformed cryptographic frame: {reason}")]
    MalformedFrame {
        /// Publicly safe frame validation reason.
        reason: &'static str,
    },

    /// Payload exceeded bounded protocol frame capacity (anti-DoS guard).
    #[error("payload length ({actual} bytes) exceeds maximum allowed ({max} bytes)")]
    PayloadTooLarge {
        /// Attempted payload byte length.
        actual: usize,
        /// Protocol-enforced upper bound.
        max: usize,
    },

    /// Packet sequence number was replayed, out-of-sequence on ordered signaling, or older than the sliding window.
    #[error("replayed or stale packet sequence rejected")]
    ReplayDetected,

    /// Channel nonce counter reached its 56-bit partition limit; session rekey/reconnect required.
    #[error("channel nonce space exhausted; session rotation required")]
    NonceExhausted,

    /// Noise handshake state machine called out of turn or promoted before completion.
    #[error("invalid Noise handshake state transition: {reason}")]
    HandshakeStateError {
        /// Publicly safe state machine error description.
        reason: &'static str,
    },

    /// Responder's Noise static X25519 key did not match the public key pinned in the QR code.
    #[error("remote host static key does not match QR-pinned identity")]
    RemoteKeyMismatch,

    /// Attempted to transmit screen media on the Host before explicit on-device user consent was granted.
    #[error("session consent gate locked: explicit on-device user approval required before streaming")]
    ConsentRequired,
}
