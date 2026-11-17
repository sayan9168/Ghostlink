//! Ephemeral session identity, blind signaling room tokens, uniform one-time PINs,
//! and offline QR pairing URI payloads.
//!
//! GhostLink enforces a **zero-persistent-tracking** policy: no hardware serials,
//! `ANDROID_ID` values, or MAC addresses ever enter this module.

use std::fmt;
use std::str::FromStr;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::error::CryptoError;

/// Byte length of an 80-bit ephemeral [`SessionId`].
pub const SESSION_ID_LEN: usize = 10;

/// Character count of an ungrouped Crockford Base32 [`SessionId`].
pub const SESSION_ID_CHARS: usize = 16;

/// Default lifetime (in seconds) for a freshly generated QR pairing URI.
pub const DEFAULT_QR_TTL_SECS: u64 = 180;

/// Maximum permitted lifetime (in seconds) for any QR pairing URI.
pub const MAX_QR_TTL_SECS: u64 = 600;

/// Permitted clock-skew grace window (in seconds) when validating QR TTL upper bounds.
pub const MAX_CLOCK_SKEW_SECS: u64 = 30;

/// Maximum accepted byte length of a `ghostlink://v1?...` URI string.
const MAX_QR_URI_LEN: usize = 256;

const QR_URI_PREFIX: &str = "ghostlink://v1?";
const BLIND_ROOM_HKDF_SALT: &[u8] = b"ghostlink-v1-blind-room-salt";
const BLIND_ROOM_HKDF_INFO: &[u8] = b"ghostlink-v1-rendezvous-room-id";

/// Douglas Crockford's unambiguous 32-character alphabet (omits `I`, `L`, `O`, `U`).
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A 256-bit secret byte array that automatically wipes its memory when dropped
/// and compares in constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes32(pub(crate) [u8; 32]);

impl SecretBytes32 {
    /// Generates 256 bits of fresh entropy from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps raw 32-byte key material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying 32 secret bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes32([REDACTED])")
    }
}

impl PartialEq for SecretBytes32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SecretBytes32 {}

/// Ephemeral 80-bit session identifier shared out-of-band (human display or QR code).
///
/// Formatted for humans as `XXXX-XXXX-XXXX-XXXX` using Crockford Base32 so lookalike
/// characters (`0`/`O`, `1`/`I`/`l`) cannot cause transcription failures.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; SESSION_ID_LEN]);

impl SessionId {
    /// Mints a fresh 80-bit random [`SessionId`] from the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut raw = [0u8; SESSION_ID_LEN];
        OsRng.fill_bytes(&mut raw);
        Self(raw)
    }

    /// Constructs a [`SessionId`] from 10 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SESSION_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 10-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_ID_LEN] {
        &self.0
    }

    /// Formats the ID as grouped human-readable Crockford Base32 (`XXXX-XXXX-XXXX-XXXX`).
    #[must_use]
    pub fn to_display_code(&self) -> String {
        let acc = self.pack_u128();
        let mut out = String::with_capacity(19);
        for i in 0..SESSION_ID_CHARS {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            let shift = (SESSION_ID_CHARS - 1 - i) * 5;
            let idx = ((acc >> shift) & 0x1F) as usize;
            out.push(CROCKFORD_ALPHABET[idx] as char);
        }
        out
    }

    /// Formats the ID as compact 16-character Crockford Base32 without separators.
    #[must_use]
    pub fn to_compact_code(&self) -> String {
        let acc = self.pack_u128();
        let mut out = String::with_capacity(SESSION_ID_CHARS);
        for i in 0..SESSION_ID_CHARS {
            let shift = (SESSION_ID_CHARS - 1 - i) * 5;
            let idx = ((acc >> shift) & 0x1F) as usize;
            out.push(CROCKFORD_ALPHABET[idx] as char);
        }
        out
    }

    /// Parses a human-entered or QR-scanned Crockford Base32 session string.
    ///
    /// Accepts hyphens, spaces, lowercase letters, and Crockford visual aliases
    /// (`O`/`o` -> `0`, `I`/`i`/`L`/`l` -> `1`).
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        let mut acc: u128 = 0;
        let mut count: usize = 0;

        for b in input.bytes() {
            if b == b'-' || b.is_ascii_whitespace() {
                continue;
            }
            if count >= SESSION_ID_CHARS {
                return Err(CryptoError::InvalidSessionId);
            }
            let val = decode_crockford_byte(b).ok_or(CryptoError::InvalidSessionId)?;
            acc = (acc << 5) | u128::from(val);
            count += 1;
        }

        if count != SESSION_ID_CHARS {
            return Err(CryptoError::InvalidSessionId);
        }

        let be16 = acc.to_be_bytes();
        let mut raw = [0u8; SESSION_ID_LEN];
        raw.copy_from_slice(&be16[6..16]);
        Ok(Self(raw))
    }

    /// Derives the unlinkable 256-bit [`BlindRoomId`] revealed to the signaling server.
    ///
    /// Because HKDF-SHA256 is one-way, the signaling server can route peers sharing
    /// the same [`BlindRoomId`] without ever learning the underlying [`SessionId`].
    #[must_use]
    pub fn derive_blind_room_id(&self) -> BlindRoomId {
        let hk = Hkdf::<Sha256>::new(Some(BLIND_ROOM_HKDF_SALT), &self.0);
        let mut room = [0u8; 32];
        hk.expand(BLIND_ROOM_HKDF_INFO, &mut room)
            .expect("32-byte HKDF-SHA256 output length is statically valid");
        BlindRoomId(room)
    }

    fn pack_u128(&self) -> u128 {
        let mut acc: u128 = 0;
        for &b in &self.0 {
            acc = (acc << 8) | u128::from(b);
        }
        acc
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_display_code())
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", self.to_display_code())
    }
}

impl FromStr for SessionId {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Maps a single ASCII byte to its 5-bit Crockford value (`0..32`).
const fn decode_crockford_byte(b: u8) -> Option<u8> {
    match b {
        b'0' | b'O' | b'o' => Some(0),
        b'1' | b'I' | b'i' | b'L' | b'l' => Some(1),
        b'2' => Some(2),
        b'3' => Some(3),
        b'4' => Some(4),
        b'5' => Some(5),
        b'6' => Some(6),
        b'7' => Some(7),
        b'8' => Some(8),
        b'9' => Some(9),
        b'A' | b'a' => Some(10),
        b'B' | b'b' => Some(11),
        b'C' | b'c' => Some(12),
        b'D' | b'd' => Some(13),
        b'E' | b'e' => Some(14),
        b'F' | b'f' => Some(15),
        b'G' | b'g' => Some(16),
        b'H' | b'h' => Some(17),
        b'J' | b'j' => Some(18),
        b'K' | b'k' => Some(19),
        b'M' | b'm' => Some(20),
        b'N' | b'n' => Some(21),
        b'P' | b'p' => Some(22),
        b'Q' | b'q' => Some(23),
        b'R' | b'r' => Some(24),
        b'S' | b's' => Some(25),
        b'T' | b't' => Some(26),
        b'V' | b'v' => Some(27),
        b'W' | b'w' => Some(28),
        b'X' | b'x' => Some(29),
        b'Y' | b'y' => Some(30),
        b'Z' | b'z' => Some(31),
        _ => None,
    }
}

/// Unlinkable 256-bit rendezvous slot identifier derived from a [`SessionId`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlindRoomId([u8; 32]);

impl BlindRoomId {
    /// Returns the raw 32-byte blind room digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encodes the room identifier as a 43-character URL-safe unpadded Base64 token.
    #[must_use]
    pub fn to_url_token(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl fmt::Debug for BlindRoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlindRoomId({}..)", &self.to_url_token()[..8])
    }
}

/// Uniformly distributed 6-digit one-time pairing PIN (`000000`–`999999`) used with SPAKE2.
///
/// Automatically zeroized on drop and redacted from [`fmt::Debug`] logs.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OneTimePin([u8; 6]);

impl OneTimePin {
    /// Generates an unbiased 6-digit numeric PIN via rejection sampling over `OsRng`.
    #[must_use]
    pub fn generate() -> Self {
        let mut sample: u32 = loop {
            let candidate = OsRng.next_u32() & 0x000F_FFFF; // 0..1_048_576
            if candidate < 1_000_000 {
                break candidate;
            }
        };

        let mut digits = [b'0'; 6];
        let mut cursor = sample;
        for slot in digits.iter_mut().rev() {
            *slot = b'0' + (cursor % 10) as u8;
            cursor /= 10;
        }
        sample.zeroize();
        cursor.zeroize();

        Self(digits)
    }

    /// Parses a user-supplied 6-digit PIN string (ignoring optional hyphens or spaces).
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        let mut digits = [0u8; 6];
        let mut idx = 0usize;

        for b in input.bytes() {
            if b == b'-' || b.is_ascii_whitespace() {
                continue;
            }
            if !b.is_ascii_digit() || idx >= 6 {
                digits.zeroize();
                return Err(CryptoError::InvalidPin);
            }
            digits[idx] = b;
            idx += 1;
        }

        if idx != 6 {
            digits.zeroize();
            return Err(CryptoError::InvalidPin);
        }

        Ok(Self(digits))
    }

    /// Returns the 6 ASCII digit bytes (`b'0'..=b'9'`) for SPAKE2 password input.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Formats the PIN as `XXX-XXX` inside a [`Zeroizing`] string for temporary UI rendering.
    #[must_use]
    pub fn to_grouped_display(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(7));
        for (i, &b) in self.0.iter().enumerate() {
            if i == 3 {
                out.push('-');
            }
            out.push(b as char);
        }
        out
    }
}

impl fmt::Debug for OneTimePin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OneTimePin([REDACTED])")
    }
}

impl PartialEq for OneTimePin {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for OneTimePin {}

/// High-entropy, short-lived QR code pairing payload (`ghostlink://v1?...`).
///
/// Scanning this payload pins the Android Host's ephemeral-per-session Noise X25519
/// static public key and establishes a 256-bit pre-shared pairing secret without
/// manual PIN entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingQrPayload {
    session_id: SessionId,
    host_noise_pubkey: [u8; 32],
    qr_secret: SecretBytes32,
    expires_at_unix_secs: u64,
}

impl PairingQrPayload {
    /// Mints a fresh QR pairing payload with a bounded expiration window.
    pub fn generate(
        session_id: SessionId,
        host_noise_pubkey: [u8; 32],
        now_unix_secs: u64,
        ttl_secs: u64,
    ) -> Result<Self, CryptoError> {
        if ttl_secs == 0 || ttl_secs > MAX_QR_TTL_SECS {
            return Err(CryptoError::QrPayloadExpired);
        }
        let expires_at_unix_secs = now_unix_secs
            .checked_add(ttl_secs)
            .ok_or(CryptoError::QrPayloadExpired)?;

        Ok(Self {
            session_id,
            host_noise_pubkey,
            qr_secret: SecretBytes32::generate(),
            expires_at_unix_secs,
        })
    }

    /// Returns the ephemeral [`SessionId`].
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the Android Host's pinned 32-byte Noise X25519 static public key.
    #[must_use]
    pub const fn host_noise_pubkey(&self) -> &[u8; 32] {
        &self.host_noise_pubkey
    }

    /// Borrows the 256-bit secret key material embedded in the QR code.
    #[must_use]
    pub const fn qr_secret(&self) -> &SecretBytes32 {
        &self.qr_secret
    }

    /// Returns the UTC Unix timestamp (seconds) after which this QR payload must be rejected.
    #[must_use]
    pub const fn expires_at_unix_secs(&self) -> u64 {
        self.expires_at_unix_secs
    }

    /// Serializes the payload into a `ghostlink://v1?...` URI wrapped in [`Zeroizing`]
    /// so the secret parameter is wiped from heap memory once rendered into a QR bitmap.
    #[must_use]
    pub fn to_uri(&self) -> Zeroizing<String> {
        let sid = self.session_id.to_compact_code();
        let pk = URL_SAFE_NO_PAD.encode(self.host_noise_pubkey);
        let mut sec = Zeroizing::new(URL_SAFE_NO_PAD.encode(self.qr_secret.as_bytes()));

        let uri = Zeroizing::new(format!(
            "{QR_URI_PREFIX}sid={sid}&pk={pk}&sec={}&exp={}",
            sec.as_str(),
            self.expires_at_unix_secs
        ));
        sec.zeroize();
        uri
    }

    /// Parses and validates a scanned `ghostlink://v1?...` URI against `now_unix_secs`.
    pub fn from_uri(uri: &str, now_unix_secs: u64) -> Result<Self, CryptoError> {
        if uri.len() > MAX_QR_URI_LEN {
            return Err(CryptoError::InvalidQrUri {
                reason: "URI exceeds maximum allowed length",
            });
        }
        let query = uri
            .strip_prefix(QR_URI_PREFIX)
            .ok_or(CryptoError::InvalidQrUri {
                reason: "unsupported URI scheme or protocol version",
            })?;

        let mut sid_opt: Option<SessionId> = None;
        let mut pk_opt: Option<[u8; 32]> = None;
        let mut sec_opt: Option<SecretBytes32> = None;
        let mut exp_opt: Option<u64> = None;

        for pair in query.split('&') {
            let (key, val) = pair.split_once('=').ok_or(CryptoError::InvalidQrUri {
                reason: "malformed query key=value segment",
            })?;

            match key {
                "sid" => {
                    if sid_opt.is_some() {
                        return Err(CryptoError::InvalidQrUri {
                            reason: "duplicate sid parameter",
                        });
                    }
                    sid_opt = Some(SessionId::parse(val)?);
                }
                "pk" => {
                    if pk_opt.is_some() {
                        return Err(CryptoError::InvalidQrUri {
                            reason: "duplicate pk parameter",
                        });
                    }
                    let decoded =
                        URL_SAFE_NO_PAD
                            .decode(val)
                            .map_err(|_| CryptoError::InvalidQrUri {
                                reason: "invalid Base64url encoding in pk",
                            })?;
                    let arr: [u8; 32] =
                        decoded.try_into().map_err(|_| CryptoError::InvalidQrUri {
                            reason: "pk must decode to exactly 32 bytes",
                        })?;
                    pk_opt = Some(arr);
                }
                "sec" => {
                    if sec_opt.is_some() {
                        return Err(CryptoError::InvalidQrUri {
                            reason: "duplicate sec parameter",
                        });
                    }
                    let mut decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(val).map_err(|_| {
                        CryptoError::InvalidQrUri {
                            reason: "invalid Base64url encoding in sec",
                        }
                    })?);
                    if decoded.len() != 32 {
                        return Err(CryptoError::InvalidQrUri {
                            reason: "sec must decode to exactly 32 bytes",
                        });
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    decoded.zeroize();
                    sec_opt = Some(SecretBytes32::from_bytes(arr));
                    arr.zeroize();
                }
                "exp" => {
                    if exp_opt.is_some() {
                        return Err(CryptoError::InvalidQrUri {
                            reason: "duplicate exp parameter",
                        });
                    }
                    let parsed = val.parse::<u64>().map_err(|_| CryptoError::InvalidQrUri {
                        reason: "invalid integer in exp parameter",
                    })?;
                    exp_opt = Some(parsed);
                }
                _ => {
                    return Err(CryptoError::InvalidQrUri {
                        reason: "unexpected query parameter in QR URI",
                    });
                }
            }
        }

        let session_id = sid_opt.ok_or(CryptoError::InvalidQrUri {
            reason: "missing sid parameter",
        })?;
        let host_noise_pubkey = pk_opt.ok_or(CryptoError::InvalidQrUri {
            reason: "missing pk parameter",
        })?;
        let qr_secret = sec_opt.ok_or(CryptoError::InvalidQrUri {
            reason: "missing sec parameter",
        })?;
        let expires_at_unix_secs = exp_opt.ok_or(CryptoError::InvalidQrUri {
            reason: "missing exp parameter",
        })?;

        if now_unix_secs > expires_at_unix_secs {
            return Err(CryptoError::QrPayloadExpired);
        }
        if expires_at_unix_secs.saturating_sub(now_unix_secs)
            > MAX_QR_TTL_SECS + MAX_CLOCK_SKEW_SECS
        {
            return Err(CryptoError::QrPayloadExpired);
        }

        Ok(Self {
            session_id,
            host_noise_pubkey,
            qr_secret,
            expires_at_unix_secs,
        })
    }
}
