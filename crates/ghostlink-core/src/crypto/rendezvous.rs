//! Zero-knowledge rendezvous authentication (`SPAKE2` + QR secret derivation) and
//! directional `ChaCha20-Poly1305` blind signaling envelopes.
//!
//! Ensures the WebSocket signaling server never observes plaintext WebRTC SDP offers,
//! SDP answers, local LAN addresses, or STUN/TURN reflexive IP candidates.

use std::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::error::CryptoError;
use crate::crypto::identity::{BlindRoomId, OneTimePin, PairingQrPayload, SessionId};

/// Wire version byte for encrypted signaling envelopes.
pub const SIGNALING_ENVELOPE_VERSION: u8 = 0x01;

/// Byte length of the unencrypted header prepended to a blind signaling envelope.
pub const SIGNALING_HEADER_LEN: usize = 10;

/// Poly1305 authentication tag byte length.
pub const AEAD_TAG_LEN: usize = 16;

/// Upper bound on a single signaling plaintext payload (32 KiB covers multi-NIC WebRTC SDPs).
pub const MAX_SIGNALING_PLAINTEXT_BYTES: usize = 32 * 1024;

/// Maximum accepted byte length for an inbound SPAKE2 public message.
const MAX_SPAKE2_MSG_BYTES: usize = 64;

const DIRECTION_CLIENT_TO_HOST: u8 = 0x01;
const DIRECTION_HOST_TO_CLIENT: u8 = 0x02;

const SIGNALING_AAD_DOMAIN: &[u8; 20] = b"ghostlink-sig-aad-v1";

/// Endpoint role within a GhostLink pairing and remote-control session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerRole {
    /// Desktop controller initiating the remote session (`SPAKE2` Side A / Noise Initiator).
    Client,
    /// Android target device sharing its screen (`SPAKE2` Side B / Noise Responder).
    Host,
}

impl PeerRole {
    const fn outbound_direction(self) -> u8 {
        match self {
            Self::Client => DIRECTION_CLIENT_TO_HOST,
            Self::Host => DIRECTION_HOST_TO_CLIENT,
        }
    }

    const fn inbound_direction(self) -> u8 {
        match self {
            Self::Client => DIRECTION_HOST_TO_CLIENT,
            Self::Host => DIRECTION_CLIENT_TO_HOST,
        }
    }
}

/// Domain-separated cryptographic subkeys derived from either `SPAKE2` or a [`PairingQrPayload`].
///
/// Automatically wipes all derived symmetric keys on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedPairingKeys {
    #[zeroize(skip)]
    session_id: SessionId,
    #[zeroize(skip)]
    blind_room_id: BlindRoomId,
    c2h_sig_key: [u8; 32],
    h2c_sig_key: [u8; 32],
    c2h_confirm_tag: [u8; 32],
    h2c_confirm_tag: [u8; 32],
    noise_psk: [u8; 32],
    #[zeroize(skip)]
    pinned_host_noise_pubkey: Option<[u8; 32]>,
}

impl DerivedPairingKeys {
    /// Expands pairing subkeys from a high-entropy [`PairingQrPayload`].
    #[must_use]
    pub fn from_qr_payload(payload: &PairingQrPayload) -> Self {
        Self::expand_from_root_secret(
            payload.session_id(),
            payload.qr_secret().as_bytes(),
            b"ghostlink-v1-kdf-mode-qr",
            Some(*payload.host_noise_pubkey()),
        )
    }

    fn expand_from_root_secret(
        session_id: SessionId,
        root_ikm: &[u8],
        mode_domain: &[u8],
        pinned_host_noise_pubkey: Option<[u8; 32]>,
    ) -> Self {
        let blind_room_id = session_id.derive_blind_room_id();

        let mut salt = Vec::with_capacity(mode_domain.len() + 32);
        salt.extend_from_slice(mode_domain);
        salt.extend_from_slice(blind_room_id.as_bytes());

        let hk = Hkdf::<Sha256>::new(Some(&salt), root_ikm);

        let mut c2h_sig_key = [0u8; 32];
        let mut h2c_sig_key = [0u8; 32];
        let mut c2h_confirm_tag = [0u8; 32];
        let mut h2c_confirm_tag = [0u8; 32];
        let mut noise_psk = [0u8; 32];

        hk.expand(b"ghostlink-v1-sig-key-c2h", &mut c2h_sig_key)
            .expect("valid HKDF output length");
        hk.expand(b"ghostlink-v1-sig-key-h2c", &mut h2c_sig_key)
            .expect("valid HKDF output length");
        hk.expand(b"ghostlink-v1-confirm-tag-c2h", &mut c2h_confirm_tag)
            .expect("valid HKDF output length");
        hk.expand(b"ghostlink-v1-confirm-tag-h2c", &mut h2c_confirm_tag)
            .expect("valid HKDF output length");
        hk.expand(b"ghostlink-v1-noise-xxpsk2", &mut noise_psk)
            .expect("valid HKDF output length");

        Self {
            session_id,
            blind_room_id,
            c2h_sig_key,
            h2c_sig_key,
            c2h_confirm_tag,
            h2c_confirm_tag,
            noise_psk,
            pinned_host_noise_pubkey,
        }
    }

    /// Returns the ephemeral [`SessionId`] bound to these keys.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the unlinkable [`BlindRoomId`] used for WebSocket routing.
    #[must_use]
    pub const fn blind_room_id(&self) -> BlindRoomId {
        self.blind_room_id
    }

    /// Returns the 256-bit pre-shared key mixed into `Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s`.
    #[must_use]
    pub const fn noise_psk(&self) -> &[u8; 32] {
        &self.noise_psk
    }

    /// Returns the pinned Android Host Noise static public key if paired via QR scan.
    #[must_use]
    pub const fn pinned_host_noise_pubkey(&self) -> Option<&[u8; 32]> {
        self.pinned_host_noise_pubkey.as_ref()
    }
}

impl fmt::Debug for DerivedPairingKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedPairingKeys")
            .field("blind_room_id", &self.blind_room_id)
            .field(
                "has_pinned_host_pubkey",
                &self.pinned_host_noise_pubkey.is_some(),
            )
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

/// Single-use `SPAKE2` (`Ed25519Group`) password-authenticated key agreement state
/// for manual `SessionId` + 6-digit [`OneTimePin`] pairing.
pub struct Spake2Handshake {
    session_id: SessionId,
    state: Spake2<Ed25519Group>,
}

impl Spake2Handshake {
    /// Starts a `SPAKE2` exchange for `role`, returning `(handshake_state, outbound_public_msg)`.
    ///
    /// Both endpoints bind their `idA` and `idB` identities to the session's [`BlindRoomId`]
    /// to prevent cross-session reflection or relay-splice attacks.
    #[must_use]
    pub fn start(role: PeerRole, session_id: SessionId, pin: &OneTimePin) -> (Self, Vec<u8>) {
        let room_id = session_id.derive_blind_room_id();

        let mut id_client = Vec::with_capacity(20 + 32);
        id_client.extend_from_slice(b"ghostlink-v1-client:");
        id_client.extend_from_slice(room_id.as_bytes());

        let mut id_host = Vec::with_capacity(18 + 32);
        id_host.extend_from_slice(b"ghostlink-v1-host:");
        id_host.extend_from_slice(room_id.as_bytes());

        let password = Password::new(pin.as_bytes());
        let identity_a = Identity::new(&id_client);
        let identity_b = Identity::new(&id_host);

        let (state, outbound_msg) = match role {
            PeerRole::Client => Spake2::<Ed25519Group>::start_a(&password, &identity_a, &identity_b),
            PeerRole::Host => Spake2::<Ed25519Group>::start_b(&password, &identity_a, &identity_b),
        };

        (Self { session_id, state }, outbound_msg)
    }

    /// Completes `SPAKE2` using the peer's public share and derives [`DerivedPairingKeys`].
    ///
    /// Note: per the `SPAKE2` specification, a mistyped PIN produces mismatched keys rather
    /// than failing point decompression; call [`BlindSignalingChannel::verify_peer_confirmation_tag`]
    /// or open an AEAD signaling frame to confirm mutual PIN knowledge in constant time.
    pub fn finish(self, peer_public_msg: &[u8]) -> Result<DerivedPairingKeys, CryptoError> {
        if peer_public_msg.is_empty() || peer_public_msg.len() > MAX_SPAKE2_MSG_BYTES {
            return Err(CryptoError::Spake2ProtocolFailure);
        }

        let shared_secret = Zeroizing::new(
            self.state
                .finish(peer_public_msg)
                .map_err(|_| CryptoError::Spake2ProtocolFailure)?,
        );

        Ok(DerivedPairingKeys::expand_from_root_secret(
            self.session_id,
            &shared_secret,
            b"ghostlink-v1-kdf-mode-spake2",
            None,
        ))
    }
}

impl fmt::Debug for Spake2Handshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Spake2Handshake")
            .field("session_id", &self.session_id)
            .field("state", &"[EPHEMERAL_SECRET]")
            .finish()
    }
}

/// Directional, replay-protected `ChaCha20-Poly1305` envelope cipher for WebSocket signaling.
///
/// Encrypts SDP offers/answers and trickled ICE candidates end-to-end so the rendezvous
/// server sees only opaque ciphertext bound to [`BlindRoomId`].
pub struct BlindSignalingChannel {
    role: PeerRole,
    blind_room_id: BlindRoomId,
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    local_confirm_tag: [u8; 32],
    expected_peer_confirm_tag: [u8; 32],
    tx_seq: u64,
    expected_rx_seq: u64,
}

impl BlindSignalingChannel {
    /// Initializes directional `ChaCha20-Poly1305` ciphers from [`DerivedPairingKeys`].
    #[must_use]
    pub fn new(role: PeerRole, keys: &DerivedPairingKeys) -> Self {
        let (tx_key, rx_key, local_confirm_tag, expected_peer_confirm_tag) = match role {
            PeerRole::Client => (
                &keys.c2h_sig_key,
                &keys.h2c_sig_key,
                keys.c2h_confirm_tag,
                keys.h2c_confirm_tag,
            ),
            PeerRole::Host => (
                &keys.h2c_sig_key,
                &keys.c2h_sig_key,
                keys.h2c_confirm_tag,
                keys.c2h_confirm_tag,
            ),
        };

        Self {
            role,
            blind_room_id: keys.blind_room_id(),
            tx_cipher: ChaCha20Poly1305::new(tx_key.into()),
            rx_cipher: ChaCha20Poly1305::new(rx_key.into()),
            local_confirm_tag,
            expected_peer_confirm_tag,
            tx_seq: 0,
            expected_rx_seq: 0,
        }
    }

    /// Returns the directional 32-byte key-confirmation tag to send to the remote peer
    /// immediately after `SPAKE2` finishes (before exchanging SDP/ICE candidates).
    #[must_use]
    pub const fn local_confirmation_tag(&self) -> &[u8; 32] {
        &self.local_confirm_tag
    }

    /// Verifies the remote peer's 32-byte key-confirmation tag in constant time.
    pub fn verify_peer_confirmation_tag(&self, peer_tag: &[u8]) -> Result<(), CryptoError> {
        if peer_tag.len() != 32 {
            return Err(CryptoError::AuthenticationFailed);
        }
        let matches: bool = self.expected_peer_confirm_tag.ct_eq(peer_tag).into();
        if matches {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }

    /// Encrypts a plaintext signaling payload (SDP or ICE JSON/binary) into a blind wire envelope.
    ///
    /// Wire layout: `[version: 1B][direction: 1B][seq_be: 8B][ciphertext + 16B Poly1305 tag]`.
    pub fn seal_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_SIGNALING_PLAINTEXT_BYTES {
            return Err(CryptoError::PayloadTooLarge {
                actual: plaintext.len(),
                max: MAX_SIGNALING_PLAINTEXT_BYTES,
            });
        }
        if self.tx_seq == u64::MAX {
            return Err(CryptoError::NonceExhausted);
        }

        let seq = self.tx_seq;
        let direction = self.role.outbound_direction();
        let header = build_header(direction, seq);
        let nonce_bytes = build_nonce(direction, seq);
        let aad = build_aad(&self.blind_room_id, &header);

        let ciphertext = self
            .tx_cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        self.tx_seq += 1;

        let mut envelope = Vec::with_capacity(SIGNALING_HEADER_LEN + ciphertext.len());
        envelope.extend_from_slice(&header);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// Authenticates and decrypts an inbound blind signaling envelope.
    ///
    /// Rejects wrong versions, reflected self-messages, out-of-order/replayed sequence numbers,
    /// cross-room spliced frames, and tampered ciphertexts without advancing `expected_rx_seq`.
    pub fn open_frame(&mut self, envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let max_wire_len = SIGNALING_HEADER_LEN + MAX_SIGNALING_PLAINTEXT_BYTES + AEAD_TAG_LEN;
        if envelope.len() > max_wire_len {
            return Err(CryptoError::PayloadTooLarge {
                actual: envelope.len(),
                max: max_wire_len,
            });
        }
        if envelope.len() < SIGNALING_HEADER_LEN + AEAD_TAG_LEN {
            return Err(CryptoError::MalformedFrame {
                reason: "signaling envelope shorter than minimum header + AEAD tag",
            });
        }

        let version = envelope[0];
        if version != SIGNALING_ENVELOPE_VERSION {
            return Err(CryptoError::MalformedFrame {
                reason: "unsupported signaling envelope version",
            });
        }

        let direction = envelope[1];
        if direction != self.role.inbound_direction() {
            return Err(CryptoError::MalformedFrame {
                reason: "invalid or reflected signaling frame direction",
            });
        }

        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&envelope[2..SIGNALING_HEADER_LEN]);
        let seq = u64::from_be_bytes(seq_bytes);

        if seq != self.expected_rx_seq {
            return Err(CryptoError::ReplayDetected);
        }

        let mut header = [0u8; SIGNALING_HEADER_LEN];
        header.copy_from_slice(&envelope[..SIGNALING_HEADER_LEN]);
        let nonce_bytes = build_nonce(direction, seq);
        let aad = build_aad(&self.blind_room_id, &header);

        let plaintext = self
            .rx_cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &envelope[SIGNALING_HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        self.expected_rx_seq = self
            .expected_rx_seq
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;

        Ok(plaintext)
    }
}

impl Drop for BlindSignalingChannel {
    fn drop(&mut self) {
        self.local_confirm_tag.zeroize();
        self.expected_peer_confirm_tag.zeroize();
    }
}

impl fmt::Debug for BlindSignalingChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindSignalingChannel")
            .field("role", &self.role)
            .field("blind_room_id", &self.blind_room_id)
            .field("tx_seq", &self.tx_seq)
            .field("expected_rx_seq", &self.expected_rx_seq)
            .finish()
    }
}

fn build_header(direction: u8, seq: u64) -> [u8; SIGNALING_HEADER_LEN] {
    let mut header = [0u8; SIGNALING_HEADER_LEN];
    header[0] = SIGNALING_ENVELOPE_VERSION;
    header[1] = direction;
    header[2..10].copy_from_slice(&seq.to_be_bytes());
    header
}

fn build_nonce(direction: u8, seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = direction;
    nonce[4..12].copy_from_slice(&seq.to_be_bytes());
    nonce
}

fn build_aad(blind_room_id: &BlindRoomId, header: &[u8; SIGNALING_HEADER_LEN]) -> [u8; 62] {
    let mut aad = [0u8; 62];
    aad[0..20].copy_from_slice(SIGNALING_AAD_DOMAIN);
    aad[20..52].copy_from_slice(blind_room_id.as_bytes());
    aad[52..62].copy_from_slice(header);
    aad
}
