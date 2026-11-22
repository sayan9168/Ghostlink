//! Inner End-to-End Encryption (`Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s`), Short Authentication
//! String (`SAS`) derivation, Mandatory Consent Gate, and Dual-Domain Stateless Transport.
//!
//! ## Why Stateless Noise Transport?
//! Standard stateful Noise increments an implicit counter on every packet. Over GhostLink's
//! unordered, zero-retransmit video DataChannel (`dc-video`), a single dropped or reordered UDP
//! datagram would permanently desynchronize stateful AEAD counters. By promoting `snow` into
//! [`snow::StatelessTransportState`] with explicit domain-partitioned 64-bit nonces and isolated
//! 1024-packet sliding replay windows, `dc-video` survives heavy 4G/5G loss and reordering
//! without head-of-line blocking or cryptographic desynchronization.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use hkdf::Hkdf;
use sha2::Sha256;
use snow::{params::NoiseParams, Builder, HandshakeState, StatelessTransportState};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::error::CryptoError;
use crate::crypto::identity::{BlindRoomId, SecretBytes32};
use crate::crypto::rendezvous::{DerivedPairingKeys, PeerRole, AEAD_TAG_LEN};
use crate::crypto::replay::SlidingReplayWindow;

/// Canonical Noise Protocol pattern securing all GhostLink sessions.
pub const NOISE_PATTERN: &str = "Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s";

/// Outer wire header length prepended to every stateless Noise transport frame (`8` bytes).
pub const TRANSPORT_HEADER_LEN: usize = 8;

/// Maximum application payload accepted per single Noise transport record (`60 KiB`).
///
/// Strictly bounded below Noise's `65,535`-byte record limit (`1 + 61,440 + 16 = 61,457 < 65,535`).
pub const MAX_TRANSPORT_PAYLOAD_BYTES: usize = 60 * 1024;

/// Maximum application payload permitted inside handshake messages (`1 KiB`).
pub const MAX_HANDSHAKE_PAYLOAD_BYTES: usize = 1024;

/// Maximum wire size accepted for a single inbound Noise handshake message.
const MAX_HANDSHAKE_WIRE_BYTES: usize = 2048;

/// 56-bit per-channel sequence ceiling (`2^56` packets ≈ 3.8 million years at 600 pkt/s).
const MAX_CHANNEL_SEQ: u64 = 1u64 << 56;
const CHANNEL_SEQ_MASK: u64 = MAX_CHANNEL_SEQ - 1;

/// 64 visually and phonetically distinct words (exact 6 bits/word) for SAS display.
const SAS_WORDLIST: [&str; 64] = [
    "AMBER", "ANCHOR", "APOLLO", "ARCTIC", "ATLAS", "AURORA", "BAMBOO", "BEACON",
    "BISON", "BLAZE", "BRONZE", "CANYON", "CEDAR", "COBALT", "COMET", "CORAL",
    "COSMOS", "CRYSTAL", "CYPRESS", "DELTA", "DYNAMO", "EMBER", "FALCON", "FJORD",
    "FOREST", "GALAXY", "GARNET", "GLACIER", "GRANITE", "HARBOR", "HELIUM", "HORIZON",
    "INDIGO", "ISLAND", "JASPER", "JUNGLE", "KRYPTON", "LAGOON", "LANTERN", "LOTUS",
    "MAGNET", "MARBLE", "MATRIX", "MEADOW", "METEOR", "MIRAGE", "NEBULA", "NICKEL",
    "OBSIDIAN", "ONYX", "ORBIT", "OSPREY", "PHANTOM", "PHOENIX", "PLASMA", "PRISM",
    "QUARTZ", "RAVEN", "RIVER", "SAPPHIRE", "SIERRA", "SOLAR", "TOPAZ", "VELVET",
];

/// Logical DataChannel domain isolating nonces and anti-replay windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelDomain {
    /// Reliable, ordered SCTP DataChannel (`dc-ctrl`: input events, codec headers, PLI, consent).
    Control,
    /// Unreliable, unordered UDP DataChannel (`dc-video`: low-latency H.264/H.265 NALU fragments).
    Media,
}

impl ChannelDomain {
    /// Non-zero 1-byte domain prefix occupying bits `56..64` of the 64-bit Noise nonce
    /// and byte `0` of the inner authenticated plaintext.
    #[must_use]
    pub const fn tag_byte(self) -> u8 {
        match self {
            Self::Control => 0x01,
            Self::Media => 0x02,
        }
    }
}

/// Freshly generated ephemeral-per-session X25519 static keypair for Noise `XXpsk2`.
///
/// Private key bytes are held inside [`SecretBytes32`] and wiped on drop.
#[derive(Clone)]
pub struct EphemeralNoiseKeypair {
    private_key: SecretBytes32,
    public_key: [u8; 32],
}

impl EphemeralNoiseKeypair {
    /// Generates a new random X25519 keypair via `snow`'s cryptographic resolver.
    pub fn generate() -> Result<Self, CryptoError> {
        let params: NoiseParams =
            NOISE_PATTERN
                .parse()
                .map_err(|_| CryptoError::HandshakeStateError {
                    reason: "invalid static Noise parameter specification",
                })?;
        let builder = Builder::new(params);
        let mut kp = builder
            .generate_keypair()
            .map_err(|_| CryptoError::HandshakeStateError {
                reason: "CSPRNG keypair generation failed",
            })?;

        if kp.private.len() != 32 || kp.public.len() != 32 {
            kp.private.zeroize();
            return Err(CryptoError::HandshakeStateError {
                reason: "unexpected X25519 key length",
            });
        }

        let mut priv_arr = [0u8; 32];
        priv_arr.copy_from_slice(&kp.private);
        kp.private.zeroize();

        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&kp.public);

        let private_key = SecretBytes32::from_bytes(priv_arr);
        priv_arr.zeroize();

        Ok(Self {
            private_key,
            public_key: pub_arr,
        })
    }

    /// Returns the 32-byte X25519 public key (safe to embed in a short-lived QR code).
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub(crate) const fn private_key_bytes(&self) -> &[u8; 32] {
        self.private_key.as_bytes()
    }
}

impl fmt::Debug for EphemeralNoiseKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralNoiseKeypair")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Human-verifiable Short Authentication String derived from the `Noise_XXpsk2` transcript hash.
///
/// Displayed simultaneously on the Desktop Client and the Android Host's Mandatory Consent UI
/// before screen mirroring or input injection can unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SasCode {
    numeric: String,
    words: [&'static str; 4],
}

impl SasCode {
    /// Deterministically derives an unbiased 6-digit code and 4-word phrase from `handshake_hash`.
    #[must_use]
    pub(crate) fn from_handshake_hash(handshake_hash: &[u8], blind_room_id: &BlindRoomId) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(blind_room_id.as_bytes()), handshake_hash);

        // Unbiased 6-digit numeric SAS via rejection sampling over HKDF counter blocks
        let mut counter: u8 = 0;
        let code_val: u32 = loop {
            let mut info = [0u8; 25];
            info[..24].copy_from_slice(b"ghostlink-v1-sas-digits:");
            info[24] = counter;

            let mut block = [0u8; 4];
            hk.expand(&info, &mut block)
                .expect("4-byte HKDF expansion is statically valid");
            let candidate = u32::from_be_bytes(block) & 0x000F_FFFF; // 20 bits: 0..1_048_576
            if candidate < 1_000_000 {
                break candidate;
            }
            counter = counter.wrapping_add(1);
        };

        let numeric = format!("{:03}-{:03}", code_val / 1000, code_val % 1000);

        // Unbiased 4-word SAS (4 * 6 bits = 24 bits, exact power-of-two dictionary size 64)
        let mut word_bytes = [0u8; 4];
        hk.expand(b"ghostlink-v1-sas-words-24b", &mut word_bytes)
            .expect("4-byte HKDF expansion is statically valid");
        let packed24 = (u32::from(word_bytes[0]) << 16)
            | (u32::from(word_bytes[1]) << 8)
            | u32::from(word_bytes[2]);

        let words = [
            SAS_WORDLIST[((packed24 >> 18) & 0x3F) as usize],
            SAS_WORDLIST[((packed24 >> 12) & 0x3F) as usize],
            SAS_WORDLIST[((packed24 >> 6) & 0x3F) as usize],
            SAS_WORDLIST[(packed24 & 0x3F) as usize],
        ];

        Self { numeric, words }
    }

    /// Returns the grouped 6-digit verification string (e.g., `"849-201"`).
    #[must_use]
    pub fn numeric(&self) -> &str {
        &self.numeric
    }

    /// Returns the 4 unambiguous verification words (24 bits of visual entropy).
    #[must_use]
    pub const fn words(&self) -> &[&'static str; 4] {
        &self.words
    }

    /// Formats the 4 SAS words separated by `" · "` for consent UI banners.
    #[must_use]
    pub fn words_display(&self) -> String {
        self.words.join(" · ")
    }
}

/// 3-message `Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s` handshake state machine.
pub struct NoiseHandshake {
    role: PeerRole,
    blind_room_id: BlindRoomId,
    pinned_host_pubkey: Option<[u8; 32]>,
    state: HandshakeState,
}

impl NoiseHandshake {
    /// Initializes a `Noise_XXpsk2` handshake bound to the session prologue and derived PSK.
    pub fn new(
        role: PeerRole,
        local_keypair: &EphemeralNoiseKeypair,
        pairing_keys: &DerivedPairingKeys,
    ) -> Result<Self, CryptoError> {
        let params: NoiseParams =
            NOISE_PATTERN
                .parse()
                .map_err(|_| CryptoError::HandshakeStateError {
                    reason: "invalid Noise pattern string",
                })?;

        let mut prologue = Vec::with_capacity(19 + 10 + 32);
        prologue.extend_from_slice(b"ghostlink-noise-v1:");
        prologue.extend_from_slice(pairing_keys.session_id().as_bytes());
        prologue.extend_from_slice(pairing_keys.blind_room_id().as_bytes());

        let builder = Builder::new(params)
            .local_private_key(local_keypair.private_key_bytes())
            .prologue(&prologue)
            .psk(2, pairing_keys.noise_psk());

        let state = match role {
            PeerRole::Client => builder.build_initiator(),
            PeerRole::Host => builder.build_responder(),
        }
        .map_err(|_| CryptoError::HandshakeStateError {
            reason: "failed to construct Noise HandshakeState",
        })?;

        let pinned_host_pubkey = match role {
            PeerRole::Client => pairing_keys.pinned_host_noise_pubkey().copied(),
            PeerRole::Host => None,
        };

        Ok(Self {
            role,
            blind_room_id: pairing_keys.blind_room_id(),
            pinned_host_pubkey,
            state,
        })
    }

    /// Returns `true` when it is this endpoint's turn to call [`Self::write_message`].
    #[must_use]
    pub fn is_my_turn(&self) -> bool {
        self.state.is_my_turn()
    }

    /// Returns `true` once all 3 `XXpsk2` handshake messages have been processed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Generates the next outbound handshake message, optionally authenticating `payload`.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.state.is_handshake_finished() {
            return Err(CryptoError::HandshakeStateError {
                reason: "handshake already completed",
            });
        }
        if !self.state.is_my_turn() {
            return Err(CryptoError::HandshakeStateError {
                reason: "cannot write handshake message when expecting peer message",
            });
        }
        if payload.len() > MAX_HANDSHAKE_PAYLOAD_BYTES {
            return Err(CryptoError::PayloadTooLarge {
                actual: payload.len(),
                max: MAX_HANDSHAKE_PAYLOAD_BYTES,
            });
        }

        let mut buf = vec![0u8; MAX_HANDSHAKE_WIRE_BYTES];
        let written = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        buf.truncate(written);
        Ok(buf)
    }

    /// Processes an inbound handshake message and returns any embedded payload.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.state.is_handshake_finished() {
            return Err(CryptoError::HandshakeStateError {
                reason: "handshake already completed",
            });
        }
        if self.state.is_my_turn() {
            return Err(CryptoError::HandshakeStateError {
                reason: "cannot read handshake message when local write is expected",
            });
        }
        if message.is_empty() || message.len() > MAX_HANDSHAKE_WIRE_BYTES {
            return Err(CryptoError::MalformedFrame {
                reason: "handshake message outside valid wire length bounds",
            });
        }

        let mut payload_buf = vec![0u8; MAX_HANDSHAKE_WIRE_BYTES];
        let len = self
            .state
            .read_message(message, &mut payload_buf)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        payload_buf.truncate(len);
        Ok(payload_buf)
    }

    /// Finalizes the completed handshake, verifies any QR-pinned static key in constant time,
    /// extracts the [`SasCode`], and promotes into a thread-safe [`NoiseTransport`].
    pub fn into_transport(self) -> Result<(NoiseTransport, SasCode), CryptoError> {
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::HandshakeStateError {
                reason: "cannot promote incomplete Noise handshake to transport mode",
            });
        }

        let remote_slice =
            self.state
                .get_remote_static()
                .ok_or(CryptoError::HandshakeStateError {
                    reason: "missing remote static X25519 key after XXpsk2 completion",
                })?;
        let remote_static: [u8; 32] =
            remote_slice
                .try_into()
                .map_err(|_| CryptoError::HandshakeStateError {
                    reason: "invalid remote static X25519 key length",
                })?;

        if let Some(expected_host_pk) = self.pinned_host_pubkey {
            let matches: bool = remote_static.ct_eq(&expected_host_pk).into();
            if !matches {
                return Err(CryptoError::RemoteKeyMismatch);
            }
        }

        let sas = SasCode::from_handshake_hash(self.state.get_handshake_hash(), &self.blind_room_id);
        let stateless = self.state.into_stateless_transport_mode().map_err(|_| {
            CryptoError::HandshakeStateError {
                reason: "failed to enter stateless Noise transport mode",
            }
        })?;

        // Mandatory Consent Invariant: Host always boots with media streaming LOCKED.
        let initial_consent = match self.role {
            PeerRole::Host => false,
            PeerRole::Client => true,
        };

        let transport = NoiseTransport {
            role: self.role,
            remote_static_pubkey: remote_static,
            consent_granted: AtomicBool::new(initial_consent),
            stateless,
            ctrl_tx_seq: AtomicU64::new(0),
            media_tx_seq: AtomicU64::new(0),
            ctrl_replay: Mutex::new(SlidingReplayWindow::new()),
            media_replay: Mutex::new(SlidingReplayWindow::new()),
        };

        Ok((transport, sas))
    }
}

impl fmt::Debug for NoiseHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseHandshake")
            .field("role", &self.role)
            .field("is_finished", &self.state.is_handshake_finished())
            .finish()
    }
}

/// Concurrent, dual-domain stateless `ChaCha20-Poly1305` transport session with enforced
/// Host consent gating and isolated 1024-packet anti-replay windows.
///
/// Safe to share via `Arc<NoiseTransport>` across the video encoder/decoder task (`dc-video`)
/// and control/input task (`dc-ctrl`) without mutex contention during AEAD operations.
pub struct NoiseTransport {
    role: PeerRole,
    remote_static_pubkey: [u8; 32],
    consent_granted: AtomicBool,
    stateless: StatelessTransportState,
    ctrl_tx_seq: AtomicU64,
    media_tx_seq: AtomicU64,
    ctrl_replay: Mutex<SlidingReplayWindow>,
    media_replay: Mutex<SlidingReplayWindow>,
}

impl NoiseTransport {
    /// Returns the local endpoint's [`PeerRole`].
    #[must_use]
    pub const fn role(&self) -> PeerRole {
        self.role
    }

    /// Returns the authenticated 32-byte ephemeral static public key of the remote peer.
    #[must_use]
    pub const fn remote_static_pubkey(&self) -> &[u8; 32] {
        &self.remote_static_pubkey
    }

    /// Returns `true` if explicit on-device user consent is currently active for this session.
    #[must_use]
    pub fn is_consent_granted(&self) -> bool {
        self.consent_granted.load(Ordering::Acquire)
    }

    /// Unlocks Host screen-media transmission after the Android user explicitly approves
    /// the Mandatory Consent + SAS prompt and grants `MediaProjection`.
    pub fn grant_user_consent(&self) {
        self.consent_granted.store(true, Ordering::Release);
    }

    /// Immediately revokes Host consent (e.g., when the user taps "Stop Sharing" in the
    /// Android notification shade or locks the session), blocking any further media encryption.
    pub fn revoke_user_consent(&self) {
        self.consent_granted.store(false, Ordering::Release);
    }

    /// Encrypts and authenticates `payload` for transmission over `domain`.
    ///
    /// Wire layout: `[domain_tag: 1B | seq_u56_be: 7B][ChaCha20-Poly1305([domain_tag || payload])]`.
    pub fn seal(&self, domain: ChannelDomain, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.role == PeerRole::Host
            && domain == ChannelDomain::Media
            && !self.is_consent_granted()
        {
            return Err(CryptoError::ConsentRequired);
        }

        if payload.len() > MAX_TRANSPORT_PAYLOAD_BYTES {
            return Err(CryptoError::PayloadTooLarge {
                actual: payload.len(),
                max: MAX_TRANSPORT_PAYLOAD_BYTES,
            });
        }

        let counter = match domain {
            ChannelDomain::Control => &self.ctrl_tx_seq,
            ChannelDomain::Media => &self.media_tx_seq,
        };
        let seq = reserve_sequence(counter)?;

        let domain_byte = domain.tag_byte();
        let noise_nonce = (u64::from(domain_byte) << 56) | seq;

        let mut inner_plain = Zeroizing::new(Vec::with_capacity(1 + payload.len()));
        inner_plain.push(domain_byte);
        inner_plain.extend_from_slice(payload);

        let max_ct_len = inner_plain.len() + AEAD_TAG_LEN;
        let mut wire = vec![0u8; TRANSPORT_HEADER_LEN + max_ct_len];
        wire[..TRANSPORT_HEADER_LEN].copy_from_slice(&noise_nonce.to_be_bytes());

        let written = self
            .stateless
            .write_message(noise_nonce, &inner_plain, &mut wire[TRANSPORT_HEADER_LEN..])
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        wire.truncate(TRANSPORT_HEADER_LEN + written);
        Ok(wire)
    }

    /// Verifies, replay-checks, and decrypts an inbound `frame` arriving on `expected_domain`.
    pub fn open(&self, expected_domain: ChannelDomain, frame: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let min_len = TRANSPORT_HEADER_LEN + 1 + AEAD_TAG_LEN;
        let max_len = TRANSPORT_HEADER_LEN + 1 + MAX_TRANSPORT_PAYLOAD_BYTES + AEAD_TAG_LEN;

        if frame.len() > max_len {
            return Err(CryptoError::PayloadTooLarge {
                actual: frame.len(),
                max: max_len,
            });
        }
        if frame.len() < min_len {
            return Err(CryptoError::MalformedFrame {
                reason: "transport frame shorter than minimum header + domain tag + MAC",
            });
        }

        let mut nonce_bytes = [0u8; TRANSPORT_HEADER_LEN];
        nonce_bytes.copy_from_slice(&frame[..TRANSPORT_HEADER_LEN]);
        let noise_nonce = u64::from_be_bytes(nonce_bytes);

        let wire_domain = (noise_nonce >> 56) as u8;
        if wire_domain != expected_domain.tag_byte() {
            return Err(CryptoError::MalformedFrame {
                reason: "cross-channel transport nonce prefix mismatch",
            });
        }
        let seq = noise_nonce & CHANNEL_SEQ_MASK;

        let replay_mutex = match expected_domain {
            ChannelDomain::Control => &self.ctrl_replay,
            ChannelDomain::Media => &self.media_replay,
        };

        // Phase 1: Fast read-only replay pre-check (does NOT mutate window on unverified frames)
        {
            let guard = replay_mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.check_plausible(seq)?;
        }

        // Lock-free ChaCha20-Poly1305 verification & decryption
        let ciphertext = &frame[TRANSPORT_HEADER_LEN..];
        let mut inner_plain = Zeroizing::new(vec![0u8; ciphertext.len() - AEAD_TAG_LEN]);
        let plain_len = self
            .stateless
            .read_message(noise_nonce, ciphertext, &mut inner_plain)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        if plain_len == 0 || inner_plain[0] != expected_domain.tag_byte() {
            return Err(CryptoError::AuthenticationFailed);
        }

        // Phase 2: Atomic replay commit now that Poly1305 MAC authenticity is proven
        {
            let mut guard = replay_mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.check_and_commit(seq)?;
        }

        Ok(inner_plain[1..plain_len].to_vec())
    }
}

impl fmt::Debug for NoiseTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseTransport")
            .field("role", &self.role)
            .field("consent_granted", &self.is_consent_granted())
            .field("ctrl_tx_seq", &self.ctrl_tx_seq.load(Ordering::Relaxed))
            .field("media_tx_seq", &self.media_tx_seq.load(Ordering::Relaxed))
            .finish()
    }
}

// Saturate at the sequence limit: failed sends must never wrap the counter and
// eventually permit reuse of a nonce under the same transport key.
fn reserve_sequence(counter: &AtomicU64) -> Result<u64, CryptoError> {
    counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |seq| {
        if seq < MAX_CHANNEL_SEQ { Some(seq + 1) } else { None }
    }).map_err(|_| CryptoError::NonceExhausted)
}

#[cfg(test)]
mod sequence_tests {
    use super::*;

    #[test]
    fn sequence_exhaustion_is_permanent() {
        let counter = AtomicU64::new(MAX_CHANNEL_SEQ - 1);
        assert_eq!(reserve_sequence(&counter).unwrap(), MAX_CHANNEL_SEQ - 1);
        for _ in 0..3 {
            assert!(matches!(reserve_sequence(&counter), Err(CryptoError::NonceExhausted)));
            assert_eq!(counter.load(Ordering::Relaxed), MAX_CHANNEL_SEQ);
        }
    }

    #[test]
    fn concurrent_reservations_are_unique() {
        let counter = AtomicU64::new(MAX_CHANNEL_SEQ - 2);
        std::thread::scope(|scope| {
            let a = scope.spawn(|| reserve_sequence(&counter));
            let b = scope.spawn(|| reserve_sequence(&counter));
            let c = scope.spawn(|| reserve_sequence(&counter));
            let results = [a.join().unwrap(), b.join().unwrap(), c.join().unwrap()];
            let mut values: Vec<_> = results.into_iter().filter_map(Result::ok).collect();
            values.sort_unstable();
            assert_eq!(values, vec![MAX_CHANNEL_SEQ - 2, MAX_CHANNEL_SEQ - 1]);
        });
    }
}
