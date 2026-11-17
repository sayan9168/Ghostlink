//! RAM-only, ciphertext-only, single-shot 2-peer blind rendezvous room registry.
//!
//! ## Security Properties
//! - **Blind Routing**: Rooms are indexed exclusively by 256-bit `BlindRoomId` digests
//!   (43-char Base64url). The server never sees the human-shared `SessionId`.
//! - **Single-Shot Slot Consumption**: Each room accepts at most **one** `Host` join and
//!   **one** `Client` join during its TTL window, defeating online 6-digit PIN brute-force.
//! - **Non-Blocking Bounded Queues**: Slow or adversarial WebSocket readers cannot stall
//!   unrelated rooms or exhaust server memory.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use ghostlink_core::crypto::PeerRole;
use thiserror::Error;
use tokio::sync::mpsc;

/// Exact URL-safe unpadded Base64 string length of a 32-byte `BlindRoomId`.
pub const BLIND_ROOM_TOKEN_CHARS: usize = 43;

/// Per-peer outbound channel capacity (`32` encrypted signaling frames).
const PEER_MAILBOX_CAPACITY: usize = 32;

/// Maximum frames buffered before the counterpart peer completes WebSocket upgrade
/// (`SPAKE2` share + confirmation + SDP offer + initial ICE candidates).
pub const MAX_PREJOIN_BUFFERED_FRAMES: usize = 8;

/// Rejection reasons when attempting to join a blind rendezvous room.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoomJoinError {
    /// Path token was not a valid 43-char Base64url 32-byte `BlindRoomId`.
    #[error("invalid blind room token format")]
    InvalidRoomToken,

    /// Path role segment was neither `"host"` nor `"client"`.
    #[error("invalid peer role (expected 'host' or 'client')")]
    InvalidRole,

    /// Role slot is already occupied or was already consumed in this single-shot room.
    #[error("rendezvous role slot already occupied or consumed")]
    SlotAlreadyConsumed,

    /// Server reached its global `max_active_rooms` RAM cap.
    #[error("rendezvous registry at maximum capacity")]
    RegistryFull,
}

/// Errors encountered while relaying an opaque binary frame inside a room.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// Frame was empty or exceeded `max_ws_frame_bytes`.
    #[error("signaling binary frame outside allowed size bounds")]
    FrameBoundsViolation,

    /// Room expired or no longer exists.
    #[error("rendezvous room expired or closed")]
    RoomExpired,

    /// Counterpart peer already disconnected from the single-shot session.
    #[error("counterpart peer has already disconnected")]
    PeerDisconnected,

    /// Counterpart has not joined yet and the bounded pre-join mailbox is full.
    #[error("pre-join buffer limit reached")]
    PreJoinBufferFull,

    /// Counterpart's outbound WebSocket queue is saturated (slow-reader protection).
    #[error("counterpart outbound queue saturated")]
    PeerBackpressure,
}

struct RoomSlot {
    created_at: Instant,
    host_joined_once: bool,
    client_joined_once: bool,
    host_tx: Option<mpsc::Sender<Bytes>>,
    client_tx: Option<mpsc::Sender<Bytes>>,
    pending_for_host: VecDeque<Bytes>,
    pending_for_client: VecDeque<Bytes>,
}

impl RoomSlot {
    fn new(now: Instant) -> Self {
        Self {
            created_at: now,
            host_joined_once: false,
            client_joined_once: false,
            host_tx: None,
            client_tx: None,
            pending_for_host: VecDeque::new(),
            pending_for_client: VecDeque::new(),
        }
    }

    fn is_expired(&self, now: Instant, ttl: Duration) -> bool {
        now.saturating_duration_since(self.created_at) >= ttl
    }
}

/// Validates and decodes a 43-character URL-safe Base64 `BlindRoomId` path parameter.
pub fn parse_blind_room_token(token: &str) -> Result<[u8; 32], RoomJoinError> {
    if token.len() != BLIND_ROOM_TOKEN_CHARS {
        return Err(RoomJoinError::InvalidRoomToken);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| RoomJoinError::InvalidRoomToken)?;
    decoded
        .try_into()
        .map_err(|_| RoomJoinError::InvalidRoomToken)
}

/// Parses the URL role segment (`"host"` or `"client"`) into [`PeerRole`].
pub fn parse_peer_role(role_str: &str) -> Result<PeerRole, RoomJoinError> {
    match role_str {
        "host" => Ok(PeerRole::Host),
        "client" => Ok(PeerRole::Client),
        _ => Err(RoomJoinError::InvalidRole),
    }
}

/// Concurrent, RAM-only blind rendezvous room table.
pub struct BlindRendezvousRegistry {
    room_ttl: Duration,
    max_rooms: usize,
    max_frame_bytes: usize,
    rooms: Mutex<HashMap<[u8; 32], RoomSlot>>,
}

impl BlindRendezvousRegistry {
    /// Creates an empty in-memory registry with bounded capacity and TTL.
    #[must_use]
    pub fn new(room_ttl: Duration, max_rooms: usize, max_frame_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            room_ttl,
            max_rooms,
            max_frame_bytes,
            rooms: Mutex::new(HashMap::new()),
        })
    }

    /// Registers `role` inside `room_key`, returning an inbound frame receiver and an
    /// RAII [`PeerLease`] that automatically detaches the sender when dropped.
    pub fn join_room(
        self: &Arc<Self>,
        room_key: [u8; 32],
        role: PeerRole,
        now: Instant,
    ) -> Result<(mpsc::Receiver<Bytes>, PeerLease), RoomJoinError> {
        let mut guard = self
            .rooms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(existing) = guard.get(&room_key) {
            if existing.is_expired(now, self.room_ttl) {
                guard.remove(&room_key);
            }
        }

        if !guard.contains_key(&room_key) && guard.len() >= self.max_rooms {
            let ttl = self.room_ttl;
            guard.retain(|_, slot| !slot.is_expired(now, ttl));
            if guard.len() >= self.max_rooms {
                return Err(RoomJoinError::RegistryFull);
            }
        }

        let slot = guard
            .entry(room_key)
            .or_insert_with(|| RoomSlot::new(now));

        match role {
            PeerRole::Host if slot.host_joined_once => {
                return Err(RoomJoinError::SlotAlreadyConsumed);
            }
            PeerRole::Client if slot.client_joined_once => {
                return Err(RoomJoinError::SlotAlreadyConsumed);
            }
            _ => {}
        }

        let (tx, rx) = mpsc::channel(PEER_MAILBOX_CAPACITY);

        match role {
            PeerRole::Host => {
                slot.host_joined_once = true;
                while let Some(frame) = slot.pending_for_host.pop_front() {
                    let _ = tx.try_send(frame);
                }
                slot.host_tx = Some(tx);
            }
            PeerRole::Client => {
                slot.client_joined_once = true;
                while let Some(frame) = slot.pending_for_client.pop_front() {
                    let _ = tx.try_send(frame);
                }
                slot.client_tx = Some(tx);
            }
        }

        let lease = PeerLease {
            registry: Arc::clone(self),
            room_key,
            role,
        };

        Ok((rx, lease))
    }

    /// Forwards an opaque encrypted binary frame to the counterpart peer in `room_key`.
    pub fn relay_binary_frame(
        &self,
        room_key: &[u8; 32],
        sender_role: PeerRole,
        payload: Bytes,
        now: Instant,
    ) -> Result<(), RelayError> {
        if payload.is_empty() || payload.len() > self.max_frame_bytes {
            return Err(RelayError::FrameBoundsViolation);
        }

        let mut guard = self
            .rooms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let Some(slot) = guard.get_mut(room_key) else {
            return Err(RelayError::RoomExpired);
        };

        if slot.is_expired(now, self.room_ttl) {
            guard.remove(room_key);
            return Err(RelayError::RoomExpired);
        }

        match sender_role {
            PeerRole::Client => {
                if let Some(host_tx) = &slot.host_tx {
                    host_tx
                        .try_send(payload)
                        .map_err(|_| RelayError::PeerBackpressure)
                } else if !slot.host_joined_once {
                    if slot.pending_for_host.len() >= MAX_PREJOIN_BUFFERED_FRAMES {
                        return Err(RelayError::PreJoinBufferFull);
                    }
                    slot.pending_for_host.push_back(payload);
                    Ok(())
                } else {
                    Err(RelayError::PeerDisconnected)
                }
            }
            PeerRole::Host => {
                if let Some(client_tx) = &slot.client_tx {
                    client_tx
                        .try_send(payload)
                        .map_err(|_| RelayError::PeerBackpressure)
                } else if !slot.client_joined_once {
                    if slot.pending_for_client.len() >= MAX_PREJOIN_BUFFERED_FRAMES {
                        return Err(RelayError::PreJoinBufferFull);
                    }
                    slot.pending_for_client.push_back(payload);
                    Ok(())
                } else {
                    Err(RelayError::PeerDisconnected)
                }
            }
        }
    }

    /// Reaps all expired rooms from RAM, returning the count of evicted slots.
    pub fn reap_expired(&self, now: Instant) -> usize {
        let mut guard = self
            .rooms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = guard.len();
        let ttl = self.room_ttl;
        guard.retain(|_, slot| !slot.is_expired(now, ttl));
        before.saturating_sub(guard.len())
    }

    /// Returns current active/tombstoned room count in memory (for aggregate anonymous health gauges).
    #[must_use]
    pub fn active_room_count(&self) -> usize {
        self.rooms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    fn detach_peer(&self, room_key: &[u8; 32], role: PeerRole) {
        let mut guard = self
            .rooms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(slot) = guard.get_mut(room_key) {
            match role {
                PeerRole::Host => {
                    slot.host_tx = None;
                    slot.pending_for_host.clear();
                }
                PeerRole::Client => {
                    slot.client_tx = None;
                    slot.pending_for_client.clear();
                }
            }
            // Retain the lightweight tombstone until `room_ttl` expires whenever a Client
            // has touched the room so a consumed `BlindRoomId` cannot be brute-forced or replayed.
            if slot.host_tx.is_none() && slot.client_tx.is_none() && !slot.client_joined_once {
                guard.remove(room_key);
            }
        }
    }
}

/// RAII lease ensuring a WebSocket peer's channel and buffered frames are wiped on disconnect.
pub struct PeerLease {
    registry: Arc<BlindRendezvousRegistry>,
    room_key: [u8; 32],
    role: PeerRole,
}

impl Drop for PeerLease {
    fn drop(&mut self) {
        self.registry.detach_peer(&self.room_key, self.role);
    }
}
