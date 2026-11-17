//! # `ghostlink-core`
//!
//! Shared Rust cryptographic, protocol, and transport foundation for **GhostLink** —
//! a privacy-first, P2P Android remote control and screen mirroring engine operating
//! without public IPs or trusted relay servers.
//!
//! ## Security Invariants
//! - `#![forbid(unsafe_code)]` enforced workspace-wide.
//! - Zero persistent device identifiers: all session IDs, PINs, and Noise static keys
//!   are freshly generated from the OS CSPRNG per pairing window and zeroized on drop.
//! - Signaling and TURN relays remain cryptographically blind to session keys, WebRTC SDP
//!   network metadata, media NALUs, and control inputs.

/// Cryptographic identity, blind PAKE rendezvous, anti-replay, and stateless Noise E2EE engine.
pub mod crypto;

/// Bounded, zero-copy media datagram framing and deterministic binary control wire protocol.
pub mod proto;
