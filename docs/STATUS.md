# Implementation status

This repository is not yet a working end-to-end remote-control product.

| Component | Implemented | Remaining verification / work |
|---|---|---|
| Rust crypto and wire protocol | PAKE, Noise, replay protection, bounded codecs and test sources | Rust build/test/Clippy execution and security review |
| Signaling | RAM registry, binary WS relay, rate limits, TURN minting and test sources | Run integration tests, load tests, TLS deployment, coturn allocation test |
| Android host | Local consent screen, foreground MediaProjection, H.264 surface encoder, Stop action, lifecycle unit tests | Android CI/device tests; authenticated frame transport; peer-specific consent; accessibility input |
| P2P transport | Bounded single-frame video fragmentation/reassembly helpers (not integrated) | ICE/STUN/TURN, authenticated channel establishment, backpressure, deadlines and loss handling |
| Desktop | Not implemented | Pairing UI, transport, decoding/rendering, bounded input/control path |
| CI | Rust test/Clippy/docs and Android unit/lint/APK workflow | First successful run and fixes as needed |

## Completion order

1. Make both build jobs green; fix existing errors before integrating more modules.
2. Add a transport abstraction and real ICE connectivity, preserving the Rust
   cryptographic trust boundaries. Define MTU, fragmentation and retransmit limits.
3. Implement Android/Rust integration, authenticated peer display and local
   session approval. Never transmit capture frames before that approval.
4. Implement desktop pairing, hardware/software decode fallback, rendering and
   consent-gated input. Network reconnects must not silently restore authorization.
5. Add accessibility gestures only behind visible opt-in, session limits and Stop.
6. Run two-device NAT/TURN and abuse tests, dependency/security audits, sign
   platform releases and publish installation/deployment instructions.

## Security caveats on existing signaling

Binary-only WS frames do **not** prove encryption: a malicious client can send
plaintext inside a binary frame. Clients must enforce authenticated encryption.
Rooms and queues are dropped on expiry; ordinary Rust allocations are not a
cryptographic memory wipe. HMAC IP buckets do not remove IP addresses held by the
OS/TCP stack, reverse proxy or hosting provider. The application intentionally
omits access logging; that is not a guarantee of infrastructure-wide anonymity.

The public signaling API must not be treated as production-certified until its
builds, expiry/rejoin behavior, resource ceilings and deployment configuration are
tested. No completed milestone implies the desktop or P2P integrations exist.

## Video packetization foundation

`ghostlink_core::proto::packetize` splits frames into bounded fragments and
reassembles a single frame out of order. The caller must authenticate each fragment
before assembly, select a payload size accounting for actual transport overhead,
and reset incomplete frames on a deadline or disconnect. It is not a network
transport, and is not yet connected to Android or a desktop decoder.
