# GhostLink 🔗🔒

A privacy-first, P2P-based Android remote control and screen mirroring tool that works without a public IP address. Inspired by Tor's decentralized philosophy and QtScrcpy's functionality.

## ✨ Key Features
- 🌐 **No Public IP Required** – NAT traversal via libp2p/WebRTC; works across any network
- 🔐 **End-to-End Encrypted** – Zero-knowledge relay servers; no data logging
- 📱 **Single Install Setup** – Share a unique ID or QR code to connect instantly
- 🖥️ **Cross-Platform** – Android host + Windows/macOS/Linux controller client
- ⚡ **Low-Latency Streaming** – H.264/H.265 hardware encoding with adaptive bitrate
- 🛡️ **Consent-First Design** – Mandatory on-device approval notification for every session
- 🔄 **Auto-Reconnection** – Seamless recovery from network interruptions

## 🆚 GhostLink vs Traditional Tools
| Feature | QtScrcpy / scrcpy | GhostLink |
|---------|-------------------|-----------|
| Public IP Needed | Yes (for remote) | ❌ No |
| Port Forwarding | Required | ❌ Not needed |
| Encryption | ADB-level only | ✅ E2EE |
| Setup Complexity | Manual config | Single install + ID |
| Privacy Model | Centralized trust | Zero-knowledge P2P |

## 🏗️ Architecture Overview
[Android Host] ←→ P2P (libp2p/WebRTC) ←→ [Desktop Client]
↕                                        ↕
MediaProjection                          Video Decoder
Input Injection                          Input Capture
↕                                        ↕
[E2EE Layer] ←→ Signaling Server ←→ [E2EE Layer]
(No-log relay)
## 🚧 Development status

GhostLink is under development; the features above are design goals, not a
shipped product. There are no desktop installers or end-to-end remote sessions yet.
See [implementation status](docs/STATUS.md) for completed and remaining work.

### Rust components

Install a current stable Rust toolchain, then run:

```sh
cargo test --workspace
cargo run -p ghostlink-signal
```

The signaling binary defaults to `0.0.0.0:8080`. Terminate TLS before exposing it
publicly; a working signaling server alone does not provide remote screen sharing.

### Android local capture milestone

See [Android build and device-test instructions](android/README.md). This app
requires visible local approval and currently discards encoded frames: nothing
is transmitted or recorded. CI builds a debug APK, not a signed release.

## ⚠️ Security Notice
GhostLink is designed for **authorized personal use only**. Always obtain explicit consent before connecting to any device. Unauthorized access is illegal and unethical.
