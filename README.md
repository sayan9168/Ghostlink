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
## 🚀 Quick Start
1. Install GhostLink on Android device → Grant permissions → Get Device ID
2. Install GhostLink Client on desktop → Enter Device ID
3. Approve connection prompt on Android → Connected!

## ⚠️ Security Notice
GhostLink is designed for **authorized personal use only**. Always obtain explicit consent before connecting to any device. Unauthorized access is illegal and unethical.
