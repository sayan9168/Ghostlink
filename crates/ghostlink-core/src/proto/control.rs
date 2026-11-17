//! Deterministic, OOM-safe big-endian binary control-plane wire protocol (`dc-ctrl`).
//!
//! Carries Mandatory Consent lifecycle notifications, out-of-band `SPS/PPS/VPS` codec configs,
//! `NaN`-proof controller inputs, instant `PLI` keyframe requests, real-time RTT/encode latency
//! pings, integer fixed-point Adaptive Bitrate (`ABR`) telemetry, and opt-in clipboard sync.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::proto::error::ProtoError;
use crate::proto::input::{
    validate_clean_text, AndroidGlobalAction, InputEvent, KeyAction, KeyEvent, KeyModifiers,
    NormalizedCoord, ScrollEvent, TouchAction, TouchEvent, TouchPointer, MAX_TEXT_INJECT_BYTES,
    MAX_TOUCH_POINTERS,
};
use crate::proto::video::{
    CodecConfig, DisplayGeometry, ScreenRotation, VideoCodec, MAX_PARAM_SET_BYTES,
};
use crate::proto::PROTO_WIRE_VERSION;

/// Hard upper bound on any encoded [`ControlMessage`] frame (`24 KiB`).
pub const MAX_CONTROL_FRAME_BYTES: usize = 24 * 1024;

/// Maximum UTF-8 payload permitted in an opt-in [`ControlMessage::ClipboardSync`] (`16 KiB`).
pub const MAX_CLIPBOARD_BYTES: usize = 16 * 1024;

/// Minimum allowed Adaptive Bitrate recommendation (`250 kbps`).
pub const MIN_BITRATE_KBPS: u32 = 250;

/// Maximum allowed Adaptive Bitrate recommendation (`50 Mbps`).
pub const MAX_BITRATE_KBPS: u32 = 50_000;

/// Maximum valid packet-loss ratio in parts-per-million (`1,000,000` = `100%`).
pub const MAX_LOSS_PPM: u32 = 1_000_000;

const OP_CONSENT_STATUS: u8 = 0x01;
const OP_CODEC_CONFIG: u8 = 0x02;
const OP_INPUT_EVENT: u8 = 0x03;
const OP_PLI_REQUEST: u8 = 0x04;
const OP_LATENCY_PING: u8 = 0x05;
const OP_LATENCY_PONG: u8 = 0x06;
const OP_ABR_FEEDBACK: u8 = 0x07;
const OP_CLIPBOARD_SYNC: u8 = 0x08;
const OP_SESSION_CLOSE: u8 = 0x09;

const INPUT_SUB_TOUCH: u8 = 0x01;
const INPUT_SUB_SCROLL: u8 = 0x02;
const INPUT_SUB_KEY: u8 = 0x03;
const INPUT_SUB_GLOBAL: u8 = 0x04;
const INPUT_SUB_TEXT: u8 = 0x05;

/// On-device human authorization state reported by the Android Host over `dc-ctrl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsentDecision {
    /// Host Noise handshake succeeded; waiting for human approval on the SAS dialog.
    PendingUserApproval,
    /// User tapped Approve and granted OS `MediaProjection` permission.
    Approved {
        /// `true` if Android 14/15 Single-App screen capture was selected instead of full display.
        single_app_mode: bool,
    },
    /// User explicitly rejected the incoming connection prompt.
    DeniedByUser,
    /// User tapped "Disconnect / Stop Sharing" mid-session on the Android device.
    RevokedMidSession,
}

/// Trigger cause for a Picture Loss Indication (`PLI`) hardware IDR keyframe request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PliReason {
    /// Stream joined or decoder reset; awaiting initial random-access IDR frame.
    InitialSync = 0x01,
    /// Non-disposable reference `frame_id` gap detected on `dc-video`.
    FrameGap = 0x02,
    /// Fragment reassembly timer expired for an incomplete reference frame.
    FragmentTimeout = 0x03,
    /// Hardware/software `FFmpeg` decoder reported bitstream corruption.
    DecoderError = 0x04,
}

impl PliReason {
    const fn from_wire(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            0x01 => Ok(Self::InitialSync),
            0x02 => Ok(Self::FrameGap),
            0x03 => Ok(Self::FragmentTimeout),
            0x04 => Ok(Self::DecoderError),
            other => Err(ProtoError::UnknownDiscriminant {
                field: "PliReason",
                value: other,
            }),
        }
    }
}

/// Active ICE network path classification displayed in the Desktop Client HUD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TransportMode {
    /// Direct peer-to-peer UDP (`host` or STUN `srflx`/`prflx` hole-punched path).
    DirectP2p = 0x01,
    /// Relayed through an untrusted zero-log TURN server (`relay` candidate, still E2EE via Noise).
    ZeroKnowledgeTurnRelay = 0x02,
}

impl TransportMode {
    const fn from_wire(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            0x01 => Ok(Self::DirectP2p),
            0x02 => Ok(Self::ZeroKnowledgeTurnRelay),
            other => Err(ProtoError::UnknownDiscriminant {
                field: "TransportMode",
                value: other,
            }),
        }
    }
}

/// Validated receiver network telemetry driving Android `MediaCodec` runtime bitrate adaptation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AbrTelemetry {
    observed_loss_ppm: u32,
    jitter_us: u32,
    recommended_bitrate_kbps: u32,
    transport_mode: TransportMode,
}

impl AbrTelemetry {
    /// Validates loss bounds (`0..=1_000_000` ppm) and encoder bitrate range (`250..=50_000` kbps).
    pub const fn new(
        observed_loss_ppm: u32,
        jitter_us: u32,
        recommended_bitrate_kbps: u32,
        transport_mode: TransportMode,
    ) -> Result<Self, ProtoError> {
        if observed_loss_ppm > MAX_LOSS_PPM {
            return Err(ProtoError::BoundsViolation {
                field: "AbrTelemetry.observed_loss_ppm",
                actual: observed_loss_ppm as usize,
                min: 0,
                max: MAX_LOSS_PPM as usize,
            });
        }
        if recommended_bitrate_kbps < MIN_BITRATE_KBPS
            || recommended_bitrate_kbps > MAX_BITRATE_KBPS
        {
            return Err(ProtoError::BoundsViolation {
                field: "AbrTelemetry.recommended_bitrate_kbps",
                actual: recommended_bitrate_kbps as usize,
                min: MIN_BITRATE_KBPS as usize,
                max: MAX_BITRATE_KBPS as usize,
            });
        }

        Ok(Self {
            observed_loss_ppm,
            jitter_us,
            recommended_bitrate_kbps,
            transport_mode,
        })
    }

    /// Returns observed UDP packet loss in parts-per-million (`10_000` = `1.0%`).
    #[must_use]
    pub const fn observed_loss_ppm(self) -> u32 {
        self.observed_loss_ppm
    }

    /// Returns inter-arrival jitter estimate in microseconds.
    #[must_use]
    pub const fn jitter_us(self) -> u32 {
        self.jitter_us
    }

    /// Returns target encoder bitrate in kilobits per second (`250..=50_000`).
    #[must_use]
    pub const fn recommended_bitrate_kbps(self) -> u32 {
        self.recommended_bitrate_kbps
    }

    /// Returns the active [`TransportMode`] (`DirectP2p` vs `ZeroKnowledgeTurnRelay`).
    #[must_use]
    pub const fn transport_mode(self) -> TransportMode {
        self.transport_mode
    }
}

/// Graceful teardown reason sent prior to closing DataChannels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CloseReason {
    /// Operator clicked Disconnect cleanly.
    UserRequested = 0x01,
    /// Session exceeded configured inactivity timeout.
    IdleTimeout = 0x02,
    /// Android user revoked screen-sharing or Accessibility consent.
    ConsentRevoked = 0x03,
    /// Peer violated wire framing or cryptographic invariants.
    ProtocolViolation = 0x04,
}

impl CloseReason {
    const fn from_wire(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            0x01 => Ok(Self::UserRequested),
            0x02 => Ok(Self::IdleTimeout),
            0x03 => Ok(Self::ConsentRevoked),
            0x04 => Ok(Self::ProtocolViolation),
            other => Err(ProtoError::UnknownDiscriminant {
                field: "CloseReason",
                value: other,
            }),
        }
    }
}

/// Bidirectional control-plane protocol frame transmitted over `ChannelDomain::Control` (`dc-ctrl`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Host -> Client consent gate status transition.
    ConsentStatus(ConsentDecision),
    /// Host -> Client reliable `SPS/PPS(/VPS)` & geometry update.
    CodecConfig(CodecConfig),
    /// Client -> Host remote touch, scroll, key, global action, or text input.
    Input(InputEvent),
    /// Client -> Host request for immediate hardware IDR sync frame.
    PliRequest {
        /// Last contiguous decoded `frame_id`, if any.
        last_good_frame_id: Option<u32>,
        /// Diagnostic trigger reason.
        reason: PliReason,
    },
    /// Client -> Host monotonic timestamp probe for real-time HUD RTT measurement.
    LatencyPing {
        /// Monotonic ping sequence number.
        seq: u32,
        /// Client monotonic send timestamp in microseconds.
        client_tx_mono_us: u64,
    },
    /// Host -> Client echo response carrying most recent `MediaCodec` frame encode latency.
    LatencyPong {
        /// Echoed ping sequence number.
        seq: u32,
        /// Echoed client monotonic send timestamp in microseconds.
        client_tx_mono_us: u64,
        /// Latest Android hardware `MediaCodec` encode duration in microseconds.
        host_encode_us: u32,
    },
    /// Client -> Host receiver loss/jitter report for dynamic `MediaCodec` bitrate tuning.
    AbrFeedback(AbrTelemetry),
    /// Bidirectional opt-in UTF-8 clipboard synchronization (`1..=16,384` bytes, NUL-free).
    ClipboardSync {
        /// Validated UTF-8 clipboard text.
        utf8_text: String,
    },
    /// Bidirectional clean session termination signal.
    SessionClose {
        /// Teardown reason code.
        reason: CloseReason,
    },
}

impl ControlMessage {
    /// Constructs a validated [`ControlMessage::ClipboardSync`] message (`1..=16 KiB`, NUL-free).
    pub fn clipboard_sync(text: impl Into<String>) -> Result<Self, ProtoError> {
        let utf8_text = text.into();
        validate_clean_text("ClipboardSync.utf8_text", &utf8_text, 1, MAX_CLIPBOARD_BYTES)?;
        Ok(Self::ClipboardSync { utf8_text })
    }

    /// Deterministically encodes this message into big-endian wire bytes ready for
    /// [`crate::crypto::NoiseTransport::seal`] on `ChannelDomain::Control`.
    pub fn encode(&self) -> Result<Bytes, ProtoError> {
        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(PROTO_WIRE_VERSION);

        match self {
            Self::ConsentStatus(decision) => {
                buf.put_u8(OP_CONSENT_STATUS);
                match decision {
                    ConsentDecision::PendingUserApproval => buf.put_u8(0x01),
                    ConsentDecision::Approved { single_app_mode } => {
                        buf.put_u8(0x02);
                        buf.put_u8(u8::from(*single_app_mode));
                    }
                    ConsentDecision::DeniedByUser => buf.put_u8(0x03),
                    ConsentDecision::RevokedMidSession => buf.put_u8(0x04),
                }
            }
            Self::CodecConfig(cfg) => {
                buf.put_u8(OP_CODEC_CONFIG);
                buf.put_u8(cfg.codec() as u8);
                let g = cfg.geometry();
                buf.put_u16(g.width_px());
                buf.put_u16(g.height_px());
                buf.put_u8(g.rotation() as u8);
                buf.put_u8(g.target_fps());
                put_len_prefixed(&mut buf, "CodecConfig.sps", cfg.sps(), MAX_PARAM_SET_BYTES)?;
                put_len_prefixed(&mut buf, "CodecConfig.pps", cfg.pps(), MAX_PARAM_SET_BYTES)?;
                match cfg.vps() {
                    Some(vps) => {
                        buf.put_u8(0x01);
                        put_len_prefixed(&mut buf, "CodecConfig.vps", vps, MAX_PARAM_SET_BYTES)?;
                    }
                    None => buf.put_u8(0x00),
                }
            }
            Self::Input(ev) => {
                buf.put_u8(OP_INPUT_EVENT);
                encode_input_event(&mut buf, ev)?;
            }
            Self::PliRequest {
                last_good_frame_id,
                reason,
            } => {
                buf.put_u8(OP_PLI_REQUEST);
                buf.put_u8(*reason as u8);
                match last_good_frame_id {
                    Some(fid) => {
                        buf.put_u8(0x01);
                        buf.put_u32(*fid);
                    }
                    None => buf.put_u8(0x00),
                }
            }
            Self::LatencyPing {
                seq,
                client_tx_mono_us,
            } => {
                buf.put_u8(OP_LATENCY_PING);
                buf.put_u32(*seq);
                buf.put_u64(*client_tx_mono_us);
            }
            Self::LatencyPong {
                seq,
                client_tx_mono_us,
                host_encode_us,
            } => {
                buf.put_u8(OP_LATENCY_PONG);
                buf.put_u32(*seq);
                buf.put_u64(*client_tx_mono_us);
                buf.put_u32(*host_encode_us);
            }
            Self::AbrFeedback(abr) => {
                buf.put_u8(OP_ABR_FEEDBACK);
                buf.put_u32(abr.observed_loss_ppm());
                buf.put_u32(abr.jitter_us());
                buf.put_u32(abr.recommended_bitrate_kbps());
                buf.put_u8(abr.transport_mode() as u8);
            }
            Self::ClipboardSync { utf8_text } => {
                validate_clean_text("ClipboardSync.utf8_text", utf8_text, 1, MAX_CLIPBOARD_BYTES)?;
                buf.put_u8(OP_CLIPBOARD_SYNC);
                put_len_prefixed(
                    &mut buf,
                    "ClipboardSync.utf8_text",
                    utf8_text.as_bytes(),
                    MAX_CLIPBOARD_BYTES,
                )?;
            }
            Self::SessionClose { reason } => {
                buf.put_u8(OP_SESSION_CLOSE);
                buf.put_u8(*reason as u8);
            }
        }

        if buf.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(ProtoError::BoundsViolation {
                field: "ControlMessage.frame",
                actual: buf.len(),
                min: 2,
                max: MAX_CONTROL_FRAME_BYTES,
            });
        }

        Ok(buf.freeze())
    }

    /// Safely decodes and validates a [`ControlMessage`] from a decrypted [`Bytes`] buffer.
    ///
    /// Checks remaining byte availability **before** any collection allocation, defeating
    /// untrusted length-prefix memory-exhaustion attacks.
    pub fn decode(mut wire: Bytes) -> Result<Self, ProtoError> {
        if wire.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(ProtoError::BoundsViolation {
                field: "ControlMessage.frame",
                actual: wire.len(),
                min: 2,
                max: MAX_CONTROL_FRAME_BYTES,
            });
        }

        let version = read_u8(&mut wire)?;
        if version != PROTO_WIRE_VERSION {
            return Err(ProtoError::UnsupportedWireVersion {
                actual: version,
                expected: PROTO_WIRE_VERSION,
            });
        }

        let opcode = read_u8(&mut wire)?;
        let msg = match opcode {
            OP_CONSENT_STATUS => {
                let tag = read_u8(&mut wire)?;
                let decision = match tag {
                    0x01 => ConsentDecision::PendingUserApproval,
                    0x02 => {
                        let mode_byte = read_u8(&mut wire)?;
                        let single_app_mode = decode_bool("ConsentDecision.single_app_mode", mode_byte)?;
                        ConsentDecision::Approved { single_app_mode }
                    }
                    0x03 => ConsentDecision::DeniedByUser,
                    0x04 => ConsentDecision::RevokedMidSession,
                    other => {
                        return Err(ProtoError::UnknownDiscriminant {
                            field: "ConsentDecision",
                            value: other,
                        });
                    }
                };
                Self::ConsentStatus(decision)
            }
            OP_CODEC_CONFIG => {
                let codec = VideoCodec::from_wire(read_u8(&mut wire)?)?;
                let width_px = read_u16(&mut wire)?;
                let height_px = read_u16(&mut wire)?;
                let rotation = ScreenRotation::from_wire(read_u8(&mut wire)?)?;
                let target_fps = read_u8(&mut wire)?;
                let geometry = DisplayGeometry::new(width_px, height_px, rotation, target_fps)?;

                let sps = read_bounded_bytes(&mut wire, "CodecConfig.sps", 1, MAX_PARAM_SET_BYTES)?;
                let pps = read_bounded_bytes(&mut wire, "CodecConfig.pps", 1, MAX_PARAM_SET_BYTES)?;
                let has_vps = decode_bool("CodecConfig.has_vps", read_u8(&mut wire)?)?;
                let vps = if has_vps {
                    Some(read_bounded_bytes(
                        &mut wire,
                        "CodecConfig.vps",
                        1,
                        MAX_PARAM_SET_BYTES,
                    )?)
                } else {
                    None
                };

                Self::CodecConfig(CodecConfig::new(codec, geometry, sps, pps, vps)?)
            }
            OP_INPUT_EVENT => Self::Input(decode_input_event(&mut wire)?),
            OP_PLI_REQUEST => {
                let reason = PliReason::from_wire(read_u8(&mut wire)?)?;
                let has_fid = decode_bool("PliRequest.has_frame_id", read_u8(&mut wire)?)?;
                let last_good_frame_id = if has_fid {
                    Some(read_u32(&mut wire)?)
                } else {
                    None
                };
                Self::PliRequest {
                    last_good_frame_id,
                    reason,
                }
            }
            OP_LATENCY_PING => {
                let seq = read_u32(&mut wire)?;
                let client_tx_mono_us = read_u64(&mut wire)?;
                Self::LatencyPing {
                    seq,
                    client_tx_mono_us,
                }
            }
            OP_LATENCY_PONG => {
                let seq = read_u32(&mut wire)?;
                let client_tx_mono_us = read_u64(&mut wire)?;
                let host_encode_us = read_u32(&mut wire)?;
                Self::LatencyPong {
                    seq,
                    client_tx_mono_us,
                    host_encode_us,
                }
            }
            OP_ABR_FEEDBACK => {
                let observed_loss_ppm = read_u32(&mut wire)?;
                let jitter_us = read_u32(&mut wire)?;
                let recommended_bitrate_kbps = read_u32(&mut wire)?;
                let transport_mode = TransportMode::from_wire(read_u8(&mut wire)?)?;
                Self::AbrFeedback(AbrTelemetry::new(
                    observed_loss_ppm,
                    jitter_us,
                    recommended_bitrate_kbps,
                    transport_mode,
                )?)
            }
            OP_CLIPBOARD_SYNC => {
                let utf8_text = read_bounded_utf8(
                    &mut wire,
                    "ClipboardSync.utf8_text",
                    1,
                    MAX_CLIPBOARD_BYTES,
                )?;
                Self::ClipboardSync { utf8_text }
            }
            OP_SESSION_CLOSE => {
                let reason = CloseReason::from_wire(read_u8(&mut wire)?)?;
                Self::SessionClose { reason }
            }
            unknown => return Err(ProtoError::UnknownOpcode(unknown)),
        };

        if !wire.is_empty() {
            return Err(ProtoError::TrailingBytes { count: wire.len() });
        }

        Ok(msg)
    }
}

fn encode_input_event(buf: &mut BytesMut, ev: &InputEvent) -> Result<(), ProtoError> {
    match ev {
        InputEvent::Touch(touch) => {
            buf.put_u8(INPUT_SUB_TOUCH);
            buf.put_u8(touch.action() as u8);
            buf.put_u8(touch.active_pointer_id());
            buf.put_u16(touch.duration_ms());
            let pointers = touch.pointers();
            buf.put_u8(pointers.len() as u8);
            for p in pointers {
                buf.put_u8(p.pointer_id());
                buf.put_u16(p.x().raw());
                buf.put_u16(p.y().raw());
                buf.put_u8(p.pressure_u8());
            }
        }
        InputEvent::Scroll(scroll) => {
            buf.put_u8(INPUT_SUB_SCROLL);
            buf.put_u16(scroll.x().raw());
            buf.put_u16(scroll.y().raw());
            buf.put_i16(scroll.delta_x_ticks());
            buf.put_i16(scroll.delta_y_ticks());
        }
        InputEvent::Key(key) => {
            buf.put_u8(INPUT_SUB_KEY);
            buf.put_u8(key.action() as u8);
            buf.put_u16(key.android_keycode());
            buf.put_u8(key.modifiers().bits());
        }
        InputEvent::GlobalAction(action) => {
            buf.put_u8(INPUT_SUB_GLOBAL);
            buf.put_u8(*action as u8);
        }
        InputEvent::TextInject(text) => {
            validate_clean_text("InputEvent.TextInject", text, 1, MAX_TEXT_INJECT_BYTES)?;
            buf.put_u8(INPUT_SUB_TEXT);
            put_len_prefixed(
                buf,
                "InputEvent.TextInject",
                text.as_bytes(),
                MAX_TEXT_INJECT_BYTES,
            )?;
        }
    }
    Ok(())
}

fn decode_input_event(wire: &mut Bytes) -> Result<InputEvent, ProtoError> {
    let sub = read_u8(wire)?;
    match sub {
        INPUT_SUB_TOUCH => {
            let action = TouchAction::from_wire(read_u8(wire)?)?;
            let active_pointer_id = read_u8(wire)?;
            let duration_ms = read_u16(wire)?;
            let count = read_u8(wire)? as usize;

            if count == 0 || count > MAX_TOUCH_POINTERS {
                return Err(ProtoError::BoundsViolation {
                    field: "TouchEvent.pointers",
                    actual: count,
                    min: 1,
                    max: MAX_TOUCH_POINTERS,
                });
            }

            let needed_bytes = count * 6;
            if wire.len() < needed_bytes {
                return Err(ProtoError::TruncatedFrame {
                    needed: needed_bytes - wire.len(),
                    remaining: wire.len(),
                });
            }

            let mut pointers = Vec::with_capacity(count);
            for _ in 0..count {
                let pid = read_u8(wire)?;
                let x = NormalizedCoord::from_raw(read_u16(wire)?);
                let y = NormalizedCoord::from_raw(read_u16(wire)?);
                let pressure_u8 = read_u8(wire)?;
                pointers.push(TouchPointer::new(pid, x, y, pressure_u8)?);
            }

            Ok(InputEvent::Touch(TouchEvent::new(
                action,
                active_pointer_id,
                duration_ms,
                pointers,
            )?))
        }
        INPUT_SUB_SCROLL => {
            let x = NormalizedCoord::from_raw(read_u16(wire)?);
            let y = NormalizedCoord::from_raw(read_u16(wire)?);
            let dx = read_i16(wire)?;
            let dy = read_i16(wire)?;
            Ok(InputEvent::Scroll(ScrollEvent::new(x, y, dx, dy)?))
        }
        INPUT_SUB_KEY => {
            let action = KeyAction::from_wire(read_u8(wire)?)?;
            let keycode = read_u16(wire)?;
            let modifiers = KeyModifiers::from_bits(read_u8(wire)?)?;
            Ok(InputEvent::Key(KeyEvent::new(action, keycode, modifiers)?))
        }
        INPUT_SUB_GLOBAL => {
            let action = AndroidGlobalAction::from_wire(read_u8(wire)?)?;
            Ok(InputEvent::GlobalAction(action))
        }
        INPUT_SUB_TEXT => {
            let text =
                read_bounded_utf8(wire, "InputEvent.TextInject", 1, MAX_TEXT_INJECT_BYTES)?;
            Ok(InputEvent::TextInject(text))
        }
        other => Err(ProtoError::UnknownDiscriminant {
            field: "InputEvent",
            value: other,
        }),
    }
}

fn put_len_prefixed(
    buf: &mut BytesMut,
    field: &'static str,
    slice: &[u8],
    max_len: usize,
) -> Result<(), ProtoError> {
    if slice.is_empty() || slice.len() > max_len || slice.len() > usize::from(u16::MAX) {
        return Err(ProtoError::BoundsViolation {
            field,
            actual: slice.len(),
            min: 1,
            max: max_len,
        });
    }
    buf.put_u16(slice.len() as u16);
    buf.put_slice(slice);
    Ok(())
}

const fn decode_bool(field: &'static str, raw: u8) -> Result<bool, ProtoError> {
    match raw {
        0x00 => Ok(false),
        0x01 => Ok(true),
        other => Err(ProtoError::UnknownDiscriminant {
            field,
            value: other,
        }),
    }
}

fn ensure_remaining(wire: &Bytes, needed: usize) -> Result<(), ProtoError> {
    if wire.len() < needed {
        Err(ProtoError::TruncatedFrame {
            needed: needed - wire.len(),
            remaining: wire.len(),
        })
    } else {
        Ok(())
    }
}

fn read_u8(wire: &mut Bytes) -> Result<u8, ProtoError> {
    ensure_remaining(wire, 1)?;
    Ok(wire.get_u8())
}

fn read_u16(wire: &mut Bytes) -> Result<u16, ProtoError> {
    ensure_remaining(wire, 2)?;
    Ok(wire.get_u16())
}

fn read_i16(wire: &mut Bytes) -> Result<i16, ProtoError> {
    ensure_remaining(wire, 2)?;
    Ok(wire.get_i16())
}

fn read_u32(wire: &mut Bytes) -> Result<u32, ProtoError> {
    ensure_remaining(wire, 4)?;
    Ok(wire.get_u32())
}

fn read_u64(wire: &mut Bytes) -> Result<u64, ProtoError> {
    ensure_remaining(wire, 8)?;
    Ok(wire.get_u64())
}

fn read_bounded_bytes(
    wire: &mut Bytes,
    field: &'static str,
    min_len: usize,
    max_len: usize,
) -> Result<Bytes, ProtoError> {
    let len = usize::from(read_u16(wire)?);
    if len < min_len || len > max_len {
        return Err(ProtoError::BoundsViolation {
            field,
            actual: len,
            min: min_len,
            max: max_len,
        });
    }
    ensure_remaining(wire, len)?;
    Ok(wire.split_to(len))
}

fn read_bounded_utf8(
    wire: &mut Bytes,
    field: &'static str,
    min_len: usize,
    max_len: usize,
) -> Result<String, ProtoError> {
    let slice = read_bounded_bytes(wire, field, min_len, max_len)?;
    let parsed = std::str::from_utf8(&slice).map_err(|_| ProtoError::InvalidUtf8Text)?;
    validate_clean_text(field, parsed, min_len, max_len)?;
    Ok(parsed.to_owned())
}
