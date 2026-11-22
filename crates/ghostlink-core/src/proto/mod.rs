//! # `ghostlink_core::proto` — Module 1B
//!
//! Bounded, zero-copy video NALU datagram framing (`dc-video`) and deterministic,
//! OOM-safe big-endian binary control-plane wire protocol (`dc-ctrl`).
//!
//! Pairs directly with [`crate::crypto::NoiseTransport`] so media slices travel over
//! `ChannelDomain::Media` and control messages travel over `ChannelDomain::Control`
//! with compile-time channel-domain safety.

use bytes::Bytes;
use thiserror::Error;

use crate::crypto::{ChannelDomain, CryptoError, NoiseTransport};

pub mod control;
pub mod error;
pub mod input;
pub mod packetize;
pub mod video;

pub use control::{
    AbrTelemetry, CloseReason, ConsentDecision, ControlMessage, PliReason, TransportMode,
    MAX_BITRATE_KBPS, MAX_CLIPBOARD_BYTES, MAX_CONTROL_FRAME_BYTES, MAX_LOSS_PPM,
    MIN_BITRATE_KBPS,
};
pub use error::ProtoError;
pub use input::{
    AndroidGlobalAction, InputEvent, KeyAction, KeyEvent, KeyModifiers, NormalizedCoord,
    ScrollEvent, TouchAction, TouchEvent, TouchPointer, MAX_ANDROID_KEYCODE, MAX_GESTURE_STEP_MS,
    MAX_SCROLL_TICKS_ABS, MAX_TEXT_INJECT_BYTES, MAX_TOUCH_POINTERS,
};
pub use video::{
    CodecConfig, DisplayGeometry, ScreenRotation, VideoCodec, VideoDatagram, VideoFrameFlags,
    MAX_FRAGMENTS_PER_FRAME, MAX_PARAM_SET_BYTES, MAX_TARGET_FPS,
    MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES, MIN_DISPLAY_DIM_PX, VIDEO_HEADER_LEN,
};

/// Wire format version `1` shared across `dc-video` nibbles and `dc-ctrl` frame headers.
pub const PROTO_WIRE_VERSION: u8 = 0x01;

/// Combined error returned by end-to-end encrypted wire framing helpers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SealedWireError {
    /// Cryptographic transport error (MAC failure, replay, or locked Host consent gate).
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Binary wire framing or semantic bounds validation error.
    #[error(transparent)]
    Proto(#[from] ProtoError),
}

/// Encodes a [`ControlMessage`] and seals it onto `ChannelDomain::Control`.
pub fn seal_control_message(
    transport: &NoiseTransport,
    msg: &ControlMessage,
) -> Result<Vec<u8>, SealedWireError> {
    let encoded = msg.encode()?;
    Ok(transport.seal(ChannelDomain::Control, &encoded)?)
}

/// Decrypts a `ChannelDomain::Control` frame and decodes a validated [`ControlMessage`].
pub fn open_control_message(
    transport: &NoiseTransport,
    encrypted_frame: &[u8],
) -> Result<ControlMessage, SealedWireError> {
    let plain = transport.open(ChannelDomain::Control, encrypted_frame)?;
    Ok(ControlMessage::decode(Bytes::from(plain))?)
}

/// Encodes a [`VideoDatagram`] and seals it onto `ChannelDomain::Media`
/// (enforcing the Android Host's Mandatory Consent Gate automatically).
pub fn seal_video_datagram(
    transport: &NoiseTransport,
    datagram: &VideoDatagram,
) -> Result<Vec<u8>, SealedWireError> {
    let encoded = datagram.encode();
    Ok(transport.seal(ChannelDomain::Media, &encoded)?)
}

/// Decrypts a `ChannelDomain::Media` frame and zero-copy decodes a validated [`VideoDatagram`].
pub fn open_video_datagram(
    transport: &NoiseTransport,
    encrypted_frame: &[u8],
) -> Result<VideoDatagram, SealedWireError> {
    let plain = transport.open(ChannelDomain::Media, encrypted_frame)?;
    Ok(VideoDatagram::decode(Bytes::from(plain))?)
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::crypto::{
        EphemeralNoiseKeypair, NoiseHandshake, OneTimePin, PeerRole, SessionId, Spake2Handshake,
    };

    #[test]
    fn video_datagram_zero_copy_roundtrip_and_r04_bounds() {
        let nalu = Bytes::from_static(&[0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21]);
        let dgram = VideoDatagram::new(
            VideoCodec::H264,
            VideoFrameFlags::KEYFRAME.union(VideoFrameFlags::CONFIG_INLINE),
            42,
            16_667,
            0,
            1,
            nalu.clone(),
        )
        .expect("valid single-fragment IDR");

        assert!(dgram.flags().is_keyframe());
        assert!(dgram.flags().has_inline_config());
        assert!(dgram.flags().is_end_of_frame());

        let wire = dgram.encode();
        assert_eq!(wire.len(), VIDEO_HEADER_LEN + nalu.len());

        let decoded = VideoDatagram::decode(wire).expect("decode valid video datagram");
        assert_eq!(decoded, dgram);

        // Malicious R-04 fragment_count = 65_535 OOM attempt rejected immediately
        let mut malicious = BytesMut::from(&dgram.encode()[..]);
        malicious[16] = 0xFF;
        malicious[17] = 0xFF;
        assert!(matches!(
            VideoDatagram::decode(malicious.freeze()),
            Err(ProtoError::BoundsViolation {
                field: "VideoDatagram.fragment_count",
                ..
            })
        ));

        // Reserved upper-nibble flag bit rejected
        let mut bad_flags = BytesMut::from(&dgram.encode()[..]);
        bad_flags[1] |= 0x80;
        assert!(matches!(
            VideoDatagram::decode(bad_flags.freeze()),
            Err(ProtoError::ReservedFlagsSet { .. })
        ));

        // Inconsistent EOF bit (middle fragment 0/2 claiming END_OF_FRAME) rejected
        let mid = VideoDatagram::new(
            VideoCodec::H265,
            VideoFrameFlags::NONE,
            99,
            33_333,
            0,
            2,
            nalu,
        )
        .expect("mid fragment");
        assert!(!mid.flags().is_end_of_frame());
        let mut forged_eof = BytesMut::from(&mid.encode()[..]);
        forged_eof[1] |= VideoFrameFlags::END_OF_FRAME.bits();
        assert!(matches!(
            VideoDatagram::decode(forged_eof.freeze()),
            Err(ProtoError::InvalidFragmentation { .. })
        ));
    }

    #[test]
    fn codec_config_vps_rules_and_annex_b_csd_assembly() {
        let geom = DisplayGeometry::new(1080, 2400, ScreenRotation::Rot0, 60).expect("geom");
        let sps = Bytes::from_static(&[0x67, 0x42, 0xC0, 0x1F]);
        let pps = Bytes::from_static(&[0x68, 0xCE, 0x3C, 0x80]);
        let vps = Bytes::from_static(&[0x40, 0x01, 0x0C, 0x01]);

        // H.264 with HEVC VPS must be rejected
        assert_eq!(
            CodecConfig::new(
                VideoCodec::H264,
                geom,
                sps.clone(),
                pps.clone(),
                Some(vps.clone())
            ),
            Err(ProtoError::UnexpectedVpsForH264)
        );

        let hevc_cfg =
            CodecConfig::new(VideoCodec::H265, geom, sps, pps, Some(vps)).expect("valid HEVC");
        let csd = hevc_cfg.to_annex_b_csd();
        assert!(csd.starts_with(&[0x00, 0x00, 0x00, 0x01, 0x40]));
        assert_eq!(csd.len(), 3 * (4 + 4));
    }

    #[test]
    fn normalized_coord_nan_proof_and_multi_touch_validation() {
        // NaN, Infinity, and negative strict unit floats are rejected
        assert_eq!(
            NormalizedCoord::from_unit_f32_strict(f32::NAN),
            Err(ProtoError::InvalidViewportCoordinate)
        );
        assert_eq!(
            NormalizedCoord::from_unit_f32_strict(f32::INFINITY),
            Err(ProtoError::InvalidViewportCoordinate)
        );
        assert_eq!(
            NormalizedCoord::from_unit_f32_strict(-0.01),
            Err(ProtoError::InvalidViewportCoordinate)
        );

        // Out-of-window mouse drag (-25px on 1080px window) clamps safely to 0.0
        let left_edge = NormalizedCoord::from_viewport_clamped(-25.0, 1080.0).expect("clamped");
        assert_eq!(left_edge, NormalizedCoord::ZERO);
        assert!(left_edge.to_android_px(1080) >= 0.0);

        let bottom_edge = NormalizedCoord::ONE;
        assert!((bottom_edge.to_android_px(2400) - 2399.0).abs() < 0.01);

        // Duplicate pointer_id in multi-touch pinch gesture rejected
        let p0 = TouchPointer::new(0, NormalizedCoord::HALF, NormalizedCoord::HALF, 200).unwrap();
        let p0_dup = TouchPointer::new(0, NormalizedCoord::ONE, NormalizedCoord::ONE, 200).unwrap();
        assert_eq!(
            TouchEvent::new(TouchAction::Move, 0, 16, vec![p0, p0_dup]),
            Err(ProtoError::InvalidPointerSet { pointer_id: 0 })
        );
    }

    #[test]
    fn control_messages_binary_roundtrip_oom_prealloc_and_trailing_byte_defense() {
        let geom = DisplayGeometry::new(1440, 3200, ScreenRotation::Rot90, 120).unwrap();
        let cfg = CodecConfig::new(
            VideoCodec::H264,
            geom,
            Bytes::from_static(&[0x67, 0x64, 0x00, 0x32]),
            Bytes::from_static(&[0x68, 0xEB, 0xE3, 0xCB]),
            None,
        )
        .unwrap();

        let p0 = TouchPointer::new(0, NormalizedCoord::HALF, NormalizedCoord::HALF, 255).unwrap();
        let p1 = TouchPointer::new(1, NormalizedCoord::ONE, NormalizedCoord::ZERO, 180).unwrap();
        let pinch = TouchEvent::new(TouchAction::Move, 1, 8, vec![p0, p1]).unwrap();

        let messages = vec![
            ControlMessage::ConsentStatus(ConsentDecision::PendingUserApproval),
            ControlMessage::ConsentStatus(ConsentDecision::Approved {
                single_app_mode: true,
            }),
            ControlMessage::CodecConfig(cfg),
            ControlMessage::Input(InputEvent::Touch(pinch)),
            ControlMessage::Input(InputEvent::Scroll(
                ScrollEvent::new(NormalizedCoord::HALF, NormalizedCoord::HALF, 0, -120).unwrap(),
            )),
            ControlMessage::Input(InputEvent::Key(
                KeyEvent::new(
                    KeyAction::Down,
                    66,
                    KeyModifiers::CTRL.union(KeyModifiers::SHIFT),
                )
                .unwrap(),
            )),
            ControlMessage::Input(InputEvent::GlobalAction(AndroidGlobalAction::Back)),
            ControlMessage::Input(InputEvent::text_inject("নমস্কার GhostLink 🔒").unwrap()),
            ControlMessage::PliRequest {
                last_good_frame_id: Some(1024),
                reason: PliReason::FrameGap,
            },
            ControlMessage::LatencyPing {
                seq: 7,
                client_tx_mono_us: 99_123_456,
            },
            ControlMessage::LatencyPong {
                seq: 7,
                client_tx_mono_us: 99_123_456,
                host_encode_us: 3_400,
            },
            ControlMessage::AbrFeedback(
                AbrTelemetry::new(12_500, 2_100, 6_000, TransportMode::DirectP2p).unwrap(),
            ),
            ControlMessage::clipboard_sync("opt-in clipboard payload").unwrap(),
            ControlMessage::SessionClose {
                reason: CloseReason::UserRequested,
            },
        ];

        for expected in messages {
            let encoded = expected.encode().expect("encode control msg");
            let decoded = ControlMessage::decode(encoded.clone()).expect("decode control msg");
            assert_eq!(decoded, expected);

            // Appending 1 smuggled trailing byte must be rejected
            let mut smuggled = BytesMut::from(&encoded[..]);
            smuggled.extend_from_slice(&[0x00]);
            assert_eq!(
                ControlMessage::decode(smuggled.freeze()),
                Err(ProtoError::TrailingBytes { count: 1 })
            );
        }

        // Truncated 5-byte ClipboardSync claiming length = 16_000 fails without preallocating 16 KiB
        let bogus_len_bomb = Bytes::from_static(&[PROTO_WIRE_VERSION, 0x08, 0x3E, 0x80, 0x41]);
        assert!(matches!(
            ControlMessage::decode(bogus_len_bomb),
            Err(ProtoError::TruncatedFrame { .. })
        ));

        // Embedded NUL byte in text injection rejected
        assert_eq!(
            InputEvent::text_inject("hello\0world"),
            Err(ProtoError::InvalidUtf8Text)
        );
    }

    #[test]
    fn e2ee_sealed_wire_integration_with_consent_gate() {
        let sid = SessionId::generate();
        let pin = OneTimePin::parse("314-159").unwrap();
        let (c_spake, c_msg) = Spake2Handshake::start(PeerRole::Client, sid, &pin);
        let (h_spake, h_msg) = Spake2Handshake::start(PeerRole::Host, sid, &pin);
        let c_keys = c_spake.finish(&h_msg).unwrap();
        let h_keys = h_spake.finish(&c_msg).unwrap();

        let c_kp = EphemeralNoiseKeypair::generate().unwrap();
        let h_kp = EphemeralNoiseKeypair::generate().unwrap();
        let mut c_hs = NoiseHandshake::new(PeerRole::Client, &c_kp, &c_keys).unwrap();
        let mut h_hs = NoiseHandshake::new(PeerRole::Host, &h_kp, &h_keys).unwrap();

        let m1 = c_hs.write_message(b"").unwrap();
        h_hs.read_message(&m1).unwrap();
        let m2 = h_hs.write_message(b"").unwrap();
        c_hs.read_message(&m2).unwrap();
        let m3 = c_hs.write_message(b"").unwrap();
        h_hs.read_message(&m3).unwrap();

        let (client_tp, _) = c_hs.into_transport().unwrap();
        let (host_tp, _) = h_hs.into_transport().unwrap();

        let dgram = VideoDatagram::new(
            VideoCodec::H264,
            VideoFrameFlags::KEYFRAME,
            0,
            0,
            0,
            1,
            Bytes::from_static(&[0x00, 0x00, 0x00, 0x01, 0x65]),
        )
        .unwrap();

        // Video datagram blocked until Host consent is granted
        assert_eq!(
            seal_video_datagram(&host_tp, &dgram),
            Err(SealedWireError::Crypto(CryptoError::ConsentRequired))
        );

        // Host sends ConsentStatus::Approved over Control plane and unlocks Media plane
        host_tp.grant_user_consent();
        let ctrl_ct = seal_control_message(
            &host_tp,
            &ControlMessage::ConsentStatus(ConsentDecision::Approved {
                single_app_mode: false,
            }),
        )
        .unwrap();
        assert_eq!(
            open_control_message(&client_tp, &ctrl_ct).unwrap(),
            ControlMessage::ConsentStatus(ConsentDecision::Approved {
                single_app_mode: false,
            })
        );

        let video_ct = seal_video_datagram(&host_tp, &dgram).unwrap();
        assert_eq!(open_video_datagram(&client_tp, &video_ct).unwrap(), dgram);
    }
}
