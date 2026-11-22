//! Zero-copy video NALU datagram framing (`dc-video`) and codec configuration metadata.
//!
//! Designed for sub-millisecond `MediaCodec` -> `webrtc-rs` -> `FFmpeg` streaming without
//! dynamic length-prefix allocation pitfalls or head-of-line blocking.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::proto::error::ProtoError;
use crate::proto::PROTO_WIRE_VERSION;

/// Fixed big-endian header byte length of a [`VideoDatagram`].
pub const VIDEO_HEADER_LEN: usize = 18;

/// Maximum NALU slice payload carried inside one [`VideoDatagram`] (`1,400` bytes).
///
/// This is a protocol ceiling, not a path-MTU guarantee. The sender must choose
/// a smaller payload when transport, encryption, or tunnel overhead requires it.
pub const MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES: usize = 1400;

/// Hard upper bound on fragments per compressed video frame (`1,536` ≈ `2.05 MiB`).
///
/// Blocks `R-04` reassembly memory-exhaustion attacks from malicious peers advertising
/// `fragment_count = 65_535`.
pub const MAX_FRAGMENTS_PER_FRAME: u16 = 1536;

/// Maximum byte length accepted for an individual `SPS`, `PPS`, or `VPS` parameter set.
pub const MAX_PARAM_SET_BYTES: usize = 2048;

/// Minimum allowed captured display width or height in physical pixels.
pub const MIN_DISPLAY_DIM_PX: u16 = 64;

/// Maximum allowed captured display width or height in physical pixels (`8K` ceiling).
pub const MAX_DISPLAY_DIM_PX: u16 = 8192;

/// Maximum supported capture frame rate (`240 Hz`).
pub const MAX_TARGET_FPS: u8 = 240;

const ANNEX_B_START_CODE: &[u8; 4] = &[0x00, 0x00, 0x00, 0x01];

/// Hardware-accelerated video codec negotiated for screen mirroring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum VideoCodec {
    /// ITU-T H.264 / AVC (`"video/avc"` in Android `MediaFormat`).
    H264 = 0x01,
    /// ITU-T H.265 / HEVC (`"video/hevc"` in Android `MediaFormat`).
    H265 = 0x02,
}

impl VideoCodec {
    /// Decodes a 4-bit or 8-bit wire codec identifier.
    pub const fn from_wire(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            0x01 => Ok(Self::H264),
            0x02 => Ok(Self::H265),
            other => Err(ProtoError::UnknownDiscriminant {
                field: "VideoCodec",
                value: other,
            }),
        }
    }

    /// Returns the canonical Android `MediaFormat` MIME type string.
    #[must_use]
    pub const fn android_mime_type(self) -> &'static str {
        match self {
            Self::H264 => "video/avc",
            Self::H265 => "video/hevc",
        }
    }
}

/// Captured display orientation reported by Android `VirtualDisplay` / `Configuration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ScreenRotation {
    /// Natural portrait / 0 degrees clockwise.
    Rot0 = 0,
    /// Landscape / 90 degrees clockwise.
    Rot90 = 1,
    /// Inverted portrait / 180 degrees clockwise.
    Rot180 = 2,
    /// Reverse landscape / 270 degrees clockwise.
    Rot270 = 3,
}

impl ScreenRotation {
    /// Parses a wire rotation discriminant (`0..=3`).
    pub const fn from_wire(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            0 => Ok(Self::Rot0),
            1 => Ok(Self::Rot90),
            2 => Ok(Self::Rot180),
            3 => Ok(Self::Rot270),
            other => Err(ProtoError::UnknownDiscriminant {
                field: "ScreenRotation",
                value: other,
            }),
        }
    }

    /// Returns clockwise rotation in degrees (`0`, `90`, `180`, or `270`).
    #[must_use]
    pub const fn degrees(self) -> u16 {
        match self {
            Self::Rot0 => 0,
            Self::Rot90 => 90,
            Self::Rot180 => 180,
            Self::Rot270 => 270,
        }
    }
}

/// Validated capture surface dimensions, orientation, and target frame rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DisplayGeometry {
    width_px: u16,
    height_px: u16,
    rotation: ScreenRotation,
    target_fps: u8,
}

impl DisplayGeometry {
    /// Validates and constructs capture geometry metadata.
    pub const fn new(
        width_px: u16,
        height_px: u16,
        rotation: ScreenRotation,
        target_fps: u8,
    ) -> Result<Self, ProtoError> {
        if width_px < MIN_DISPLAY_DIM_PX || width_px > MAX_DISPLAY_DIM_PX {
            return Err(ProtoError::BoundsViolation {
                field: "DisplayGeometry.width_px",
                actual: width_px as usize,
                min: MIN_DISPLAY_DIM_PX as usize,
                max: MAX_DISPLAY_DIM_PX as usize,
            });
        }
        if height_px < MIN_DISPLAY_DIM_PX || height_px > MAX_DISPLAY_DIM_PX {
            return Err(ProtoError::BoundsViolation {
                field: "DisplayGeometry.height_px",
                actual: height_px as usize,
                min: MIN_DISPLAY_DIM_PX as usize,
                max: MAX_DISPLAY_DIM_PX as usize,
            });
        }
        if target_fps == 0 || target_fps > MAX_TARGET_FPS {
            return Err(ProtoError::BoundsViolation {
                field: "DisplayGeometry.target_fps",
                actual: target_fps as usize,
                min: 1,
                max: MAX_TARGET_FPS as usize,
            });
        }

        Ok(Self {
            width_px,
            height_px,
            rotation,
            target_fps,
        })
    }

    /// Returns capture width in pixels (`64..=8192`).
    #[must_use]
    pub const fn width_px(self) -> u16 {
        self.width_px
    }

    /// Returns capture height in pixels (`64..=8192`).
    #[must_use]
    pub const fn height_px(self) -> u16 {
        self.height_px
    }

    /// Returns current screen orientation.
    #[must_use]
    pub const fn rotation(self) -> ScreenRotation {
        self.rotation
    }

    /// Returns encoder target frame rate (`1..=240`).
    #[must_use]
    pub const fn target_fps(self) -> u8 {
        self.target_fps
    }
}

/// Out-of-band codec parameter sets (`SPS`, `PPS`, and optional HEVC `VPS`) transmitted
/// reliably over `dc-ctrl` at stream start and on dynamic Android 14/15 capture resize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodecConfig {
    codec: VideoCodec,
    geometry: DisplayGeometry,
    sps: Bytes,
    pps: Bytes,
    vps: Option<Bytes>,
}

impl CodecConfig {
    /// Validates parameter set bounds and codec-specific `VPS` rules.
    pub fn new(
        codec: VideoCodec,
        geometry: DisplayGeometry,
        sps: Bytes,
        pps: Bytes,
        vps: Option<Bytes>,
    ) -> Result<Self, ProtoError> {
        validate_param_set("CodecConfig.sps", &sps)?;
        validate_param_set("CodecConfig.pps", &pps)?;

        match (codec, &vps) {
            (VideoCodec::H264, Some(_)) => return Err(ProtoError::UnexpectedVpsForH264),
            (VideoCodec::H264, None) => {}
            (VideoCodec::H265, Some(v)) => validate_param_set("CodecConfig.vps", v)?,
            (VideoCodec::H265, None) => {}
        }

        Ok(Self {
            codec,
            geometry,
            sps,
            pps,
            vps,
        })
    }

    /// Returns the active [`VideoCodec`].
    #[must_use]
    pub const fn codec(&self) -> VideoCodec {
        self.codec
    }

    /// Returns the stream's [`DisplayGeometry`].
    #[must_use]
    pub const fn geometry(&self) -> DisplayGeometry {
        self.geometry
    }

    /// Returns the Sequence Parameter Set (`SPS`) bytes.
    #[must_use]
    pub const fn sps(&self) -> &Bytes {
        &self.sps
    }

    /// Returns the Picture Parameter Set (`PPS`) bytes.
    #[must_use]
    pub const fn pps(&self) -> &Bytes {
        &self.pps
    }

    /// Returns the optional HEVC Video Parameter Set (`VPS`) bytes.
    #[must_use]
    pub const fn vps(&self) -> Option<&Bytes> {
        self.vps.as_ref()
    }

    /// Assembles canonical Annex-B (`00 00 00 01`) codec-specific data (`CSD`) ready
    /// to initialize an FFmpeg `AVCodecContext` hardware decoder.
    #[must_use]
    pub fn to_annex_b_csd(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(
            self.vps.as_ref().map_or(0, |v| v.len() + 4) + self.sps.len() + self.pps.len() + 8,
        );
        if let Some(vps) = &self.vps {
            append_annex_b_nalu(&mut out, vps);
        }
        append_annex_b_nalu(&mut out, &self.sps);
        append_annex_b_nalu(&mut out, &self.pps);
        out.freeze()
    }
}

fn validate_param_set(field: &'static str, buf: &Bytes) -> Result<(), ProtoError> {
    if buf.is_empty() || buf.len() > MAX_PARAM_SET_BYTES {
        return Err(ProtoError::BoundsViolation {
            field,
            actual: buf.len(),
            min: 1,
            max: MAX_PARAM_SET_BYTES,
        });
    }
    Ok(())
}

fn append_annex_b_nalu(dst: &mut BytesMut, nalu: &[u8]) {
    if !nalu.starts_with(ANNEX_B_START_CODE) && !nalu.starts_with(&[0x00, 0x00, 0x01]) {
        dst.put_slice(ANNEX_B_START_CODE);
    }
    dst.put_slice(nalu);
}

/// Validated bitflags carried in byte `1` of a [`VideoDatagram`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VideoFrameFlags(u8);

impl VideoFrameFlags {
    /// Empty flag set (non-disposable delta P-frame intermediate fragment).
    pub const NONE: Self = Self(0x00);
    /// Instant-Decoder-Refresh (`IDR` / `CRA`) random-access keyframe.
    pub const KEYFRAME: Self = Self(0x01);
    /// Inline Annex-B `SPS/PPS(/VPS)` parameter sets are prepended to this frame.
    pub const CONFIG_INLINE: Self = Self(0x02);
    /// Final fragment of the encoded video frame (`fragment_index + 1 == fragment_count`).
    pub const END_OF_FRAME: Self = Self(0x04);
    /// Non-reference frame that may be skipped without corrupting subsequent delta frames.
    pub const DISPOSABLE: Self = Self(0x08);

    const VALID_MASK: u8 = 0x0F;

    /// Parses a wire flag byte, rejecting any set reserved upper-nibble bits (`0xF0`).
    pub const fn from_bits(raw: u8) -> Result<Self, ProtoError> {
        if (raw & !Self::VALID_MASK) != 0 {
            return Err(ProtoError::ReservedFlagsSet {
                field: "VideoFrameFlags",
                raw,
            });
        }
        Ok(Self(raw))
    }

    /// Returns the raw validated flag byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Combines two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns `true` if this fragment belongs to a random-access keyframe.
    #[must_use]
    pub const fn is_keyframe(self) -> bool {
        (self.0 & Self::KEYFRAME.0) != 0
    }

    /// Returns `true` if inline codec parameter sets precede the frame bitstream.
    #[must_use]
    pub const fn has_inline_config(self) -> bool {
        (self.0 & Self::CONFIG_INLINE.0) != 0
    }

    /// Returns `true` if this fragment is the final slice of `frame_id`.
    #[must_use]
    pub const fn is_end_of_frame(self) -> bool {
        (self.0 & Self::END_OF_FRAME.0) != 0
    }

    /// Returns `true` if dropping this frame does not break decoder reference state.
    #[must_use]
    pub const fn is_disposable(self) -> bool {
        (self.0 & Self::DISPOSABLE.0) != 0
    }

    const fn with_eof(self, is_last: bool) -> Self {
        if is_last {
            Self(self.0 | Self::END_OF_FRAME.0)
        } else {
            Self(self.0 & !Self::END_OF_FRAME.0)
        }
    }
}

/// MTU-sized video NALU fragment transmitted over the unreliable, unordered `dc-video` DataChannel.
///
/// ## Wire Format (`18` bytes big-endian header + `1..=1400` bytes zero-copy payload)
/// - Byte `0`: `(PROTO_WIRE_VERSION << 4) | (codec as u8)`
/// - Byte `1`: [`VideoFrameFlags`]
/// - Bytes `2..6`: `frame_id` (`u32` BE)
/// - Bytes `6..14`: `pts_us` (`u64` BE presentation timestamp in microseconds)
/// - Bytes `14..16`: `fragment_index` (`u16` BE, `0..fragment_count`)
/// - Bytes `16..18`: `fragment_count` (`u16` BE, `1..=1536`)
/// - Bytes `18..`: `payload` (`Bytes` NALU slice)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoDatagram {
    codec: VideoCodec,
    flags: VideoFrameFlags,
    frame_id: u32,
    pts_us: u64,
    fragment_index: u16,
    fragment_count: u16,
    payload: Bytes,
}

impl VideoDatagram {
    /// Constructs a validated [`VideoDatagram`], automatically synchronizing `END_OF_FRAME`
    /// with `fragment_index + 1 == fragment_count`.
    pub fn new(
        codec: VideoCodec,
        flags: VideoFrameFlags,
        frame_id: u32,
        pts_us: u64,
        fragment_index: u16,
        fragment_count: u16,
        payload: Bytes,
    ) -> Result<Self, ProtoError> {
        if fragment_count == 0 || fragment_count > MAX_FRAGMENTS_PER_FRAME {
            return Err(ProtoError::BoundsViolation {
                field: "VideoDatagram.fragment_count",
                actual: fragment_count as usize,
                min: 1,
                max: MAX_FRAGMENTS_PER_FRAME as usize,
            });
        }
        if fragment_index >= fragment_count {
            return Err(ProtoError::InvalidFragmentation {
                fragment_index,
                fragment_count,
            });
        }
        if payload.is_empty() || payload.len() > MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES {
            return Err(ProtoError::BoundsViolation {
                field: "VideoDatagram.payload",
                actual: payload.len(),
                min: 1,
                max: MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES,
            });
        }

        let is_last = fragment_index + 1 == fragment_count;
        let normalized_flags = flags.with_eof(is_last);

        Ok(Self {
            codec,
            flags: normalized_flags,
            frame_id,
            pts_us,
            fragment_index,
            fragment_count,
            payload,
        })
    }

    /// Returns the fragment's [`VideoCodec`].
    #[must_use]
    pub const fn codec(&self) -> VideoCodec {
        self.codec
    }

    /// Returns the validated [`VideoFrameFlags`].
    #[must_use]
    pub const fn flags(&self) -> VideoFrameFlags {
        self.flags
    }

    /// Returns the monotonically wrapping 32-bit frame identifier.
    #[must_use]
    pub const fn frame_id(&self) -> u32 {
        self.frame_id
    }

    /// Returns the capture presentation timestamp in microseconds.
    #[must_use]
    pub const fn pts_us(&self) -> u64 {
        self.pts_us
    }

    /// Returns the zero-based fragment index within `frame_id`.
    #[must_use]
    pub const fn fragment_index(&self) -> u16 {
        self.fragment_index
    }

    /// Returns the total fragment count for `frame_id`.
    #[must_use]
    pub const fn fragment_count(&self) -> u16 {
        self.fragment_count
    }

    /// Borrows the zero-copy NALU fragment payload slice.
    #[must_use]
    pub const fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Consumes the datagram and returns the underlying zero-copy payload [`Bytes`].
    #[must_use]
    pub fn into_payload(self) -> Bytes {
        self.payload
    }

    /// Serializes the 18-byte header and payload into a contiguous [`Bytes`] buffer
    /// ready to pass into [`crate::crypto::NoiseTransport::seal`].
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(VIDEO_HEADER_LEN + self.payload.len());
        let ver_codec = (PROTO_WIRE_VERSION << 4) | ((self.codec as u8) & 0x0F);
        buf.put_u8(ver_codec);
        buf.put_u8(self.flags.bits());
        buf.put_u32(self.frame_id);
        buf.put_u64(self.pts_us);
        buf.put_u16(self.fragment_index);
        buf.put_u16(self.fragment_count);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    /// Zero-copy decodes and validates a [`VideoDatagram`] from a decrypted [`Bytes`] buffer.
    pub fn decode(mut wire: Bytes) -> Result<Self, ProtoError> {
        if wire.len() < VIDEO_HEADER_LEN {
            return Err(ProtoError::TruncatedFrame {
                needed: VIDEO_HEADER_LEN - wire.len(),
                remaining: wire.len(),
            });
        }

        let mut hdr = &wire[..VIDEO_HEADER_LEN];
        let ver_codec = hdr.get_u8();
        let version = ver_codec >> 4;
        if version != PROTO_WIRE_VERSION {
            return Err(ProtoError::UnsupportedWireVersion {
                actual: version,
                expected: PROTO_WIRE_VERSION,
            });
        }

        let codec = VideoCodec::from_wire(ver_codec & 0x0F)?;
        let flags = VideoFrameFlags::from_bits(hdr.get_u8())?;
        let frame_id = hdr.get_u32();
        let pts_us = hdr.get_u64();
        let fragment_index = hdr.get_u16();
        let fragment_count = hdr.get_u16();

        if fragment_count == 0 || fragment_count > MAX_FRAGMENTS_PER_FRAME {
            return Err(ProtoError::BoundsViolation {
                field: "VideoDatagram.fragment_count",
                actual: fragment_count as usize,
                min: 1,
                max: MAX_FRAGMENTS_PER_FRAME as usize,
            });
        }
        if fragment_index >= fragment_count {
            return Err(ProtoError::InvalidFragmentation {
                fragment_index,
                fragment_count,
            });
        }

        let expected_eof = fragment_index + 1 == fragment_count;
        if flags.is_end_of_frame() != expected_eof {
            return Err(ProtoError::InvalidFragmentation {
                fragment_index,
                fragment_count,
            });
        }

        let payload = wire.split_off(VIDEO_HEADER_LEN);
        if payload.is_empty() || payload.len() > MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES {
            return Err(ProtoError::BoundsViolation {
                field: "VideoDatagram.payload",
                actual: payload.len(),
                min: 1,
                max: MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES,
            });
        }

        Ok(Self {
            codec,
            flags,
            frame_id,
            pts_us,
            fragment_index,
            fragment_count,
            payload,
        })
    }
}
