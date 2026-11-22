//! Bounded video fragmentation and single-frame reassembly.
//!
//! These helpers do not provide networking, encryption, consent, loss recovery or
//! timeouts. Authenticate datagrams before passing them to the assembler, and discard
//! incomplete frames on a caller-defined deadline or session termination.

use bytes::{Bytes, BytesMut};
use thiserror::Error;

use super::{ProtoError, VideoCodec, VideoDatagram, VideoFrameFlags, MAX_FRAGMENTS_PER_FRAME,
    MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES};

/// Largest frame accepted by the wire protocol at the maximum fragment size.
pub const MAX_VIDEO_FRAME_BYTES: usize =
    MAX_FRAGMENTS_PER_FRAME as usize * MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES;

/// Split one nonempty encoded frame into validated, zero-copy datagrams.
///
/// `payload_limit` must be chosen for the actual transport after accounting for
/// all framing and encryption overhead. This function does not guarantee a path MTU.
pub fn fragment_frame(
    codec: VideoCodec,
    flags: VideoFrameFlags,
    frame_id: u32,
    pts_us: u64,
    payload: Bytes,
    payload_limit: usize,
) -> Result<Vec<VideoDatagram>, ProtoError> {
    if payload_limit == 0 || payload_limit > MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES {
        return Err(ProtoError::BoundsViolation { field: "payload_limit", actual: payload_limit,
            min: 1, max: MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES });
    }
    let max = payload_limit * MAX_FRAGMENTS_PER_FRAME as usize;
    if payload.is_empty() || payload.len() > max {
        return Err(ProtoError::BoundsViolation { field: "video_frame", actual: payload.len(),
            min: 1, max });
    }
    let count = payload.len().div_ceil(payload_limit) as u16;
    let mut fragments = Vec::with_capacity(count as usize);
    for index in 0..count {
        let start = index as usize * payload_limit;
        let end = (start + payload_limit).min(payload.len());
        fragments.push(VideoDatagram::new(codec, flags, frame_id, pts_us, index, count,
            payload.slice(start..end))?);
    }
    Ok(fragments)
}

/// Errors returned when fragments do not belong to the same frame.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReassemblyError {
    /// The datagram does not satisfy the wire protocol bounds.
    #[error("invalid video fragment")]
    InvalidFragment,
    /// A fragment has different frame metadata from the frame being assembled.
    #[error("fragment metadata differs from the current frame")]
    MetadataMismatch,
    /// The same index was received again with different contents.
    #[error("conflicting duplicate fragment")]
    ConflictingDuplicate,
}

/// One fully reconstructed encoded frame.
#[derive(Debug, PartialEq, Eq)]
pub struct ReassembledFrame {
    /// Codec of the encoded payload.
    pub codec: VideoCodec,
    /// Frame flags, without the fragment-specific end-of-frame bit.
    pub flags: VideoFrameFlags,
    /// Wrapping frame identifier.
    pub frame_id: u32,
    /// Presentation timestamp in microseconds.
    pub pts_us: u64,
    /// Encoded frame bytes in fragment order.
    pub payload: Bytes,
}

/// Bounded assembler for a single frame; incomplete frames must be reset by the caller.
///
/// This intentionally does not allocate storage for multiple frames. Duplicates are
/// ignored if identical and rejected if conflicting. Call `reset` for packet loss,
/// timeout, a new session, or before switching to a different frame.
#[derive(Debug, Default)]
pub struct FrameAssembler {
    current: Option<PartialFrame>,
}

#[derive(Debug)]
struct PartialFrame {
    codec: VideoCodec,
    flags: u8,
    frame_id: u32,
    pts_us: u64,
    fragments: Vec<Option<Bytes>>,
    received: usize,
    bytes: usize,
}

impl FrameAssembler {
    /// Drop any incomplete frame and its buffered fragments.
    pub fn reset(&mut self) { self.current = None; }

    /// Add an authenticated fragment, returning a frame only once all parts arrive.
    ///
    /// On an error the current partial frame is retained; callers may reset it.
    pub fn push(&mut self, fragment: VideoDatagram) -> Result<Option<ReassembledFrame>, ReassemblyError> {
        // Serde can construct a datagram without calling its validating constructor.
        let count = fragment.fragment_count() as usize;
        let index = fragment.fragment_index() as usize;
        let raw_flags = fragment.flags().bits();
        if count == 0 || count > MAX_FRAGMENTS_PER_FRAME as usize || index >= count ||
            fragment.payload().is_empty() || fragment.payload().len() > MAX_VIDEO_FRAGMENT_PAYLOAD_BYTES ||
            VideoFrameFlags::from_bits(raw_flags).is_err() ||
            fragment.flags().is_end_of_frame() != (index + 1 == count) {
            return Err(ReassemblyError::InvalidFragment);
        }
        let flags = raw_flags & !VideoFrameFlags::END_OF_FRAME.bits();
        let current = self.current.get_or_insert_with(|| PartialFrame {
            codec: fragment.codec(), flags, frame_id: fragment.frame_id(), pts_us: fragment.pts_us(),
            fragments: vec![None; count], received: 0, bytes: 0,
        });
        if current.codec != fragment.codec() || current.flags != flags ||
            current.frame_id != fragment.frame_id() || current.pts_us != fragment.pts_us() ||
            current.fragments.len() != count {
            return Err(ReassemblyError::MetadataMismatch);
        }
        let slot = &mut current.fragments[fragment.fragment_index() as usize];
        if let Some(existing) = slot {
            return if existing == fragment.payload() { Ok(None) } else { Err(ReassemblyError::ConflictingDuplicate) };
        }
        current.bytes += fragment.payload().len();
        *slot = Some(fragment.into_payload());
        current.received += 1;
        if current.received != count { return Ok(None); }
        let complete = self.current.take().expect("current frame exists");
        let mut payload = BytesMut::with_capacity(complete.bytes);
        for part in complete.fragments {
            payload.extend_from_slice(&part.expect("all fragments received"));
        }
        // Flags originate from validated VideoDatagram values with EOF cleared.
        let flags = VideoFrameFlags::from_bits(complete.flags).expect("validated flags");
        Ok(Some(ReassembledFrame { codec: complete.codec, flags, frame_id: complete.frame_id,
            pts_us: complete.pts_us, payload: payload.freeze() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_order_and_duplicate_round_trip() {
        let data = Bytes::from_static(b"abcdefghij");
        let parts = fragment_frame(VideoCodec::H264, VideoFrameFlags::KEYFRAME, 7, 10, data.clone(), 4).unwrap();
        assert_eq!(parts.len(), 3);
        let mut assembler = FrameAssembler::default();
        assert_eq!(assembler.push(parts[2].clone()).unwrap(), None);
        assert_eq!(assembler.push(parts[2].clone()).unwrap(), None);
        assert_eq!(assembler.push(parts[0].clone()).unwrap(), None);
        let frame = assembler.push(parts[1].clone()).unwrap().unwrap();
        assert_eq!(frame.payload, data);
        assert_eq!(frame.flags, VideoFrameFlags::KEYFRAME);
    }

    #[test]
    fn bounds_and_conflicts() {
        assert!(fragment_frame(VideoCodec::H264, VideoFrameFlags::NONE, 1, 0, Bytes::new(), 1).is_err());
        assert!(fragment_frame(VideoCodec::H264, VideoFrameFlags::NONE, 1, 0, Bytes::from_static(b"x"), 0).is_err());
        assert!(fragment_frame(VideoCodec::H264, VideoFrameFlags::NONE, 1, 0, Bytes::from(vec![0; 1537]), 1).is_err());
        let parts = fragment_frame(VideoCodec::H264, VideoFrameFlags::NONE, 1, 0, Bytes::from_static(b"ab"), 1).unwrap();
        let other = fragment_frame(VideoCodec::H264, VideoFrameFlags::NONE, 1, 0, Bytes::from_static(b"xb"), 1).unwrap();
        let different = fragment_frame(VideoCodec::H264, VideoFrameFlags::NONE, 2, 0, Bytes::from_static(b"ab"), 1).unwrap();
        let mut assembler = FrameAssembler::default();
        assembler.push(parts[0].clone()).unwrap();
        assert_eq!(assembler.push(other[0].clone()), Err(ReassemblyError::ConflictingDuplicate));
        assert_eq!(assembler.push(different[0].clone()), Err(ReassemblyError::MetadataMismatch));
        assembler.reset();
        assert!(assembler.push(different[0].clone()).unwrap().is_none());
    }
}
