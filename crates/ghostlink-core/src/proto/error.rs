//! Non-leaky, OOM-safe wire protocol error definitions for GhostLink media and control planes.

use thiserror::Error;

/// Unified error boundary for GhostLink wire framing, bounds validation, and binary decoding.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Frame declared an unsupported protocol wire version.
    #[error("unsupported wire protocol version 0x{actual:02X} (expected 0x{expected:02X})")]
    UnsupportedWireVersion {
        /// Version byte/nibble observed on the wire.
        actual: u8,
        /// Version supported by this build.
        expected: u8,
    },

    /// Control frame carried an unrecognized message opcode.
    #[error("unknown control message opcode 0x{0:02X}")]
    UnknownOpcode(u8),

    /// Enumerated wire field carried an unassigned byte discriminant.
    #[error("unknown discriminant 0x{value:02X} for protocol field '{field}'")]
    UnknownDiscriminant {
        /// Protocol field name.
        field: &'static str,
        /// Unassigned wire byte value.
        value: u8,
    },

    /// Bitmask field set one or more reserved/must-be-zero bits.
    #[error("reserved protocol flag bits set (0x{raw:02X}) in field '{field}'")]
    ReservedFlagsSet {
        /// Protocol bitflags field name.
        field: &'static str,
        /// Raw flag byte read from the wire.
        raw: u8,
    },

    /// Input buffer ended before the declared structure or length-prefixed slice completed.
    #[error("truncated wire frame: needed at least {needed} more bytes, only {remaining} available")]
    TruncatedFrame {
        /// Minimum additional bytes required to complete the field.
        needed: usize,
        /// Bytes actually remaining in the buffer.
        remaining: usize,
    },

    /// Unconsumed bytes remained after decoding a single control frame.
    #[error("unexpected {count} trailing byte(s) after control frame end")]
    TrailingBytes {
        /// Number of unexpected trailing bytes.
        count: usize,
    },

    /// Numeric or byte-length field violated protocol anti-DoS or platform safety bounds.
    #[error("protocol bounds violation on '{field}': value {actual} outside [{min}, {max}]")]
    BoundsViolation {
        /// Validated field name.
        field: &'static str,
        /// Observed value or length.
        actual: usize,
        /// Inclusive lower bound.
        min: usize,
        /// Inclusive upper bound.
        max: usize,
    },

    /// Video fragment index/count relationship or `END_OF_FRAME` bit was inconsistent.
    #[error("invalid video fragment indexing ({fragment_index}/{fragment_count}) or inconsistent EOF flag")]
    InvalidFragmentation {
        /// Zero-based fragment index.
        fragment_index: u16,
        /// Total fragments declared for the frame.
        fragment_count: u16,
    },

    /// Codec configuration attempted to attach an HEVC `VPS` to an H.264 stream.
    #[error("invalid codec parameter set: H.264/AVC stream must not include an HEVC VPS")]
    UnexpectedVpsForH264,

    /// Floating-point viewport coordinate was `NaN`, infinite, or outside `[0.0, 1.0]`.
    #[error("invalid viewport coordinate or dimension (non-finite or out of range)")]
    InvalidViewportCoordinate,

    /// Multi-touch event contained duplicate `pointer_id` entries in the same stroke batch,
    /// or `active_pointer_id` did not reference a pointer present in the batch.
    #[error("invalid multi-touch pointer set: duplicate or missing pointer_id {pointer_id}")]
    InvalidPointerSet {
        /// Offending pointer slot identifier.
        pointer_id: u8,
    },

    /// UTF-8 text injection or clipboard payload contained invalid UTF-8 or embedded NUL (`\0`) bytes.
    #[error("invalid UTF-8 string or prohibited NUL control byte in text payload")]
    InvalidUtf8Text,
}
