//! `NaN`-proof normalized coordinate mapping, multi-touch stroke batches, scroll vectors,
//! keyboard events, and non-root Android `AccessibilityService` global actions.

use serde::{Deserialize, Serialize};

use crate::proto::error::ProtoError;

/// Maximum simultaneous touch pointers per gesture frame (`10` matches Android API 26–33
/// `GestureDescription.getMaxStrokeCount()`).
pub const MAX_TOUCH_POINTERS: usize = 10;

/// Maximum per-step stroke duration (`1,000 ms`) allowed in [`TouchEvent`] to prevent
/// stuck-pointer denial of service on the Android Host.
pub const MAX_GESTURE_STEP_MS: u16 = 1000;

/// Maximum absolute scroll delta per event in `1/120`-notch high-resolution wheel units.
pub const MAX_SCROLL_TICKS_ABS: i16 = 2400;

/// Highest valid `android.view.KeyEvent.KEYCODE_*` identifier accepted over the wire.
pub const MAX_ANDROID_KEYCODE: u16 = 512;

/// Maximum UTF-8 byte length for a single [`InputEvent::TextInject`] message (`4 KiB`).
pub const MAX_TEXT_INJECT_BYTES: usize = 4096;

/// `UQ0.16` fixed-point normalized viewport coordinate (`0..=65,535` ↔ `[0.0, 1.0]`).
///
/// Eliminates IEEE-754 `NaN`, `±Infinity`, and negative coordinate edge cases on the wire,
/// guaranteeing that Android's `AccessibilityService` `Path.moveTo(x, y)` can never crash
/// with `IllegalArgumentException`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NormalizedCoord(u16);

impl NormalizedCoord {
    /// Origin coordinate (`0.0`).
    pub const ZERO: Self = Self(0);
    /// Midpoint coordinate (`~0.5`).
    pub const HALF: Self = Self(32_768);
    /// Maximum edge coordinate (`1.0`).
    pub const ONE: Self = Self(u16::MAX);

    /// Wraps any raw 16-bit fixed-point value (`0..=65,535`). Always valid by construction.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the underlying `0..=65,535` fixed-point representation.
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Converts a strict unit float in `[0.0, 1.0]`, rejecting `NaN`, `±Inf`, or out-of-range values.
    pub fn from_unit_f32_strict(unit: f32) -> Result<Self, ProtoError> {
        if !unit.is_finite() || !(0.0..=1.0).contains(&unit) {
            return Err(ProtoError::InvalidViewportCoordinate);
        }
        let scaled = (f64::from(unit) * f64::from(u16::MAX)).round() as u16;
        Ok(Self(scaled))
    }

    /// Maps a desktop cursor position (`cursor_px`) against a positive window viewport dimension
    /// (`viewport_extent_px`), clamping out-of-window drag excursions cleanly to `[0.0, 1.0]`.
    pub fn from_viewport_clamped(
        cursor_px: f32,
        viewport_extent_px: f32,
    ) -> Result<Self, ProtoError> {
        if !cursor_px.is_finite() || !viewport_extent_px.is_finite() || viewport_extent_px <= 0.0 {
            return Err(ProtoError::InvalidViewportCoordinate);
        }
        let clamped = (f64::from(cursor_px) / f64::from(viewport_extent_px)).clamp(0.0, 1.0);
        let scaled = (clamped * f64::from(u16::MAX)).round() as u16;
        Ok(Self(scaled))
    }

    /// Converts back to a unit `f32` in `[0.0, 1.0]`.
    #[must_use]
    pub fn to_unit_f32(self) -> f32 {
        f32::from(self.0) / f32::from(u16::MAX)
    }

    /// Maps this normalized coordinate onto an Android physical display axis of `display_extent_px`
    /// pixels (`[0.0, (display_extent_px - 1) as f32]`).
    #[must_use]
    pub fn to_android_px(self, display_extent_px: u16) -> f32 {
        if display_extent_px <= 1 {
            return 0.0;
        }
        let max_px = f64::from(display_extent_px - 1);
        ((f64::from(self.0) * max_px) / f64::from(u16::MAX)) as f32
    }
}

/// Phase of a touch gesture lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TouchAction {
    /// Primary or secondary finger touched the surface.
    Down = 0x01,
    /// Active finger(s) moved across the surface (`willContinue = true` stroke).
    Move = 0x02,
    /// Primary or secondary finger lifted cleanly (`willContinue = false` stroke).
    Up = 0x03,
    /// Gesture aborted (window focus lost or session interrupted).
    Cancel = 0x04,
}

impl TouchAction {
    /// Parses a wire `TouchAction` discriminant.
    pub const fn from_wire(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            0x01 => Ok(Self::Down),
            0x02 => Ok(Self::Move),
            0x03 => Ok(Self::Up),
            0x04 => Ok(Self::Cancel),
            other => Err(ProtoError::UnknownDiscriminant {
                field: "TouchAction",
                value: other,
            }),
        }
    }
}

/// Single finger contact point within a [`TouchEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TouchPointer {
    pointer_id: u8,
    x: NormalizedCoord,
    y: NormalizedCoord,
    pressure_u8: u8,
}

impl TouchPointer {
    /// Constructs a validated contact point (`pointer_id < 10`).
    pub const fn new(
        pointer_id: u8,
        x: NormalizedCoord,
        y: NormalizedCoord,
        pressure_u8: u8,
    ) -> Result<Self, ProtoError> {
        if (pointer_id as usize) >= MAX_TOUCH_POINTERS {
            return Err(ProtoError::BoundsViolation {
                field: "TouchPointer.pointer_id",
                actual: pointer_id as usize,
                min: 0,
                max: MAX_TOUCH_POINTERS - 1,
            });
        }
        Ok(Self {
            pointer_id,
            x,
            y,
            pressure_u8,
        })
    }

    /// Returns the pointer slot ID (`0..10`).
    #[must_use]
    pub const fn pointer_id(self) -> u8 {
        self.pointer_id
    }

    /// Returns the normalized horizontal coordinate.
    #[must_use]
    pub const fn x(self) -> NormalizedCoord {
        self.x
    }

    /// Returns the normalized vertical coordinate.
    #[must_use]
    pub const fn y(self) -> NormalizedCoord {
        self.y
    }

    /// Returns quantized contact pressure (`0..=255`).
    #[must_use]
    pub const fn pressure_u8(self) -> u8 {
        self.pressure_u8
    }
}

/// Validated single- or multi-touch event mapped onto Android `AccessibilityService.dispatchGesture()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TouchEvent {
    action: TouchAction,
    active_pointer_id: u8,
    duration_ms: u16,
    pointers: Vec<TouchPointer>,
}

impl TouchEvent {
    /// Validates pointer bounds, uniqueness, active pointer membership, and stroke duration.
    pub fn new(
        action: TouchAction,
        active_pointer_id: u8,
        duration_ms: u16,
        pointers: Vec<TouchPointer>,
    ) -> Result<Self, ProtoError> {
        if pointers.is_empty() || pointers.len() > MAX_TOUCH_POINTERS {
            return Err(ProtoError::BoundsViolation {
                field: "TouchEvent.pointers",
                actual: pointers.len(),
                min: 1,
                max: MAX_TOUCH_POINTERS,
            });
        }
        if duration_ms == 0 || duration_ms > MAX_GESTURE_STEP_MS {
            return Err(ProtoError::BoundsViolation {
                field: "TouchEvent.duration_ms",
                actual: duration_ms as usize,
                min: 1,
                max: MAX_GESTURE_STEP_MS as usize,
            });
        }

        let mut seen_mask: u16 = 0;
        let mut active_found = false;
        for p in &pointers {
            let bit = 1u16 << p.pointer_id();
            if (seen_mask & bit) != 0 {
                return Err(ProtoError::InvalidPointerSet {
                    pointer_id: p.pointer_id(),
                });
            }
            seen_mask |= bit;
            if p.pointer_id() == active_pointer_id {
                active_found = true;
            }
        }

        if !active_found {
            return Err(ProtoError::InvalidPointerSet {
                pointer_id: active_pointer_id,
            });
        }

        Ok(Self {
            action,
            active_pointer_id,
            duration_ms,
            pointers,
        })
    }

    /// Returns the gesture lifecycle [`TouchAction`].
    #[must_use]
    pub const fn action(&self) -> TouchAction {
        self.action
    }

    /// Returns the pointer ID that initiated this transition.
    #[must_use]
    pub const fn active_pointer_id(&self) -> u8 {
        self.active_pointer_id
    }

    /// Returns the stroke interpolation step duration in milliseconds (`1..=1000`).
    #[must_use]
    pub const fn duration_ms(&self) -> u16 {
        self.duration_ms
    }

    /// Borrows all active contact pointers (`1..=10`).
    #[must_use]
    pub fn pointers(&self) -> &[TouchPointer] {
        &self.pointers
    }
}

/// High-resolution desktop mouse-wheel / trackpad two-finger scroll event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScrollEvent {
    x: NormalizedCoord,
    y: NormalizedCoord,
    delta_x_ticks: i16,
    delta_y_ticks: i16,
}

impl ScrollEvent {
    /// Constructs a bounded scroll event (`|delta| <= 2400`, at least one non-zero axis).
    pub const fn new(
        x: NormalizedCoord,
        y: NormalizedCoord,
        delta_x_ticks: i16,
        delta_y_ticks: i16,
    ) -> Result<Self, ProtoError> {
        if delta_x_ticks == 0 && delta_y_ticks == 0 {
            return Err(ProtoError::BoundsViolation {
                field: "ScrollEvent.delta_ticks",
                actual: 0,
                min: 1,
                max: MAX_SCROLL_TICKS_ABS as usize,
            });
        }
        if delta_x_ticks < -MAX_SCROLL_TICKS_ABS || delta_x_ticks > MAX_SCROLL_TICKS_ABS {
            return Err(ProtoError::BoundsViolation {
                field: "ScrollEvent.delta_x_ticks",
                actual: delta_x_ticks.unsigned_abs() as usize,
                min: 0,
                max: MAX_SCROLL_TICKS_ABS as usize,
            });
        }
        if delta_y_ticks < -MAX_SCROLL_TICKS_ABS || delta_y_ticks > MAX_SCROLL_TICKS_ABS {
            return Err(ProtoError::BoundsViolation {
                field: "ScrollEvent.delta_y_ticks",
                actual: delta_y_ticks.unsigned_abs() as usize,
                min: 0,
                max: MAX_SCROLL_TICKS_ABS as usize,
            });
        }

        Ok(Self {
            x,
            y,
            delta_x_ticks,
            delta_y_ticks,
        })
    }

    /// Returns the normalized anchor horizontal coordinate.
    #[must_use]
    pub const fn x(self) -> NormalizedCoord {
        self.x
    }

    /// Returns the normalized anchor vertical coordinate.
    #[must_use]
    pub const fn y(self) -> NormalizedCoord {
        self.y
    }

    /// Returns signed horizontal scroll delta (`120` = one standard wheel detent).
    #[must_use]
    pub const fn delta_x_ticks(self) -> i16 {
        self.delta_x_ticks
    }

    /// Returns signed vertical scroll delta (`120` = one standard wheel detent).
    #[must_use]
    pub const fn delta_y_ticks(self) -> i16 {
        self.delta_y_ticks
    }
}

/// Key press or release transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeyAction {
    /// Physical key pressed.
    Down = 0x01,
    /// Physical key released.
    Up = 0x02,
}

impl KeyAction {
    /// Parses a wire `KeyAction` discriminant.
    pub const fn from_wire(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            0x01 => Ok(Self::Down),
            0x02 => Ok(Self::Up),
            other => Err(ProtoError::UnknownDiscriminant {
                field: "KeyAction",
                value: other,
            }),
        }
    }
}

/// Validated keyboard modifier bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyModifiers(u8);

impl KeyModifiers {
    /// No modifier keys active.
    pub const NONE: Self = Self(0x00);
    /// Shift modifier active.
    pub const SHIFT: Self = Self(0x01);
    /// Control modifier active.
    pub const CTRL: Self = Self(0x02);
    /// Alt / Option modifier active.
    pub const ALT: Self = Self(0x04);
    /// Super / Command / Windows modifier active.
    pub const META: Self = Self(0x08);
    /// Caps Lock latched.
    pub const CAPS_LOCK: Self = Self(0x10);

    const VALID_MASK: u8 = 0x1F;

    /// Parses a wire modifier byte, rejecting any set reserved upper bits (`0xE0`).
    pub const fn from_bits(raw: u8) -> Result<Self, ProtoError> {
        if (raw & !Self::VALID_MASK) != 0 {
            return Err(ProtoError::ReservedFlagsSet {
                field: "KeyModifiers",
                raw,
            });
        }
        Ok(Self(raw))
    }

    /// Returns the raw modifier byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Combines two modifier sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Bounded Android keycode event (`1..=512`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyEvent {
    action: KeyAction,
    android_keycode: u16,
    modifiers: KeyModifiers,
}

impl KeyEvent {
    /// Validates and constructs an Android key event.
    pub const fn new(
        action: KeyAction,
        android_keycode: u16,
        modifiers: KeyModifiers,
    ) -> Result<Self, ProtoError> {
        if android_keycode == 0 || android_keycode > MAX_ANDROID_KEYCODE {
            return Err(ProtoError::BoundsViolation {
                field: "KeyEvent.android_keycode",
                actual: android_keycode as usize,
                min: 1,
                max: MAX_ANDROID_KEYCODE as usize,
            });
        }
        Ok(Self {
            action,
            android_keycode,
            modifiers,
        })
    }

    /// Returns press/release [`KeyAction`].
    #[must_use]
    pub const fn action(self) -> KeyAction {
        self.action
    }

    /// Returns the `android.view.KeyEvent.KEYCODE_*` constant (`1..=512`).
    #[must_use]
    pub const fn android_keycode(self) -> u16 {
        self.android_keycode
    }

    /// Returns active [`KeyModifiers`].
    #[must_use]
    pub const fn modifiers(self) -> KeyModifiers {
        self.modifiers
    }
}

/// Non-root system navigation actions invoked via `AccessibilityService.performGlobalAction(int)`.
///
/// Works on retail Android 8.0–15+ without requiring privileged `INJECT_EVENTS` permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AndroidGlobalAction {
    /// Navigate Back (`GLOBAL_ACTION_BACK = 1`, e.g., Desktop right-click).
    Back = 0x01,
    /// Navigate Home (`GLOBAL_ACTION_HOME = 2`, e.g., Desktop middle-click).
    Home = 0x02,
    /// Open Overview / Recents (`GLOBAL_ACTION_RECENTS = 3`).
    Recents = 0x03,
    /// Expand Notification Shade (`GLOBAL_ACTION_NOTIFICATIONS = 4`).
    Notifications = 0x04,
    /// Expand Quick Settings (`GLOBAL_ACTION_QUICK_SETTINGS = 5`).
    QuickSettings = 0x05,
    /// Lock Device Screen (`GLOBAL_ACTION_LOCK_SCREEN = 8`, requires Android 9 / API 28+).
    LockScreen = 0x06,
    /// Trigger System Screenshot (`GLOBAL_ACTION_TAKE_SCREENSHOT = 9`, requires Android 9 / API 28+).
    TakeScreenshot = 0x07,
}

impl AndroidGlobalAction {
    /// Parses a wire `AndroidGlobalAction` discriminant.
    pub const fn from_wire(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            0x01 => Ok(Self::Back),
            0x02 => Ok(Self::Home),
            0x03 => Ok(Self::Recents),
            0x04 => Ok(Self::Notifications),
            0x05 => Ok(Self::QuickSettings),
            0x06 => Ok(Self::LockScreen),
            0x07 => Ok(Self::TakeScreenshot),
            other => Err(ProtoError::UnknownDiscriminant {
                field: "AndroidGlobalAction",
                value: other,
            }),
        }
    }

    /// Maps onto the exact `android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_*` SDK integer.
    #[must_use]
    pub const fn android_sdk_action_id(self) -> i32 {
        match self {
            Self::Back => 1,
            Self::Home => 2,
            Self::Recents => 3,
            Self::Notifications => 4,
            Self::QuickSettings => 5,
            Self::LockScreen => 8,
            Self::TakeScreenshot => 9,
        }
    }

    /// Returns the minimum Android SDK level required to execute this global action.
    #[must_use]
    pub const fn min_android_sdk(self) -> u8 {
        match self {
            Self::Back
            | Self::Home
            | Self::Recents
            | Self::Notifications
            | Self::QuickSettings => 26,
            Self::LockScreen | Self::TakeScreenshot => 28,
        }
    }
}

/// Unified controller input event carried inside [`crate::proto::ControlMessage::Input`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputEvent {
    /// Single- or multi-touch gesture stroke batch.
    Touch(TouchEvent),
    /// Smooth mouse-wheel / trackpad scroll vector.
    Scroll(ScrollEvent),
    /// Physical keyboard key transition.
    Key(KeyEvent),
    /// System-level Android navigation action (`Back`, `Home`, `Recents`, etc.).
    GlobalAction(AndroidGlobalAction),
    /// Validated, NUL-free Unicode text injection (`1..=4096` UTF-8 bytes) for focused input fields.
    TextInject(String),
}

impl InputEvent {
    /// Constructs a validated [`InputEvent::TextInject`], rejecting empty strings, payloads
    /// exceeding `4 KiB`, or strings containing embedded `\0` bytes.
    pub fn text_inject(text: impl Into<String>) -> Result<Self, ProtoError> {
        let s = text.into();
        validate_clean_text("InputEvent.TextInject", &s, 1, MAX_TEXT_INJECT_BYTES)?;
        Ok(Self::TextInject(s))
    }
}

pub(crate) fn validate_clean_text(
    field: &'static str,
    s: &str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<(), ProtoError> {
    if s.len() < min_bytes || s.len() > max_bytes {
        return Err(ProtoError::BoundsViolation {
            field,
            actual: s.len(),
            min: min_bytes,
            max: max_bytes,
        });
    }
    if s.as_bytes().contains(&0) {
        return Err(ProtoError::InvalidUtf8Text);
    }
    Ok(())
}
