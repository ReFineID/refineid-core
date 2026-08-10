// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Refined Card Access Number input.
//!
//! A CAN is printed on the card, but it is sensitive access data because it
//! enables PACE access to the chip. Consuming construction checks the value
//! once; downstream code receives only the opaque, zeroizing [`Can`] type.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of ASCII digits in a FINEID Card Access Number.
///
/// ICAO Doc 9303 Part 5 section 3.2.3 specifies a six-digit numeric CAN.
pub const CAN_DIGITS: usize = 6;

/// Explicitly unvalidated, owned CAN text at an input boundary.
///
/// The wrapper must be created immediately after secure UI or terminal input.
/// It owns and zeroizes the original allocation on every exit path.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnvalidatedCan {
    text: String,
}

impl UnvalidatedCan {
    /// Take ownership of text read from an input surface.
    #[must_use]
    pub fn from_owned_text(text: String) -> Self {
        Self { text }
    }
}

impl fmt::Debug for UnvalidatedCan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnvalidatedCan([redacted])")
    }
}

/// A validated, opaque FINEID Card Access Number.
///
/// The type is deliberately non-clonable, non-copyable, zeroizing, and has no
/// public raw-value accessor. A future PACE command constructor will consume
/// it through a crate-private path.
#[derive(ZeroizeOnDrop)]
pub struct Can([u8; CAN_DIGITS]);

impl fmt::Debug for Can {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Can([redacted])")
    }
}

/// Structural reason that candidate CAN input was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanError {
    /// No bytes were supplied.
    Empty,
    /// The candidate did not contain exactly [`CAN_DIGITS`] bytes.
    WrongLength {
        /// Candidate length in bytes.
        got: usize,
    },
    /// The candidate contained a non-ASCII-digit byte.
    NonDigit {
        /// Zero-based offset of the rejected byte.
        at: usize,
    },
}

impl Can {
    /// Consume unvalidated input and reconstruct it as a [`Can`].
    ///
    /// # Errors
    ///
    /// Returns [`CanError`] for empty, wrong-length, or non-digit input.
    pub fn reconstruct(input: UnvalidatedCan) -> Result<Self, CanError> {
        let bytes = input.text.as_bytes();
        if bytes.is_empty() {
            return Err(CanError::Empty);
        }
        if bytes.len() != CAN_DIGITS {
            return Err(CanError::WrongLength { got: bytes.len() });
        }
        if let Some(at) = bytes.iter().position(|byte| !byte.is_ascii_digit()) {
            return Err(CanError::NonDigit { at });
        }

        let mut reconstructed = [0_u8; CAN_DIGITS];
        reconstructed.copy_from_slice(bytes);
        Ok(Self(reconstructed))
    }

    /// Number of validated CAN digits.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        CAN_DIGITS
    }

    /// Borrow the validated digits for the PACE key-derivation step.
    ///
    /// This is the crate-private path the handshake consumes the CAN
    /// through: the value never leaves this crate as raw bytes, and no
    /// public `as_bytes` accessor exists.
    pub(crate) const fn password_bytes(&self) -> &[u8; CAN_DIGITS] {
        &self.0
    }
}

impl fmt::Display for CanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("CAN cannot be empty"),
            Self::WrongLength { got } => {
                write!(f, "CAN must contain exactly {CAN_DIGITS} digits, got {got}")
            }
            Self::NonDigit { at } => {
                write!(f, "CAN must contain ASCII digits; non-digit at offset {at}")
            }
        }
    }
}

impl core::error::Error for CanError {}

#[cfg(test)]
mod tests {
    use super::{CAN_DIGITS, Can, CanError, UnvalidatedCan};

    const SHORT_CAN_DIGITS: usize = CAN_DIGITS - 1;
    const LONG_CAN_DIGITS: usize = CAN_DIGITS + 1;
    const NON_DIGIT_OFFSET: usize = 2;

    fn input(text: &str) -> UnvalidatedCan {
        UnvalidatedCan::from_owned_text(text.to_owned())
    }

    #[test]
    fn valid_input_is_reconstructed_once() {
        let can = Can::reconstruct(input("123456")).expect("fixture is a valid CAN");
        assert_eq!(can.digit_count(), CAN_DIGITS);
        assert_eq!(can.0, *b"123456");
    }

    #[test]
    fn structural_failures_are_typed() {
        assert!(matches!(Can::reconstruct(input("")), Err(CanError::Empty)));
        assert!(matches!(
            Can::reconstruct(input("12345")),
            Err(CanError::WrongLength {
                got: SHORT_CAN_DIGITS
            })
        ));
        assert!(matches!(
            Can::reconstruct(input("1234567")),
            Err(CanError::WrongLength {
                got: LONG_CAN_DIGITS
            })
        ));
        assert!(matches!(
            Can::reconstruct(input("12a456")),
            Err(CanError::NonDigit {
                at: NON_DIGIT_OFFSET
            })
        ));
    }

    #[test]
    fn every_six_digit_value_is_structurally_valid() {
        for text in ["000000", "000001", "100000", "012300", "010101"] {
            assert!(
                Can::reconstruct(input(text)).is_ok(),
                "{text} should be accepted"
            );
        }
    }

    #[test]
    fn debug_is_always_redacted() {
        let raw = input("123456");
        assert_eq!(format!("{raw:?}"), "UnvalidatedCan([redacted])");

        let can = Can::reconstruct(input("123456")).expect("fixture is a valid CAN");
        assert_eq!(format!("{can:?}"), "Can([redacted])");
    }
}
