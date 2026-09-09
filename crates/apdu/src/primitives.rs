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

//! Shared APDU primitives used across protocol crates.
//!
//! Every byte sequence crossing the card boundary gets a typed container
//! that names its role and validates its constraints at construction.
//! Encoding into the wire byte stream happens at each typed command's
//! serialisation boundary; this module is the type layer, not the encoder.

use core::fmt;

/// ISO 7816-4 application identifier.
///
/// Per ISO 7816-5 an AID is five to sixteen bytes. SELECT-by-AID commands
/// pass the AID in the data field; this type captures the length
/// constraint at construction so a malformed AID never reaches the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aid {
    /// AID bytes; the constructor guarantees the ISO 7816-5 length range.
    bytes: Vec<u8>,
}

/// Error returned by [`Aid::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AidError {
    /// The candidate length is outside the ISO 7816-5 range.
    LengthOutOfRange {
        /// Length of the rejected input in bytes.
        got: usize,
    },
}

impl Aid {
    /// Minimum AID length in bytes, per ISO 7816-5.
    pub const MIN_LENGTH: usize = 5;
    /// Maximum AID length in bytes, per ISO 7816-5.
    pub const MAX_LENGTH: usize = 16;

    /// Construct from a byte vector, validating the ISO 7816-5 length
    /// range.
    ///
    /// # Errors
    ///
    /// [`AidError::LengthOutOfRange`] when the length is outside
    /// [`Aid::MIN_LENGTH`] through [`Aid::MAX_LENGTH`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, AidError> {
        if bytes.len() < Self::MIN_LENGTH || bytes.len() > Self::MAX_LENGTH {
            return Err(AidError::LengthOutOfRange { got: bytes.len() });
        }
        Ok(Self { bytes })
    }

    /// Construct from a borrowed slice; copies into an owned buffer.
    ///
    /// # Errors
    ///
    /// See [`Aid::new`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AidError> {
        Self::new(bytes.to_vec())
    }

    /// Borrow the underlying AID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the AID in bytes; within the ISO 7816-5 range by
    /// constructor invariant.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `false` by constructor invariant; retained for idiomatic pairing
    /// with [`Aid::len`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Display for Aid {
    /// Render as colon-grouped uppercase hexadecimal for diagnostics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for byte in &self.bytes {
            if first {
                first = false;
            } else {
                f.write_str(":")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Display for AidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOutOfRange { got } => write!(
                f,
                "AID length {got} outside the ISO 7816-5 range of {min} to {max} bytes",
                min = Aid::MIN_LENGTH,
                max = Aid::MAX_LENGTH,
            ),
        }
    }
}

impl core::error::Error for AidError {}

/// ISO 7816-4 short file identifier.
///
/// A five-bit value from one to thirty, encoded into P1 of the SFI-form
/// READ BINARY with the selection flag set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sfi(u8);

/// Error returned by [`Sfi::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfiError {
    /// The value was zero or above [`Sfi::MAX`].
    OutOfRange {
        /// The rejected value.
        got: u8,
    },
}

impl Sfi {
    /// Largest short file identifier, per ISO 7816-4 section 5.3.1.1.
    pub const MAX: u8 = 30;
    /// P1 flag bit selecting SFI-form addressing in READ BINARY, per the
    /// FINEID S1 v4.2 section 3.4.2 coding table.
    const SHORT_FORM_FLAG: u8 = 0x80;

    /// Construct a validated short file identifier.
    ///
    /// # Errors
    ///
    /// [`SfiError::OutOfRange`] when the value is zero or above
    /// [`Sfi::MAX`].
    pub const fn new(value: u8) -> Result<Self, SfiError> {
        if value == 0 || value > Self::MAX {
            return Err(SfiError::OutOfRange { got: value });
        }
        Ok(Self(value))
    }

    /// Encode as the P1 byte of an SFI-form READ BINARY: the selection
    /// flag with the identifier in the low bits.
    #[must_use]
    pub const fn as_p1_short_form(self) -> u8 {
        Self::SHORT_FORM_FLAG | self.0
    }

    /// The raw identifier value; within range by constructor invariant.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl fmt::Display for Sfi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SFI {}", self.0)
    }
}

impl fmt::Display for SfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { got } => {
                write!(
                    f,
                    "SFI {got} outside the ISO 7816-4 range of 1 to {}",
                    Sfi::MAX
                )
            }
        }
    }
}

impl core::error::Error for SfiError {}

/// Two-byte ISO 7816-4 section 5.3.1.1 file identifier.
///
/// EF, DF, and MF identifiers are exactly two bytes on the wire; the
/// owned array carries the length contract at the type level. Well-known
/// identifiers belong to the protocol crate that reads the file; only the
/// Master File identifier is universal enough to live here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId([u8; FileId::LENGTH]);

impl FileId {
    /// Wire length of every file identifier, in bytes.
    pub const LENGTH: usize = 2;

    /// File identifier of the Master File, reserved by ISO 7816-4
    /// section 8.2.1.1.
    pub const MF: Self = Self::from_u16(0x3F00);

    /// Wrap the two wire bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Build a file identifier from the single 16-bit value it names, so a
    /// well-known identifier reads as the number the specification prints
    /// (for example the EF.4331 certificate file) rather than a pair of
    /// wire bytes. The value is stored big-endian, as it travels on the
    /// wire.
    #[must_use]
    pub const fn from_u16(id: u16) -> Self {
        Self(id.to_be_bytes())
    }

    /// Borrow the two wire bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Aid, AidError, FileId, Sfi, SfiError};

    /// Synthetic seven-byte AID for shape tests; the ASCII value has no
    /// protocol meaning, only a valid length.
    const TEST_AID: &[u8] = b"testaid";
    /// One byte below the minimum AID length.
    const TOO_SHORT_AID_LEN: usize = Aid::MIN_LENGTH - 1;
    /// One byte above the maximum AID length.
    const TOO_LONG_AID_LEN: usize = Aid::MAX_LENGTH + 1;
    /// Filler byte for generated length fixtures.
    const FILLER: u8 = 0x5A;

    #[test]
    fn aid_accepts_the_valid_length_range() -> Result<(), AidError> {
        let aid = Aid::from_slice(TEST_AID)?;
        assert_eq!(aid.len(), TEST_AID.len());
        assert!(!aid.is_empty());
        assert_eq!(aid.as_bytes(), TEST_AID);
        // The Display form is the AID bytes as colon-separated hex; here
        // the ASCII fixture `testaid` in its byte spelling.
        assert_eq!(format!("{aid}"), "74:65:73:74:61:69:64");

        assert!(Aid::new(vec![FILLER; Aid::MIN_LENGTH]).is_ok());
        assert!(Aid::new(vec![FILLER; Aid::MAX_LENGTH]).is_ok());
        Ok(())
    }

    #[test]
    fn aid_rejects_out_of_range_lengths() {
        assert!(matches!(
            Aid::new(vec![FILLER; TOO_SHORT_AID_LEN]),
            Err(AidError::LengthOutOfRange {
                got: TOO_SHORT_AID_LEN
            })
        ));
        assert!(matches!(
            Aid::new(vec![FILLER; TOO_LONG_AID_LEN]),
            Err(AidError::LengthOutOfRange {
                got: TOO_LONG_AID_LEN
            })
        ));
        assert!(matches!(
            Aid::new(vec![]),
            Err(AidError::LengthOutOfRange { got: 0 })
        ));
    }

    #[test]
    fn sfi_accepts_the_valid_range() -> Result<(), SfiError> {
        let lowest = Sfi::new(1)?;
        assert_eq!(lowest.value(), 1);
        assert_eq!(lowest.as_p1_short_form(), Sfi::SHORT_FORM_FLAG | 1);

        let highest = Sfi::new(Sfi::MAX)?;
        assert_eq!(highest.as_p1_short_form(), Sfi::SHORT_FORM_FLAG | Sfi::MAX);
        Ok(())
    }

    #[test]
    fn sfi_rejects_zero_and_overflow() {
        assert!(matches!(Sfi::new(0), Err(SfiError::OutOfRange { got: 0 })));
        const ABOVE_MAX: u8 = Sfi::MAX + 1;
        assert!(matches!(
            Sfi::new(ABOVE_MAX),
            Err(SfiError::OutOfRange { got: ABOVE_MAX })
        ));
    }

    #[test]
    fn file_id_round_trips_its_bytes() {
        let fid = FileId::new(*FileId::MF.as_bytes());
        assert_eq!(fid, FileId::MF);
        assert_eq!(fid.as_bytes().len(), FileId::LENGTH);
    }
}
