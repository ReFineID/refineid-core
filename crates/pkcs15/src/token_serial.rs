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

//! Typed chip-serial forms.
//!
//! Three string-shaped identifiers name the same physical card for
//! different audiences and must never cross-substitute: the full
//! chip-side [`TokenSerial`] from EF.TokenInfo, the plastic-printed
//! [`PrintedSerial`] a cardholder can read and quote, and the X.509
//! certificate serial, which is out of this crate's scope.

use core::fmt;
use core::ops::Deref;

/// Hex characters produced per input byte.
const HEX_CHARS_PER_BYTE: usize = 2;
/// Bits in one hex nibble.
const NIBBLE_BITS: u32 = 4;
/// Mask selecting the low nibble of a byte.
const LOW_NIBBLE_MASK: u8 = 0x0F;
/// Value offset of the letter hex digits.
const HEX_LETTER_VALUE_OFFSET: u8 = 10;
/// Distinct hex digits.
const HEX_ALPHABET_LEN: usize = 16;
/// Lowercase hex digit alphabet, indexed by nibble value.
const HEX_DIGITS: &[u8; HEX_ALPHABET_LEN] = b"0123456789abcdef";

/// First printable ASCII byte.
const PRINTABLE_ASCII_MIN: u8 = 0x20;
/// Last printable ASCII byte.
const PRINTABLE_ASCII_MAX: u8 = 0x7E;

/// Characters printed on the plastic, for both card generations.
const PRINTED_SERIAL_CHARS: usize = 9;
/// Full serial length on the older card generation: a twenty-digit
/// decimal string.
const OLDER_FULL_SERIAL_CHARS: usize = 20;
/// Start of the printed window inside the older generation's full
/// serial, after its series and batch prefix.
const OLDER_PRINTED_START: usize = 10;

/// Full chip-side card identifier.
///
/// Derived from the PKCS#15 EF.TokenInfo serial-number octet string via
/// [`render_token_serial`]. The format varies by chip generation, but
/// the value is stable per physical card and serves as the session
/// identity binding for trust-gated flows: read at session open,
/// re-read before a modifying command, compare for equality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSerial(String);

impl TokenSerial {
    /// Wrap an already-rendered token serial. No structural check; the
    /// format varies per chip generation.
    #[must_use]
    pub const fn new(serial: String) -> Self {
        Self(serial)
    }

    /// Borrow the underlying serial string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decode this serial as ASCII hex bytes.
    fn decoded_hex_bytes(&self) -> Option<Vec<u8>> {
        let text = self.as_str();
        if !text.len().is_multiple_of(HEX_CHARS_PER_BYTE) {
            return None;
        }
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(text.len().div_euclid(HEX_CHARS_PER_BYTE));
        for pair in bytes.chunks_exact(HEX_CHARS_PER_BYTE) {
            let &[hi_char, lo_char] = pair else {
                return None;
            };
            let hi = nybble(hi_char)?;
            let lo = nybble(lo_char)?;
            out.push(hi.wrapping_shl(NIBBLE_BITS) | lo);
        }
        Some(out)
    }
}

impl AsRef<str> for TokenSerial {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TokenSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for TokenSerial {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for TokenSerial {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Plastic-printed card identifier.
///
/// Derived from a [`TokenSerial`] by per-generation truncation in
/// [`derive_printed_serial`]: what a cardholder reads off the plastic
/// and can cross-reference. Never carries the full chip serial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrintedSerial(String);

impl PrintedSerial {
    /// Wrap an already-derived printed serial.
    #[must_use]
    pub const fn new(serial: String) -> Self {
        Self(serial)
    }

    /// Borrow the underlying serial string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for PrintedSerial {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PrintedSerial {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrintedSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Encode bytes as a lowercase hex string.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(HEX_CHARS_PER_BYTE));
    for byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> NIBBLE_BITS)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & LOW_NIBBLE_MASK)]));
    }
    out
}

/// Convert an EF.TokenInfo serial hex string to its most readable
/// stable form.
///
/// Newer chips store the serial as printable ASCII, so the hex decodes
/// to a readable string; older chips use binary-coded digits whose hex
/// form is all-decimal but does not decode to printable ASCII, and the
/// hex string is kept for those. Both forms are stable per card.
#[must_use]
pub fn render_token_serial(hex_token: TokenSerial) -> TokenSerial {
    if let Some(bytes) = hex_token.decoded_hex_bytes()
        && !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| (PRINTABLE_ASCII_MIN..=PRINTABLE_ASCII_MAX).contains(&b))
        && let Ok(text) = core::str::from_utf8(&bytes)
    {
        return TokenSerial::new(text.to_owned());
    }
    hex_token
}

/// Derive the plastic-printed serial from the full chip serial.
///
/// The truncation rule varies per chip generation, and each generation
/// has a recognisable surface shape:
///
/// - newer cards render to printable ASCII with alphabetic characters;
///   the printed form is the last nine characters;
/// - older cards keep a twenty-character all-decimal string; the
///   printed form is the nine-character window after the ten-character
///   series and batch prefix.
///
/// Returns `None` when the input matches neither shape, so callers omit
/// the serial rather than emit a misleading partial one.
#[must_use]
pub fn derive_printed_serial(full: &TokenSerial) -> Option<PrintedSerial> {
    let text = full.as_str();
    let bytes = text.as_bytes();
    if !text.is_ascii() {
        return None;
    }
    if bytes.iter().any(u8::is_ascii_alphabetic) {
        let tail_start = bytes.len().checked_sub(PRINTED_SERIAL_CHARS)?;
        let tail = text.get(tail_start..)?;
        Some(PrintedSerial::new(tail.to_owned()))
    } else if bytes.len() == OLDER_FULL_SERIAL_CHARS && bytes.iter().all(u8::is_ascii_digit) {
        let window = text.get(OLDER_PRINTED_START..OLDER_PRINTED_START + PRINTED_SERIAL_CHARS)?;
        Some(PrintedSerial::new(window.to_owned()))
    } else {
        None
    }
}

/// Decode one ASCII hex digit.
const fn nybble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(
            byte.wrapping_sub(b'a')
                .wrapping_add(HEX_LETTER_VALUE_OFFSET),
        ),
        b'A'..=b'F' => Some(
            byte.wrapping_sub(b'A')
                .wrapping_add(HEX_LETTER_VALUE_OFFSET),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OLDER_FULL_SERIAL_CHARS, PRINTED_SERIAL_CHARS, TokenSerial, derive_printed_serial,
        hex_encode, render_token_serial,
    };

    /// Synthetic newer-generation serial: printable ASCII with
    /// alphabetic characters, series and batch prefix, nine-character
    /// printed tail.
    const NEWER_SERIAL_TEXT: &str = "DEMO0001AB1234567";
    /// Printed tail of [`NEWER_SERIAL_TEXT`].
    const NEWER_PRINTED_TAIL: &str = "AB1234567";
    /// Synthetic older-generation serial: twenty decimal characters.
    const OLDER_SERIAL_TEXT: &str = "01234567890123456789";
    /// Printed window of [`OLDER_SERIAL_TEXT`]: the nine characters
    /// after the ten-character prefix.
    const OLDER_PRINTED_WINDOW: &str = "012345678";

    fn hex_of(text: &str) -> TokenSerial {
        TokenSerial::new(hex_encode(text.as_bytes()))
    }

    #[test]
    fn newer_serial_renders_to_ascii() {
        let rendered = render_token_serial(hex_of(NEWER_SERIAL_TEXT));
        assert_eq!(rendered, NEWER_SERIAL_TEXT);
    }

    #[test]
    fn non_printable_bytes_keep_the_hex_form() {
        let bytes = [u8::MAX, 0, u8::MAX, 0];
        let hex = TokenSerial::new(hex_encode(&bytes));
        let expected = hex.as_str().to_owned();
        let rendered = render_token_serial(hex);
        assert_eq!(rendered.as_str(), expected);
    }

    #[test]
    fn odd_length_hex_keeps_the_original() {
        let odd = TokenSerial::new("abc".to_owned());
        let rendered = render_token_serial(odd);
        assert_eq!(rendered, "abc");
    }

    #[test]
    fn newer_shape_derives_the_printed_tail() {
        let full = TokenSerial::new(NEWER_SERIAL_TEXT.to_owned());
        let printed = derive_printed_serial(&full).expect("newer shape derives");
        assert_eq!(printed.as_str(), NEWER_PRINTED_TAIL);
        assert_eq!(printed.as_str().len(), PRINTED_SERIAL_CHARS);
    }

    #[test]
    fn older_shape_derives_the_printed_window() {
        let full = TokenSerial::new(OLDER_SERIAL_TEXT.to_owned());
        assert_eq!(full.as_str().len(), OLDER_FULL_SERIAL_CHARS);
        let printed = derive_printed_serial(&full).expect("older shape derives");
        assert_eq!(printed.as_str(), OLDER_PRINTED_WINDOW);
    }

    #[test]
    fn unrecognised_shapes_derive_nothing() {
        /// A non-ASCII code point exercising the ASCII guard.
        const NON_ASCII_CODEPOINT: u32 = 0x00E4;
        let non_ascii_char = char::from_u32(NON_ASCII_CODEPOINT).expect("valid code point");
        let mut non_ascii = String::new();
        non_ascii.push(non_ascii_char);
        non_ascii.push_str("A12345678");

        for text in ["", "12345", "abc", non_ascii.as_str()] {
            let full = TokenSerial::new(text.to_owned());
            assert!(
                derive_printed_serial(&full).is_none(),
                "shape {text:?} must not derive a printed serial"
            );
        }
    }

    #[test]
    fn hex_round_trips_through_decode() {
        let text = "A1c2";
        let serial = TokenSerial::new(hex_encode(text.as_bytes()));
        let rendered = render_token_serial(serial);
        assert_eq!(rendered, text);
    }
}
