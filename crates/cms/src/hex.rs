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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Const-eval hex decoding for specification constants.
//!
//! The "parse, don't validate" form for spec constants (FIPS 186-4
//! curve parameters, NIST known-answer vectors): a mistyped digit or a
//! length mismatch fails compilation, so no runtime path ever sees a
//! malformed constant.

/// Nibble value of the first alphabetic hex digit (`A` or `a`).
const HEX_ALPHA_OFFSET: u8 = 10;
/// Hex digits per encoded byte.
const HEX_DIGITS_PER_BYTE: usize = 2;
/// Bit width of one hex digit.
const NIBBLE_SHIFT: u32 = 4;

/// Hex decode namespace.
///
/// All entry points are associated functions on this unit struct so
/// callers read as `Hex::decode_const(digits)`. The unit struct exists
/// only to host the methods inside an `impl` block (typing-discipline:
/// no free fns with borrowed parameters).
#[derive(Debug, Clone, Copy)]
pub struct Hex;

impl Hex {
    /// Decode one ASCII hex digit at const-eval time.
    ///
    /// The assert is the validation: every caller is a const item, so
    /// a non-hex digit fails the build instead of ever reaching a
    /// citizen.
    const fn nibble(digit: u8) -> u8 {
        assert!(
            digit.is_ascii_hexdigit(),
            "hex constant contains a non-hex digit"
        );
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'A'..=b'F' => digit - b'A' + HEX_ALPHA_OFFSET,
            _ => digit - b'a' + HEX_ALPHA_OFFSET,
        }
    }

    /// Decode a hex string literal into a fixed-size byte array at
    /// const-eval time.
    ///
    /// The length assert bounds every index and product below, and
    /// every caller is a const item, so any slip is a compile error
    /// rather than a runtime panic.
    pub(crate) const fn decode_const<const N: usize>(hex_digits: &str) -> [u8; N] {
        let src = hex_digits.as_bytes();
        assert!(
            src.len() == HEX_DIGITS_PER_BYTE * N,
            "hex constant length does not match the declared byte width"
        );
        let mut out = [0_u8; N];
        let mut i = 0;
        while i < N {
            let high = Self::nibble(src[HEX_DIGITS_PER_BYTE * i]);
            let low = Self::nibble(src[HEX_DIGITS_PER_BYTE * i + 1]);
            out[i] = (high << NIBBLE_SHIFT) | low;
            i += 1;
        }
        out
    }
}
