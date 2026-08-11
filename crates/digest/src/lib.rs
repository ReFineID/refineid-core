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

//! Typed SHA-2 digest values and hash-algorithm identifiers.
//!
//! A host that computes a digest and ships it to a card needs three small
//! things from a shared crate rather than a vendored copy: a value type
//! that names the algorithm it carries, a hash-algorithm identifier it can
//! parse from a platform-supplied string, and the digest lengths as named
//! constants. This crate provides exactly that and nothing more -- it holds
//! no key and performs no card I/O.
//!
//! [`Sha256`] and [`Sha384`] are fixed-length newtypes over the `sha2`
//! crate's one-shot digest. Carrying the algorithm in the type keeps a raw
//! byte array from standing in for a computed digest, and keeps a SHA-256
//! value from being handed where a SHA-384 value is expected. [`HashAlg`]
//! names the SHA-1/SHA-2 family for callers that receive the algorithm as a
//! string and need its digest length. The digest bytes themselves are not
//! hand-rolled: `of` delegates to the `sha2` crate; the wrapper adds only
//! the name and the length contract.

use sha2::Digest as _;

/// SHA-1 digest length in bytes (FIPS 180-4 section 1: a 160-bit digest).
pub const SHA1_LEN: usize = 20;
/// SHA-256 digest length in bytes (FIPS 180-4 section 1: a 256-bit digest).
pub const SHA256_LEN: usize = 32;
/// SHA-384 digest length in bytes (FIPS 180-4 section 1: a 384-bit digest).
pub const SHA384_LEN: usize = 48;
/// SHA-512 digest length in bytes (FIPS 180-4 section 1: a 512-bit digest).
pub const SHA512_LEN: usize = 64;

/// A SHA-256 digest value.
///
/// Exactly [`SHA256_LEN`] bytes, bound to the algorithm by its type so it
/// cannot be confused with a raw array or with a SHA-384 value. The field
/// is private: a value exists only through [`Sha256::of`] (a live digest)
/// or [`Sha256::from_bytes`] (a caller-asserted precomputed digest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256([u8; SHA256_LEN]);

impl Sha256 {
    /// Compute the SHA-256 digest of `data` with the `sha2` crate.
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        let out = sha2::Sha256::digest(data);
        let mut bytes = [0_u8; SHA256_LEN];
        bytes.copy_from_slice(&out);
        Self(bytes)
    }

    /// Wrap a precomputed SHA-256 digest.
    ///
    /// The caller asserts the bytes are a SHA-256 digest; the constructor
    /// cannot verify that without the original message.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SHA256_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_LEN] {
        &self.0
    }

    /// Consume the value and return the owned digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; SHA256_LEN] {
        self.0
    }
}

/// A SHA-384 digest value.
///
/// Exactly [`SHA384_LEN`] bytes, bound to the algorithm by its type so it
/// cannot be confused with a raw array or with a SHA-256 value. The field
/// is private: a value exists only through [`Sha384::of`] (a live digest)
/// or [`Sha384::from_bytes`] (a caller-asserted precomputed digest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha384([u8; SHA384_LEN]);

impl Sha384 {
    /// Compute the SHA-384 digest of `data` with the `sha2` crate.
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        let out = sha2::Sha384::digest(data);
        let mut bytes = [0_u8; SHA384_LEN];
        bytes.copy_from_slice(&out);
        Self(bytes)
    }

    /// Wrap a precomputed SHA-384 digest.
    ///
    /// The caller asserts the bytes are a SHA-384 digest; the constructor
    /// cannot verify that without the original message.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SHA384_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA384_LEN] {
        &self.0
    }

    /// Consume the value and return the owned digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; SHA384_LEN] {
        self.0
    }
}

/// A SHA-1/SHA-2 hash-algorithm identifier.
///
/// Parsed from a platform-supplied name and used to size or select a
/// digest. The variant set matches the SHA-1/SHA-2 family named across the
/// FINEID signing profiles for host-computed digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-1 (FIPS 180-4).
    Sha1,
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SHA-384 (FIPS 180-4).
    Sha384,
    /// SHA-512 (FIPS 180-4).
    Sha512,
}

impl HashAlg {
    /// The digest output length in bytes for this algorithm.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => SHA1_LEN,
            Self::Sha256 => SHA256_LEN,
            Self::Sha384 => SHA384_LEN,
            Self::Sha512 => SHA512_LEN,
        }
    }
}

/// A hash-algorithm name that [`HashAlg`] does not recognize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownHashAlg;

impl core::fmt::Display for UnknownHashAlg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("unknown hash algorithm name")
    }
}

impl core::error::Error for UnknownHashAlg {}

impl TryFrom<&str> for HashAlg {
    type Error = UnknownHashAlg;

    /// Parse a hash-algorithm name.
    ///
    /// Accepts `SHA1`, `SHA256`, `SHA384`, and `SHA512` in any letter case.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownHashAlg`] when `name` is not one of the recognized
    /// algorithms.
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        if name.eq_ignore_ascii_case("SHA1") {
            Ok(Self::Sha1)
        } else if name.eq_ignore_ascii_case("SHA256") {
            Ok(Self::Sha256)
        } else if name.eq_ignore_ascii_case("SHA384") {
            Ok(Self::Sha384)
        } else if name.eq_ignore_ascii_case("SHA512") {
            Ok(Self::Sha512)
        } else {
            Err(UnknownHashAlg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HashAlg, SHA1_LEN, SHA256_LEN, SHA384_LEN, SHA512_LEN, Sha256, Sha384, UnknownHashAlg,
    };

    /// SHA-256 of the ASCII message "abc" (FIPS 180-4 known-answer test).
    const SHA256_ABC: [u8; SHA256_LEN] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    /// SHA-256 of the empty message (FIPS 180-4 known-answer test).
    const SHA256_EMPTY: [u8; SHA256_LEN] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    /// SHA-384 of the ASCII message "abc" (FIPS 180-4 known-answer test).
    const SHA384_ABC: [u8; SHA384_LEN] = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50,
        0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff,
        0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34,
        0xc8, 0x25, 0xa7,
    ];

    #[test]
    fn sha256_of_abc_matches_fips_known_answer() {
        assert_eq!(Sha256::of(b"abc").as_bytes(), &SHA256_ABC);
    }

    #[test]
    fn sha256_of_empty_matches_fips_known_answer() {
        assert_eq!(Sha256::of(b"").as_bytes(), &SHA256_EMPTY);
    }

    #[test]
    fn sha384_of_abc_matches_fips_known_answer() {
        assert_eq!(Sha384::of(b"abc").as_bytes(), &SHA384_ABC);
    }

    #[test]
    fn sha256_from_bytes_round_trips_through_accessors() {
        let value = Sha256::from_bytes(SHA256_ABC);
        assert_eq!(value.as_bytes(), &SHA256_ABC);
        assert_eq!(value.into_bytes(), SHA256_ABC);
    }

    #[test]
    fn sha384_from_bytes_round_trips_through_accessors() {
        let value = Sha384::from_bytes(SHA384_ABC);
        assert_eq!(value.as_bytes(), &SHA384_ABC);
        assert_eq!(value.into_bytes(), SHA384_ABC);
    }

    #[test]
    fn digest_equality_is_by_value() {
        assert_eq!(Sha256::of(b"abc"), Sha256::of(b"abc"));
        let different_inputs_differ = Sha256::of(b"abc") != Sha256::of(b"abcd");
        assert!(different_inputs_differ);
    }

    #[test]
    fn hash_alg_parses_names_case_insensitively() {
        assert_eq!(HashAlg::try_from("SHA1"), Ok(HashAlg::Sha1));
        assert_eq!(HashAlg::try_from("sha256"), Ok(HashAlg::Sha256));
        assert_eq!(HashAlg::try_from("Sha384"), Ok(HashAlg::Sha384));
        assert_eq!(HashAlg::try_from("SHA512"), Ok(HashAlg::Sha512));
    }

    #[test]
    fn hash_alg_rejects_unknown_names() {
        assert_eq!(HashAlg::try_from("MD5"), Err(UnknownHashAlg));
    }

    #[test]
    fn hash_alg_digest_len_matches_named_constants() {
        assert_eq!(HashAlg::Sha1.digest_len(), SHA1_LEN);
        assert_eq!(HashAlg::Sha256.digest_len(), SHA256_LEN);
        assert_eq!(HashAlg::Sha384.digest_len(), SHA384_LEN);
        assert_eq!(HashAlg::Sha512.digest_len(), SHA512_LEN);
    }
}
