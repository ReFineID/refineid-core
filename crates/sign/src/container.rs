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

//! Algorithm-typed signature bytes and the decipher containers.
//!
//! Binding a signature to the scheme that produced it keeps an RSA
//! signature from being handed where an ECDSA one is expected, and vice
//! versa. The card returns raw bytes; the constructor checks the length
//! the algorithm fixes, so a `Signature<Alg>` that exists is exactly
//! `Alg`'s width and downstream never re-measures it.

use core::marker::PhantomData;

use zeroize::ZeroizeOnDrop;

use crate::{ECDSA_P256_SIG_BYTES, ECDSA_P384_SIG_BYTES, RSA_3072_MODULUS_BYTES};

/// RSASSA-PKCS1-v1_5 over SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPkcs1Sha256;

/// RSASSA-PKCS1-v1_5 over SHA-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPkcs1Sha384;

/// RSASSA-PSS over SHA-256. The card performs the PSS encoding and the
/// private-key operation from the host-supplied digest; the salt is the
/// card's, so two signatures over the same digest differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPssSha256;

/// ECDSA over NIST P-384 (secp384r1), raw `r || s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaP384;

/// ECDSA over NIST P-256 (secp256r1), raw `r || s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaP256;

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::RsaPkcs1Sha256 {}
    impl Sealed for super::RsaPkcs1Sha384 {}
    impl Sealed for super::RsaPssSha256 {}
    impl Sealed for super::EcdsaP384 {}
    impl Sealed for super::EcdsaP256 {}
}

/// An algorithm marker whose signature length is fixed at design time.
///
/// ECDSA widths follow from the curve. The RSA widths are modulus-wide
/// and this crate commits to RSA-3072, the only RSA size behind the two
/// key references [`crate::KeyRef`] names; a card exposing a different
/// modulus here would first need the commitment generalised.
pub trait SignatureLength: sealed::Sealed {
    /// The signature length the algorithm fixes, in bytes.
    const SIG_BYTES: usize;
}

impl SignatureLength for RsaPkcs1Sha256 {
    const SIG_BYTES: usize = RSA_3072_MODULUS_BYTES;
}

impl SignatureLength for RsaPkcs1Sha384 {
    const SIG_BYTES: usize = RSA_3072_MODULUS_BYTES;
}

impl SignatureLength for RsaPssSha256 {
    const SIG_BYTES: usize = RSA_3072_MODULUS_BYTES;
}

impl SignatureLength for EcdsaP384 {
    const SIG_BYTES: usize = ECDSA_P384_SIG_BYTES;
}

impl SignatureLength for EcdsaP256 {
    const SIG_BYTES: usize = ECDSA_P256_SIG_BYTES;
}

/// The card returned signature bytes of the wrong length for the
/// selected algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureLengthError {
    /// The length the card returned.
    pub got: usize,
    /// The length the algorithm fixes.
    pub expected: usize,
}

impl core::fmt::Display for SignatureLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "signature is {} bytes, the algorithm fixes {}",
            self.got, self.expected
        )
    }
}

impl core::error::Error for SignatureLengthError {}

/// Signature bytes bound to the algorithm that produced them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature<Alg> {
    bytes: Vec<u8>,
    algorithm: PhantomData<fn() -> Alg>,
}

impl<Alg: SignatureLength> Signature<Alg> {
    /// Wrap card-returned signature bytes, checking the length the
    /// algorithm fixes.
    ///
    /// # Errors
    ///
    /// [`SignatureLengthError`] when the length is not
    /// [`SignatureLength::SIG_BYTES`] for `Alg`.
    pub fn from_card_bytes(bytes: Vec<u8>) -> Result<Self, SignatureLengthError> {
        if bytes.len() != Alg::SIG_BYTES {
            return Err(SignatureLengthError {
                got: bytes.len(),
                expected: Alg::SIG_BYTES,
            });
        }
        Ok(Self {
            bytes,
            algorithm: PhantomData,
        })
    }
}

impl<Alg> Signature<Alg> {
    /// Borrow the signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume into the owned signature bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Signature length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the signature is empty; never true for a constructed
    /// signature, kept for the accessor pair.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The cryptogram is not exactly one RSA-3072 modulus-wide block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptogramLengthError {
    /// The length that was offered.
    pub got: usize,
    /// The modulus width the decipher key fixes.
    pub expected: usize,
}

impl core::fmt::Display for CryptogramLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "cryptogram is {} bytes, the modulus is {} wide",
            self.got, self.expected
        )
    }
}

impl core::error::Error for CryptogramLengthError {}

/// An RSA cryptogram for PSO:DECIPHER: exactly one modulus-wide block.
///
/// The padding scheme inside the block is named by the algorithm
/// reference at the decipher call, not recoverable from the bytes, so
/// the type carries the one predicate the border can check -- the
/// RSA-3072 modulus width this crate commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaCryptogram {
    bytes: Vec<u8>,
}

impl RsaCryptogram {
    /// Wrap an encrypted block, checking the modulus width.
    ///
    /// # Errors
    ///
    /// [`CryptogramLengthError`] when the length is not
    /// [`RSA_3072_MODULUS_BYTES`].
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptogramLengthError> {
        if bytes.len() != RSA_3072_MODULUS_BYTES {
            return Err(CryptogramLengthError {
                got: bytes.len(),
                expected: RSA_3072_MODULUS_BYTES,
            });
        }
        Ok(Self { bytes })
    }

    /// Borrow the cryptogram bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Plaintext recovered by PSO:DECIPHER.
///
/// The recovered content is the secret the whole decipher exists to
/// deliver, so the container zeroises its storage on drop and its
/// `Debug` shows only the length -- the same custody the transport
/// applies to the response body that carried it.
#[derive(ZeroizeOnDrop)]
pub struct RecoveredPlaintext {
    bytes: Vec<u8>,
}

impl RecoveredPlaintext {
    /// Wrap the card-recovered plaintext; only the decipher chain
    /// produces one.
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the recovered plaintext.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Plaintext length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the card returned no plaintext.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl core::fmt::Debug for RecoveredPlaintext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveredPlaintext")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EcdsaP384, RSA_3072_MODULUS_BYTES, RecoveredPlaintext, RsaCryptogram, RsaPssSha256,
        Signature, SignatureLength as _,
    };
    use crate::ECDSA_P384_SIG_BYTES;

    /// Arbitrary fill byte for synthetic card bytes.
    const SAMPLE_BYTE: u8 = 0xAB;

    #[test]
    fn a_signature_of_the_fixed_length_constructs() {
        let bytes = vec![SAMPLE_BYTE; ECDSA_P384_SIG_BYTES];
        let signature =
            Signature::<EcdsaP384>::from_card_bytes(bytes.clone()).expect("exact length");
        assert_eq!(signature.len(), EcdsaP384::SIG_BYTES);
        assert!(!signature.is_empty());
        assert_eq!(signature.as_bytes(), bytes.as_slice());
        assert_eq!(signature.into_bytes(), bytes);
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_rejected() {
        // An RSA-wide buffer offered as a P-384 signature.
        let error =
            Signature::<EcdsaP384>::from_card_bytes(vec![SAMPLE_BYTE; RSA_3072_MODULUS_BYTES])
                .expect_err("wrong length");
        assert_eq!(error.got, RSA_3072_MODULUS_BYTES);
        assert_eq!(error.expected, ECDSA_P384_SIG_BYTES);
    }

    #[test]
    fn an_empty_signature_is_rejected() {
        let error = Signature::<RsaPssSha256>::from_card_bytes(Vec::new()).expect_err("empty");
        assert_eq!(error.got, 0);
        assert_eq!(error.expected, RSA_3072_MODULUS_BYTES);
    }

    #[test]
    fn a_modulus_wide_cryptogram_constructs() {
        let bytes = vec![SAMPLE_BYTE; RSA_3072_MODULUS_BYTES];
        let cryptogram = RsaCryptogram::from_bytes(bytes.clone()).expect("modulus-wide");
        assert_eq!(cryptogram.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn a_short_cryptogram_is_rejected() {
        let error =
            RsaCryptogram::from_bytes(vec![SAMPLE_BYTE; ECDSA_P384_SIG_BYTES]).expect_err("short");
        assert_eq!(error.got, ECDSA_P384_SIG_BYTES);
        assert_eq!(error.expected, RSA_3072_MODULUS_BYTES);
    }

    #[test]
    fn recovered_plaintext_debug_shows_only_the_length() {
        let plaintext = RecoveredPlaintext::new(vec![SAMPLE_BYTE; ECDSA_P384_SIG_BYTES]);
        let rendered = format!("{plaintext:?}");
        assert!(rendered.contains("len"));
        let fill = format!("{SAMPLE_BYTE}");
        assert!(!rendered.contains(&fill), "no byte values in Debug");
    }
}
