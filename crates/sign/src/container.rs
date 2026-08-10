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

//! Algorithm-typed signature bytes.
//!
//! Binding a signature to the scheme that produced it keeps an RSA
//! signature from being handed where an ECDSA one is expected, and vice
//! versa. The card returns raw bytes; the type parameter records what
//! the selected security environment computed.

use core::marker::PhantomData;

/// RSASSA-PKCS1-v1_5 over SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPkcs1Sha256;

/// RSASSA-PSS over SHA-256. The card performs the PSS encoding and the
/// private-key operation from the host-supplied digest; the salt is the
/// card's, so two signatures over the same digest differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPssSha256;

/// A raw RSASSA-PKCS1 private-key operation with no hash indicated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPkcs1;

/// ECDSA over NIST P-384 (secp384r1), raw `r || s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaP384;

/// ECDSA over NIST P-256 (secp256r1), raw `r || s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaP256;

/// Signature bytes bound to the algorithm that produced them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature<Alg> {
    bytes: Vec<u8>,
    algorithm: PhantomData<fn() -> Alg>,
}

impl<Alg> Signature<Alg> {
    /// Wrap raw signature bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            algorithm: PhantomData,
        }
    }

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

    /// `true` when the signature is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
