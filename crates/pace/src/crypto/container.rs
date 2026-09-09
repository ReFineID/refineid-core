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

//! Algorithm-typed byte containers.
//!
//! Binding ciphertext and message-authentication bytes to the algorithm
//! that produced them makes a cross-algorithm mix a compile error: a
//! CBC ciphertext cannot be handed to a routine expecting some other
//! mode, and a truncated CMAC tag cannot stand in for a full one.

use core::marker::PhantomData;

/// Marker for AES-CBC ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesCbc;

/// Marker for an AES-CMAC tag truncated to the secure-messaging length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmacAesTruncated;

/// Ciphertext bytes bound to the cipher that produced them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext<Alg> {
    bytes: Vec<u8>,
    algorithm: PhantomData<fn() -> Alg>,
}

impl<Alg> Ciphertext<Alg> {
    /// Wrap ciphertext bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            algorithm: PhantomData,
        }
    }

    /// Borrow the ciphertext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Message-authentication bytes bound to the algorithm that produced
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mac<Alg> {
    bytes: Vec<u8>,
    algorithm: PhantomData<fn() -> Alg>,
}

impl<Alg> Mac<Alg> {
    /// Wrap message-authentication bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            algorithm: PhantomData,
        }
    }

    /// Borrow the message-authentication bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
