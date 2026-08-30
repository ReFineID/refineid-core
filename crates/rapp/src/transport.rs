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

use std::collections::BTreeMap;

use super::{MAX_FRAME_SIZE, WireValue};

/// Invalid bounded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// A transport attempted to allocate or deliver an oversized frame.
    Oversized {
        /// Received byte count.
        got: usize,
        /// Protocol maximum.
        maximum: usize,
    },
}

/// One bounded RAPP transport frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryFrame(Vec<u8>);

impl BinaryFrame {
    /// Validate and take ownership of frame bytes.
    ///
    /// # Errors
    /// [`FrameError::Oversized`] when the bytes exceed the frame limit.
    pub fn reconstruct(bytes: Vec<u8>) -> Result<Self, FrameError> {
        if bytes.len() > MAX_FRAME_SIZE {
            return Err(FrameError::Oversized {
                got: bytes.len(),
                maximum: MAX_FRAME_SIZE,
            });
        }
        Ok(Self(bytes))
    }

    /// Borrow frame bytes for one transport or cryptographic operation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the frame into its allocation.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Transport candidate advertised in a pairing offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportCandidate {
    /// Registered transport profile.
    pub profile: String,
    /// Candidate identifier echoed after authentication.
    pub candidate_id: String,
    /// Profile-specific public parameters included in deterministic CBOR.
    pub parameters: BTreeMap<String, WireValue>,
}

/// Reliable ordered binary-frame channel required by RAPP Core.
///
/// Transport authentication is never treated as RAPP identity. Every
/// implementation still runs the required Noise handshake over this channel.
pub trait FrameTransport {
    /// Adapter-specific failure type. It must not contain credential values.
    type Error;

    /// Candidate identifier known to both endpoints after establishment.
    fn candidate_id(&self) -> &str;

    /// Send exactly one bounded frame.
    ///
    /// # Errors
    /// The adapter-specific transport failure.
    fn send(&mut self, frame: BinaryFrame) -> Result<(), Self::Error>;

    /// Receive exactly one bounded frame, or `None` for EOF.
    ///
    /// # Errors
    /// The adapter-specific transport failure.
    fn receive(&mut self) -> Result<Option<BinaryFrame>, Self::Error>;

    /// Close and cancel pending transport work.
    ///
    /// # Errors
    /// The adapter-specific transport failure.
    fn close(&mut self) -> Result<(), Self::Error>;
}
