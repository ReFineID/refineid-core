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

//! The single operating-system random-number seam for this crate.
//!
//! Every random draw goes through here so the fail-closed policy lives
//! in one place: a failed operating-system generator is always a hard
//! error the caller propagates, never silently degraded into a weakened
//! mode. A dead generator means no cryptographic operation on the host
//! can be trusted, so aborting the operation is the only safe response.

/// The operating-system random-number generator was unavailable.
pub type Failure = getrandom::Error;

/// Fill the buffer with operating-system random bytes, or fail.
///
/// # Errors
///
/// Returns [`Failure`] when the generator is unavailable. Propagate it;
/// never proceed with a partially filled buffer.
pub fn fill(buffer: &mut [u8]) -> Result<(), Failure> {
    getrandom::fill(buffer)
}
