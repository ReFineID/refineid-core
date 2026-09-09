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

//! Strict-DER CMS `SignedData` parsing and offline signature verification.
//!
//! The host-side trust checks for card-delivered documents: an eMRTD
//! `EF.SOD` security object, its Document Signer Certificate, and the
//! chain hop to an externally trusted CSCA anchor. Parsing is strict
//! DER over [`refineid_ber`]; signature verification is implemented
//! here over [`crypto_bigint`] with no platform crypto dependency, so
//! every platform verifies bytes identically.
//!
//! The card is trusted to deliver its own certificates -- the Document
//! Signer Certificate always comes from the CMS `certificates` field --
//! but never to vouch for itself: the CSCA trust anchor must always
//! come from the verifier.

pub mod container;
pub mod ecdsa;
mod hex;
pub mod oid;
pub mod rsa;
pub mod signed_data;
pub mod x509;
