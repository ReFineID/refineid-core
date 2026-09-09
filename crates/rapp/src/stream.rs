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

//! The `fi.refineid.stream.v1` transport profile's protocol bytes.
//!
//! The stream profile (specification Section 16.1) carries RAPP frames over
//! one reliable ordered byte stream. The requester listens and the proxy
//! dials, for both pairing and sessions; Noise roles are unchanged. This
//! module owns the profile's two byte formats — the plaintext rendezvous
//! preamble and the offer candidate parameters — so that every platform
//! produces identical bytes. Socket I/O and the length-prefix framing live
//! in platform adapters, never here.

use std::collections::BTreeMap;

use super::{RendezvousToken, WireValue, decode_deterministic_cbor, encode_deterministic_cbor};

/// Registered transport profile name for the stream profile.
pub const STREAM_PROFILE: &str = "fi.refineid.stream.v1";

/// Domain string opening every stream rendezvous preamble.
const STREAM_RENDEZVOUS_DOMAIN: &str = "RAPP-stream-v1";

/// Preamble purpose naming a pairing attempt.
const PURPOSE_PAIRING: &str = "pairing";

/// Preamble purpose naming a session attempt for a stored pairing.
const PURPOSE_SESSION: &str = "session";

/// Upper bound on an encoded rendezvous preamble frame. The accepting
/// endpoint rejects a longer preamble before parsing it.
pub const MAX_STREAM_RENDEZVOUS_FRAME: usize = 64;

/// Candidate parameter key carrying the listener endpoint list.
const PARAMETER_ENDPOINTS: &str = "endpoints";

/// Maximum listener endpoints one stream candidate may carry.
pub const MAX_STREAM_ENDPOINTS: usize = 8;

/// Maximum UTF-8 bytes of one `host:port` endpoint literal.
pub const MAX_STREAM_ENDPOINT_BYTES: usize = 255;

/// One plaintext rendezvous preamble, the first frame the dialing proxy
/// sends on a fresh stream connection before any Noise message.
///
/// The preamble is unauthenticated routing metadata, exactly like a relay
/// token: it selects which handshake the accepting requester initiates and
/// enables nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRendezvous {
    /// Connect to the listener's currently active pairing offer.
    Pairing,
    /// Connect for a fresh session with the stored pairing this token names.
    Session(RendezvousToken),
}

impl StreamRendezvous {
    /// Encode the preamble frame payload.
    ///
    /// # Errors
    /// [`StreamError::Malformed`] when deterministic encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let (purpose, token_bytes) = match self {
            Self::Pairing => (PURPOSE_PAIRING, Vec::new()),
            Self::Session(token) => (PURPOSE_SESSION, token.as_bytes().to_vec()),
        };
        encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text(STREAM_RENDEZVOUS_DOMAIN.to_owned()),
            WireValue::Text(purpose.to_owned()),
            WireValue::Bytes(token_bytes),
        ]))
        .map_err(|_| StreamError::Malformed)
    }

    /// Decode and validate one received preamble frame payload.
    ///
    /// Every failure is pre-authentication invalid input (specification
    /// Section 14.5, class 1): the caller closes the connection and changes
    /// no stored state.
    ///
    /// # Errors
    /// [`StreamError`] on an oversized frame, a malformed preamble, or an
    /// unregistered purpose.
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_STREAM_RENDEZVOUS_FRAME {
            return Err(StreamError::Oversized);
        }
        let WireValue::Array(elements) =
            decode_deterministic_cbor(bytes).map_err(|_| StreamError::Malformed)?
        else {
            return Err(StreamError::Malformed);
        };
        let [
            WireValue::Text(domain),
            WireValue::Text(purpose),
            WireValue::Bytes(token_bytes),
        ] = elements.as_slice()
        else {
            return Err(StreamError::Malformed);
        };
        if domain != STREAM_RENDEZVOUS_DOMAIN {
            return Err(StreamError::Malformed);
        }
        match purpose.as_str() {
            PURPOSE_PAIRING => {
                if token_bytes.is_empty() {
                    Ok(Self::Pairing)
                } else {
                    Err(StreamError::Malformed)
                }
            }
            PURPOSE_SESSION => RendezvousToken::reconstruct(token_bytes)
                .map(Self::Session)
                .map_err(|_| StreamError::Malformed),
            _ => Err(StreamError::UnknownPurpose),
        }
    }
}

/// Validated `fi.refineid.stream.v1` candidate parameters from a pairing
/// offer: the requester's listener addresses as `host:port` literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCandidateParameters {
    endpoints: Vec<String>,
}

impl StreamCandidateParameters {
    /// Validate listener endpoint literals for placement in an offer.
    ///
    /// # Errors
    /// [`StreamError`] on an out-of-bounds endpoint count or literal length.
    pub fn new(endpoints: Vec<String>) -> Result<Self, StreamError> {
        if endpoints.is_empty() || endpoints.len() > MAX_STREAM_ENDPOINTS {
            return Err(StreamError::EndpointCount);
        }
        if endpoints
            .iter()
            .any(|endpoint| endpoint.is_empty() || endpoint.len() > MAX_STREAM_ENDPOINT_BYTES)
        {
            return Err(StreamError::EndpointLength);
        }
        Ok(Self { endpoints })
    }

    /// Listener addresses in the requester's stated preference order.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Candidate `parameters` map for the pairing offer.
    #[must_use]
    pub fn to_parameters(&self) -> BTreeMap<String, WireValue> {
        let endpoints = self
            .endpoints
            .iter()
            .map(|endpoint| WireValue::Text(endpoint.clone()))
            .collect();
        let mut parameters = BTreeMap::new();
        parameters.insert(PARAMETER_ENDPOINTS.to_owned(), WireValue::Array(endpoints));
        parameters
    }

    /// Reconstruct and validate parameters scanned from an offer or loaded
    /// from a stored pairing's transport binding.
    ///
    /// # Errors
    /// [`StreamError`] on unknown keys, wrong types, or out-of-bounds
    /// endpoints.
    pub fn from_parameters(parameters: &BTreeMap<String, WireValue>) -> Result<Self, StreamError> {
        if parameters.len() != 1 {
            return Err(StreamError::Malformed);
        }
        let Some(WireValue::Array(elements)) = parameters.get(PARAMETER_ENDPOINTS) else {
            return Err(StreamError::Malformed);
        };
        let endpoints = elements
            .iter()
            .map(|element| match element {
                WireValue::Text(endpoint) => Ok(endpoint.clone()),
                _ => Err(StreamError::Malformed),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(endpoints)
    }
}

/// Rejected stream-profile bytes or parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// Structure, domain, type, or token length was not exactly as specified.
    Malformed,
    /// Preamble frame exceeded [`MAX_STREAM_RENDEZVOUS_FRAME`].
    Oversized,
    /// Purpose string is not registered; the connection closes unanswered.
    UnknownPurpose,
    /// Candidate carried no endpoint or more than [`MAX_STREAM_ENDPOINTS`].
    EndpointCount,
    /// An endpoint literal was empty or exceeded [`MAX_STREAM_ENDPOINT_BYTES`].
    EndpointLength,
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for StreamError {}

#[cfg(test)]
mod tests {
    use super::super::RENDEZVOUS_TOKEN_SIZE;
    use super::*;

    fn token() -> RendezvousToken {
        RendezvousToken::from_array([0x5a; RENDEZVOUS_TOKEN_SIZE])
    }

    #[test]
    fn pairing_preamble_round_trips() {
        let encoded = StreamRendezvous::Pairing.encode().expect("encode");
        assert!(encoded.len() <= MAX_STREAM_RENDEZVOUS_FRAME);
        assert_eq!(
            StreamRendezvous::decode(&encoded).expect("decode"),
            StreamRendezvous::Pairing
        );
    }

    #[test]
    fn session_preamble_round_trips() {
        let encoded = StreamRendezvous::Session(token()).encode().expect("encode");
        assert!(encoded.len() <= MAX_STREAM_RENDEZVOUS_FRAME);
        assert_eq!(
            StreamRendezvous::decode(&encoded).expect("decode"),
            StreamRendezvous::Session(token())
        );
    }

    #[test]
    fn pairing_preamble_with_token_bytes_is_rejected() {
        let encoded = encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text(STREAM_RENDEZVOUS_DOMAIN.to_owned()),
            WireValue::Text(PURPOSE_PAIRING.to_owned()),
            WireValue::Bytes(vec![0x01]),
        ]))
        .expect("encode");
        assert_eq!(
            StreamRendezvous::decode(&encoded),
            Err(StreamError::Malformed)
        );
    }

    #[test]
    fn session_preamble_with_short_token_is_rejected() {
        let encoded = encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text(STREAM_RENDEZVOUS_DOMAIN.to_owned()),
            WireValue::Text(PURPOSE_SESSION.to_owned()),
            WireValue::Bytes(vec![0x01; RENDEZVOUS_TOKEN_SIZE - 1]),
        ]))
        .expect("encode");
        assert_eq!(
            StreamRendezvous::decode(&encoded),
            Err(StreamError::Malformed)
        );
    }

    #[test]
    fn unknown_purpose_is_its_own_rejection() {
        let encoded = encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text(STREAM_RENDEZVOUS_DOMAIN.to_owned()),
            WireValue::Text("resume".to_owned()),
            WireValue::Bytes(Vec::new()),
        ]))
        .expect("encode");
        assert_eq!(
            StreamRendezvous::decode(&encoded),
            Err(StreamError::UnknownPurpose)
        );
    }

    #[test]
    fn wrong_domain_is_rejected() {
        let encoded = encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text("RAPP-relay-v1".to_owned()),
            WireValue::Text(PURPOSE_PAIRING.to_owned()),
            WireValue::Bytes(Vec::new()),
        ]))
        .expect("encode");
        assert_eq!(
            StreamRendezvous::decode(&encoded),
            Err(StreamError::Malformed)
        );
    }

    #[test]
    fn oversized_preamble_is_rejected_before_parsing() {
        let oversized = vec![0_u8; MAX_STREAM_RENDEZVOUS_FRAME + 1];
        assert_eq!(
            StreamRendezvous::decode(&oversized),
            Err(StreamError::Oversized)
        );
    }

    #[test]
    fn candidate_parameters_round_trip() {
        let parameters = StreamCandidateParameters::new(vec![
            "192.0.2.10:47110".to_owned(),
            "[2001:db8::10]:47110".to_owned(),
        ])
        .expect("candidate");
        let map = parameters.to_parameters();
        assert_eq!(
            StreamCandidateParameters::from_parameters(&map).expect("reconstruct"),
            parameters
        );
    }

    #[test]
    fn candidate_parameters_reject_unknown_keys() {
        let parameters =
            StreamCandidateParameters::new(vec!["192.0.2.10:47110".to_owned()]).expect("candidate");
        let mut map = parameters.to_parameters();
        map.insert("relay".to_owned(), WireValue::Null);
        assert_eq!(
            StreamCandidateParameters::from_parameters(&map),
            Err(StreamError::Malformed)
        );
    }

    #[test]
    fn candidate_parameters_bound_endpoint_count() {
        let endpoints = vec!["192.0.2.10:47110".to_owned(); MAX_STREAM_ENDPOINTS + 1];
        assert_eq!(
            StreamCandidateParameters::new(endpoints),
            Err(StreamError::EndpointCount)
        );
    }
}
