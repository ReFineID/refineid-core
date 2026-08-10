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

//! Scripted-transport tests for the signing choreography.

use refineid_apdu::{
    CardTransport, CommandApdu, CredentialCommand, ResponseApdu, StatusWord, TransportOutcome,
};
use refineid_sign::commands::{SHA256_LEN, SHA384_LEN};
use refineid_sign::{ECDSA_P384_SIG_BYTES, KeyRef, RSA_3072_SIG_BYTES, SignError, SignOps};

/// Digest filler byte for the fixtures.
const DIGEST_FILL: u8 = 0x5A;
/// Signature filler byte for the fixtures.
const SIG_FILL: u8 = 0xC3;

/// Expected MSE:Set AT wire for the RSA auth key.
const EXPECTED_MSE_AT: &[u8] = &[
    0x00, 0x22, 0x41, 0xA4, 0x06, 0x80, 0x01, 0x42, 0x84, 0x01, 0x01,
];
/// Expected MSE:Set DST wire for the ECDSA signature key.
const EXPECTED_MSE_DST: &[u8] = &[
    0x00, 0x22, 0x41, 0xB6, 0x06, 0x80, 0x01, 0x54, 0x84, 0x01, 0x02,
];
/// Expected PSO:HASH prefix for a SHA-256 digest (before the digest
/// bytes): header, Lc, then the hash-value tag and length.
const EXPECTED_PSO_HASH_SHA256: &[u8] = &[0x00, 0x2A, 0x90, 0xA0, 0x22, 0x90, 0x20];
/// Expected PSO:HASH prefix for a SHA-384 digest.
const EXPECTED_PSO_HASH_SHA384: &[u8] = &[0x00, 0x2A, 0x90, 0xA0, 0x32, 0x90, 0x30];
/// Expected PSO:CDS wire.
const EXPECTED_PSO_CDS: &[u8] = &[0x00, 0x2A, 0x9E, 0x9A, 0x00];

fn success(body: Vec<u8>) -> ResponseApdu {
    let [sw1, sw2] = StatusWord::Success.as_u16().to_be_bytes();
    ResponseApdu { body, sw1, sw2 }
}

/// A transport that checks each command against a scripted expectation
/// and returns the paired response.
struct Scripted {
    steps: Vec<(Vec<u8>, ResponseApdu)>,
    cursor: usize,
}

impl Scripted {
    fn new(steps: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
        Self { steps, cursor: 0 }
    }

    fn drained(&self) -> bool {
        self.cursor == self.steps.len()
    }
}

impl CardTransport for Scripted {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let (expected, response) = self
            .steps
            .get(self.cursor)
            .ok_or_else(|| format!("script exhausted at step {}", self.cursor))?;
        if expected != command.as_bytes() {
            return Err(format!("unexpected command at step {}", self.cursor));
        }
        self.cursor += 1;
        Ok(TransportOutcome::Response(response.clone()))
    }

    fn transmit_credential(
        &mut self,
        _command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        Err("signing issues no credential command".to_owned())
    }
}

fn sha256_hash_wire(digest: &[u8]) -> Vec<u8> {
    let mut wire = EXPECTED_PSO_HASH_SHA256.to_vec();
    wire.extend_from_slice(digest);
    wire
}

#[test]
fn rsa_sha256_drives_the_three_command_chain() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (EXPECTED_MSE_AT.to_vec(), success(vec![])),
        (sha256_hash_wire(&digest), success(vec![])),
        (EXPECTED_PSO_CDS.to_vec(), success(signature.clone())),
    ]);

    let result = transport
        .sign_prehashed_sha256_rsa(KeyRef::Auth, digest)
        .expect("scripted RSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert_eq!(result.len(), RSA_3072_SIG_BYTES);
    assert!(transport.drained());
}

#[test]
fn ecdsa_p384_uses_the_dst_template_and_raw_signature() {
    let digest = [DIGEST_FILL; SHA384_LEN];
    let signature = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let mut hash_wire = EXPECTED_PSO_HASH_SHA384.to_vec();
    hash_wire.extend_from_slice(&digest);
    let mut transport = Scripted::new(vec![
        (EXPECTED_MSE_DST.to_vec(), success(vec![])),
        (hash_wire, success(vec![])),
        (EXPECTED_PSO_CDS.to_vec(), success(signature.clone())),
    ]);

    let result = transport
        .sign_prehashed_sha384_ecdsa(KeyRef::Sign, digest)
        .expect("scripted ECDSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert!(transport.drained());
}

#[test]
fn an_unexpected_signature_length_is_rejected() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    // The card returns a short signature: an RSA key that is not
    // RSA-3072, or a misconfiguration.
    let short = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (EXPECTED_MSE_AT.to_vec(), success(vec![])),
        (sha256_hash_wire(&digest), success(vec![])),
        (EXPECTED_PSO_CDS.to_vec(), success(short)),
    ]);

    let error = transport
        .sign_prehashed_sha256_rsa(KeyRef::Auth, digest)
        .expect_err("a short signature is rejected");
    assert!(matches!(
        error,
        SignError::UnexpectedSignatureLength {
            got: ECDSA_P384_SIG_BYTES,
            expected: RSA_3072_SIG_BYTES,
        }
    ));
}

#[test]
fn a_status_word_failure_names_the_stage() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let [sw1, sw2] = StatusWord::SecurityNotSatisfied.as_u16().to_be_bytes();
    let rejected = ResponseApdu {
        body: vec![],
        sw1,
        sw2,
    };
    let mut transport = Scripted::new(vec![(EXPECTED_MSE_AT.to_vec(), rejected)]);

    let error = transport
        .sign_prehashed_sha256_rsa(KeyRef::Auth, digest)
        .expect_err("a rejected MSE fails");
    assert!(matches!(
        error,
        SignError::Status("MSE:Set", StatusWord::SecurityNotSatisfied)
    ));
}
