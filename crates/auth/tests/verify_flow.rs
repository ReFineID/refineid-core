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

//! Scripted-transport tests for the VERIFY flow.

use refineid_apdu::{
    CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
    TransportOutcome,
};
use refineid_auth::{
    PIN1_REFERENCE, PIN2_REFERENCE, Pin1, Pin2, PinOps, PinSlot, PinStatus, UnvalidatedSecret,
    VerifyOutcome,
};

/// A valid PIN1 fixture.
const PIN1_DIGITS: &[u8] = b"1234";
/// A valid PIN2 fixture.
const PIN2_DIGITS: &[u8] = b"654321";
/// The expected VERIFY PIN1 wire: header, Lc, then the padded block.
const EXPECTED_VERIFY_PIN1: &[u8] = &[
    0x00, 0x20, 0x00, 0x11, 0x0C, b'1', b'2', b'3', b'4', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,
];
/// The expected counter-safe PIN1 status probe wire: header only.
const EXPECTED_STATUS_PROBE: &[u8] = &[0x00, 0x20, 0x00, 0x11];
/// A retry count returned on a wrong PIN.
const TWO_RETRIES: u8 = 2;
/// Wire index of the P2 reference byte.
const P2_INDEX: usize = 3;

fn pin1() -> Pin1 {
    Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(PIN1_DIGITS.to_vec()))
        .expect("valid PIN1 fixture")
}

fn pin2() -> Pin2 {
    Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(PIN2_DIGITS.to_vec()))
        .expect("valid PIN2 fixture")
}

fn response(sw: StatusWord) -> ResponseApdu {
    let [sw1, sw2] = sw.as_u16().to_be_bytes();
    ResponseApdu {
        body: vec![],
        sw1,
        sw2,
    }
}

/// A transport that records what it was handed and answers with a fixed
/// status word. A credential command's wire is captured through the
/// consuming exposure so the test can assert the exact bytes.
struct Recorder {
    plain_wire: Option<Vec<u8>>,
    credential_wire: Option<Vec<u8>>,
    sw: StatusWord,
}

impl Recorder {
    fn new(sw: StatusWord) -> Self {
        Self {
            plain_wire: None,
            credential_wire: None,
            sw,
        }
    }
}

impl CardTransport for Recorder {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        self.plain_wire = Some(command.as_bytes().to_vec());
        Ok(TransportOutcome::Response(response(self.sw)))
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        self.credential_wire = Some(command.expose_wire(<[u8]>::to_vec));
        Ok(TransportOutcome::Response(response(self.sw)))
    }
}

#[test]
fn verify_pin1_ships_the_padded_block_as_a_credential_command() {
    let mut transport = Recorder::new(StatusWord::Success);
    let outcome = transport
        .verify_pin1(pin1())
        .expect("scripted verify succeeds");
    assert_eq!(outcome, VerifyOutcome::Ok);
    assert_eq!(
        transport.credential_wire.as_deref(),
        Some(EXPECTED_VERIFY_PIN1),
        "the PIN must travel only through the credential path"
    );
    assert!(
        transport.plain_wire.is_none(),
        "a VERIFY must not use the plain transmit path"
    );
}

#[test]
fn verify_pin2_targets_the_qualified_signature_reference() {
    let mut transport = Recorder::new(StatusWord::Success);
    transport
        .verify_pin2(pin2())
        .expect("scripted verify succeeds");
    let wire = transport
        .credential_wire
        .expect("credential command was sent");
    assert_eq!(wire.get(P2_INDEX).copied(), Some(PIN2_REFERENCE));
    let distinct_references = PIN2_REFERENCE != PIN1_REFERENCE;
    assert!(distinct_references);
}

#[test]
fn a_wrong_pin_reports_the_remaining_retries() {
    let two = PinRetries::from_nibble(TWO_RETRIES).expect("fits a nibble");
    let mut transport = Recorder::new(StatusWord::PinIncorrect { retries: two });
    let outcome = transport
        .verify_pin1(pin1())
        .expect("scripted verify completes");
    assert_eq!(outcome, VerifyOutcome::WrongPin { retries_left: two });
}

#[test]
fn a_blocked_slot_reports_locked() {
    let mut transport = Recorder::new(StatusWord::AuthenticationBlocked);
    let outcome = transport
        .verify_pin1(pin1())
        .expect("scripted verify completes");
    assert_eq!(outcome, VerifyOutcome::Locked);
}

#[test]
fn the_status_probe_uses_the_plain_path_and_sends_no_data() {
    let mut transport = Recorder::new(StatusWord::Success);
    let status = transport
        .pin_status(PinSlot::Pin1)
        .expect("scripted probe succeeds");
    assert_eq!(status, PinStatus::Verified);
    assert_eq!(transport.plain_wire.as_deref(), Some(EXPECTED_STATUS_PROBE));
    assert!(
        transport.credential_wire.is_none(),
        "the counter-safe probe carries no credential"
    );
}
