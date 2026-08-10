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

//! Scripted-transport tests for the change and unblock flows through the
//! public, scheme-resolving entry points.

use refineid_apdu::{
    CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
    TransportOutcome,
};
use refineid_auth::{
    ManageOutcome, PIN1_REFERENCE, PIN1_REFERENCE_ORGANIZATIONAL, PUK_REFERENCE_ORGANIZATIONAL,
    Pin1, PinManageOps, Puk, UnvalidatedSecret,
};

/// Wire index of the P2 reference byte.
const P2_INDEX: usize = 3;
/// A retry count returned on a wrong credential.
const TWO_RETRIES: u8 = 2;
/// Commands the organizational unblock sends: a VERIFY then a RESET.
const ORG_UNBLOCK_COMMAND_COUNT: usize = 2;

fn response(sw: StatusWord) -> ResponseApdu {
    let [sw1, sw2] = sw.as_u16().to_be_bytes();
    ResponseApdu {
        body: vec![],
        sw1,
        sw2,
    }
}

fn pin1(digits: &[u8]) -> Pin1 {
    Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(digits.to_vec()))
        .expect("valid PIN1 fixture")
}

fn puk(digits: &[u8]) -> Puk {
    Puk::reconstruct(UnvalidatedSecret::from_owned_bytes(digits.to_vec()))
        .expect("valid PUK fixture")
}

/// A transport that answers the counter-safe resolution probe by P2 --
/// so a session resolves its numbering -- then records the credential
/// commands it is handed and answers each from a scripted queue.
struct ResolvingRecorder {
    citizen_probe: StatusWord,
    organizational_probe: StatusWord,
    responses: Vec<StatusWord>,
    cursor: usize,
    commands: Vec<Vec<u8>>,
}

impl CardTransport for ResolvingRecorder {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let reference = command.as_bytes().get(P2_INDEX).copied();
        let sw = if reference == Some(PIN1_REFERENCE) {
            self.citizen_probe
        } else {
            self.organizational_probe
        };
        Ok(TransportOutcome::Response(response(sw)))
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        self.commands.push(command.expose_wire(<[u8]>::to_vec));
        let sw = *self
            .responses
            .get(self.cursor)
            .ok_or_else(|| format!("script exhausted at command {}", self.cursor))?;
        self.cursor += 1;
        Ok(TransportOutcome::Response(response(sw)))
    }
}

#[test]
fn change_pin1_resolves_the_citizen_numbering_then_updates() {
    // The citizen probe answers a real state, so resolution settles on
    // the citizen numbering without a second probe.
    let mut transport = ResolvingRecorder {
        citizen_probe: StatusWord::Success,
        organizational_probe: StatusWord::ReferenceDataNotFound,
        responses: vec![StatusWord::Success],
        cursor: 0,
        commands: vec![],
    };
    let outcome = transport
        .change_pin1(pin1(b"1234"), pin1(b"5678"))
        .expect("scripted change succeeds");
    assert_eq!(outcome, ManageOutcome::Ok);
    assert_eq!(transport.commands.len(), 1);
    assert_eq!(
        transport.commands[0].get(P2_INDEX).copied(),
        Some(PIN1_REFERENCE)
    );
}

#[test]
fn unblock_pin1_resolves_organizational_then_sends_the_two_command_flow() {
    // The citizen probe answers reference-not-found, so resolution
    // re-probes and settles on the organizational numbering.
    let two = PinRetries::from_nibble(TWO_RETRIES).expect("fits a nibble");
    let mut transport = ResolvingRecorder {
        citizen_probe: StatusWord::ReferenceDataNotFound,
        organizational_probe: StatusWord::PinIncorrect { retries: two },
        responses: vec![StatusWord::Success, StatusWord::Success],
        cursor: 0,
        commands: vec![],
    };
    let outcome = transport
        .unblock_pin1(puk(b"12345678"), pin1(b"5678"))
        .expect("scripted unblock succeeds");
    assert_eq!(outcome, ManageOutcome::Ok);
    assert_eq!(transport.commands.len(), ORG_UNBLOCK_COMMAND_COUNT);
    // First the PUK is verified under the organizational PUK reference,
    // then the reset targets the organizational PIN1 reference.
    assert_eq!(
        transport.commands[0].get(P2_INDEX).copied(),
        Some(PUK_REFERENCE_ORGANIZATIONAL)
    );
    assert_eq!(
        transport.commands[1].get(P2_INDEX).copied(),
        Some(PIN1_REFERENCE_ORGANIZATIONAL)
    );
}
