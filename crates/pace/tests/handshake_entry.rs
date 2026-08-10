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

//! Public-entry tests for the PACE handshake.
//!
//! The full four-round handshake and its live behaviour are validated on
//! hardware per the admission checklist; these tests drive the public
//! entry point through its first exchange and confirm the error surface,
//! which needs no card.

use refineid_apdu::{
    CardTransport, CommandApdu, CredentialCommand, ResponseApdu, StatusWord, TransportOutcome,
};
use refineid_pace::{Can, PaceError, UnvalidatedCan, run_pace_with_can};

/// A valid six-digit Card Access Number fixture.
const CAN_TEXT: &str = "123456";
/// Instruction byte the opening command carries.
const MSE_INS: u8 = 0x22;

fn fixture_can() -> Can {
    Can::reconstruct(UnvalidatedCan::from_owned_text(CAN_TEXT.to_owned()))
        .expect("fixture is a valid CAN")
}

/// A transport whose first response is a fixed outcome.
struct FirstExchange {
    outcome: Option<TransportOutcome>,
    saw_mse: bool,
}

impl CardTransport for FirstExchange {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        // The opening command is MSE:Set AT; record that it was issued.
        if command.as_bytes().get(1) == Some(&MSE_INS) {
            self.saw_mse = true;
        }
        self.outcome
            .take()
            .ok_or_else(|| "no further scripted outcome".to_owned())
    }

    fn transmit_credential(
        &mut self,
        _command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        Err("the handshake issues no credential command".to_owned())
    }
}

fn status_response(sw: StatusWord) -> TransportOutcome {
    let [sw1, sw2] = sw.as_u16().to_be_bytes();
    TransportOutcome::Response(ResponseApdu {
        body: vec![],
        sw1,
        sw2,
    })
}

#[test]
fn opening_status_word_failure_names_the_stage() {
    let mut transport = FirstExchange {
        outcome: Some(status_response(StatusWord::SecurityNotSatisfied)),
        saw_mse: false,
    };
    let error =
        run_pace_with_can(&mut transport, fixture_can()).expect_err("a rejected opening fails");
    assert!(transport.saw_mse, "the opening MSE:Set AT must be issued");
    assert!(matches!(
        error,
        PaceError::Status("MSE:Set AT", StatusWord::SecurityNotSatisfied)
    ));
}

#[test]
fn transport_state_transition_surfaces_as_an_outcome() {
    let mut transport = FirstExchange {
        outcome: Some(TransportOutcome::NoCard),
        saw_mse: false,
    };
    let error = run_pace_with_can(&mut transport, fixture_can()).expect_err("a lost card fails");
    assert!(matches!(
        error,
        PaceError::Outcome(TransportOutcome::NoCard)
    ));
}
