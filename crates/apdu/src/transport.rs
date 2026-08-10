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

//! Card transport port.
//!
//! [`CardTransport`] is the boundary between the protocol layer and the
//! actual card-access mechanism (PC/SC, NFC, USB CCID, embedded HAL).
//! Adapters live in their own crates so the protocol layer stays unaware
//! of where the bytes are going. The port carries only typed commands:
//! there is no byte-slice transmit, so a builder-granted permission such
//! as the single wrong-Le correction survives to the adapter, and a
//! credential command cannot be smuggled through a generic path.

use crate::command::{CommandApdu, CredentialCommand};
use crate::status_word::StatusWord;

/// One card response: body plus the two status bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseApdu {
    /// Response data body, excluding SW1 and SW2. Empty for status-only
    /// responses.
    pub body: Vec<u8>,
    /// First status byte, per ISO 7816-4 section 5.1.3.
    pub sw1: u8,
    /// Second status byte, per ISO 7816-4 section 5.1.3.
    pub sw2: u8,
}

impl ResponseApdu {
    /// The status bytes combined into their sixteen-bit value. Prefer
    /// [`ResponseApdu::status_word`] for typed matching; the raw value is
    /// kept available for diagnostics.
    #[must_use]
    pub const fn sw(&self) -> u16 {
        u16::from_be_bytes([self.sw1, self.sw2])
    }

    /// Decoded status word. This is the canonical accessor; consumers
    /// match on the typed enum rather than compare raw bytes.
    #[must_use]
    pub const fn status_word(&self) -> StatusWord {
        StatusWord::from_bytes(self.sw1, self.sw2)
    }

    /// `true` iff the status word is the success code.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.status_word().is_success()
    }
}

/// Transport-level state transitions and faults that matter above the
/// pure byte-moving layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportOutcome {
    /// A real APDU response; the pipeline matches on its status word and
    /// continues.
    Response(ResponseApdu),
    /// Card slot was sensed empty during the exchange.
    NoCard,
    /// Transport timed out with the card in an unknown state; the
    /// response may have landed before the timeout fired.
    TimeoutUnknownState,
    /// Card reset itself, warm or cold, during the exchange.
    CardReset,
    /// Protocol block or window state lost; subsequent frames cannot be
    /// interpreted.
    ProtocolDesync,
    /// Reader was unplugged or its session terminated.
    ReaderRemoved,
}

impl TransportOutcome {
    /// Drop the outcome wrapper if it carries a real APDU response;
    /// otherwise hand the outcome back for the caller's typed dispatch.
    ///
    /// # Errors
    ///
    /// Any non-response transport state.
    pub fn into_response(self) -> Result<ResponseApdu, Self> {
        match self {
            Self::Response(response) => Ok(response),
            other => Err(other),
        }
    }

    /// Project a non-response outcome to its [`TransportErrorKind`];
    /// `None` for the response variant.
    #[must_use]
    pub const fn kind(&self) -> Option<TransportErrorKind> {
        match self {
            Self::Response(_) => None,
            Self::NoCard => Some(TransportErrorKind::NoCard),
            Self::TimeoutUnknownState => Some(TransportErrorKind::TimeoutUnknownState),
            Self::CardReset => Some(TransportErrorKind::CardReset),
            Self::ProtocolDesync => Some(TransportErrorKind::ProtocolDesync),
            Self::ReaderRemoved => Some(TransportErrorKind::ReaderRemoved),
        }
    }
}

impl core::fmt::Display for TransportOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Response(response) => write!(
                f,
                "response {} body of {} bytes",
                response.status_word(),
                response.body.len()
            ),
            Self::NoCard => f.write_str("no card present"),
            Self::TimeoutUnknownState => f.write_str("transport timeout; card state unknown"),
            Self::CardReset => f.write_str("card reset during transport"),
            Self::ProtocolDesync => f.write_str("transport protocol desynchronised"),
            Self::ReaderRemoved => f.write_str("reader or card removed"),
        }
    }
}

/// Coarse classification for transport errors that are not already
/// represented as a [`TransportOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// Backend-specific error; the adapter's `Display` carries the
    /// detail.
    Backend,
    /// Card slot was sensed empty.
    NoCard,
    /// Transport timed out; card state unknown.
    TimeoutUnknownState,
    /// Card reset mid-exchange.
    CardReset,
    /// Protocol desync; block or window numbering corrupted.
    ProtocolDesync,
    /// Reader unplugged or session terminated.
    ReaderRemoved,
}

/// Adapter-specific transport errors classify themselves into a small
/// stable fault vocabulary so the use-case layer can match on a typed
/// kind rather than a substring of `Display`.
pub trait TransportErrorExt {
    /// Classify this error. The default is [`TransportErrorKind::Backend`];
    /// adapters with richer information override.
    fn kind(&self) -> TransportErrorKind {
        TransportErrorKind::Backend
    }
}

impl TransportErrorExt for String {}
impl TransportErrorExt for &'static str {}

/// Send-and-receive APDU primitive.
///
/// Adapters own the transport-level mechanics that never surface to the
/// protocol layer: response chaining, and at most one wrong-Le correction
/// obtained through [`CommandApdu::corrected_wrong_le`] -- the buffer
/// itself refuses further corrections.
///
/// The credential path is separate and consumed by value. An adapter
/// implementing [`CardTransport::transmit_credential`] must send the
/// exposed bytes exactly once: no retry on any status word or fault, no
/// correction, no re-sending of the credential buffer, no retention
/// beyond its send path, and no logging or tracing of the wire bytes.
/// It must still settle a chained response: a card may answer a
/// credential command with a "more data" status, and the adapter
/// fetches the remainder with follow-up commands that carry no
/// credential material. Scratch copies the backend requires must be
/// zeroized after the send.
pub trait CardTransport {
    /// Adapter-specific error type; `Display` for diagnostics and
    /// [`TransportErrorExt`] for the typed fault classifier.
    type Error: core::fmt::Debug + core::fmt::Display + TransportErrorExt;

    /// Synchronously transmit a replay-safe command and return either a
    /// concrete response or a transport-level state transition.
    ///
    /// # Errors
    ///
    /// Transport-specific failures other than the [`TransportOutcome`]
    /// state transitions.
    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error>;

    /// Synchronously transmit a credential command exactly once,
    /// consuming it. See the trait documentation for the adapter
    /// obligations on this path.
    ///
    /// # Errors
    ///
    /// Transport-specific failures other than the [`TransportOutcome`]
    /// state transitions. A failure consumes the command; the caller
    /// rebuilds from the validated credential type if the user retries.
    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::{CardTransport, ResponseApdu, TransportErrorKind, TransportOutcome};
    use crate::command::{
        ApduClass, CommandApdu, CommandHeader, CredentialBody, CredentialCommand,
    };
    use crate::status_word::StatusWord;

    /// Synthetic instruction byte for transport tests.
    const TEST_INS: u8 = 0xEE;
    /// Synthetic parameter byte for transport tests.
    const TEST_P1: u8 = 0x01;
    /// Synthetic parameter byte for transport tests.
    const TEST_P2: u8 = 0x02;
    /// Le used by scripted case-2 exchanges.
    const TEST_LE: u8 = 0x08;
    /// Wire length of a status-word pair.
    const SW_LEN: usize = 2;

    fn success_bytes() -> [u8; SW_LEN] {
        StatusWord::Success.as_u16().to_be_bytes()
    }

    fn success_response() -> ResponseApdu {
        let [sw1, sw2] = success_bytes();
        ResponseApdu {
            body: vec![],
            sw1,
            sw2,
        }
    }

    /// In-memory transport that replays a canned request-response trace
    /// and records credential wire lengths without retaining the bytes.
    struct MockTransport {
        script: Vec<(Vec<u8>, ResponseApdu)>,
        cursor: usize,
        credential_wire_lens: Vec<usize>,
    }

    impl MockTransport {
        fn new(script: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
            Self {
                script,
                cursor: 0,
                credential_wire_lens: vec![],
            }
        }
    }

    impl CardTransport for MockTransport {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let (expected, response) = self
                .script
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
            command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            let wire_len = command.expose_wire(|wire| wire.len());
            self.credential_wire_lens.push(wire_len);
            Ok(TransportOutcome::Response(success_response()))
        }
    }

    fn header() -> CommandHeader {
        CommandHeader {
            class: ApduClass::Plain,
            instruction: TEST_INS,
            p1: TEST_P1,
            p2: TEST_P2,
        }
    }

    #[test]
    fn response_status_helpers_project_the_typed_word() {
        let ok = success_response();
        assert!(ok.is_ok());
        assert_eq!(ok.sw(), StatusWord::Success.as_u16());
        assert_eq!(ok.status_word(), StatusWord::Success);

        let [sw1, sw2] = StatusWord::SecurityNotSatisfied.as_u16().to_be_bytes();
        let denied = ResponseApdu {
            body: vec![],
            sw1,
            sw2,
        };
        assert!(!denied.is_ok());
        assert_eq!(denied.status_word(), StatusWord::SecurityNotSatisfied);
    }

    #[test]
    fn outcome_projects_fault_kinds_and_responses() {
        assert_eq!(
            TransportOutcome::CardReset.kind(),
            Some(TransportErrorKind::CardReset)
        );
        assert_eq!(TransportOutcome::Response(success_response()).kind(), None);

        let outcome = TransportOutcome::Response(success_response());
        assert!(outcome.into_response().is_ok());
        assert_eq!(
            TransportOutcome::NoCard.into_response(),
            Err(TransportOutcome::NoCard)
        );
    }

    #[test]
    fn typed_transmit_drives_a_script() {
        let command = CommandApdu::case_2(header(), TEST_LE);
        let mut transport =
            MockTransport::new(vec![(command.as_bytes().to_vec(), success_response())]);
        let outcome = transport
            .transmit(&command)
            .expect("scripted exchange succeeds");
        let response = outcome.into_response().expect("scripted response is real");
        assert!(response.is_ok());
    }

    #[test]
    fn credential_transmit_consumes_the_command() {
        let mut source = [TEST_P1, TEST_P2];
        let body_len = source.len();
        let body = CredentialBody::take_from(&mut source).expect("fixture length is valid");
        let command = CredentialCommand::assemble(header(), body);
        let wire_len = command.len();

        let mut transport = MockTransport::new(vec![]);
        let outcome = transport
            .transmit_credential(command)
            .expect("mock credential exchange succeeds");
        assert!(outcome.into_response().expect("real response").is_ok());
        assert_eq!(transport.credential_wire_lens, vec![wire_len]);
        assert!(wire_len > body_len);
    }
}
