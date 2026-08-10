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

//! VERIFY PIN1 and PIN2 against a FINEID card.
//!
//! The typed PIN digits are right-padded with the pad byte to the
//! slot's stored length and shipped as a credential command, consumed
//! exactly once by the transport. Because `Pin1` and `Pin2` are
//! validated at construction, no local re-check is needed and the slot
//! is fixed by the argument type, so a PIN2 can never be sent to the
//! PIN1 slot.
//!
//! The counter-safe status probe (`VERIFY` with an empty data field)
//! reads the retry state without decrementing any counter, per FINEID
//! S1 v4.2 section 4.1.2, and is the safe pre-flight before an
//! operation that would burn a retry on a wrong PIN.

use refineid_apdu::{
    ApduClass, CardTransport, CommandApdu, CommandHeader, CredentialBody, CredentialBodyError,
    CredentialCommand, PinRetries, StatusWord, TransportOutcome,
};

use crate::credentials::{Pin1, Pin2};

/// PKCS#15 PIN1 reference: the authentication PIN (FINEID S1 v4.2
/// section 3.5.1).
pub const PIN1_REFERENCE: u8 = 0x11;
/// PKCS#15 PIN2 reference: the qualified-signature PIN (FINEID S1 v4.2
/// section 3.5.2).
pub const PIN2_REFERENCE: u8 = 0x82;

/// VERIFY instruction byte (ISO 7816-4 section 7.5.6).
const VERIFY_INS: u8 = 0x20;
/// VERIFY P1 selecting the verify operation.
const VERIFY_P1: u8 = 0x00;

/// FINEID stored length for both PIN slots: the padded block length in
/// bytes (FINEID S1 v4.2 section 3.5).
pub const PIN_STORED_LENGTH: usize = 12;
/// Padding byte applied to the right of the typed digits; FINEID cards
/// reject any other padding value.
const PIN_PAD_BYTE: u8 = 0x00;

/// Which PIN slot a status probe targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSlot {
    /// PIN1: the authentication and digital-signature PIN.
    Pin1,
    /// PIN2: the qualified-signature PIN.
    Pin2,
}

impl PinSlot {
    /// The VERIFY P2 reference byte for this slot.
    #[must_use]
    pub const fn reference(self) -> u8 {
        match self {
            Self::Pin1 => PIN1_REFERENCE,
            Self::Pin2 => PIN2_REFERENCE,
        }
    }
}

/// Outcome of a VERIFY round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The PIN was accepted; the card stays authenticated until a
    /// selection or reset clears the state.
    Ok,
    /// The PIN was wrong; `retries_left` attempts remain before the slot
    /// locks. Zero means the next failure locks it.
    WrongPin {
        /// Attempts remaining before the slot locks.
        retries_left: PinRetries,
    },
    /// The authentication method is blocked; only an unblock recovers
    /// it.
    Locked,
    /// Any other status word, surfaced for the caller to map.
    Other(u16),
}

/// Outcome of a counter-safe status probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    /// The PIN is already verified in this card session.
    Verified,
    /// The PIN is not verified; `retries` attempts remain.
    Remaining(PinRetries),
    /// Verification failed with no retry information.
    NoInfo,
    /// The PIN method is blocked or its usage counter is exhausted.
    Locked,
    /// Any other status word, surfaced for the caller.
    Other(u16),
}

/// A VERIFY-path failure.
#[derive(Debug)]
pub enum AuthError<E> {
    /// An adapter-level transport failure.
    Transport(E),
    /// A transport-level state transition instead of a response.
    Outcome(TransportOutcome),
    /// The credential command could not be assembled; unreachable for a
    /// validated PIN, kept fail-closed.
    Command(CredentialBodyError),
}

impl<E: core::fmt::Display> core::fmt::Display for AuthError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "auth transport: {e}"),
            Self::Outcome(outcome) => write!(f, "auth transport state: {outcome}"),
            Self::Command(e) => write!(f, "auth command: {e}"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for AuthError<E> {}

/// Decode a VERIFY response status word into an outcome. Public so an
/// unrelated operation can classify a PIN-state status word it receives.
#[must_use]
pub const fn classify_verify_sw(sw: StatusWord) -> VerifyOutcome {
    match sw {
        StatusWord::Success => VerifyOutcome::Ok,
        StatusWord::PinIncorrect { retries } => VerifyOutcome::WrongPin {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            VerifyOutcome::Locked
        }
        other => VerifyOutcome::Other(other.as_u16()),
    }
}

/// Decode a status-probe response status word.
#[must_use]
pub const fn classify_pin_status_sw(sw: StatusWord) -> PinStatus {
    match sw {
        StatusWord::Success => PinStatus::Verified,
        StatusWord::PinIncorrect { retries } => PinStatus::Remaining(retries),
        StatusWord::AuthenticationFailed => PinStatus::NoInfo,
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            PinStatus::Locked
        }
        other => PinStatus::Other(other.as_u16()),
    }
}

/// Right-pad the typed digits into a fresh stored-length block.
fn padded_block(digits: &[u8]) -> [u8; PIN_STORED_LENGTH] {
    let mut block = [PIN_PAD_BYTE; PIN_STORED_LENGTH];
    let copy_len = digits.len().min(PIN_STORED_LENGTH);
    block[..copy_len].copy_from_slice(&digits[..copy_len]);
    block
}

/// PIN management operations, layered as default methods on every
/// [`CardTransport`].
///
/// Bring the trait into scope to use the methods; the blanket
/// implementation applies to every transport, so a plain contact
/// transport and a PACE secure-messaging transport both gain the same
/// PIN operations.
pub trait PinOps: CardTransport {
    /// VERIFY PIN1 (the authentication PIN). The PIN is consumed and its
    /// digits are zeroized; the slot is fixed by the argument type.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition. A wrong
    /// PIN is not an error; it is [`VerifyOutcome::WrongPin`].
    fn verify_pin1(&mut self, pin: Pin1) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        self.verify(PinSlot::Pin1, pin.digits())
    }

    /// VERIFY PIN2 (the qualified-signature PIN). The PIN is consumed and
    /// its digits are zeroized; the slot is fixed by the argument type.
    ///
    /// # Errors
    ///
    /// As [`PinOps::verify_pin1`].
    fn verify_pin2(&mut self, pin: Pin2) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        self.verify(PinSlot::Pin2, pin.digits())
    }

    /// Probe the retry state of a slot without decrementing any counter.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn pin_status(&mut self, slot: PinSlot) -> Result<PinStatus, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let command = CommandApdu::case_1(CommandHeader {
            class: ApduClass::Plain,
            instruction: VERIFY_INS,
            p1: VERIFY_P1,
            p2: slot.reference(),
        });
        let response = self
            .transmit(&command)
            .map_err(AuthError::Transport)?
            .into_response()
            .map_err(AuthError::Outcome)?;
        Ok(classify_pin_status_sw(response.status_word()))
    }

    /// Assemble and send the VERIFY credential command for `slot`.
    ///
    /// # Errors
    ///
    /// As [`PinOps::verify_pin1`].
    fn verify(
        &mut self,
        slot: PinSlot,
        digits: &[u8],
    ) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let mut block = padded_block(digits);
        let body = match CredentialBody::take_from(&mut block) {
            Ok(body) => body,
            Err(error) => return Err(AuthError::Command(error)),
        };
        let command = CredentialCommand::assemble(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: VERIFY_INS,
                p1: VERIFY_P1,
                p2: slot.reference(),
            },
            body,
        );
        let response = self
            .transmit_credential(command)
            .map_err(AuthError::Transport)?
            .into_response()
            .map_err(AuthError::Outcome)?;
        Ok(classify_verify_sw(response.status_word()))
    }
}

impl<T: CardTransport + ?Sized> PinOps for T {}

#[cfg(test)]
mod tests {
    use super::{
        PIN_STORED_LENGTH, PinSlot, PinStatus, VerifyOutcome, classify_pin_status_sw,
        classify_verify_sw, padded_block,
    };
    use refineid_apdu::{PinRetries, StatusWord};

    /// A retry count for the classifier tests.
    const THREE_RETRIES: u8 = 3;
    /// Length of the PIN fixture used in the padding test.
    const PIN_FIXTURE_LEN: usize = 4;

    #[test]
    fn slot_references_are_distinct() {
        assert_eq!(PinSlot::Pin1.reference(), super::PIN1_REFERENCE);
        assert_eq!(PinSlot::Pin2.reference(), super::PIN2_REFERENCE);
        let distinct = PinSlot::Pin1.reference() != PinSlot::Pin2.reference();
        assert!(distinct);
    }

    #[test]
    fn padding_fills_to_the_stored_length() {
        let block = padded_block(b"1234");
        assert_eq!(block.len(), PIN_STORED_LENGTH);
        assert_eq!(&block[..PIN_FIXTURE_LEN], b"1234");
        assert!(
            block[PIN_FIXTURE_LEN..]
                .iter()
                .all(|&byte| byte == super::PIN_PAD_BYTE)
        );
    }

    #[test]
    fn verify_classifier_covers_the_outcomes() {
        assert_eq!(classify_verify_sw(StatusWord::Success), VerifyOutcome::Ok);
        let three = PinRetries::from_nibble(THREE_RETRIES).expect("fits a nibble");
        assert_eq!(
            classify_verify_sw(StatusWord::PinIncorrect { retries: three }),
            VerifyOutcome::WrongPin {
                retries_left: three
            }
        );
        assert_eq!(
            classify_verify_sw(StatusWord::AuthenticationBlocked),
            VerifyOutcome::Locked
        );
        assert_eq!(
            classify_verify_sw(StatusWord::ReferenceDataInvalidated),
            VerifyOutcome::Locked
        );
        assert_eq!(
            classify_verify_sw(StatusWord::FileNotFound),
            VerifyOutcome::Other(StatusWord::FileNotFound.as_u16())
        );
    }

    #[test]
    fn status_classifier_covers_the_states() {
        assert_eq!(
            classify_pin_status_sw(StatusWord::Success),
            PinStatus::Verified
        );
        let three = PinRetries::from_nibble(THREE_RETRIES).expect("fits a nibble");
        assert_eq!(
            classify_pin_status_sw(StatusWord::PinIncorrect { retries: three }),
            PinStatus::Remaining(three)
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::AuthenticationFailed),
            PinStatus::NoInfo
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::AuthenticationBlocked),
            PinStatus::Locked
        );
    }
}
