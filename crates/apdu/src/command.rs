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

//! Command ownership paths.
//!
//! Outgoing commands have exactly two representations. Replay-safe public
//! commands use the debuggable [`CommandApdu`]; it is built through the
//! ISO 7816-4 case constructors or the typed builders in
//! [`crate::iso7816`], never from an opaque byte blob. Credential-bearing
//! commands use the separate [`CredentialCommand`]; it is zeroizing,
//! non-clonable, non-debuggable, and consumed by an at-most-once transport
//! operation.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ISO 7816-4 short-form command header length: CLA, INS, P1, P2.
pub const APDU_HEADER_LEN: usize = 4;

/// Length of the short-form Lc field.
pub(crate) const LC_LEN: usize = 1;

/// Length of the short-form Le field.
pub(crate) const LE_LEN: usize = 1;

/// Maximum data-field length of a short-form command APDU.
pub const SHORT_APDU_DATA_MAX: usize = 255;

/// Command class byte, per FINEID S1 v4.2 section 3 and ISO 7816-4
/// section 5.4.
///
/// The secure-messaging wrap itself is applied by the PACE crate's session
/// layer; this enum picks which class byte goes on the wire before that
/// wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduClass {
    /// Plain command: no secure messaging, no chaining, logical channel 0.
    Plain,
    /// Secure messaging applies, with the command header authenticated.
    SecureMessaging,
    /// First portion of a command-chained body; the card waits for the
    /// final portion (FINEID S1 v4.2 section 3.6.2).
    ChainedFirst,
}

impl ApduClass {
    /// Class byte for [`ApduClass::Plain`].
    const CLA_PLAIN: u8 = 0x00;
    /// Class byte for [`ApduClass::SecureMessaging`].
    const CLA_SECURE_MESSAGING: u8 = 0x0C;
    /// Class byte for [`ApduClass::ChainedFirst`].
    const CLA_CHAINED_FIRST: u8 = 0x10;

    /// Wire byte for this class.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Plain => Self::CLA_PLAIN,
            Self::SecureMessaging => Self::CLA_SECURE_MESSAGING,
            Self::ChainedFirst => Self::CLA_CHAINED_FIRST,
        }
    }
}

/// The four header bytes of an ISO 7816-4 command.
///
/// Instruction and parameter bytes are protocol-specific; callers name them
/// as constants traced to the governing specification, as this repository's
/// numeric policy enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandHeader {
    /// Command class.
    pub class: ApduClass,
    /// Instruction byte (INS).
    pub instruction: u8,
    /// First parameter byte (P1).
    pub p1: u8,
    /// Second parameter byte (P2).
    pub p2: u8,
}

impl CommandHeader {
    /// The header as its four wire bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; APDU_HEADER_LEN] {
        [self.class.as_byte(), self.instruction, self.p1, self.p2]
    }
}

/// Structural reason a command data field was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandDataError {
    /// The data field was empty; case 1 or case 2 has no data field.
    Empty,
    /// The data field exceeds the short-form capacity of
    /// [`SHORT_APDU_DATA_MAX`] bytes.
    TooLong {
        /// Rejected data length in bytes.
        got: usize,
    },
}

impl fmt::Display for CommandDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("command data field cannot be empty"),
            Self::TooLong { got } => write!(
                f,
                "command data field of {got} bytes exceeds the short-form \
                 capacity of {SHORT_APDU_DATA_MAX} bytes"
            ),
        }
    }
}

impl core::error::Error for CommandDataError {}

/// One outgoing replay-safe command APDU.
///
/// The type deliberately has no constructor from raw bytes and does not
/// implement `Clone`: a command buffer is built once, through a case
/// constructor or a typed builder, and adapters transmit through a borrow.
/// The only sanctioned duplicate is the single corrected command returned
/// by [`CommandApdu::corrected_wrong_le`].
///
/// Credential-bearing commands must never pass through this type; they use
/// [`CredentialCommand`].
#[derive(Debug, PartialEq, Eq)]
pub struct CommandApdu {
    /// Wire bytes: CLA INS P1 P2, then Lc + data and/or Le by case.
    bytes: Vec<u8>,
    /// Whether a T=0 adapter may correct Le once after a wrong-Le status.
    /// Only typed, read-only case-2 builders opt in.
    wrong_le_retry: bool,
}

/// Length of a short case-2 command: header plus Le.
const SHORT_CASE_2_LEN: usize = APDU_HEADER_LEN + LE_LEN;

impl CommandApdu {
    /// Case 1: header only; no data field, no response data expected.
    #[must_use]
    pub fn case_1(header: CommandHeader) -> Self {
        Self::from_wire(header.to_bytes().to_vec())
    }

    /// Case 2: header plus Le; response data expected. An Le byte of zero
    /// asks for as many bytes as the card has, up to the short-form
    /// maximum.
    #[must_use]
    pub fn case_2(header: CommandHeader, le: u8) -> Self {
        let mut bytes = header.to_bytes().to_vec();
        bytes.push(le);
        Self::from_wire(bytes)
    }

    /// Case 3: header plus Lc and data; no response data expected.
    ///
    /// # Errors
    ///
    /// Returns [`CommandDataError`] when `data` is empty or exceeds
    /// [`SHORT_APDU_DATA_MAX`] bytes.
    pub fn case_3(header: CommandHeader, data: &[u8]) -> Result<Self, CommandDataError> {
        let lc = Self::short_form_lc(data)?;
        let mut bytes = Vec::with_capacity(APDU_HEADER_LEN + LC_LEN + data.len());
        bytes.extend_from_slice(&header.to_bytes());
        bytes.push(lc);
        bytes.extend_from_slice(data);
        Ok(Self::from_wire(bytes))
    }

    /// Case 4: header plus Lc, data, and Le; response data expected.
    ///
    /// # Errors
    ///
    /// Returns [`CommandDataError`] when `data` is empty or exceeds
    /// [`SHORT_APDU_DATA_MAX`] bytes.
    pub fn case_4(header: CommandHeader, data: &[u8], le: u8) -> Result<Self, CommandDataError> {
        let lc = Self::short_form_lc(data)?;
        let mut bytes = Vec::with_capacity(APDU_HEADER_LEN + LC_LEN + data.len() + LE_LEN);
        bytes.extend_from_slice(&header.to_bytes());
        bytes.push(lc);
        bytes.extend_from_slice(data);
        bytes.push(le);
        Ok(Self::from_wire(bytes))
    }

    /// Validate a short-form data field and return its Lc byte.
    fn short_form_lc(data: &[u8]) -> Result<u8, CommandDataError> {
        if data.is_empty() {
            return Err(CommandDataError::Empty);
        }
        if data.len() > SHORT_APDU_DATA_MAX {
            return Err(CommandDataError::TooLong { got: data.len() });
        }
        match u8::try_from(data.len()) {
            Ok(lc) => Ok(lc),
            Err(_) => Err(CommandDataError::TooLong { got: data.len() }),
        }
    }

    /// Wrap wire bytes produced by an in-crate typed builder. The builders
    /// are the boundary that guarantees a well-formed command shape.
    pub(crate) const fn from_wire(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            wrong_le_retry: false,
        }
    }

    /// Mark a builder-proven short case-2 command as safe for one
    /// corrected-Le retry. Crate-private so callers cannot opt arbitrary
    /// commands into replay; the length check keeps the permission
    /// unreachable for any non-case-2 shape.
    #[must_use]
    pub(crate) fn allow_wrong_le_retry(mut self) -> Self {
        self.wrong_le_retry = self.bytes.len() == SHORT_CASE_2_LEN;
        self
    }

    /// The single corrected command permitted after a wrong-Le status.
    /// The returned command cannot be corrected again, so an adapter
    /// cannot replay indefinitely. Returns `None` for every command whose
    /// builder did not opt into the retry.
    #[must_use]
    pub fn corrected_wrong_le(&self, le: u8) -> Option<Self> {
        if !self.wrong_le_retry {
            return None;
        }
        let mut bytes = self.bytes.clone();
        let last = bytes.last_mut()?;
        *last = le;
        Some(Self {
            bytes,
            wrong_le_retry: false,
        })
    }

    /// Borrow the wire bytes for transmission.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Capacity of a credential command's data field: two stored-length
/// credential blocks. FINEID S4-1 v4.2 section 4.1 stores each PIN in a
/// twelve-byte block, and the largest credential payload carries an
/// old-and-new block pair.
pub const CREDENTIAL_BODY_MAX: usize = 24;

/// Capacity of a complete credential command: header, Lc, and data field.
/// Credential commands are case 3; they carry no Le.
pub const CREDENTIAL_APDU_MAX: usize = APDU_HEADER_LEN + LC_LEN + CREDENTIAL_BODY_MAX;

/// Structural reason credential data was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialBodyError {
    /// No bytes were supplied.
    Empty,
    /// The credential data exceeds [`CREDENTIAL_BODY_MAX`] bytes.
    TooLong {
        /// Rejected data length in bytes.
        got: usize,
    },
}

impl fmt::Display for CredentialBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("credential data cannot be empty"),
            Self::TooLong { got } => write!(
                f,
                "credential data of {got} bytes exceeds the capacity of \
                 {CREDENTIAL_BODY_MAX} bytes"
            ),
        }
    }
}

impl core::error::Error for CredentialBodyError {}

/// Validated data field of one credential command.
///
/// Construction takes custody: the source buffer is zeroized on every
/// path, so the caller's raw credential representation is destroyed at the
/// boundary. The type is not `Clone`, not `Copy`, not raw-debuggable, and
/// zeroizes its own storage on drop.
#[derive(ZeroizeOnDrop)]
pub struct CredentialBody {
    /// Fixed-capacity storage; only the first `length` bytes are wire
    /// data.
    bytes: [u8; CREDENTIAL_BODY_MAX],
    /// Wire data length in bytes.
    length: u8,
}

impl CredentialBody {
    /// Take custody of credential data. Copies the bytes into
    /// fixed-capacity storage and zeroizes `source` before returning,
    /// on the success path and on every error path.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialBodyError`] when `source` is empty or exceeds
    /// [`CREDENTIAL_BODY_MAX`] bytes.
    pub fn take_from(source: &mut [u8]) -> Result<Self, CredentialBodyError> {
        if source.is_empty() {
            return Err(CredentialBodyError::Empty);
        }
        if source.len() > CREDENTIAL_BODY_MAX {
            let got = source.len();
            source.zeroize();
            return Err(CredentialBodyError::TooLong { got });
        }
        let length = match u8::try_from(source.len()) {
            Ok(length) => length,
            Err(_) => {
                let got = source.len();
                source.zeroize();
                return Err(CredentialBodyError::TooLong { got });
            }
        };
        let mut bytes = [0_u8; CREDENTIAL_BODY_MAX];
        bytes[..source.len()].copy_from_slice(source);
        source.zeroize();
        Ok(Self { bytes, length })
    }

    /// Number of wire data bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }

    /// `false` by construction; retained for idiomatic pairing with
    /// [`CredentialBody::len`].
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl fmt::Debug for CredentialBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialBody([redacted])")
    }
}

/// One credential-bearing command APDU.
///
/// This is the second ownership path mandated by the migration policy: a
/// zeroizing, non-clonable type whose debug rendering is redacted, consumed
/// exactly once by
/// [`CardTransport::transmit_credential`](crate::transport::CardTransport::transmit_credential).
/// It never enters generic tracing before redaction, and no raw-byte
/// accessor exists; the only wire access is the consuming
/// [`CredentialCommand::expose_wire`].
#[derive(ZeroizeOnDrop)]
pub struct CredentialCommand {
    /// Fixed-capacity wire storage; only the first `length` bytes are the
    /// command.
    bytes: [u8; CREDENTIAL_APDU_MAX],
    /// Wire length in bytes.
    length: u8,
}

/// Wire bytes preceding the data field of a credential command: the header
/// and the Lc byte.
const CREDENTIAL_WIRE_PREFIX: u8 = 5;

impl CredentialCommand {
    /// Assemble a case-3 credential command from a header and a validated
    /// data field. The body is consumed; its storage zeroizes on drop.
    #[must_use]
    pub fn assemble(header: CommandHeader, body: CredentialBody) -> Self {
        let mut bytes = [0_u8; CREDENTIAL_APDU_MAX];
        bytes[..APDU_HEADER_LEN].copy_from_slice(&header.to_bytes());
        bytes[APDU_HEADER_LEN] = body.length;
        let data_len = usize::from(body.length);
        let body_start = APDU_HEADER_LEN + LC_LEN;
        bytes[body_start..body_start + data_len].copy_from_slice(&body.bytes[..data_len]);
        let length = CREDENTIAL_WIRE_PREFIX + body.length;
        Self { bytes, length }
    }

    /// Wire length of the assembled command in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }

    /// `false` by construction; retained for idiomatic pairing with
    /// [`CredentialCommand::len`].
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Consume the command and expose its wire bytes to a transport
    /// adapter for one transmission.
    ///
    /// The storage zeroizes when the call returns. The adapter must hand
    /// the bytes to its send path without retaining a copy, must zeroize
    /// any scratch buffer it fills from them, and must never route them
    /// through logging or tracing.
    pub fn expose_wire<R>(self, adapter_send: impl FnOnce(&[u8]) -> R) -> R {
        let wire_len = usize::from(self.length);
        adapter_send(&self.bytes[..wire_len])
    }
}

impl fmt::Debug for CredentialCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialCommand([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        APDU_HEADER_LEN, ApduClass, CREDENTIAL_APDU_MAX, CREDENTIAL_BODY_MAX, CommandApdu,
        CommandDataError, CommandHeader, CredentialBody, CredentialBodyError, CredentialCommand,
        LC_LEN, LE_LEN, SHORT_APDU_DATA_MAX,
    };

    /// Synthetic instruction byte for shape tests. The value has no
    /// protocol meaning; command semantics are out of scope here.
    const TEST_INS: u8 = 0xEE;
    /// Synthetic P1 byte for shape tests.
    const TEST_P1: u8 = 0x01;
    /// Synthetic P2 byte for shape tests.
    const TEST_P2: u8 = 0x02;
    /// Synthetic Le byte for case-2 and case-4 shape tests.
    const TEST_LE: u8 = 0x10;
    /// Corrected Le reported by a card via a wrong-Le status.
    const CORRECTED_LE: u8 = 0x2C;
    /// Data length above the short-form capacity.
    const OVER_SHORT_CAPACITY: usize = SHORT_APDU_DATA_MAX + 1;
    /// Data length above the credential-body capacity.
    const OVER_CREDENTIAL_CAPACITY: usize = CREDENTIAL_BODY_MAX + 1;

    fn header() -> CommandHeader {
        CommandHeader {
            class: ApduClass::Plain,
            instruction: TEST_INS,
            p1: TEST_P1,
            p2: TEST_P2,
        }
    }

    fn expected_prefix() -> Vec<u8> {
        vec![ApduClass::Plain.as_byte(), TEST_INS, TEST_P1, TEST_P2]
    }

    #[test]
    fn apdu_class_bytes_are_distinct() {
        assert_eq!(ApduClass::Plain.as_byte(), 0);
        assert!(ApduClass::Plain.as_byte() != ApduClass::SecureMessaging.as_byte());
        assert!(ApduClass::SecureMessaging.as_byte() != ApduClass::ChainedFirst.as_byte());
    }

    #[test]
    fn case_1_is_header_only() {
        let apdu = CommandApdu::case_1(header());
        assert_eq!(apdu.as_bytes(), expected_prefix().as_slice());
        assert_eq!(apdu.as_bytes().len(), APDU_HEADER_LEN);
    }

    #[test]
    fn case_2_appends_le() {
        let apdu = CommandApdu::case_2(header(), TEST_LE);
        let mut expected = expected_prefix();
        expected.push(TEST_LE);
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn case_3_appends_lc_and_data() -> Result<(), CommandDataError> {
        let data = [TEST_P1, TEST_P2, TEST_LE];
        let apdu = CommandApdu::case_3(header(), &data)?;
        let mut expected = expected_prefix();
        expected.push(u8::try_from(data.len()).expect("fixture data fits an Lc byte"));
        expected.extend_from_slice(&data);
        assert_eq!(apdu.as_bytes(), expected.as_slice());
        Ok(())
    }

    #[test]
    fn case_4_appends_lc_data_and_le() -> Result<(), CommandDataError> {
        let data = [TEST_P1, TEST_P2];
        let apdu = CommandApdu::case_4(header(), &data, TEST_LE)?;
        let mut expected = expected_prefix();
        expected.push(u8::try_from(data.len()).expect("fixture data fits an Lc byte"));
        expected.extend_from_slice(&data);
        expected.push(TEST_LE);
        assert_eq!(apdu.as_bytes(), expected.as_slice());
        Ok(())
    }

    #[test]
    fn data_field_boundaries_are_enforced() {
        assert!(matches!(
            CommandApdu::case_3(header(), &[]),
            Err(CommandDataError::Empty)
        ));
        let max = vec![TEST_P1; SHORT_APDU_DATA_MAX];
        assert!(CommandApdu::case_3(header(), &max).is_ok());
        let over = vec![TEST_P1; OVER_SHORT_CAPACITY];
        assert!(matches!(
            CommandApdu::case_3(header(), &over),
            Err(CommandDataError::TooLong {
                got: OVER_SHORT_CAPACITY
            })
        ));
        assert!(matches!(
            CommandApdu::case_4(header(), &[], TEST_LE),
            Err(CommandDataError::Empty)
        ));
    }

    #[test]
    fn wrong_le_correction_requires_builder_opt_in() {
        let plain = CommandApdu::case_2(header(), TEST_LE);
        assert!(plain.corrected_wrong_le(CORRECTED_LE).is_none());

        let retryable = CommandApdu::case_2(header(), TEST_LE).allow_wrong_le_retry();
        let corrected = retryable
            .corrected_wrong_le(CORRECTED_LE)
            .expect("builder opted the case-2 command into one correction");
        let mut expected = expected_prefix();
        expected.push(CORRECTED_LE);
        assert_eq!(corrected.as_bytes(), expected.as_slice());
        assert!(
            corrected.corrected_wrong_le(TEST_LE).is_none(),
            "a corrected command cannot be corrected again"
        );
    }

    #[test]
    fn wrong_le_opt_in_is_unreachable_for_non_case_2_shapes() {
        let data = [TEST_P1];
        let case_3 = CommandApdu::case_3(header(), &data)
            .expect("fixture data fits an Lc byte")
            .allow_wrong_le_retry();
        assert!(case_3.corrected_wrong_le(CORRECTED_LE).is_none());
    }

    #[test]
    fn credential_body_takes_custody_and_zeroizes_the_source() {
        let mut source = [TEST_P1, TEST_P2, TEST_LE];
        let body = CredentialBody::take_from(&mut source).expect("fixture length is valid");
        assert_eq!(body.len(), source.len());
        assert!(!body.is_empty());
        assert!(
            source.iter().all(|byte| *byte == 0),
            "source must be zeroized after custody transfer"
        );
    }

    #[test]
    fn credential_body_boundaries_are_enforced() {
        let mut empty: [u8; 0] = [];
        assert!(matches!(
            CredentialBody::take_from(&mut empty),
            Err(CredentialBodyError::Empty)
        ));

        let mut max = [TEST_P1; CREDENTIAL_BODY_MAX];
        assert!(CredentialBody::take_from(&mut max).is_ok());

        let mut over = [TEST_P1; OVER_CREDENTIAL_CAPACITY];
        assert!(matches!(
            CredentialBody::take_from(&mut over),
            Err(CredentialBodyError::TooLong {
                got: OVER_CREDENTIAL_CAPACITY
            })
        ));
        assert!(
            over.iter().all(|byte| *byte == 0),
            "source must be zeroized on the error path"
        );
    }

    #[test]
    fn credential_command_assembles_a_case_3_wire_shape() {
        let mut source = [TEST_P1, TEST_P2];
        let data_len = source.len();
        let body = CredentialBody::take_from(&mut source).expect("fixture length is valid");
        let command = CredentialCommand::assemble(header(), body);
        assert_eq!(command.len(), APDU_HEADER_LEN + LC_LEN + data_len);
        assert!(!command.is_empty());
        assert!(command.len() <= CREDENTIAL_APDU_MAX);

        command.expose_wire(|wire| {
            let mut expected = expected_prefix();
            expected.push(u8::try_from(data_len).expect("fixture data fits an Lc byte"));
            expected.extend_from_slice(&[TEST_P1, TEST_P2]);
            assert_eq!(wire, expected.as_slice());
        });
    }

    #[test]
    fn credential_types_debug_is_always_redacted() {
        let mut source = [TEST_P1, TEST_P2];
        let body = CredentialBody::take_from(&mut source).expect("fixture length is valid");
        assert_eq!(format!("{body:?}"), "CredentialBody([redacted])");

        let command = CredentialCommand::assemble(header(), body);
        assert_eq!(format!("{command:?}"), "CredentialCommand([redacted])");
    }

    #[test]
    fn credential_capacity_covers_a_block_pair_and_nothing_more() {
        assert_eq!(
            CREDENTIAL_APDU_MAX,
            APDU_HEADER_LEN + LC_LEN + CREDENTIAL_BODY_MAX
        );
        assert_eq!(
            usize::from(super::CREDENTIAL_WIRE_PREFIX),
            APDU_HEADER_LEN + LC_LEN
        );
        assert_eq!(LE_LEN, LC_LEN);
    }
}
