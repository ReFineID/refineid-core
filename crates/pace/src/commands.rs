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

//! The two ISO 7816-4 commands the PACE handshake issues.
//!
//! `MSE:Set AT` opens the handshake, carrying the mechanism, password
//! reference, and domain parameter. `GENERAL AUTHENTICATE` runs the four
//! authentication rounds; the first three set the command-chaining
//! class, the last does not. Both carry no credential material, so they
//! are ordinary replay-safe commands.

use refineid_apdu::{ApduClass, CommandApdu, CommandDataError, CommandHeader};

/// `MANAGE SECURITY ENVIRONMENT` instruction.
const MSE_INS: u8 = 0x22;
/// P1 for `MSE:Set` used to configure verification.
const MSE_P1_SET_AT: u8 = 0xC1;
/// P2 selecting the authentication template.
const MSE_P2_AUTH_TEMPLATE: u8 = 0xA4;

/// `GENERAL AUTHENTICATE` instruction.
const GA_INS: u8 = 0x86;
/// P1 for `GENERAL AUTHENTICATE`.
const GA_P1: u8 = 0x00;
/// P2 for `GENERAL AUTHENTICATE`.
const GA_P2: u8 = 0x00;
/// Le requesting every available response byte.
const GA_LE_ANY: u8 = 0x00;

/// `MSE:Set AT`, the PACE opening command. The data field is the
/// pre-assembled BER-TLV mechanism, password-reference, and domain
/// objects.
#[derive(Debug, Clone)]
pub struct MseSetAt {
    /// Pre-assembled BER-TLV data field.
    pub data: Vec<u8>,
}

impl MseSetAt {
    /// Serialise into a case-3 command APDU.
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] when the data field is empty or exceeds the
    /// short-form capacity.
    pub fn into_apdu(self) -> Result<CommandApdu, CommandDataError> {
        CommandApdu::case_3(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: MSE_INS,
                p1: MSE_P1_SET_AT,
                p2: MSE_P2_AUTH_TEMPLATE,
            },
            &self.data,
        )
    }
}

/// `GENERAL AUTHENTICATE`, carrying a step-specific payload wrapped in
/// the dynamic-authentication-data template.
#[derive(Debug, Clone)]
pub struct GeneralAuthenticate {
    /// `true` for the chained rounds, `false` for the final round.
    pub chain: bool,
    /// The dynamic-authentication-data payload.
    pub payload: Vec<u8>,
}

impl GeneralAuthenticate {
    /// Serialise into a case-4 command APDU.
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] when the payload is empty or exceeds the
    /// short-form capacity.
    pub fn into_apdu(self) -> Result<CommandApdu, CommandDataError> {
        let class = if self.chain {
            ApduClass::ChainedFirst
        } else {
            ApduClass::Plain
        };
        CommandApdu::case_4(
            CommandHeader {
                class,
                instruction: GA_INS,
                p1: GA_P1,
                p2: GA_P2,
            },
            &self.payload,
            GA_LE_ANY,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{GeneralAuthenticate, MseSetAt};
    use refineid_apdu::CommandDataError;

    /// A synthetic MSE data field.
    const MSE_DATA: &[u8] = &[0x80, 0x01, 0xAA];
    /// Expected MSE wire: header, Lc, then the data.
    const EXPECTED_MSE_WIRE: &[u8] = &[0x00, 0x22, 0xC1, 0xA4, 0x03, 0x80, 0x01, 0xAA];

    /// A synthetic GENERAL AUTHENTICATE payload.
    const GA_PAYLOAD: &[u8] = &[0x7C, 0x00];
    /// Expected chained GENERAL AUTHENTICATE wire.
    const EXPECTED_GA_CHAINED_WIRE: &[u8] = &[0x10, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00];
    /// Expected final GENERAL AUTHENTICATE wire.
    const EXPECTED_GA_FINAL_WIRE: &[u8] = &[0x00, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00];

    #[test]
    fn mse_set_at_matches_the_specified_wire() -> Result<(), CommandDataError> {
        let apdu = MseSetAt {
            data: MSE_DATA.to_vec(),
        }
        .into_apdu()?;
        assert_eq!(apdu.as_bytes(), EXPECTED_MSE_WIRE);
        Ok(())
    }

    #[test]
    fn general_authenticate_chaining_selects_the_class() -> Result<(), CommandDataError> {
        let chained = GeneralAuthenticate {
            chain: true,
            payload: GA_PAYLOAD.to_vec(),
        }
        .into_apdu()?;
        assert_eq!(chained.as_bytes(), EXPECTED_GA_CHAINED_WIRE);

        let final_round = GeneralAuthenticate {
            chain: false,
            payload: GA_PAYLOAD.to_vec(),
        }
        .into_apdu()?;
        assert_eq!(final_round.as_bytes(), EXPECTED_GA_FINAL_WIRE);
        Ok(())
    }
}
