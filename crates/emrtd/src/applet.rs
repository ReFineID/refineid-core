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

//! eMRTD application selection.

use refineid_apdu::{ApduClass, CardTransport, CommandApdu, CommandHeader, TransportOutcome};

use crate::error::EmrtdError;

const INS_SELECT: u8 = 0xA4;
const P1_SELECT_BY_NAME: u8 = 0x04;
const P2_NO_FCI: u8 = 0x0C;

/// Length of the eMRTD AID in bytes.
pub const EMRTD_AID_LEN: usize = 7;

/// Applet Application Identifier (AID) per ICAO 9303-11 section 4.1.2.
pub const EMRTD_APPLET_AID: [u8; EMRTD_AID_LEN] = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

/// Transmits a `SELECT` APDU for the ICAO 9303 eMRTD application.
///
/// # Errors
///
/// Returns an [`EmrtdError`] on transport failures or if the card refuses selection.
pub fn select_emrtd_application<T: CardTransport + ?Sized>(
    transport: &mut T,
) -> Result<(), EmrtdError<T::Error>> {
    let header = CommandHeader {
        class: ApduClass::Plain,
        instruction: INS_SELECT,
        p1: P1_SELECT_BY_NAME,
        p2: P2_NO_FCI,
    };
    let command = CommandApdu::case_3(header, &EMRTD_APPLET_AID).map_err(EmrtdError::Command)?;
    let outcome = transport
        .transmit(&command)
        .map_err(EmrtdError::Transport)?;
    match outcome {
        TransportOutcome::Response(response) => {
            if response.is_ok() {
                Ok(())
            } else {
                Err(EmrtdError::Status {
                    operation: "SELECT eMRTD application",
                    sw: response.status_word(),
                })
            }
        }
        non_response => Err(EmrtdError::from(non_response)),
    }
}
