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

//! EF.TokenInfo parsing.

use refineid_ber::{
    BerError, BerTag, BerTlv, BerTlvIter, Integer, OctetString, PrintableString, Sequence,
    Utf8String,
};

use crate::token_serial::{TokenSerial, hex_encode};

/// Context tag zero: the implicit-tagged label field in PKCS#15
/// `TokenInfo`, the alternate location for the label string.
const TAG_TOKEN_INFO_LABEL_IMPLICIT: u16 = 0x80;

/// Subset of PKCS#15 `TokenInfo` that card-status surfaces need, per
/// ISO/IEC 7816-15 section 8.2.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// `TokenInfo.version`: the structure's integer version.
    pub version: Option<u32>,
    /// `TokenInfo.serialNumber` as a hex string: the chip-side long
    /// serial, kept distinct from the plastic-printed and certificate
    /// serials by the typed forms.
    pub serial_number_hex: Option<TokenSerial>,
    /// `TokenInfo.manufacturerID`.
    pub manufacturer_id: Option<String>,
    /// `TokenInfo.label`.
    pub label: Option<String>,
}

impl TokenInfo {
    /// Validating constructor: parse raw EF.TokenInfo bytes into a
    /// typed `TokenInfo`. This is the trust boundary; the card hands
    /// raw bytes and construction and validation are one step.
    ///
    /// Parsing is best-effort within a well-formed outer SEQUENCE:
    /// malformed or unsupported sub-objects read as absent, because
    /// cards diverge on which fields they populate. The one hard
    /// failure is the outer SEQUENCE itself not decoding, so a
    /// malformed file stays distinct from an absent field.
    ///
    /// # Errors
    ///
    /// [`BerError`] when the outer SEQUENCE does not decode.
    pub fn parse(der: &[u8]) -> Result<Self, BerError> {
        let outer = BerTlv::<Sequence>::parse(der)?;
        let mut info = Self {
            version: None,
            serial_number_hex: None,
            manufacturer_id: None,
            label: None,
        };
        let mut children = BerTlvIter::new(outer.value());

        if let Some(Ok(version_any)) = children.next()
            && let Ok(version_tlv) = version_any.expect::<Integer>()
        {
            let mut version: u32 = 0;
            for &byte in version_tlv.value() {
                version = (version << u8::BITS) | u32::from(byte);
            }
            info.version = Some(version);
        }
        if let Some(Ok(serial_any)) = children.next()
            && let Ok(serial_tlv) = serial_any.expect::<OctetString>()
        {
            info.serial_number_hex = Some(TokenSerial::new(hex_encode(serial_tlv.value())));
        }
        // The remaining fields are optional and variably tagged. Pick
        // out string-shaped fields by tag, and the implicit-tagged
        // label, best-effort.
        for entry in children {
            let Ok(entry) = entry else { continue };
            if entry.tag() == <Utf8String as BerTag>::TAG
                || entry.tag() == <PrintableString as BerTag>::TAG
            {
                let text = String::from_utf8_lossy(entry.value()).into_owned();
                if info.manufacturer_id.is_none() {
                    info.manufacturer_id = Some(text);
                } else if info.label.is_none() {
                    info.label = Some(text);
                }
            } else if entry.tag() == TAG_TOKEN_INFO_LABEL_IMPLICIT {
                info.label = Some(String::from_utf8_lossy(entry.value()).into_owned());
            }
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use refineid_ber::{BerEncoder, BerTag, Integer, OctetString, Sequence, Utf8String, tlv};

    use super::TokenInfo;
    use crate::token_serial::{derive_printed_serial, render_token_serial};

    /// Synthetic chip serial stored in the fixture token info.
    const FIXTURE_SERIAL_TEXT: &str = "DEMO0001AB1234567";
    /// Printed tail of the fixture serial.
    const FIXTURE_PRINTED_TAIL: &str = "AB1234567";
    /// Manufacturer string in the fixture.
    const FIXTURE_MANUFACTURER: &str = "Demo Manufacturer";
    /// Label string in the fixture.
    const FIXTURE_LABEL: &str = "Demo Card";
    /// Version integer in the fixture.
    const FIXTURE_VERSION: u32 = 1;

    fn universal_tag(tag: u16) -> u8 {
        u8::try_from(tag).expect("universal tags fit one byte")
    }

    fn fixture_token_info_der() -> Vec<u8> {
        let mut inner = BerEncoder::default();
        inner
            .push_tlv(
                universal_tag(<Integer as BerTag>::TAG),
                [u8::try_from(FIXTURE_VERSION).expect("fixture version fits one byte")],
            )
            .expect("fixture encodes");
        inner
            .push_tlv(
                universal_tag(<OctetString as BerTag>::TAG),
                FIXTURE_SERIAL_TEXT.as_bytes(),
            )
            .expect("fixture encodes");
        inner
            .push_tlv(
                universal_tag(<Utf8String as BerTag>::TAG),
                FIXTURE_MANUFACTURER.as_bytes(),
            )
            .expect("fixture encodes");
        inner
            .push_tlv(
                universal_tag(<Utf8String as BerTag>::TAG),
                FIXTURE_LABEL.as_bytes(),
            )
            .expect("fixture encodes");
        tlv(universal_tag(<Sequence as BerTag>::TAG), inner.finish()).expect("fixture encodes")
    }

    #[test]
    fn parses_the_populated_fields() {
        let info = TokenInfo::parse(&fixture_token_info_der()).expect("fixture parses");
        assert_eq!(info.version, Some(FIXTURE_VERSION));
        assert_eq!(info.manufacturer_id.as_deref(), Some(FIXTURE_MANUFACTURER));
        assert_eq!(info.label.as_deref(), Some(FIXTURE_LABEL));

        let serial_hex = info.serial_number_hex.expect("fixture carries a serial");
        let rendered = render_token_serial(serial_hex);
        assert_eq!(rendered, FIXTURE_SERIAL_TEXT);
        let printed = derive_printed_serial(&rendered).expect("fixture shape derives");
        assert_eq!(printed.as_str(), FIXTURE_PRINTED_TAIL);
    }

    #[test]
    fn missing_fields_read_as_absent() {
        let der = tlv(universal_tag(<Sequence as BerTag>::TAG), []).expect("fixture encodes");
        let info = TokenInfo::parse(&der).expect("empty sequence parses");
        assert_eq!(info.version, None);
        assert!(info.serial_number_hex.is_none());
        assert!(info.manufacturer_id.is_none());
        assert!(info.label.is_none());
    }

    #[test]
    fn malformed_outer_structure_is_a_hard_error() {
        let not_a_sequence =
            tlv(universal_tag(<Integer as BerTag>::TAG), [1_u8]).expect("fixture encodes");
        assert!(TokenInfo::parse(&not_a_sequence).is_err());
        assert!(TokenInfo::parse(&[]).is_err());
    }
}
