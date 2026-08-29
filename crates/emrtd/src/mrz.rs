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

//! ICAO 9303 TD1 Machine Readable Zone (MRZ) parser.

use refineid_ber::BerTlvAny;

const DG1_TAG: u16 = 0x61;
const TD1_LINE_LEN: usize = 30;
const TD1_TOTAL_LEN: usize = 90;

const LINE_TWO_OFFSET: usize = TD1_LINE_LEN;
const LINE_THREE_OFFSET: usize = 2 * TD1_LINE_LEN;

const DOC_TYPE_OFFSET: usize = 0;
const DOC_TYPE_END: usize = 2;
const ISSUING_COUNTRY_OFFSET: usize = 2;
const ISSUING_COUNTRY_END: usize = 5;
const DOC_NUMBER_OFFSET: usize = 5;
const DOC_NUMBER_END: usize = 14;

const DOB_OFFSET: usize = 0;
const DOB_END: usize = 6;
const SEX_CHAR_INDEX: usize = 7;
const EXPIRY_OFFSET: usize = 8;
const EXPIRY_END: usize = 14;
const NATIONALITY_OFFSET: usize = 15;
const NATIONALITY_END: usize = 18;

/// Parsed Machine Readable Zone data from a TD1 document (e.g. Finnish Identity Card).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMrzTd1 {
    /// Document type (e.g., "I", "ID").
    pub document_type: String,
    /// Issuing state or organization (3-letter code, e.g. "FIN").
    pub issuing_country: String,
    /// Document number (9 characters).
    pub document_number: String,
    /// Cardholder date of birth (YYMMDD).
    pub date_of_birth: String,
    /// Cardholder sex ('M', 'F', or '<').
    pub sex: char,
    /// Document expiry date (YYMMDD).
    pub expiry_date: String,
    /// Cardholder nationality (3-letter code, e.g. "FIN").
    pub nationality: String,
    /// Primary identifier / surname.
    pub primary_identifier: String,
    /// Secondary identifier / given names.
    pub secondary_identifier: String,
}

impl ParsedMrzTd1 {
    /// Parses a 90-byte TD1 MRZ from DG1 contents.
    #[must_use]
    pub fn parse(dg1_bytes: &[u8]) -> Option<Self> {
        let tlv = BerTlvAny::parse(dg1_bytes).ok()?;
        if tlv.tag() != DG1_TAG {
            return None;
        }

        let mrz_bytes = if let Ok(inner) = BerTlvAny::parse(tlv.value()) {
            inner.value()
        } else {
            tlv.value()
        };

        if mrz_bytes.len() < TD1_TOTAL_LEN {
            return None;
        }

        let line1 = core::str::from_utf8(mrz_bytes.get(0..TD1_LINE_LEN)?).ok()?;
        let line2 =
            core::str::from_utf8(mrz_bytes.get(LINE_TWO_OFFSET..LINE_THREE_OFFSET)?).ok()?;
        let line3 = core::str::from_utf8(mrz_bytes.get(LINE_THREE_OFFSET..TD1_TOTAL_LEN)?).ok()?;

        let doc_type = line1
            .get(DOC_TYPE_OFFSET..DOC_TYPE_END)?
            .trim_matches('<')
            .to_string();
        let issuing = line1
            .get(ISSUING_COUNTRY_OFFSET..ISSUING_COUNTRY_END)?
            .trim_matches('<')
            .to_string();
        let doc_number = line1
            .get(DOC_NUMBER_OFFSET..DOC_NUMBER_END)?
            .trim_matches('<')
            .to_string();

        let dob = line2.get(DOB_OFFSET..DOB_END)?.to_string();
        let sex = line2.chars().nth(SEX_CHAR_INDEX)?;
        let expiry = line2.get(EXPIRY_OFFSET..EXPIRY_END)?.to_string();
        let nationality = line2
            .get(NATIONALITY_OFFSET..NATIONALITY_END)?
            .trim_matches('<')
            .to_string();

        let names_part = line3.trim_matches('<');
        let mut name_split = names_part.split("<<");
        let primary = name_split
            .next()
            .unwrap_or("")
            .replace('<', " ")
            .trim()
            .to_string();
        let secondary = name_split
            .next()
            .unwrap_or("")
            .replace('<', " ")
            .trim()
            .to_string();

        Some(Self {
            document_type: doc_type,
            issuing_country: issuing,
            document_number: doc_number,
            date_of_birth: dob,
            sex,
            expiry_date: expiry,
            nationality,
            primary_identifier: primary,
            secondary_identifier: secondary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ParsedMrzTd1;

    const TEST_MRZ_RAW: &[u8] = b"I<FIN1234567894<<<<<<<<<<<<<<<\
                                  8001014M3001012FIN<<<<<<<<<<<6\
                                  KOISTINEN<<PETRI<<<<<<<<<<<<<<";

    const DG1_HEADER_LEN: usize = 5;
    const TEST_DG1_HEADER: [u8; DG1_HEADER_LEN] = [0x61, 0x5D, 0x5F, 0x1F, 0x5A];

    #[test]
    fn parses_td1_mrz() {
        let mut dg1 = TEST_DG1_HEADER.to_vec();
        dg1.extend_from_slice(TEST_MRZ_RAW);

        let parsed = ParsedMrzTd1::parse(&dg1).expect("parsed mrz");
        assert_eq!(parsed.issuing_country, "FIN");
        assert_eq!(parsed.document_number, "123456789");
        assert_eq!(parsed.primary_identifier, "KOISTINEN");
        assert_eq!(parsed.secondary_identifier, "PETRI");
        assert_eq!(parsed.sex, 'M');
    }
}
