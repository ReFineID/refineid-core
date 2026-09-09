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

//! EF.COM data group inventory parsing.

use refineid_ber::{BerTlvAny, BerTlvIter};

const COM_TAG: u16 = 0x60;
const DG_LIST_TAG: u16 = 0x5C;

const TAG_DG1: u8 = 0x61;
const TAG_DG2: u8 = 0x75;
const TAG_DG7: u8 = 0x67;
const TAG_DG11: u8 = 0x6B;
const TAG_DG12: u8 = 0x6C;

/// The inventory of data groups announced in EF.COM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataGroupInventory {
    /// Whether EF.DG1 (MRZ) is present.
    pub has_dg1: bool,
    /// Whether EF.DG2 (facial image) is present.
    pub has_dg2: bool,
    /// Whether EF.DG7 (signature) is present.
    pub has_dg7: bool,
    /// Whether EF.DG11 (additional personal details) is present.
    pub has_dg11: bool,
    /// Whether EF.DG12 (additional document details) is present.
    pub has_dg12: bool,
}

impl DataGroupInventory {
    /// Creates an empty data group inventory with all groups marked absent.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            has_dg1: false,
            has_dg2: false,
            has_dg7: false,
            has_dg11: false,
            has_dg12: false,
        }
    }

    /// Parses the data group inventory from EF.COM contents.
    #[must_use]
    pub fn parse(com_bytes: &[u8]) -> Option<Self> {
        let tlv = BerTlvAny::parse(com_bytes).ok()?;
        if tlv.tag() != COM_TAG {
            return None;
        }

        let mut inventory = Self::empty();
        for child_result in BerTlvIter::new(tlv.value()) {
            let child = child_result.ok()?;
            if child.tag() == DG_LIST_TAG {
                for &tag in child.value() {
                    match tag {
                        TAG_DG1 => inventory.has_dg1 = true,
                        TAG_DG2 => inventory.has_dg2 = true,
                        TAG_DG7 => inventory.has_dg7 = true,
                        TAG_DG11 => inventory.has_dg11 = true,
                        TAG_DG12 => inventory.has_dg12 = true,
                        _ => {}
                    }
                }
                return Some(inventory);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::DataGroupInventory;

    const TEST_COM_PAYLOAD: &[u8] = &[
        0x60, 0x09, // EF.COM
        0x5F, 0x01, 0x01, 0x1E, // LDS version
        0x5C, 0x03, 0x61, 0x75, 0x67, // DG list: DG1, DG2, DG7
    ];

    #[test]
    fn parses_ef_com_inventory() {
        let inv = DataGroupInventory::parse(TEST_COM_PAYLOAD).expect("parsed inventory");
        assert!(inv.has_dg1);
        assert!(inv.has_dg2);
        assert!(inv.has_dg7);
        assert!(!inv.has_dg11);
    }
}
