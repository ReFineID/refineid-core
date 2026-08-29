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

//! ICAO 9303 EF.DG2 / ISO 19794-5 biometric facial portrait image parser and validator.

use refineid_ber::BerTlvAny;

/// Image format of the biometric facial portrait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// JPEG image (ISO/IEC 10918-1).
    Jpeg,
    /// JPEG 2000 image (ISO/IEC 15444-1).
    Jpeg2000,
}

/// A parsed, validated cardholder facial portrait extracted from EF.DG2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardFaceImage {
    format: ImageFormat,
    width_pixels: u16,
    height_pixels: u16,
    image_bytes: Vec<u8>,
}

impl CardFaceImage {
    /// Creates a new `CardFaceImage` from validated parameters.
    #[must_use]
    pub const fn new(
        format: ImageFormat,
        width_pixels: u16,
        height_pixels: u16,
        image_bytes: Vec<u8>,
    ) -> Self {
        Self {
            format,
            width_pixels,
            height_pixels,
            image_bytes,
        }
    }

    /// Detected image format.
    #[must_use]
    pub const fn format(&self) -> ImageFormat {
        self.format
    }

    /// Width in pixels.
    #[must_use]
    pub const fn width(&self) -> u16 {
        self.width_pixels
    }

    /// Height in pixels.
    #[must_use]
    pub const fn height(&self) -> u16 {
        self.height_pixels
    }

    /// Encoded raw image bytes.
    #[must_use]
    pub fn image_bytes(&self) -> &[u8] {
        &self.image_bytes
    }

    /// Consumes the structure and returns the underlying image bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.image_bytes
    }
}

const DG2_TEMPLATE_TAG: u16 = 0x75;

const JPEG_HEADER_LEN: usize = 3;
const JP2_HEADER_LEN: usize = 8;
const JP2_TAG_LEN: usize = 4;
const JPEG_SOI_LEN: usize = 2;
const JPEG_LENGTH_FIELD_LEN: usize = 2;

const JPEG_SOI_PREFIX: [u8; JPEG_HEADER_LEN] = [0xFF, 0xD8, 0xFF];
const JP2_MAGIC_BOX: [u8; JP2_HEADER_LEN] = [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20];

const JPEG_MARKER_LEAD: u8 = 0xFF;
const JPEG_MARKER_SOF0: u8 = 0xC0;
const JPEG_MARKER_SOF2: u8 = 0xC2;
const JPEG_MARKER_SOS: u8 = 0xDA;
const JPEG_MARKER_EOI: u8 = 0xD9;

const JP2_IHDR_TAG: [u8; JP2_TAG_LEN] = [0x69, 0x68, 0x64, 0x72];
const JP2_IHDR_PAYLOAD_OFFSET: usize = 4;
const JP2_IHDR_HEIGHT_OFFSET: usize = 0;
const JP2_IHDR_WIDTH_OFFSET: usize = 4;
const JP2_DIMENSION_BYTES: usize = 4;
const JP2_TWO_DIMENSIONS_LEN: usize = 8;

const JP2_DIM_BYTE_0: usize = 0;
const JP2_DIM_BYTE_1: usize = 1;
const JP2_DIM_BYTE_2: usize = 2;
const JP2_DIM_BYTE_3: usize = 3;

const BITS_PER_BYTE: usize = 8;
const MIN_JPEG_SOF_PAYLOAD: usize = 5;

const JPEG_SOF_HEIGHT_HI: usize = 1;
const JPEG_SOF_HEIGHT_LO: usize = 2;
const JPEG_SOF_WIDTH_HI: usize = 3;
const JPEG_SOF_WIDTH_LO: usize = 4;

/// Parses and validates a cardholder facial image from EF.DG2 raw bytes.
///
/// Handles CBEFF/BHT encapsulation, locates the format stream, parses and validates
/// container dimensions, and returns a typed [`CardFaceImage`].
#[must_use]
pub fn parse_card_face_image(dg2_bytes: &[u8]) -> Option<CardFaceImage> {
    let tlv = BerTlvAny::parse(dg2_bytes).ok()?;
    if tlv.tag() != DG2_TEMPLATE_TAG {
        return None;
    }
    let value = tlv.value();

    if let Some(offset) = find_subsequence(value, &JPEG_SOI_PREFIX) {
        let raw_jpeg = &value[offset..];
        let (width, height) = parse_jpeg_dimensions(raw_jpeg).unwrap_or((0, 0));
        return Some(CardFaceImage::new(
            ImageFormat::Jpeg,
            width,
            height,
            raw_jpeg.to_vec(),
        ));
    }

    if let Some(offset) = find_subsequence(value, &JP2_MAGIC_BOX) {
        let raw_jp2 = &value[offset..];
        let (width, height) = parse_jp2_dimensions(raw_jp2).unwrap_or((0, 0));
        return Some(CardFaceImage::new(
            ImageFormat::Jpeg2000,
            width,
            height,
            raw_jp2.to_vec(),
        ));
    }

    None
}

/// Parses JPEG frame headers (SOF0 or SOF2) to extract dimensions.
fn parse_jpeg_dimensions(jpeg_bytes: &[u8]) -> Option<(u16, u16)> {
    let mut i = JPEG_SOI_LEN;
    while i < jpeg_bytes.len() {
        if jpeg_bytes[i] != JPEG_MARKER_LEAD {
            i += 1;
            continue;
        }
        while i < jpeg_bytes.len() && jpeg_bytes[i] == JPEG_MARKER_LEAD {
            i += 1;
        }
        if i >= jpeg_bytes.len() {
            break;
        }
        let marker = jpeg_bytes[i];
        i += 1;

        if marker == JPEG_MARKER_SOS || marker == JPEG_MARKER_EOI {
            break;
        }

        if i + 1 >= jpeg_bytes.len() {
            break;
        }
        let len = ((jpeg_bytes[i] as usize) << BITS_PER_BYTE) | (jpeg_bytes[i + 1] as usize);

        if marker == JPEG_MARKER_SOF0 || marker == JPEG_MARKER_SOF2 {
            if len >= MIN_JPEG_SOF_PAYLOAD && i + len <= jpeg_bytes.len() {
                let payload = &jpeg_bytes[i + JPEG_LENGTH_FIELD_LEN..];
                if payload.len() >= MIN_JPEG_SOF_PAYLOAD {
                    let height = ((payload[JPEG_SOF_HEIGHT_HI] as u16) << BITS_PER_BYTE)
                        | (payload[JPEG_SOF_HEIGHT_LO] as u16);
                    let width = ((payload[JPEG_SOF_WIDTH_HI] as u16) << BITS_PER_BYTE)
                        | (payload[JPEG_SOF_WIDTH_LO] as u16);
                    return Some((width, height));
                }
            }
            break;
        }

        i += len;
    }
    None
}

/// Parses JP2 header box (ihdr) to extract dimensions.
fn parse_jp2_dimensions(jp2_bytes: &[u8]) -> Option<(u16, u16)> {
    let offset = find_subsequence(jp2_bytes, &JP2_IHDR_TAG)?;
    let payload = jp2_bytes.get(offset + JP2_IHDR_PAYLOAD_OFFSET..)?;
    if payload.len() < JP2_TWO_DIMENSIONS_LEN {
        return None;
    }

    let h_bytes =
        payload.get(JP2_IHDR_HEIGHT_OFFSET..JP2_IHDR_HEIGHT_OFFSET + JP2_DIMENSION_BYTES)?;
    let w_bytes =
        payload.get(JP2_IHDR_WIDTH_OFFSET..JP2_IHDR_WIDTH_OFFSET + JP2_DIMENSION_BYTES)?;

    let height = u32::from_be_bytes([
        h_bytes[JP2_DIM_BYTE_0],
        h_bytes[JP2_DIM_BYTE_1],
        h_bytes[JP2_DIM_BYTE_2],
        h_bytes[JP2_DIM_BYTE_3],
    ]) as u16;
    let width = u32::from_be_bytes([
        w_bytes[JP2_DIM_BYTE_0],
        w_bytes[JP2_DIM_BYTE_1],
        w_bytes[JP2_DIM_BYTE_2],
        w_bytes[JP2_DIM_BYTE_3],
    ]) as u16;

    Some((width, height))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.len() < needle.len() {
        return None;
    }
    (0..=(haystack.len() - needle.len())).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::{
        CardFaceImage, ImageFormat, JP2_HEADER_LEN, JP2_MAGIC_BOX, JPEG_HEADER_LEN,
        JPEG_SOI_PREFIX, parse_card_face_image,
    };

    const TEST_WIDTH: u16 = 300;
    const TEST_HEIGHT: u16 = 400;

    const TEST_JPEG_PAYLOAD: &[u8] = &[
        0x75, 0x1A, // Tag 75, length 26
        0x01, 0x02, 0x03, // CBEFF header
        0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08, // SOF0 marker, len 17, precision 8
        0x01, 0x90, // Height 400
        0x01, 0x2C, // Width 300
        0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, // 3 components
        0xFF, 0xD9, // EOI
    ];

    const TEST_JP2_PAYLOAD: &[u8] = &[
        0x75, 0x20, // Tag 75, length 32
        0x01, 0x02, // CBEFF header
        0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, // JP2 signature box
        0x00, 0x00, 0x00, 0x16, 0x69, 0x68, 0x64, 0x72, // ihdr box header
        0x00, 0x00, 0x01, 0x90, // Height 400
        0x00, 0x00, 0x01, 0x2C, // Width 300
        0x00, 0x03, 0x07, 0x07, 0x00, 0x00,
    ];

    #[test]
    fn parses_and_validates_jpeg_portrait() {
        let portrait = parse_card_face_image(TEST_JPEG_PAYLOAD).expect("jpeg portrait parsed");
        assert_eq!(portrait.format(), ImageFormat::Jpeg);
        assert_eq!(portrait.width(), TEST_WIDTH);
        assert_eq!(portrait.height(), TEST_HEIGHT);
        assert_eq!(&portrait.image_bytes()[..JPEG_HEADER_LEN], &JPEG_SOI_PREFIX);
    }

    #[test]
    fn parses_and_validates_jpeg2000_portrait() {
        let portrait = parse_card_face_image(TEST_JP2_PAYLOAD).expect("jp2 portrait parsed");
        assert_eq!(portrait.format(), ImageFormat::Jpeg2000);
        assert_eq!(portrait.width(), TEST_WIDTH);
        assert_eq!(portrait.height(), TEST_HEIGHT);
        assert_eq!(&portrait.image_bytes()[..JP2_HEADER_LEN], &JP2_MAGIC_BOX);
    }
}
