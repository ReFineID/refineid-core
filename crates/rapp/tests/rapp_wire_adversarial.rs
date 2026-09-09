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

//! Adversarial input against the public deterministic-CBOR decoder.

use refineid_rapp::{MAX_FRAME_PLAINTEXT, WireError, decode_deterministic_cbor};

#[test]
fn public_decoder_rejects_input_larger_than_one_plaintext_frame() {
    let oversized = vec![0_u8; MAX_FRAME_PLAINTEXT + 1];
    assert_eq!(
        decode_deterministic_cbor(&oversized),
        Err(WireError::OversizedPlaintext {
            got: MAX_FRAME_PLAINTEXT + 1,
        })
    );
}

#[test]
fn claimed_array_capacity_is_bounded_by_remaining_input() {
    // Canonical CBOR array length 65,520, with no elements following it.
    let claimed = [0x99, 0xff, 0xf0];
    assert_eq!(
        decode_deterministic_cbor(&claimed),
        Err(WireError::CollectionTooLarge { got: 65_520 })
    );
}

#[test]
fn claimed_map_work_is_bounded_by_remaining_input() {
    // Canonical CBOR map length 65,520, with no key/value pairs following it.
    let claimed = [0xb9, 0xff, 0xf0];
    assert_eq!(
        decode_deterministic_cbor(&claimed),
        Err(WireError::CollectionTooLarge { got: 65_520 })
    );
}

#[test]
fn nested_values_stop_at_the_protocol_depth_limit() {
    let mut nested = vec![0x81; 10];
    nested.push(0xf6);
    assert_eq!(
        decode_deterministic_cbor(&nested),
        Err(WireError::NestingTooDeep)
    );
}

#[test]
fn text_length_is_rejected_before_payload_allocation() {
    // Canonical CBOR text length 4,097, with no payload following it.
    let claimed = [0x79, 0x10, 0x01];
    assert_eq!(
        decode_deterministic_cbor(&claimed),
        Err(WireError::TextTooLong { got: 4_097 })
    );
}
