#![no_main]

use libfuzzer_sys::fuzz_target;
use refineid_rapp::{Envelope, decode_deterministic_cbor, encode_deterministic_cbor};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(value) = decode_deterministic_cbor(bytes) {
        let encoded = encode_deterministic_cbor(&value)
            .expect("every successfully decoded value must re-encode");
        assert_eq!(encoded, bytes, "accepted CBOR must already be canonical");
    }
    let _ = Envelope::decode(bytes);
});
