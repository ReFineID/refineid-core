use refineid_auth::{Pin1, UnvalidatedSecret};

fn main() {
    let pin = Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(b"1234".to_vec()))
        .expect("valid PIN1 fixture");
    let _ = pin.as_bytes();
}
