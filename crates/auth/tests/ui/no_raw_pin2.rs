use refineid_auth::{Pin2, UnvalidatedSecret};

fn main() {
    let pin = Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(b"123456".to_vec()))
        .expect("valid PIN2 fixture");
    let _ = pin.as_bytes();
}
