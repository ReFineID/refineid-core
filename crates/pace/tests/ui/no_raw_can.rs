use refineid_pace::{Can, UnvalidatedCan};

fn main() {
    let can = Can::reconstruct(UnvalidatedCan::from_owned_text("123456".to_owned()))
        .expect("valid CAN fixture");
    let _ = can.as_bytes();
}
