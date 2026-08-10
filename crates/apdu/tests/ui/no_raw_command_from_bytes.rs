use refineid_apdu::CommandApdu;

fn main() {
    let wire: Vec<u8> = vec![];
    let _ = CommandApdu::from(wire);
}
