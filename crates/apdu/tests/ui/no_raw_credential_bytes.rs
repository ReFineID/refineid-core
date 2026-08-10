use refineid_apdu::CredentialCommand;

fn leak(command: CredentialCommand) -> Vec<u8> {
    command.as_bytes().to_vec()
}

fn main() {
    let _ = leak;
}
