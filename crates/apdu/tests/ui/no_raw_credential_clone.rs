use refineid_apdu::CredentialCommand;

fn duplicate(command: &CredentialCommand) -> CredentialCommand {
    command.clone()
}

fn main() {
    let _ = duplicate;
}
