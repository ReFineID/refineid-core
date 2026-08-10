# refineid-core

Platform-independent ReFineID protocol core, as a family of small,
separately auditable Rust crates.

ReFineID is an open implementation for FINEID electronic identity cards.
This repository is populated in reviewed slices: code is reconstructed at
explicit trust boundaries, tested in isolation, and admitted only when it
starts with zero known policy debt. Platform integration (PC/SC backends,
graphical shells, OS keychain bridges) lives outside this repository; these
crates stay transport-agnostic and country-profile-neutral.

## Crates

- `crates/apdu` (`refineid-apdu`) -- typed ISO 7816-4 commands, status
  words, and the card transport port, with separate replay-safe and
  credential command ownership paths.
- `crates/auth` (`refineid-auth`) -- PIN and PUK role types, VERIFY
  PIN1/PIN2 over the credential-command path for both citizen and
  organizational cards, the counter-safe status probe that resolves the
  card's credential numbering, the CHANGE REFERENCE DATA and RESET RETRY
  COUNTER (unblock) chains, and the retry-risk policy.
- `crates/ber` (`refineid-ber`) -- minimal BER-TLV encoder and decoder
  with a typed tag layer.
- `crates/pace` (`refineid-pace`) -- Card Access Number input type, the
  PACE handshake, and secure messaging.
- `crates/pkcs15` (`refineid-pkcs15`) -- PKCS#15 file-system reads:
  selection, bounded reads, certificates as plain DER, EF.TokenInfo, and
  the typed chip-serial forms.
- `crates/sign` (`refineid-sign`) -- card-side signing: the MSE/PSO
  choreography for the pre-hashed RSA and P-384 ECDSA chains, over both
  the citizen chain (PSO:HASH then an empty PSO:CDS) and the
  organizational chain (an inline-digest PSO:CDS).

Planned work adds host-side-encoded RSA (PSS) and PSO:DECIPHER into
`refineid-sign`, and an X.509/SPKI layer over the certificates the read
path returns.

## Security posture

- PIN1, PIN2, and the PUK are distinct non-clonable types.
- PIN2 retention is bounded to a one-minute convenience window measured from
  the last card-confirmed use; the window never extends to PIN management.
- Credential and CAN input are accepted only through explicitly unvalidated,
  zeroize-on-drop boundaries and reconstructed into validated role types.
- Anonymous protocol numbers are rejected. Hexadecimal wire values may appear
  only in a meaningful named constant or an independently audited wire/KAT
  fixture.

Constraints are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications),
[ICAO Doc 9303](https://www.icao.int/publications/doc-series/doc-9303), and
the ISO/IEC 7816 series. See
[credential custody](docs/security/credential-custody.md),
the [core migration policy](docs/architecture/core-migration.md), and
[public provenance](docs/governance/public-provenance.md).

## Build and check

```sh
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run --locked -p xtask -- check-magic-numbers
```

The project is early public work and does not yet publish a supported
release.
