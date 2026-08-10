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
- `crates/auth` (`refineid-auth`) -- PIN role types and, in a later slice,
  the PIN verification, change, and unblock chains.
- `crates/ber` (`refineid-ber`) -- minimal BER-TLV encoder and decoder
  with a typed tag layer.
- `crates/pace` (`refineid-pace`) -- Card Access Number input type and, in a
  later slice, the PACE secure-channel driver.
- `crates/pkcs15` (`refineid-pkcs15`) -- PKCS#15 file-system reads:
  selection, bounded reads, certificates as plain DER, EF.TokenInfo, and
  the typed chip-serial forms.

Planned slices add the PACE protocol into `refineid-pace`, the PIN chains
into `refineid-auth`, and `refineid-sign` (card-side signature
operations).

## Security posture

- PIN1 and PIN2 are distinct non-clonable types.
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
