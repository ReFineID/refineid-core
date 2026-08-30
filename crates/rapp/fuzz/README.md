# RAPP fuzzing

`rapp_wire` presents arbitrary authenticated plaintext to both the restricted
deterministic-CBOR decoder and the complete RAPP envelope decoder. The target
asserts that every accepted CBOR value round-trips byte-for-byte, while parser
errors must remain bounded and non-panicking.

Install `cargo-fuzz`, then run the target with a nightly toolchain:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run rapp_wire -- -max_len=65520
```

Generated corpus and crash artifacts are intentionally ignored. Any minimized
regression that changes a security boundary belongs in a checked-in ordinary
test under `crates/refineid-rapp/tests/`.
