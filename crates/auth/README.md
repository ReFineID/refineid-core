# refineid-auth

Reviewed FINEID PIN role types and verification.

Raw input exists only in `UnvalidatedSecret`; consuming construction
validates once and reconstructs the non-clonable, zeroizing `Pin1` and
`Pin2` role types. `verify_pin1` and `verify_pin2` consume a validated
PIN through a crate-private path, pad it to the stored length, and ship
it only as a credential command, consumed exactly once; the slot is
fixed by the argument type. The counter-safe status probe reads the
retry state without spending a counter, and the retry-risk policy maps
the live counter to the safety floors different surfaces stop at.

The PIN change and PUK-unblock chains, which are card-mutating and need
the separately supplied credential role types, follow in a later slice.
No verification path is described as working against a real card until it
is observed on hardware with the retry counter checked.

Constants are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications) (S1
section 3.5) and ISO/IEC 7816-4. See the repository's
[credential custody contract](../../docs/security/credential-custody.md).
