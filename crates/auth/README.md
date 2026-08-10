# refineid-auth

Reviewed FINEID PIN role types. The crate's charter is card credential
verification: the PIN1/PIN2 input boundary today, and in a later admitted
slice the verification, change, and unblock command chains built on the
credential-command transport path.

The current slice contains only the refined input types. Raw input exists
only in `UnvalidatedSecret`; consuming construction validates once and
reconstructs the non-clonable, zeroizing `Pin1` and `Pin2` role types.

Constraints are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications).
See the repository's
[credential custody contract](../../docs/security/credential-custody.md).
