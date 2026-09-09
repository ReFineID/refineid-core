# refineid-apdu

Typed ISO 7816-4 commands and the card transport port.

The crate enforces two command ownership paths. Replay-safe public
commands are debuggable `CommandApdu` values with no raw-bytes
constructor and no `Clone`; typed builders serialise them once, and the
only sanctioned duplicate is the single wrong-Le correction a read-only
builder grants. Credential-bearing commands are zeroizing, non-clonable,
redacted `CredentialCommand` values assembled from a custody-taking
`CredentialBody` and consumed exactly once by the transport.

The `CardTransport` port carries only these typed forms. There is no
byte-slice transmit, so builder-granted permissions survive to the
adapter and credential material cannot pass through a generic path.

Wire constants are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications) and
the ISO/IEC 7816 series. The ATR parser and reader-facing session types
arrive in later slices.
