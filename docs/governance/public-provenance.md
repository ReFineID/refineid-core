# Public provenance

This repository receives reconstructed, reviewed snapshots rather than
private commit history.

Petri Koistinen is the sole author and copyright holder of the admitted
implementation. Each slice below was reconstructed for the public tree; none
was copied together with private metadata, credentials, fixtures, or
deployment details.

## Slice records

- **Input types.** Publication under Apache-2.0 directed on 2026-07-19 for
  the initial common-core slice (refined credential-input types and the Card
  Access Number type), first published in the `ReFineID` repository and
  relocated here into the crates that will own their consuming protocol
  layers. Secret, personal-information, protocol, and dependency scans were
  performed for the initial publication and repeated for the relocation.
- **APDU foundation.** Publication under Apache-2.0 directed on 2026-08-10
  for the `refineid-apdu` slice: typed ISO 7816-4 command builders and
  primitives, the decoded status word, the two command ownership paths, and
  the typed-only transport port. Reconstructed against the private
  development tree's proven wire shapes with the quarantined designs
  replaced; wire constants are traced to the DVV FINEID specifications and
  the ISO/IEC 7816 series. Secret, personal-information, protocol, and
  dependency scans were performed for this slice.
- **Read path.** Publication under Apache-2.0 directed on 2026-08-10 for
  the `refineid-ber` and `refineid-pkcs15` slices: the minimal BER-TLV
  layer, PKCS#15 selection and bounded reads, certificate retrieval as
  plain DER, EF.TokenInfo parsing, and the typed chip-serial forms.
  Reconstructed against the private development tree's proven wire
  shapes; reader discovery and certificate-content classification stayed
  behind. Constants are traced to the DVV FINEID specifications (S4-2),
  ISO/IEC 7816-15, and ITU-T X.690. Secret, personal-information,
  protocol, and dependency scans were performed for this slice.

Before a later slice is admitted, its review must record:

- every source repository and selected path;
- the authors and applicable copyright notices;
- authority to publish under the repository license;
- whether history or a clean reconstruction is appropriate; and
- the secret, personal-information, protocol, and dependency scans performed.

Code with uncertain authorship or publication rights remains private until the
uncertainty is resolved explicitly.
