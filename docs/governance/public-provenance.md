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
- **PACE secure channel.** Publication under Apache-2.0 directed on
  2026-08-10 for the `refineid-pace` slice: the PACE handshake,
  secure messaging, the brainpoolP384r1 and symmetric primitives, and
  the random seam. Reconstructed against the private development tree's
  proven wire shapes, with the curve arithmetic re-expressed on a
  macro-free fixed-width Montgomery form to satisfy the numeric-policy
  gate. Constants and flow are traced to BSI TR-03110-3, ICAO Doc 9303
  Part 11, RFC 5639, and the NIST AES and CMAC known-answer vectors.
  Secret, personal-information, protocol, and dependency scans were
  performed for this slice.
- **PIN verification.** Publication under Apache-2.0 directed on
  2026-08-10 for the `refineid-auth` verification slice: the VERIFY
  PIN1 and PIN2 chains over the credential-command path, the
  counter-safe status probe, the status-word classifiers, and the
  retry-risk policy. Reconstructed against the private development
  tree's proven wire shapes; the change and unblock chains stayed
  behind. Constants are traced to the DVV FINEID specifications (S1
  section 3.5) and ISO/IEC 7816-4 section 7.5.6. Secret,
  personal-information, protocol, and dependency scans were performed
  for this slice.
- **Card-side signing.** Publication under Apache-2.0 directed on
  2026-08-10 for the `refineid-sign` slice: the MSE/PSO signing
  choreography for the pre-hashed RSASSA-PKCS1 over SHA-256 and ECDSA
  over P-384 chains, the typed algorithm references and external-hash
  values, and the algorithm-typed signature container. Reconstructed
  against the private development tree's proven wire shapes; host-side
  encoded RSA and the decipher chains stayed behind. Constants are
  traced to the DVV FINEID specifications (S1 sections 3.6 through 3.8,
  S4-1) and ISO/IEC 7816-8, and cross-checked against the offline
  specification. Secret, personal-information, protocol, and dependency
  scans were performed for this slice.
- **Organizational card support.** Publication under Apache-2.0 directed
  on 2026-08-11 for the organizational slice across `refineid-auth` and
  `refineid-sign`: the counter-safe resolution of the card's
  credential numbering, the organizational VERIFY with typed-length
  comparison and no padding, and the organizational signing chain with
  the local qualified-key reference and the inline-digest PSO:CDS. The
  slice also corrects the signing environment to the digital-signature
  template for both keys. Reconstructed against the offline
  specifications and cross-checked against the country-neutral behaviour
  reference exercised against live organizational cards; no card was
  available, so no organizational path is recorded as hardware-validated.
  Constants and flow are traced to the DVV FINEID specifications (S4-2,
  S4-1, and S1) and the ISO/IEC 7816 series. Secret,
  personal-information, protocol, and dependency scans were performed for
  this slice.
- **PIN change and unblock.** Publication under Apache-2.0 directed on
  2026-08-11 for the `refineid-auth` management slice: the `Puk` role
  type and the CHANGE REFERENCE DATA and RESET RETRY COUNTER chains for
  both card families, including the organizational two-command unblock.
  Reconstructed against the private development tree's proven wire shapes
  and cross-checked against the country-neutral behaviour reference; the
  card-mutating and PUK-consuming paths were not run to exhaustion on
  hardware. Constants and flow are traced to the DVV FINEID
  specifications (S1 sections 3.11 and 3.12, S4-2 section 4.3) and
  ISO/IEC 7816-8. Secret, personal-information, protocol, and dependency
  scans were performed for this slice.
- **RSASSA-PSS signing.** Publication under Apache-2.0 directed on
  2026-08-11 for the `refineid-sign` PSS addition: the SHA-256 PSS
  algorithm reference, the `sign_prehashed_sha256_rsa_pss` operation, and
  the PSS-typed signature container. PSS is a card-native scheme reusing
  the pre-hashed choreography, so no new wire path was needed.
  Reconstructed against the private development tree's proven shapes and
  cross-checked against the behaviour reference and the specification's
  algorithm-reference table. Validated on hardware: the older card's
  authentication key produced a PSS signature that verified against the
  authentication certificate, with the PIN counter unconsumed. Constants
  are traced to the DVV FINEID specifications (S1 section 3.6.3 Table 6)
  and ISO/IEC 7816-8. Secret, personal-information, protocol, and
  dependency scans were performed for this slice.

Before a later slice is admitted, its review must record:

- every source repository and selected path;
- the authors and applicable copyright notices;
- authority to publish under the repository license;
- whether history or a clean reconstruction is appropriate; and
- the secret, personal-information, protocol, and dependency scans performed.

Code with uncertain authorship or publication rights remains private until the
uncertainty is resolved explicitly.
