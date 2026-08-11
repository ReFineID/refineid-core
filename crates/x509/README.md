# refineid-x509

SubjectPublicKeyInfo reconstruction from FINEID X.509 certificates.

A certificate enters as an `UnvalidatedCertificate` -- raw, untrusted DER
from the read path. `PublicKey::from_certificate` navigates its DER to the
SubjectPublicKeyInfo and reconstructs a typed `PublicKey`: an
`RsaPublicKey` carrying a validated modulus and public exponent, or an
`EcPublicKey` carrying its curve (P-256, P-384) and affine coordinates.
Each invariant is checked once at that boundary -- the modulus is a
minimal, positive magnitude, the exponent is odd and positive, an EC point
is in SEC1 uncompressed form with exact-width coordinates, the public-key
bit string has no unused bits, and no trailing bytes follow -- so a value
of the type is proof of a well-formed key rather than a byte buffer. No raw
DER survives the reconstruction; `to_spki_der` re-serialises the
SubjectPublicKeyInfo from the typed key, so a host verifier gets canonical
SPKI bytes to check a signature the card produced. The typed key pairs a
certificate with the right signing chain: an RSA key with the RSA signing
chain, a P-384 key with the ECDSA chain.

This crate deliberately does **not** validate certificates. Chain
building, validity windows, key usage, name constraints, and revocation
are a consumer or platform concern and stay out of the core, as does the
rest of the X.509 structure; only the SubjectPublicKeyInfo is parsed. The
DER walk is built on `refineid-ber`, not a general X.509 parser, so the
crate adds no new dependency.

The reconstruction is covered by unit tests over synthetic RSA-3072,
P-384, and P-256 certificates -- including the version-absent, trailing-
byte, non-canonical-integer, and truncated cases -- and round-trip tests
that pin `to_spki_der`. It is hardware-validated: the newer card's
certificate slots reconstructed as their issued P-384, RSA-3072, and
RSA-4096 keys.

Constants are traced to RFC 5280 (the certificate and
SubjectPublicKeyInfo structure), PKCS#1, and the curve and algorithm
object identifiers in RFC 5480 and RFC 8017.
