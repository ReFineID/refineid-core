# refineid-x509

SubjectPublicKeyInfo extraction from FINEID X.509 certificates.

`Spki::from_certificate` navigates a certificate's DER to the
SubjectPublicKeyInfo, classifies the public key -- RSA with its modulus
size, or a NIST elliptic curve (P-256, P-384) -- and exposes the SPKI
bytes so a host verifier can check a signature the card produced. It pairs
a certificate the read path returns with the right signing chain: an
RSA-3072 key with the RSA signing chain, a P-384 key with the ECDSA chain.

This crate deliberately does **not** validate certificates. Chain
building, validity windows, key usage, name constraints, and revocation
are a consumer or platform concern and stay out of the core, as does the
rest of the X.509 structure; only the SubjectPublicKeyInfo is parsed. The
DER walk is built on `refineid-ber`, not a general X.509 parser, so the
crate adds no new dependency.

The parser is covered by unit tests over synthetic RSA-3072, P-384, and
P-256 certificates, including the version-absent and truncated cases.

Constants are traced to RFC 5280 (the certificate and
SubjectPublicKeyInfo structure), PKCS#1, and the curve and algorithm
object identifiers in RFC 5480 and RFC 8017.
