# refineid-sign

Card-side signing for FINEID cards.

The card holds the private key and performs the private-key operation;
the host computes the digest and drives the three-command choreography
(MANAGE SECURITY ENVIRONMENT, PERFORM SECURITY OPERATION: HASH, PERFORM
SECURITY OPERATION: COMPUTE DIGITAL SIGNATURE). The PIN that gates the
key must already be verified in the card session; these commands carry
no credential material and ride the plain transport path, so the same
operations work over a PACE secure-messaging transport unchanged.

`SignOps::sign_prehashed_sha256_rsa` covers the RSA keys (RSASSA-PKCS1
over SHA-256, an RSA-3072 signature) and `sign_prehashed_sha384_ecdsa`
covers the newer P-384 keys (ECDSA over SHA-384, raw `r || s`). The
signature bytes are returned in an algorithm-typed container. Host-side
encoded RSA (for PSS, which needs command chaining) and PSO:DECIPHER
follow in a later slice.

Constants and the command choreography are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications) (S1
sections 3.6 through 3.8, S4-1) and ISO/IEC 7816-8.
