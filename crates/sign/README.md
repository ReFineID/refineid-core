# refineid-sign

Card-side signing for FINEID cards.

The card holds the private key and performs the private-key operation;
the host computes the digest and drives the MANAGE SECURITY ENVIRONMENT /
PERFORM SECURITY OPERATION choreography. MSE:SET pins the key and
algorithm in the digital-signature template -- the only template the
specification sets for PSO:COMPUTE DIGITAL SIGNATURE, for either key. The
chain's shape follows the resolved card family (`SignScheme`): the citizen
card loads the digest with PSO:HASH and signs an empty PSO:CDS, while the
organizational card carries the digest inline in a single PSO:CDS and
names its qualified key by the local DF.ESIGN reference. The PIN that
gates the key must already be verified in the card session; these commands
carry no credential material and ride the plain transport path, so the
same operations work over a PACE secure-messaging transport unchanged.

`SignOps::sign_prehashed_sha256_rsa`, `sign_prehashed_sha384_rsa`, and
`sign_prehashed_sha512_rsa` cover the RSA keys under RSASSA-PKCS1;
the corresponding `sign_prehashed_*_rsa_pss` methods cover the same
SHA-256, SHA-384, and SHA-512 digests under RSASSA-PSS. All return an
RSA-3072 signature. The
`sign_prehashed_sha256_ecdsa` plus `sign_prehashed_sha384_ecdsa` cover
the newer P-384 keys with the SHA-256 and SHA-384 schemes TLS peers can
negotiate (raw `r || s`). PSS is a card-native scheme: the card applies
the padding from the digest, so the choreography matches the pre-hashed
chain with a different algorithm reference. The signature bytes are
returned in an algorithm-typed container. PSO:DECIPHER, whose
modulus-wide ciphertext needs command chaining, follows in a later slice.

`SignOps::decipher_rsa` recovers an RSA cryptogram: it sets the
confidentiality template and ships the modulus-wide cryptogram by command
chaining (its data field exceeds the short form), and the card returns the
recovered plaintext. `DecipherAlgRef` names the padding (PKCS#1 v1.5 or
RSAES-OAEP-SHA256).

A signature that fits the short response carries its exact length as Le,
which a T=0 card requires to answer directly; the wider RSA-3072
signature uses the maximum-length encoding and the adapter chains the
61xx response.

The SHA-256 PSS, decipher, and SHA-384 ECDSA paths are hardware-validated:
on the older card the authentication key produced a SHA-256 PSS signature
that verified against its certificate and recovered a message encrypted to
it, and on the newer card the authentication key produced a P-384 ECDSA
signature that verified against its certificate. The PKCS#1,
SHA-384/SHA-512 PSS, SHA-256 ECDSA, and
organizational inline-digest chains rest on scripted-transport tests and,
for the organizational chain, the behaviour reference, until each is
observed on hardware. Constants and the command choreography are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications) (S1
sections 3.6 through 3.9, S4-1, S4-2) and ISO/IEC 7816-4 and -8.
