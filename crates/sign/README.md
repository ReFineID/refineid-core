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

`SignOps::sign_prehashed_sha256_rsa` covers the RSA keys (RSASSA-PKCS1
over SHA-256, an RSA-3072 signature) and `sign_prehashed_sha384_ecdsa`
covers the newer P-384 keys (ECDSA over SHA-384, raw `r || s`). The
signature bytes are returned in an algorithm-typed container. Host-side
encoded RSA (for PSS, which needs command chaining) and PSO:DECIPHER
follow in a later slice.

No signing path is described as working against a real card until it is
observed on hardware; the organizational chain, which no card was
available to exercise, rests on the specification and the behaviour
reference. Constants and the command choreography are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications) (S1
sections 3.6 through 3.8, S4-1, S4-2) and ISO/IEC 7816-8.
