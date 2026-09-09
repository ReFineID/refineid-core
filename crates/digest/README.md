# refineid-digest

Typed SHA-2 digest values and hash-algorithm identifiers.

A host that computes a digest and ships it to a card needs three small
things from a shared crate rather than a vendored copy: a value type that
names the algorithm it carries, a hash-algorithm identifier it can parse
from a platform-supplied string, and the digest lengths as named
constants. This crate provides exactly that and nothing more; it holds no
key and performs no card I/O.

`Sha256`, `Sha384`, and `Sha512` are fixed-length newtypes over the `sha2` crate's
one-shot digest. Carrying the algorithm in the type keeps a raw byte array
from standing in for a computed digest, and keeps a SHA-256 value from
being handed where a differently sized SHA-2 value is expected. Each value exists only
through `of` (a live digest of some bytes) or `from_bytes` (a
caller-asserted precomputed digest); the bytes are private. `HashAlg` names
the SHA-1/SHA-2 family for callers that receive the algorithm as a string
and need its digest length, and rejects an unknown name rather than
guessing at one.

The digest computation is not hand-rolled -- it delegates to the `sha2`
crate; this crate adds only the name and the length contract. Constants are
the FIPS 180-4 digest lengths.
