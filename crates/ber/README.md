# refineid-ber

Minimal BER-TLV encoder and decoder, scoped to what the card protocol
layers need: single-byte tags plus the two-byte template tags used by
PACE, short-form and one-through-four-byte long-form lengths, zero-copy
value slices on read, and owned buffers on write.

A full ASN.1 stack is deliberately not pulled in: the surface is small,
the callers are the sibling protocol crates, and a macro-heavy generated
decoder would enlarge the audit surface without adding capability.

The typed layer carries a TLV's tag identity at the type level. Parsing
a `BerTlv<T>` verifies the tag once at the trust boundary; downstream
code consumes the value knowing what it is, and the compiler refuses to
pass one tag's value where another is required.

Structure constraints are traced to ISO 7816-4 section 5.2 and ITU-T
X.690.
