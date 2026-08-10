# refineid-pace

Reviewed Card Access Number type. The crate's charter is the PACE secure
channel: the CAN input boundary today, and in a later admitted slice the
PACE handshake and secure-messaging session establishment.

The current slice contains only the refined input type. A CAN is printed on
the card, but it is sensitive access data because it enables PACE access to
the chip; the validated `Can` is opaque, non-clonable, and zeroizing.

Constraints are traced to
[ICAO Doc 9303](https://www.icao.int/publications/doc-series/doc-9303) and
the [DVV FINEID specifications](https://dvv.fi/en/fineid-specifications).
