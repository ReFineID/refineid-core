# refineid-atr

Answer-to-Reset parsing for card identification.

A driver identifies a card by the ATR the reader returns at power-up.
`Atr::new` parses that byte string into its ISO 7816-3 section 8 structure:
the transmission convention from TS, the format byte T0, the interface
byte chain (the TA/TB/TC/TD groups that each TDi's presence nibble
continues), the historical bytes, and the check character TCK. The TCK is
verified -- the XOR of T0 through TCK must be null (ISO 7816-3 section
8.2.5) -- so a corrupt ATR is rejected rather than trusted as an identity.

The historical bytes are read per ISO 7816-4 section 8: the category
indicator, and, for the compact-TLV format every FINEID card uses, each
(tag, value) entry lifted into a typed `HistoricalDataObject` -- card
service data, card capabilities, status indicator, and country decoded to
their interior, issuer-proprietary tags kept verbatim. The parsed field
types -- `T0`, the interface byte groups, and the compact-TLV entries --
carry private fields, so a value of each exists only as parser output.

The crate parses; it performs no card I/O and reads no files. Constants are
traced to ISO 7816-3 and ISO 7816-4, and the Thales and Gemalto MultiApp
ATRs serve as known-answer parser vectors.
