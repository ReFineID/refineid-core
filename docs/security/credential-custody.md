# Credential custody

This is the target contract for PIN-bearing code. The current public slice
implements only the refined input types; it does not yet cache a PIN or build a
credential APDU.

## PIN2

PIN2 is never cached. It is entered for one qualified-signature operation,
reconstructed as `Pin2`, consumed by an at-most-once credential command, and
zeroized on every success or error path.

PIN2 must never be clonable, serializable, persisted, placed on a command line,
stored in an environment variable, or rendered by `Debug`, tracing, panic, or
error output.

## PIN1 authentication convenience window

FINEID S4-1 v4.2 sections 4.1 and 8.1.7 require user interaction and manual
PIN1 entry for every authentication-key signing operation. ReFineID's explicit
product decision is to provide a bounded convenience exception for PIN1
authentication operations, including TLS client-auth signatures driven by
CryptoTokenKit. The software re-presents PIN1 to the card for every operation;
it does not treat card verification state as persistent. This exception must be
disclosed as a profile deviation in public release documentation. It never
extends to PIN2 or either qualified-signature key. The current specification is
published on the
[DVV FINEID specifications page](https://dvv.fi/en/fineid-specifications).

The default maximum is a 15-minute idle window measured by a monotonic clock
from the last card-confirmed successful use. It is not a wall-clock lifetime
from entry and it is not refreshed by checkout, prompt display, local parsing,
or a failed operation. A host with a scheduler actively releases the resident
entry at the deadline; every lookup independently rejects an expired entry.

Reusable retention is allowed only when every live credential retry counter is
in its pristine state. The cached entry is bound to the complete card token
identifier and the PIN1 authentication role. Its capability excludes PIN
management, PIN2, and qualified-signature operations.

Use is destructive checkout:

1. atomically remove the entry from the cache;
2. attempt one credential operation;
3. restore it only after the card confirms success; and
4. set `last_successful_use` to that confirmed monotonic instant.

Dropping an in-flight checkout, receiving a card error, or losing the caller
must destroy the value rather than resurrect it.

## Mandatory invalidation

Positive PIN1 state is destroyed on:

- card removal, reader loss, or token-identifier mismatch;
- wrong-PIN, blocked-PIN, malformed-response, or transport failure;
- screen lock, logout, process exit, system sleep, or explicit lock;
- retry-counter state below pristine or unavailable counter state; and
- any generation change while a checked-out value is in flight.

Process-lifetime memory of card-rejected candidates may retain only a keyed,
constant-time-comparable fingerprint bound to the full card identifier and PIN
role. It must not retain the PIN or a reversible value. This negative memory is
not persisted.

## Representation and transport

- Secret fields are private and zeroize on drop.
- PIN role types do not implement `Clone`, `Copy`, serialization, or raw
  `Debug`.
- Errors carry shape and state, never a rejected byte or credential value.
- A credential APDU is a separate zeroizing type, consumed by a transport API
  that cannot replay it.
- APDU tracing classifies and redacts before any hexadecimal formatting or sink
  call.
- UI entry uses an operating-system secure text field. CLI entry is echo-off
  and reads from a terminal, never argv or the environment.

These rules are release gates, not best-effort guidance.
