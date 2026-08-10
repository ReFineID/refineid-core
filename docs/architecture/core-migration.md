# Common-core migration policy

This repository receives reviewed snapshots, not a dump of the original
development tree or its history. Each slice must be independently buildable,
licensed, scrubbed, and understandable without private context.

The core is split into small crates so each unit can be audited alone and so
every crate's dependency set stays minimal. A crate is admitted with only the
modules its slice has passed review for; the rest of its charter arrives in
later slices.

## Trust by construction

Boundary data starts in an explicitly unvalidated type. A constructor then:

1. deconstructs the raw representation;
2. checks every structural invariant once;
3. reconstructs a domain type with private fields; and
4. destroys the raw secret-bearing representation.

Downstream code accepts the reconstructed type. It must not repeat scattered
"just in case" validation or keep the raw representation beside the typed one.
If another invariant becomes necessary, it belongs in a new constructor or a
new type-state transition.

## Numeric policy

Anonymous domain numbers are forbidden in production and ordinary tests.
Changing a hexadecimal value to decimal does not name its meaning.

Raw wire values have only two legitimate homes:

- the initializer or discriminant of a truthful named protocol constant; or
- an independently audited exact-wire or known-answer fixture whose purpose is
  to lock externally specified bytes.

The AST-based `xtask` walks integer and floating-point literals, numeric byte
escapes, radix spellings embedded in strings or documentation, patterns,
attributes, and macro token streams. Anonymous constants are not names, and
opaque macro arguments or delayed executable bodies never inherit a constant's
name. Only small reviewed sets of function-like macros, inert attributes, and
derive names may be used; other opaque macros, macro glob imports, `macro_use`,
and rebinding a trusted function-like macro name are rejected. The locked
`zeroize` derive implementation is an explicit dependency trust boundary: its
version, import, and generated drop behavior remain part of dependency and
code review. Source indirection through
symlinks, `include!`, `#[path]`, alternate Cargo target extensions, or
out-of-tree target roots is prohibited. Only the workspace-root build
directory is skipped; a source directory merely named `target` remains in
scope. Ordinary Rust comments are checked lexically. All bytes in non-Rust
files are checked for radix-prefixed values and common numeric escape forms,
even when a file is not valid UTF-8; those spellings remain prohibited until a
language-aware named-value checker exists.
Executable doctests are disabled and rejected in Cargo metadata because their
generated source is opaque to this gate. Security-sensitive negative API
contracts use checked compile-fail consumer fixtures instead.
There is no aggregate baseline: a new offender cannot be traded for an old
one. Dedicated wire-fixture support will be added only with an exact path,
symbol, reason, and primary specification citation.

## Admitted slices

The first slice admits the refined input types, each in the crate that will
own its consuming protocol:

- `refineid-pace`: `UnvalidatedCan` and an opaque, zeroizing `Can` for
  sensitive PACE access data;
- `refineid-auth`: `UnvalidatedSecret`, the zeroize-on-drop raw input
  boundary, and the non-clonable, non-copyable `Pin1` and `Pin2` role types;
- the repository policy checker and CI gate.

## Quarantined until redesigned

The following code is intentionally not copied from the private development
tree:

- unrestricted raw APDU constructors;
- command buffers that derive `Clone` or raw `Debug`;
- transports that accept an arbitrary byte slice or silently copy it;
- automatic retry paths that could replay a credential command;
- authentication and signing chains built on those transports; and
- the legacy PIN cache.

The APDU migration needs two ownership paths. Public, replay-safe commands may
use a debuggable public-command type. Credential commands need a separate
zeroizing, non-clonable, non-debuggable type that is consumed by an at-most-once
transport operation. A credential command must never enter generic tracing
before redaction.

## Admission checklist

Every later slice must pass:

- copyright and contribution provenance review;
- public-information and secret scanning;
- domain-type and ownership review;
- zero anonymous numeric literals;
- formatting, tests, Clippy with warnings denied, and rustdoc with warnings
  denied;
- focused adversarial tests for parser and state-machine boundaries; and
- observed hardware validation before a card-mutating or retry-consuming path
  is described as working.

## Provenance

Each slice's publication authorization and reconstruction record are in
[public provenance](../governance/public-provenance.md). Later migrations stop
at any file whose authorship or publication rights are not explicit.
