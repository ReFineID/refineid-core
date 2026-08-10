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

The second slice admits the APDU foundation in `refineid-apdu`:

- typed ISO 7816-4 command builders and validated primitives, every wire
  value a named constant;
- the decoded status word;
- the two command ownership paths: a debuggable public command with no
  raw-bytes constructor and no `Clone`, and a zeroizing, non-clonable,
  redacted credential command assembled from a custody-taking body and
  consumed exactly once; and
- the typed-only transport port, with no byte-slice transmit, so a
  builder-granted permission such as the single wrong-Le correction
  survives to the adapter.

## Quarantined until redesigned

The admitted APDU slice replaces the quarantined designs from the private
development tree: an unrestricted raw command constructor, command buffers
deriving `Clone`, a byte-slice transport path that silently copied buffers
and dropped builder permissions, and credential bytes travelling through
generic command types do not enter the public tree in any form.

Still outside the public tree:

- transport adapters until their custody and fault paths pass review;
- authentication and signing command chains;
- automatic retry paths of any kind around credential commands; and
- the legacy PIN cache.

A credential command must never enter generic tracing before redaction.

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
