# Supported FINEID cards

The cards these crates target, by manufacturer and platform version, with
the FINEID specification each implements and the answer-to-reset (ATR,
contact) and answer-to-select (ATS, contactless) each presents. The core
is generation-agnostic -- it reads and drives every generation through the
same commands, using the per-generation fallback variants the read and
select paths carry -- so this table is reference material, not a
switch the code makes.

| Card | FINEID spec | Category | In production |
| --- | --- | --- | --- |
| Thales MultiApp v5.0 | S4-1 v4.0 | Citizen eID | 2023-03-13 → |
| Gemalto MultiApp v4.2 | S4-1 v3.1 | Citizen eID | 2021-01-11 – 2023-03-12 |
| Gemalto MultiApp v3.0 | S4-1 v3.0 | Citizen eID | 2017-01-01 – 2021-01-10 |
| Idemia Cosmo X | S1 v5.0 | Social welfare and organizational | ~2025 → |

## Answer-to-reset and answer-to-select

Bytes are hexadecimal, most significant first.

**Thales MultiApp v5.0** (S4-1 v4.0)

- ATR: `3B 7F 96 00 00 80 31 B8 65 B0 85 05 00 11 12 24 60 82 90 00`
- ATS: `14 78 77 95 02 80 31 B8 65 B0 85 05 00 11 12 24 60 82 90 00`

**Gemalto MultiApp v4.2** (S4-1 v3.1)

- ATR: `3B 7F 96 00 00 80 31 B8 65 B0 85 04 02 1B 12 00 F6 82 90 00`
- ATS: `14 78 77 95 02 80 31 B8 65 B0 85 04 02 1B 12 00 F6 82 90 00`

**Gemalto MultiApp v3.0** (S4-1 v3.0)

- ATR: `3B 7F 96 00 00 80 31 B8 65 B0 85 03 00 EF 12 00 F6 82 90 00`
- ATS: `14 78 77 95 02 80 31 B8 65 B0 85 03 00 EF 12 00 F6 82 90 00`

**Idemia Cosmo X** (S1 v5.0)

- ATR: `3B DD 96 00 80 31 FE 45 00 31 B8 64 04 29 EC C1 73 94 01 80 83 49`
- ATS: `3B 89 80 01 00 31 B8 64 04 29 EC C1 73 94 01 80 83`

## Hardware-validation coverage

The [core migration policy](../architecture/core-migration.md) records
which paths have been observed on which card. To date the citizen paths
were exercised on the **Gemalto MultiApp v4.2** (S4-1 v3.1) and **Thales
MultiApp v5.0** (S4-1 v4.0) generations over both interfaces; the older
**Gemalto MultiApp v3.0** and the **Idemia Cosmo X** organizational card
were not available, so the organizational chains and the v3.0 generation
rest on the specification and the behaviour reference.
