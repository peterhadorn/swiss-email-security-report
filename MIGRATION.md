# Clean-history migration

This repository is a clean-history import for the Swiss Email Security Report.
It contains a deliberately scoped scanner implementation and its associated
tests, with exact source bytes imported from two predecessor snapshots:

- Runtime repository `swiss-web-report-dmarc`, external Git SHA-1
  `74fb8d16f162a471d0b9d89f852ffe2603ae0522`.
- Legacy public repository `swiss-web-report`, external Git SHA-1
  `267a25932a14a1ac19e1f4dee66aafa89c7fcb97`.

Every imported scanner file is byte-identical to both snapshots and is listed
with its SHA-256 checksum in `provenance/scanner-files.sha256`. Predecessor Git
objects, refs, branches, tags, and unrelated source files were excluded from
this repository.

The underlying measurement consists of DNS measurements performed 17–19 August
2026 over the normalized 12 April 2026 SWITCH `.ch` zone snapshot. This
repository remains private until its release gate is satisfied; it is intended
to become public only with approved aggregate data and reproducibility assets.

No raw database, zone input, domain list, hashed-domain list, or domain-level
result is included or permitted for public release.
