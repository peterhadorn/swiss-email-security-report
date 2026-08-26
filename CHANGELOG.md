# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- The separately approved Ed25519 DOI authority fingerprint for v2026.08.2.
- Repository-local .secrets/ storage is ignored for release credentials such
  as the Zenodo token.
- Clarification that the scanner repository is public while the DOI-bound
  aggregate research release remains unsealed and subject to its review gate.
- Dedicated clean-history repository foundation for the Swiss Email Security
  Report scanner and its email-security test suite.
- Pinned runtime and development dependency declarations, private-data
  exclusions, descriptive analyzer terminology, and coordinated disclosure
  guidance.
- Private, atomic scan sidecar manifests with normalized-input and output
  checksums plus runtime and resolver provenance.
- Per-query DNS statuses so partial resolver failures are retained and retried
  rather than being interpreted as record absence.
- Legacy result databases are refused as scanner outputs before any mutation;
  checkpoint and Git-provenance failures cannot leave a stale manifest behind.
- Python result-constructor terminology now explicitly uses `has_ds_record`
  and `has_tlsa_record`; only archived SQLite reads retain legacy-column
  compatibility through `metric_column()`.
- A pinned `v2026.08.2` release pipeline now validates the complete scan chain,
  stages aggregate-only metrics from one SQLite snapshot, atomically binds an
  Ed25519-authenticated reserved Zenodo DOI, and seals the exact signed,
  privacy-catalogued multilingual figure and documentation set with fresh
  inodes and whole-tree checksums. Production DOI binding remains fail-closed
  until its user-owned approval-key fingerprint is configured. Its installed
  package includes the DE/FR/IT metric catalogues, and the finalizer enforces an
  exact accessible SVG layer template plus normalized path, identifier, DNS,
  address, and hash privacy boundaries.
- The exact 30-file DE/FR/IT editorial figure matrix now ships its reviewed
  chart catalogue and OFL-licensed DM Sans asset as package data. Every SVG
  embeds and explicitly uses the hash-pinned font through one strictly
  validated inactive declaration; PNG partners are rasterized from those SVG
  elements with pinned Pillow only. Prominent percentages use locale decimal
  commas, expose exact numerators and denominators, and the redesigned social
  layout keeps its accent clear of the kicker, source, and DOI.
- Aggregate output now reports malformed numeric DMARC `pct=` values separately
  from valid partial-policy observations, rather than misclassifying or hiding
  those published record values.
- Aggregate output likewise reports unsupported DMARC alignment-tag values
  separately from valid relaxed or strict alignment observations.
- Documented the completed `v2026.08.2` full-universe run, exhaustive retained-
  error retry, final row accounting, and validated aggregate-staging boundary.
- Clarified that `provenance/scanner-files.sha256` authenticates the clean-import
  root commit rather than the subsequently evolved scanner files at current
  `HEAD`.
- Added complete review sources for the release README, methodology, data
  dictionary, correction policy, and release notes. They bind the accepted
  21–23 August run chain and final aggregate identities while remaining
  explicitly outside the DOI-bound staging tree until external approval.
