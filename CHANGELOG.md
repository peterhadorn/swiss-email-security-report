# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### WebEvolve publication — 2026-09-09

- Replace the four README article links with the published WebEvolve URLs.
- Document the permanent, language-matched redirects from KI-Barometer.
- Keep aggregate data, chart downloads and correction-policy URLs on KI-Barometer.
- No changes to scanner code, measurements, signed provenance or the sealed v2026.08.2 archive.

### Publication navigation — 2026-09-07

- Link all four report languages and their data/chart download pages.
- Distinguish current website charts from the original sealed figure archive.
- Document the September website updates separately from the August private-data
  verification and rename the default development branch to main.

### Review fixes — 2026-09-07

- Preserve the sealed release if staging cleanup fails, and require the signed
  release files during verification. Add a public `verify` CLI command.
- Allow retained scanner-exception rows to be excluded from aggregate results
  without blocking the entire export.
- Correct SPF parsing for the first `all` mechanism and disabled `redirect`
  terms. Preserve exact historical core bytes for release verification; new
  scans use a different core identity and cannot resume the historical scan.
- Correct DMARC denominator and overlapping-alignment descriptions without
  changing their counting rules.
- Prevent caption and label overlap in localized social cards.
- Rewrite the README and clarify publication state, interpretation limits,
  and what public verification can establish without private measurements.
- Add regression coverage: 418 tests pass, and the original published archive
  still passes checksum and signature verification. Sealed assets are unchanged.

### Measurement interpretation — 2026-09-06

- Documented historical DMARC parsing, DKIM key-length, DS-presence and sampling
  limitations without changing sealed v2026.08.2 data or measurement-core bytes.
- Added a separately tested future DKIM parser candidate: exclude Ed25519 and
  unknown algorithms from the RSA length heuristic; recognise combined testing
  flags. Integration requires a new measurement-core version and provenance.
- Linked the four-language public report, aggregate downloads and chart gallery.

### Added

- The sealed v2026.08.2 aggregate bundle, permanent DOI, and matching GitHub
  Release and dataset download locations.
- A single release-owner signature over the complete artifact tree, replacing
  the disproportionate five-person editorial gate without weakening checksum,
  DOI, key-fingerprint, or tamper verification.
- Privacy-safe prose references to authenticated structured identities instead
  of duplicating raw hashes in release documents.
- The reviewed WebEvolve correction contact and SECURITY.md reference in the
  strict public-text privacy catalogue.
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
