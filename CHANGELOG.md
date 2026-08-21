# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

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
