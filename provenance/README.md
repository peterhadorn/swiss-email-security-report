# Provenance guide

This directory records two different evidence layers. They must not be merged
or verified as though they described the same Git tree or measurement run.

## Clean-import source provenance

`scanner-files.sha256` authenticates the source bytes imported at clean-history
root commit `867db2561562d44bff5f34f873de98f741ec2962`. Those bytes match the
scoped predecessor snapshots identified in `MIGRATION.md`.

Later commits intentionally changed scanner and test files to add explicit
query statuses, atomic manifests, retry linkage, canonical field names, and
release validation. Consequently, running `shasum -a 256 -c
provenance/scanner-files.sha256` against current `HEAD` is expected to report
mismatches for evolved files. Verify the import manifest against the root tree:

```bash
verification_dir=$(mktemp -d)
git archive 867db2561562d44bff5f34f873de98f741ec2962 | tar -x -C "$verification_dir"
(cd "$verification_dir" && shasum -a 256 -c provenance/scanner-files.sha256)
```

## Archived legacy measurement

`2026-scan.json` records the closed 17–19 August 2026 legacy database. It is
retained as migration, arithmetic-reconciliation, and correction evidence. It
is not the `v2026.08.2` public measurement interval.

## `v2026.08.2` measurement chain

The private release builder has validated this aggregate-only chain:

- normalized source universe: 2,459,127 domains;
- source SHA-256:
  `be742a42b89dbac80b5296316d35a2d245383e31d15d5df0b1242af8ec9e07c8`;
- root interval: 2026-08-21T21:05:22.017897Z through
  2026-08-23T04:10:59.622647Z;
- root post-run accounting: 2,310,275 analyzable rows and 148,852 retained-error
  rows;
- linked retry interval: 2026-08-23T15:52:47.517343Z through
  2026-08-23T18:02:41.508091Z;
- retry attempts: all 148,852 retained-error rows;
- final accounting: 2,316,512 analyzable rows and 142,615 retained-error rows;
- final private database SHA-256:
  `a503dab7c0079c8b14f22b274592be1a7b3fc39deec9d9c0acd4e66c7729a575`.

The manifests and database remain private because they bind domain-level
measurement state. Public staging contains only the sanitized run-chain
metadata, aggregate attestation, 68 metrics, and their reconciled CSV/JSON
representations. The DOI, signed editorial review, final figures and documents,
and immutable release checksums are added only through the remaining release
gate.
