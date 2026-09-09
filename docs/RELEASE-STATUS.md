# Release and publication status

## Current publication: 9 September 2026

The report is published on WebEvolve in German, French, Italian and English.
The [README language table](../README.md#read-the-report-or-download-the-data)
links to each article and its data downloads. The former KI-Barometer article
and data-page addresses permanently redirect to the matching WebEvolve articles.
The former corrections page redirects to the German article’s correction section.

Each article includes CSV/JSON downloads, the four study chart families and
correction guidance. WebEvolve hosts byte-identical copies of the public data and
chart files. Legacy KI-Barometer file URLs remain available for existing citations.
Both Zenodo DOI [10.5281/zenodo.22116736](https://doi.org/10.5281/zenodo.22116736)
and the [GitHub release v2026.08.2](https://github.com/peterhadorn/swiss-email-security-report/releases/tag/v2026.08.2)
provide the unchanged original archive.

The article move and README edits do not represent a new scan, a new dataset or
a new verification of the private measurements. No archived release files or
signed provenance were modified.

## Verification date

The recorded independent verification took place on **26 August 2026**. It covered
the private scan records, final database, archived release files, DOI record and
the KI-Barometer publication as it existed then. That date has not been advanced
by later website or documentation updates.

## Website update: 7 September 2026

The website added updated editorial charts and explanations in four languages.
Those downloadable charts use the unchanged release metrics. Their source files
and generated downloads remain in the KI-Barometer website repository.

The original archive contains 30 charts in German, French and Italian. English
charts and newer versions are separate website downloads, not replacements for
the archived files.

The repository's default development branch is `main`. The published `v2026.08.2`
tag and release files retain their original identities.

## Technical release record

The following records describe the original release, not a new September scan.

### Original measurement and verification

- The provenance-enabled root run covered the complete normalized 2,459,127-
  domain source universe.
- Root accounting reconciles to 2,310,275 analyzable rows plus 148,852 rows
  retaining an error status.
- The linked retry attempted every one of those 148,852 error rows and wrote
  every attempted result.
- Final accounting reconciles to 2,316,512 analyzable rows plus 142,615 retained-
  error rows, for the same 2,459,127-row universe.
- The manifest chain validates its input/output database identities, source
  checksum, scanner revisions, measurement-core transition, resolver settings,
  execution pins, timestamps, and row accounting.
- The sealed release validates against the final database and contains 68
  canonical metrics, CSV and JSON representations, an aggregate attestation,
  immutable inventory, DOI-bound metadata, and final release manifest.
- Release documentation and the DE/FR/IT figure matrix are complete and validated.
- The complete local test suite passed under the pinned Python 3.12 environment at release verification.

### Original release approvals and publication

- The release owner approved and configured the Ed25519 DOI-authority fingerprint.
- Zenodo DOI 10.5281/zenodo.22116736 is published and resolves to the sealed release assets.
- The DOI-bound citation, five reviewed documents, and exact 30-file DE/FR/IT figure matrix are generated and validated.
- The release owner approved and signed the complete prospective artifact tree.
- The finalizer created the immutable inventory and sealed release directory. All checksums and signatures verified.
- Commit 721e0b5 is tagged as v2026.08.2 and the tag is published.
- GitHub and Zenodo publish the same 3,002,167-byte archive with SHA-256 07ec8531d6b257a49abd10d4e9fcb6e06835e63852e6dd8a8b8e7871c32c71f7.
- KI-Barometer originally published the manifest, aggregate JSON/CSV downloads, DOI, archive links and DE/FR/IT report pages. The articles have since moved to WebEvolve. Downloads are now also included in the WebEvolve articles. The legacy file URLs remain available.

## Requirements for a future data release

All approval steps for v2026.08.2 are complete. Changing the measurements or the
scanner code used to produce them requires a new release version and a new
record of its inputs, processing steps and approvals.
