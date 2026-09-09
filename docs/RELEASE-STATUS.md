# `v2026.08.2` release status

Last independently verified against the private run manifests, final database,
sealed assets, DOI record, and live KI-Barometer deployment on 26 August 2026.

## Website and documentation update: 7 September 2026

- The report and dataset pages are now available in German, French, Italian
  and English. All four are linked from the repository README.
- The website provides updated editorial charts in all four languages, derived
  from the unchanged release metrics. Their source and generated assets live in
  the KI-Barometer website repository.
- Website copy, chart labels and expandable technical explanations were updated.
  These presentation changes do not modify the sealed data or archive.
- The archive still contains the original 30 German, French and Italian figure
  files. English and newer editorial charts are separate website downloads.
- This documentation update does not claim a new independent verification of
  the private measurements. The verification date above remains 26 August 2026.

The repository's default development branch is now named main. The published
v2026.08.2 tag and release assets retain their existing identities.

## Completed

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
- The complete local test suite passes under the pinned Python 3.12 environment.

## Completed release gates

- The release owner approved and configured the Ed25519 DOI-authority fingerprint.
- Zenodo DOI 10.5281/zenodo.22116736 is published and resolves to the sealed release assets.
- The DOI-bound citation, five reviewed documents, and exact 30-file DE/FR/IT figure matrix are generated and validated.
- The release owner approved and signed the complete prospective artifact tree.
- The finalizer created the immutable inventory and sealed release directory; all checksums and signatures verify.
- Commit 721e0b5 is tagged as v2026.08.2 and the tag is published.
- GitHub and Zenodo publish the same 3,002,167-byte archive with SHA-256 07ec8531d6b257a49abd10d4e9fcb6e06835e63852e6dd8a8b8e7871c32c71f7.
- KI-Barometer publishes the sealed manifest, aggregate JSON/CSV downloads, DOI, archive links, and indexed DE/FR/IT report pages.

## Publication state

No controlled release gates remain for v2026.08.2. Any change to the underlying
measurement or measurement-core identity requires a new release version and
provenance chain.

## WebEvolve article migration — 9 September 2026

The report is now published on WebEvolve in German, French, Italian and English.
See the [README language table](../README.md#read-the-report-or-download-the-data)
for the current article and download URLs. The four former KI-Barometer article
URLs use permanent redirects to the matching WebEvolve translations.

The aggregate dataset, current chart downloads and corrections policy remain
on KI-Barometer. Zenodo DOI 10.5281/zenodo.22116736 and the v2026.08.2 GitHub
Release are unchanged. This is a publication-location update, not a new scan or
a new data release. No sealed files or signed provenance were modified.
