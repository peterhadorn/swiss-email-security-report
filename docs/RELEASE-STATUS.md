# `v2026.08.2` release status

Last independently verified against the private run manifests, final database,
sealed assets, DOI record, and live KI-Barometer deployment on 26 August 2026.

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
