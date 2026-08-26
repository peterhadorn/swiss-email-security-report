# `v2026.08.2` release status

Last independently verified against the private run manifests, final database,
and aggregate staging on 25 August 2026.

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
- Aggregate staging validates against the final database and contains 68
  canonical metrics, CSV and JSON representations, an aggregate attestation,
  and a staging release manifest.
- Release README, methodology, data dictionary, corrections, and release-notes
  review sources are complete and pass the final document structure contract
  after injection of DOI-bound metadata; they remain outside staging until a
  real reservation exists.
- The complete local test suite passes under the pinned Python 3.12 environment.

## Completed release gates

- The release owner approved and configured the Ed25519 DOI-authority fingerprint.
- Zenodo DOI 10.5281/zenodo.22116736 is reserved in an unpublished draft and its signed attestation is bound to aggregate staging.
- The DOI-bound citation, five reviewed documents, and exact 30-file DE/FR/IT figure matrix are generated and validated.
- The release owner approved and signed the complete prospective artifact tree.
- The finalizer created the immutable inventory and sealed release directory; all checksums and signatures verify.

## Remaining controlled gates

1. Tag the approved commit, publish identical GitHub and Zenodo assets, and verify the DOI and checksums. The scanner repository is already public; no version tag or sealed release asset is published before these gates pass.

The completed measurement and retry do not need to be rerun for these remaining
steps. Any change to the underlying measurement or measurement-core identity
would instead require a new release version and provenance chain.
