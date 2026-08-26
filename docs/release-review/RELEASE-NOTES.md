# Release notes v2026.08.2

**Review source — not a sealed release file.** Publication awaits the real DOI, DOI-bound figures/documents, distinct signoffs, and final inventory.

## Release identity

`v2026.08.2` is the initial public release candidate for the fresh provenance-enabled Swiss email-security measurement started on 21 August 2026. It is not a repackaging or silent correction of the archived 17–19 August legacy database.

Source universe:

- normalized SWITCH `.ch` zone snapshot dated 12 April 2026;
- 2,459,127 normalized domains;
- SHA-256 `be742a42b89dbac80b5296316d35a2d245383e31d15d5df0b1242af8ec9e07c8`.

Accepted run chain:

- full run: 2,459,127 attempted; 2,310,275 analyzable and 148,852 errors;
- linked retry: all 148,852 error rows attempted; 2,316,512 analyzable and 142,615 errors final;
- public interval: 2026-08-21T21:05:22.017897Z/2026-08-23T18:02:41.508091Z;
- final private database: 3,478,831,104 bytes; SHA-256 `a503dab7c0079c8b14f22b274592be1a7b3fc39deec9d9c0acd4e66c7729a575`;
- final manifest SHA-256: `3f33f98a6d2924ed3b34e64af9dcb433083d722f6977df625f4d7ad930f70cd6`.

## Included artifacts

The completed aggregate staging contains 68 canonical metrics in JSON and CSV, an aggregate attestation, and a lifecycle manifest. The sealed release additionally requires:

- complete checksum inventory;
- DOI reservation attestation and approved public key;
- citation metadata;
- methodology, data dictionary, correction policy, release README, and these release notes;
- 30 localized figure files plus their manifest;
- code and data licenses;
- authenticated scientific, privacy, German, French, and Italian signoffs.

Only aggregate public data are included. Domain-level inputs and results remain private.

## Known limitations

- 142,615 rows retained an error after the complete retry and are excluded from substantive denominators.
- The source universe is a domain corpus, not a company register.
- SPF analysis does not fully recurse through every `include` and `redirect`.
- DKIM selector detection is a lower bound; weak-key detection is a length heuristic.
- DMARC tags measure published policy signals, not recipient behavior or incidents.
- DS and TLSA metrics measure record presence, not validated DNSSEC or functional DANE.
- BIMI, MTA-STS, and TLS-RPT metrics measure DNS record presence only.
- MX provider categories are hostname fingerprints, not market share or contractual relationships.
- DNS observations are time-dependent and specific to the recorded interval.

## Corrections

Release payloads become immutable after sealing. Confirmed public-file changes create a new version with new checksums, a documented rationale, and linked DOI metadata. Prior versions remain citable.

Correction contact: `hallo@webevolve.ch`. Public policy: https://ki-barometer.ch/datasets/ch-email-security-2026/corrections/.

**Publication state.**

Completed: scan, all-error-row retry, manifest-chain validation, closed database identity, independent aggregate reconciliation, privacy checks, aggregate staging, and full local tests.

Remaining controlled gates: DOI approval/reservation, DOI-bound figure/document generation, five distinct signoffs, final sealing, GitHub and Zenodo publication, checksum comparison, and repository visibility change.
