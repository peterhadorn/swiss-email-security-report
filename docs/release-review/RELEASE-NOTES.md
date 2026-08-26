# Release notes v2026.08.2

**Review source — not a sealed release file.** Publication awaits final sealing and upload verification.

## Release identity

`v2026.08.2` is the initial public release candidate for the fresh provenance-enabled Swiss email-security measurement started on 21 August 2026. It is not a repackaging or silent correction of the archived 17–19 August legacy database.

Source universe:

- normalized SWITCH `.ch` zone snapshot dated 12 April 2026;
- 2,459,127 normalized domains;
- authenticated source identity in release.json.

Accepted run chain:

- full run: 2,459,127 attempted; 2,310,275 analyzable and 148,852 errors;
- linked retry: all 148,852 error rows attempted; 2,316,512 analyzable and 142,615 errors final;
- public interval: 2026-08-21T21:05:22.017897Z/2026-08-23T18:02:41.508091Z;
- final private database identity and size authenticated in aggregate-attestation.json;
- final manifest identity authenticated in release.json and aggregate-attestation.json.

## Included artifacts

The DOI-bound staging contains 68 canonical metrics in JSON and CSV, an aggregate attestation, the signed DOI reservation, citation metadata, five reviewed documents, 30 localized figure files and their manifest, and code and data licenses. The DOI-bound staging also contains the owner-signed approval of the complete artifact tree. The sealed release additionally requires a complete checksum inventory.

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

Completed: scan, all-error-row retry, manifest-chain validation, closed database identity, independent aggregate reconciliation, privacy checks, signed DOI reservation, DOI-bound documents and figures, and full local tests.

Remaining controlled gates: final sealing, GitHub and Zenodo publication, and checksum comparison.
