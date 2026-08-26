# Swiss Email Security Report aggregate release v2026.08.2

**Review source — not a sealed release file.** The final copy receives the reserved DOI and authenticated artifact inventory only after external DOI approval and editorial signoff.

Release-Version: v2026.08.2
Source-Snapshot-Date: 2026-04-12
Measurement-Started-At: 2026-08-21T21:05:22.017897Z
Measurement-Finished-At: 2026-08-23T18:02:41.508091Z
Repository: https://github.com/peterhadorn/swiss-email-security-report
Aggregate-data-and-figures-license: CC BY 4.0
Code-license: MIT

## Scope

This release contains aggregate observations of public DNS configuration for the normalized 12 April 2026 SWITCH `.ch` zone snapshot. It is a measurement of published technical signals, not a security rating of organizations, domains, mail providers, or services.

The source universe contains 2,459,127 domains. The provenance-enabled full run produced 2,310,275 analyzable rows and 148,852 rows retaining an error. A linked retry attempted all 148,852 error rows. Final accounting is 2,316,512 analyzable rows plus 142,615 retained-error rows.

The public measurement interval begins with the fresh full-run start and ends with the accepted retry finish. It does not use the earlier 17–19 August legacy database as the release measurement.

## Contents

The sealed bundle will contain:

- canonical aggregate metrics in JSON and CSV;
- an aggregate attestation binding the metrics to the final private database identity and run-manifest chain;
- a release manifest and complete checksum inventory;
- a DOI reservation attestation and its approved public verification key;
- German, French, and Italian SVG and PNG figures generated from canonical metric IDs;
- citation metadata, methodology, data dictionary, release notes, licenses, and correction policy;
- authenticated scientific, privacy, and language signoff metadata.

No domain list, zone snapshot, raw DNS response, domain-level error record, hashed-domain list, or SQLite database is included.

## Citation

The final citation will identify Peter Hadorn as author, the title “Swiss Email Security Report aggregate data”, release `v2026.08.2`, the reserved Zenodo DOI, and this canonical repository. No synthetic DOI is permitted in the sealed bundle.

Until DOI reservation and sealing are complete, cite neither this review source nor the aggregate staging tree as a published research release.

## Privacy

Only aggregate counts, denominators, percentages, methods, caveats, provider fingerprint categories, and provenance identities cross the private/public boundary.

Domain names and domain-level DNS material remain private. Hashed-domain publication is prohibited because the finite public `.ch` universe makes dictionary reversal practical. The private database path and infrastructure paths are excluded from public metadata.

## Licenses

Scanner and release-builder code are licensed under MIT. Aggregate data and generated figures are licensed under CC BY 4.0.

The SWITCH zone snapshot, domain list, private database, and any third-party source material are excluded from the data license grant and are not distributed.

## Reproduction

The public repository provides the scanner, manifest validators, deterministic aggregate implementations, schemas, figure generator, and release finalizer.

Reproducing the exact aggregate values additionally requires authorized access to the same source universe and private domain-level measurements. Verification of the published bundle does not: users can validate checksums, schemas, arithmetic identities, metric denominators, run-chain bindings, database identity, and cross-file references without the private records.

The release uses:

- Python 3.12 execution pins recorded in the run manifests;
- dnspython 2.8.0;
- resolver rotation across 1.1.1.1, 8.8.8.8, 9.9.9.9, 1.0.0.1, and 8.8.4.4;
- cache-disabled resolver configuration with recorded timeout and lifetime settings;
- a single explicit read-only SQLite snapshot for aggregate export;
- two independent aggregate SQL implementations compared metric by metric.

The repository test suite and release validators are the executable specification. The final top-level checksum inventory authenticates every public payload except the inventory file itself.

**Review status.**

Completed: full scan, all-error-row retry, manifest-chain validation, closed database identity, independent aggregate reconciliation, 68 canonical metrics, aggregate staging, privacy scan, and test suite.

Controlled remaining work: real DOI reservation and approval binding, DOI-bound figures and documents, five distinct editorial signoffs, final sealing, GitHub/Zenodo publication, checksum comparison, and repository visibility change.
