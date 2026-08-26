# Swiss Email Security Report

Scanner source and reproducibility assets for the Swiss Email Security Report.
It is a research repository for aggregate, independently verifiable findings
about DNS-published email-security signals in the Swiss `.ch` namespace.

The repository and sealed aggregate release are public. No raw database, zone input, domain list, hashed-domain list, sampled-domain list, DNS record contents, or domain-level measurement results are published. Do not add these materials in issues, commits, test fixtures, release assets, or derived exports.

## Download the aggregate release

- Zenodo DOI: https://doi.org/10.5281/zenodo.22116736
- GitHub Release: https://github.com/peterhadorn/swiss-email-security-report/releases/tag/v2026.08.2
- Dataset page with direct JSON and CSV downloads: https://ki-barometer.ch/datasets/ch-email-security-2026/

The same sealed archive and archive checksum are published on GitHub and Zenodo. The bundle contains 68 aggregate metrics, documentation, 30 DE/FR/IT figures, an authenticated release-owner approval, and whole-tree checksums.

## Current release state

The v2026.08.2 measurement and retry are complete. The final database contains 2,316,512 analyzable rows and 142,615 retained-error rows from the normalized 2,459,127-domain source universe. The aggregate bundle is DOI-bound, owner-approved, sealed, and checksum-verifiable. It contains no domain-level data. See docs/RELEASE-STATUS.md and provenance/README.md for the exact boundary.

## Scope

The scanner observes selected public DNS records: MX, SPF, provider-aware DKIM
selector probes, DMARC, DS, BIMI, MTA-STS TXT, TLS-RPT, CAA, and SMTP TLSA.
Record presence is descriptive evidence only. It does not demonstrate complete
standard deployment, mail flow, policy retrieval, DNSSEC validation, effective
cryptographic strength, or an organisation's security posture.

In particular, DKIM results are a provider-aware selector lower bound: a
domain can use a selector that was not probed. The key-length result is a
heuristic based on an observed public-key value, not a cryptographic key-size
measurement. MTA-STS results represent the `_mta-sts` TXT record only; the
scanner does not retrieve or validate the HTTPS policy file.

`analyze_dmarc.py` prints a local descriptive summary. It is not the canonical
release exporter and must not be used to produce public aggregate artifacts.

## Development

Requires Python 3.12 or later. Install the development extras, then run the
full email-security suite:

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
```

To inspect a local SQLite result database without exporting it:

```bash
python3 analyze_dmarc.py /path/to/dmarc_scan_results.db
```

Keep that database outside version control. The scanner source is MIT-licensed
in `LICENSE`; licensing for the sealed aggregate dataset and figures is recorded
inside the release bundle.

Each scan writes a private adjacent `*.db.manifest.json` only after SQLite has
committed, checkpointed, and closed. It records reproducibility metadata such
as normalized-input and output checksums, resolver list, scanner revision,
timestamps, runtime, and concurrency settings. The manifest is not a public
release artifact and is ignored by Git along with the result database.

Its input provenance distinguishes the normalized source list from the
effective list after `--shuffle` (seed 42) and `--limit`; `--limit 0` is an
intentional empty scan. It also records the complete public-resolver
configuration and the scanner's Git dirty state. Legacy Python attributes
`dnssec_signed` and `has_tlsa` are not accepted by the Python constructor;
use `has_ds_record` and `has_tlsa_record`. Archived SQLite columns remain
readable through the explicit `metric_column()` adapter and are never migrated
in place.

See `MIGRATION.md`, `provenance/README.md`, and `provenance/2026-scan.json` for
the scoped clean-history import, archived legacy measurement, and current
release-candidate provenance.
