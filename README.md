# Swiss Email Security Report

Scanner source and reproducibility assets for the Swiss Email Security Report.
It is a research repository for aggregate, independently verifiable findings
about DNS-published email-security signals in the Swiss `.ch` namespace.

The repository is private until the release gate. It contains no raw database,
zone input, domain list, hashed-domain list, sampled-domain list, DNS record
contents, or domain-level measurement results. Do not add these materials in
issues, commits, test fixtures, release assets, or derived exports.

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
in `LICENSE`; licensing for a future aggregate dataset and figures is recorded
with the release itself.

See `MIGRATION.md` and `provenance/2026-scan.json` for the scoped clean-history
import and measurement provenance.
