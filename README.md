# Swiss Email Security Report

How widely do Swiss `.ch` domains publish email-security records?
This project checks public DNS records and publishes aggregate results, together
with the code and documentation needed to understand how they were measured.

**It measures published DNS signals, not how secure a company or mail service is.**
A record can exist without working correctly, and an undetected record does not
always mean the technology is unused.

## Read the report or download the data

The report is published by WebEvolve in four languages. The former KI-Barometer
article URLs permanently redirect to the corresponding translations. Aggregate
data, downloadable charts and the corrections policy remain hosted on
KI-Barometer. Both studies are listed in the [WebEvolve study overview](https://webevolve.ch/studien/).

| Language | Report | Data and current charts |
| --- | --- | --- |
| Deutsch | [Artikel](https://webevolve.ch/studien/schweizer-e-mail-sicherheitsreport/) | [Daten und Grafiken](https://ki-barometer.ch/datasets/ch-email-security-2026/) |
| Français | [Rapport](https://webevolve.ch/fr/etudes/rapport-securite-e-mail-suisse/) | [Données et graphiques](https://ki-barometer.ch/fr/datasets/ch-email-security-2026/) |
| Italiano | [Rapporto](https://webevolve.ch/it/studi/rapporto-sicurezza-email-svizzera/) | [Dati e grafici](https://ki-barometer.ch/it/datasets/ch-email-security-2026/) |
| English | [Report](https://webevolve.ch/en/studies/swiss-email-security-report/) | [Data and charts](https://ki-barometer.ch/en/datasets/ch-email-security-2026/) |

- [Published dataset on Zenodo](https://doi.org/10.5281/zenodo.22116736)
- [GitHub release v2026.08.2](https://github.com/peterhadorn/swiss-email-security-report/releases/tag/v2026.08.2)

The published bundle contains 68 aggregate metrics, documentation, 30 figures
in German, French and Italian, checksums, and a signed release-owner approval.
The GitHub and Zenodo downloads contain the same sealed archive.

The website also provides newer editorial charts in German, French, Italian
and English. These use the unchanged release metrics with updated wording and
presentation. They are maintained with the KI-Barometer website, separately
from the sealed archive. Use the language links above to download the
current charts. The original 30 archived figures remain available in v2026.08.2.

## What was measured?

The published release used the SWITCH `.ch` zone snapshot from **12 April 2026**.
DNS measurement ran on **21–23 August 2026**, including a retry of every row
that retained an error after the first pass.

| Population | Domains |
| --- | ---: |
| Source universe | 2,459,127 |
| Analyzable after retry | 2,316,512 |
| Retained errors, excluded from substantive results | 142,615 |

Percentages use different denominators. For example, many email metrics refer
only to analyzable domains with a non-null MX record. Each metric states its
numerator and denominator. Domains are not companies: one company can own many.

| Signal | What the scanner observes |
| --- | --- |
| MX | Published mail-routing hosts and their hostname-based provider categories |
| SPF | A matching TXT record and selected top-level mechanisms |
| DKIM | Key material at a provider-dependent set of guessed selectors |
| DMARC | A matching TXT record and selected policy tags |
| DS and TLSA | Record presence, without DNSSEC-chain or DANE validation |
| BIMI, MTA-STS and TLS-RPT | DNS TXT signals; no policy retrieval or delivery test |
| NS and CAA | Selected supporting DNS records |

**Read the [measurement limitations](docs/KNOWN-MEASUREMENT-LIMITATIONS.md) before
interpreting results.** In particular, DKIM detection is incomplete, the historical
key-length heuristic is not a weak-key rate, and DMARC tags do not prove actual
message handling. The excluded error population may differ from the rest.

## What can you verify?

Anyone can check the public files' checksums, signatures, arithmetic, denominators,
and consistency across documents and metadata. The signatures authenticate the
release owner's declarations about the private measurement inputs.

Independently confirming the database hash, inspecting the full private run
chain, or recomputing results requires authorized access to the original private
inputs and measurements. Running a new scan today will not reproduce historical
DNS answers.

Raw inputs, domain lists, DNS records and domain-level results are **not published**.
Do not attach them to issues or commits. See [SECURITY.md](SECURITY.md) for private
vulnerability reporting and the [corrections policy](https://ki-barometer.ch/datasets/ch-email-security-2026/corrections/)
for problems with the results or wording.

## Work with the code

Use Python 3.12 or later. From a clone of this repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

The release tooling also needs an `openssl` executable with Ed25519 support.
To verify an extracted published bundle, use its absolute directory path:

```bash
python -m release.build_release verify --directory /path/to/v2026.08.2
```

To inspect your own local scanner database:

```bash
python analyze_dmarc.py /path/to/scan.db
```

The analyzer prints a descriptive summary; it is not the public release exporter.
Keep scan inputs and outputs outside version control. Scans write a private
SQLite database, an adjacent manifest and a manifest archive. Resume supports
retrying errors from a completed, compatible full scan; it is not recovery of
an interrupted or limited scan.

## Published release versus current code

**The published v2026.08.2 archive is unchanged.** Current code includes later
bug fixes and clearer descriptions. Corrected SPF parsing is used for new scans;
its measurement-core checksum differs from the published run. It cannot resume
the historical scan or be substituted into its provenance chain.

Historical verification uses the exact archived core bytes in
`dmarc_scanner/history/v2026.08.2/`. To reproduce the historical software environment,
use the [v2026.08.2 tag](https://github.com/peterhadorn/swiss-email-security-report/tree/v2026.08.2).
Changes to DOI-bound files or measurements require a new release and approval.
The exporter remains pinned to v2026.08.2; publishing a new measurement requires
new release configuration, schemas and provenance.

See the [release status](docs/RELEASE-STATUS.md), [provenance guide](provenance/README.md),
and [historical review documents](docs/release-review/README.md) for details.

## Licenses

Code is [MIT-licensed](LICENSE). Published aggregate data, documentation and figures
use [CC BY 4.0](release/LICENSE-DATA.md), with attribution to Peter Hadorn / WebEvolve.
The private source corpus and measurements are not included in that license grant.
