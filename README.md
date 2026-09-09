# Swiss Email Security Report

Forged emails can make a message look as though it came from a trusted company.
This WebEvolve study examines the public settings that Swiss `.ch` domains use
to help receiving mail services recognise and handle such messages.

For **70.01% of the email-configured domains analysed**, the scan found no rule
asking receiving services to block emails whose sender cannot be verified or
treat them as spam.
That is 1,190,194 out of 1,700,148 domains with a published email-receiving setup,
not 70% of all `.ch` domains or Swiss companies.

We checked public settings, not actual email delivery. The results do not show
whether an attack happened or how secure an organisation is overall.

The scanner code, summary data and charts are public. This repository explains
what we measured, what you can download and how you can check the published files.
For installation and commands, go to [Work with the code](#work-with-the-code).

## Read the report or download the data

Read the findings and explanations on WebEvolve in your preferred language.
Each article includes the summary data, downloadable charts and correction guidance.
The data links jump straight to its download section.

| Language | Report | Data and current charts |
| --- | --- | --- |
| Deutsch | [Artikel](https://webevolve.ch/studien/schweizer-e-mail-sicherheitsreport/) | [Daten und Grafiken](https://webevolve.ch/studien/schweizer-e-mail-sicherheitsreport/#downloads) |
| Français | [Rapport](https://webevolve.ch/fr/etudes/rapport-securite-e-mail-suisse/) | [Données et graphiques](https://webevolve.ch/fr/etudes/rapport-securite-e-mail-suisse/#downloads) |
| Italiano | [Rapporto](https://webevolve.ch/it/studi/rapporto-sicurezza-email-svizzera/) | [Dati e grafici](https://webevolve.ch/it/studi/rapporto-sicurezza-email-svizzera/#downloads) |
| English | [Report](https://webevolve.ch/en/studies/swiss-email-security-report/) | [Data and charts](https://webevolve.ch/en/studies/swiss-email-security-report/#downloads) |

## What data are available?

The [dataset on Zenodo](https://doi.org/10.5281/zenodo.22116736) and
[GitHub release v2026.08.2](https://github.com/peterhadorn/swiss-email-security-report/releases/tag/v2026.08.2)
contain the same archive. It includes 68 summary metrics in CSV and JSON,
methodology documentation, 30 charts in German, French and Italian, and files
for checking that the download has not changed.

The language links above also provide newer charts in German, French, Italian
and English. They use the same measurements with updated wording and presentation.
These downloads are separate from the original archive, which remains unchanged.

Only aggregate data is public: counts and percentages across groups of domains.
The domain list, original DNS responses, database and results for individual
domains are not published. Do not attach them to issues or commits.

The articles, data downloads and charts are now together on WebEvolve. Former
KI-Barometer article and data-page addresses redirect to the matching article.
Legacy data-file URLs remain available so existing citations and archived metadata
continue to work. You can find both studies in the
[WebEvolve study overview](https://webevolve.ch/studien/).

## What was measured?

The scan ran on **21–23 August 2026**. Domains whose first check returned an error
were checked again before the final results were calculated.

| Coverage | Domains |
| --- | ---: |
| Domains in the input list | 2,459,127 |
| Domains that could be evaluated after the second check | 2,316,512 |
| Domains still returning errors, excluded from findings | 142,615 |

The input list came from the SWITCH `.ch` zone snapshot dated 12 April 2026.
That is the source-list date, not the date of the email-security checks.

Each percentage identifies the group it describes. The 70.01% finding uses
only the 1,700,148 evaluated domains with an email-receiving setup. In technical
terms, these had a non-null MX record. This does not prove that their mail servers
were reachable or that the domains were actively used. Other metrics use different
groups. Each published metric includes its count and the total used to calculate
its percentage. One company can own several domains.

## Technical scope and limitations

The scanner reads DNS records, the public settings that describe services for a
domain. It does not send test emails or inspect mailboxes.

For the main finding, the scanner looks for a DMARC rule asking receiving services
to reject messages that fail sender authentication or treat them as suspicious.
The 70.01% combines domains where no supported rule was detected with those using
`p=none`, which asks for neither action. The scanner does not fully validate each
rule or test how receiving services apply it.

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

You can check the published counts and percentages against one another and compare
the figures across the data files and documentation. Checksums let you confirm
that your downloaded files match the published versions. Digital signatures
identify the release owner's signed declarations about the private scan inputs.
They do not independently prove what those private files contain.

Recalculating the results from individual observations requires authorised access
to the original private inputs and database. Checking the database's checksum or
full scan history also requires those private files. A new scan today will find
today's settings, not necessarily the ones observed in August 2026.

For problems with the results or wording, use the
[corrections policy](https://webevolve.ch/studien/schweizer-e-mail-sicherheitsreport/#corrections).
For private vulnerability reporting, see [SECURITY.md](SECURITY.md).

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

The analyzer prints a descriptive summary. It is not the public release exporter.
Keep scan inputs and outputs outside version control. Scans write a private
SQLite database, an adjacent manifest and a manifest archive. Resume supports
retrying errors from a completed, compatible full scan. It cannot recover
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
The exporter remains pinned to v2026.08.2. Publishing a new measurement requires
new release configuration, schemas and provenance.

See the [release status](docs/RELEASE-STATUS.md), [provenance guide](provenance/README.md),
and [historical review documents](docs/release-review/README.md) for details.

## Licenses

Code is [MIT-licensed](LICENSE). Published aggregate data, documentation and figures
use [CC BY 4.0](release/LICENSE-DATA.md), with attribution to Peter Hadorn / WebEvolve.
The private input list and individual measurements are not covered by that licence.
