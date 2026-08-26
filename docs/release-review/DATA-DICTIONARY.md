# Data dictionary

**Review source — not a sealed release file.** Final metadata will bind this content to the real DOI and authenticated inventory.

## File catalogue

- `metrics.json`: canonical structured representation of all 68 aggregate metrics.
- `metrics.csv`: row-equivalent tabular export of the canonical metrics.
- `aggregate-attestation.json`: binds the aggregate files to the final database SHA-256, run manifest, measurement-core identity, source input identity, measurement interval, and metric count.
- `release.json`: lifecycle state, source universe, resolver configuration, run-chain summary, licenses, repository, correction URL, aggregate-file identities, and eventually DOI/inventory metadata.
- `figures/manifest.json`: localized figure catalogue with metric IDs, denominators, titles, descriptions, captions, caveats, dimensions, formats, licenses, DOI, and file identities.
- `checksums.sha256`: final inventory covering every public payload except itself.
- `doi-reservation.json`: externally approved Zenodo reservation attestation.
- EDITORIAL-SIGNOFF.json: owner-signed approval binding the complete prospective artifact tree.

## Metric fields

Each row in `metrics.json` and `metrics.csv` contains:

| Field | Meaning |
|---|---|
| `metric_id` | Stable machine identifier, for example `dmarc.reject`. |
| `category` | Broad measurement family such as population, MX, SPF, DKIM, DMARC, provider, or transport. |
| `numerator` | Integer count satisfying the metric definition. |
| `denominator` | Integer population to which the percentage applies. |
| `denominator_metric_id` | Metric whose numerator defines the denominator, when applicable. |
| `percentage` | Canonical unrounded decimal percentage serialized as a string. |
| `display_percentage` | Percentage rounded exactly to the declared precision. |
| `precision` | Number of decimal places used for public display. |
| `population` | Human-readable denominator definition. |
| `unit` | Counted unit; public metrics use domains. |
| `measurement_period` | Exact UTC start/end interval shared by release metrics. |
| `method` | Deterministic measurement or aggregation rule. |
| `caveat` | Metric-specific limitation required wherever the value is interpreted. |

Counts are integers. A numerator may not be negative or exceed its denominator. Percentages are derived from the counts; they are not independent observations.

## Denominators

The release intentionally uses several denominators:

- `population.total`: all 2,459,127 normalized domains in the source universe.
- `population.analyzable`: 2,316,512 rows that do not retain the aggregate exclusion error state after retry.
- `mx.present`: 1,700,148 analyzable domains with a non-null MX observation.
- `mx.absent`: 616,364 analyzable domains without a non-null MX observation.
- `dmarc.detected_all`: 904,516 analyzable domains with a detected DMARC record, including no-MX observations where the metric definition requires them.
- `dkim.selector_observed`: 342,508 MX domains for which the tested selector set found DKIM material.

Every denominator reference must reconcile to the numerator of its declared denominator metric. Article and figure copy must state the relevant population rather than treating all percentages as shares of the full `.ch` universe.

## Error handling

The fresh full run attempted the complete 2,459,127-domain input and retained 148,852 error rows. The linked retry attempted all 148,852 and wrote every attempted result. Final state:

- analyzable: 2,316,512;
- retained error: 142,615;
- total: 2,459,127.

The retained-error population is published only as an aggregate count. Those rows are excluded from substantive denominators and are not classified as absent, unprotected, or insecure.

The retry does not imply that every individual DNS record type returned a successful answer. Record presence metrics retain their documented scanner limitations and query semantics.

## Figure fields

Each figure entry records:

- chart and family identifiers;
- locale (`de`, `fr`, or `it`), kind, SVG/PNG format, MIME type, width, and height;
- exact metric IDs and denominator metric IDs;
- localized title, description, caption, source label, and caveat signals;
- source snapshot identity and measurement interval;
- release version, DOI, repository, and CC BY 4.0 license;
- SHA-256 and byte size of the figure file.

SVG and PNG variants are generated from the same validated chart model. SVG includes accessible `<title>` and `<desc>` content and an embedded, pinned font. PNG metadata repeats the caption, DOI, and source. Website pages retain accessible tables so figures are never the sole representation of values.

**Privacy boundary.**

No public field may contain domain names, raw DNS records, reporting addresses, host lists, query-status details, private paths, database paths, or hashed-domain identifiers. Provider values are aggregate hostname-fingerprint categories, not domain-owner or contractual records.
