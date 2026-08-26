# Corrections policy

**Review source — not a sealed release file.** The final copy will contain the reserved DOI.

## Contact

Report reproducibility concerns, calculation errors, metadata errors, or material wording problems to `hallo@webevolve.ch` and identify `v2026.08.2`.

The public correction page is https://ki-barometer.ch/datasets/ch-email-security-2026/corrections/.

Security vulnerabilities in the scanner or release tooling should follow `SECURITY.md`. Do not include sensitive domain-level records or credentials in a public issue.

## Required evidence

A useful correction request should include:

- release version and DOI when available;
- affected file, metric ID, figure, table, or exact passage;
- expected and observed behavior;
- reproducible commands, calculations, or standards references;
- supporting aggregate evidence that does not disclose private domain-level data;
- a contact route for clarification.

Requests concerning one domain cannot be publicly reconciled against the private database. They will be handled only to the extent permitted by privacy, source agreements, and study integrity.

## Review process

1. Acknowledge the report and preserve the submitted evidence.
2. Reproduce the issue against the immutable released artifacts and tagged code.
3. Classify it as editorial, metadata, tooling, calculation, or underlying-measurement impact.
4. Obtain scientific and relevant language/privacy review for the proposed correction.
5. Publish the decision and its rationale. Rejected requests receive a factual explanation where practical.
6. If the correction affects a public payload, create a new version and link it to the superseded release.

No released file is silently overwritten. Checksums and DOI-bound objects remain immutable.

## Versioning

- Typographical or explanatory corrections that do not change metrics still receive documented version treatment when they alter DOI-bound files.
- Metric, denominator, aggregation, source-universe, scanner, or measurement changes require a new release version and, where necessary, a new measurement chain.
- The next patch versions are `v2026.08.3`, `v2026.08.4`, and so on; no meaning is retroactively assigned to `v2026.08.2`.
- A new DOI version links forward and backward to related records while the concept DOI may identify the release series.
- The changelog states whether code, wording, calculations, figures, metadata, or underlying measurements changed.

**Transparency.**

Prior versions remain citable and downloadable where the publication platforms permit. The dataset landing page points to the current recommended version while retaining correction history.

Corrections never disclose the private source list, domain-level results, error rows, or reversible hashes of the domain universe.
