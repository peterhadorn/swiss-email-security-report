# Methodology

**Review source — not a sealed release file.** The final document receives the reserved DOI and authenticated inventory only after approval.

## Source universe

The fixed source universe is the normalized SWITCH `.ch` zone snapshot dated 12 April 2026:

- normalized line count: 2,459,127;
- normalized SHA-256: `be742a42b89dbac80b5296316d35a2d245383e31d15d5df0b1242af8ec9e07c8`.

The source universe is a domain corpus, not a company register. One organization may control multiple domains; domains may be inactive, private, parked, delegated for specialized functions, or unrelated to inbound mail.

The zone snapshot and domain list are not distributed. Their checksum and normalized count permit identity checks without publishing the finite source list.

## Measurement interval

The public release uses the fresh provenance-enabled run and its linked retry:

1. Full run: 2026-08-21T21:05:22.017897Z to 2026-08-23T04:10:59.622647Z; attempted input 2,459,127; post-run state 2,310,275 analyzable plus 148,852 error rows.
2. Retry: 2026-08-23T15:52:47.517343Z to 2026-08-23T18:02:41.508091Z; attempted every one of the 148,852 retained-error rows; final state 2,316,512 analyzable plus 142,615 error rows.

The public measurement interval is therefore 2026-08-21T21:05:22.017897Z/2026-08-23T18:02:41.508091Z.

The earlier 17–19 August database is retained only as a legacy reconciliation record. It is not the measurement source for `v2026.08.2`.

Each manifest binds input identity, attempted count, mode, timestamps, scanner revision, measurement-core identity, resolver configuration, database pre/post accounting, and output database identity. The retry manifest links to the root manifest and its database state.

## Resolver configuration

The scanner used public recursive resolvers with rotation enabled and resolver caching disabled:

- 1.1.1.1;
- 8.8.8.8;
- 9.9.9.9;
- 1.0.0.1;
- 8.8.4.4.

The recorded dnspython version is 2.8.0. Resolver timeout was 4.0 seconds and lifetime 6.0 seconds. Network state, resolver caches, authoritative availability, rate limits, and transient DNS behavior can affect individual observations.

The scanner performed DNS queries only. It did not send e-mail, inspect mailboxes, log in, or establish HTTP, SMTP, or arbitrary port connections to the observed domains.

## Aggregation

After the accepted retry, aggregation opened the final SQLite database once using an explicit read-only URI and one read transaction. The database identity is:

- bytes: 3,478,831,104;
- SHA-256: `a503dab7c0079c8b14f22b274592be1a7b3fc39deec9d9c0acd4e66c7729a575`.

Two independent COUNT-only SQL catalogues computed all 68 public metrics against the same snapshot. The exporter compared their values metric by metric and validated:

- total/analyzable/error reconciliation;
- MX-present plus MX-absent reconciliation;
- DMARC policy buckets and effective-policy identities;
- provider-fingerprint totals;
- denominator references;
- exact percentage calculation and declared rounding;
- measurement-period consistency;
- privacy allowlists and forbidden-field scans.

The canonical JSON stores each numerator, denominator, method, population, and caveat. CSV, documents, website tables, and figures are consumers of those metric records.

The aggregate attestation binds the final database identity, final run manifest, final measurement-core digest, source input identity, interval, metric count, and canonical metric-file identities.

## Scientific limitations

### Interpretation

This is a public DNS configuration census for the documented corpus and time interval. It is not a penetration test, vulnerability scan, breach assessment, deliverability test, spam-reputation test, or quality rating.

Published policy tags do not prove how a recipient handled a concrete message. A missing MX record does not prove that a domain never sends or receives mail.

### SPF

SPF presence is not complete protection. The release classifies observed record structure but does not perform full recursive RFC 7208 evaluation of every `include` and `redirect` chain. Outcomes such as `-all`, `~all`, neutral, or no terminal mechanism describe the observed published record.

### DKIM

DKIM detection uses a provider-aware set of known selectors. Arbitrary private selectors cannot be enumerated from DNS, so `dkim.selector_observed` is a lower bound. Weak-key classification is a length heuristic, not a cryptographic audit. Testing mode measures the observed flag only.

### DMARC

`dmarc.no_detected_enforcement` combines no supported effective policy with `p=none`. It describes the published policy signal, not an exploit, compromise, or recipient decision. `p=quarantine` and `p=reject` are published requested policies, not proof of operational application.

Partial percentage and strict-alignment metrics use the documented detected-DMARC population, which differs from the MX denominator used for top-level effective-policy rates.

### DS, TLSA, and transport signals

`ds.record_present` measures DS-entry presence, not cryptographic validation of a DNSSEC chain. `tlsa.record_present` measures TLSA-entry presence, not working DANE. BIMI, MTA-STS, and TLS-RPT metrics measure DNS TXT presence only; no BIMI logo validation, MTA-STS HTTPS policy retrieval, report delivery, certificate matching, or SMTP negotiation was tested.

### MX providers

Provider categories are deterministic hostname fingerprints. They are not market-share estimates, customer counts, contractual relationships, ownership evidence, or provider security ratings. `self_hosted`, `other`, and `unknown` are classification outcomes, not judgments.

### Errors and time

The 142,615 retained-error rows are excluded from substantive denominators. Their distribution may not be random, so the results should not be generalized to those domains without qualification.

DNS is time-dependent. The release describes observations during the exact interval. Subsequent DNS changes do not make the archived observation incorrect; they may motivate a later, separately versioned measurement.

**Privacy and reproducibility.**

Public artifacts contain aggregates and provenance only. Domain-level inputs and observations remain private, and hashed-domain exports are prohibited. Reproduction code and schemas are public; exact value reproduction requires lawful access to equivalent source and measurement inputs.
