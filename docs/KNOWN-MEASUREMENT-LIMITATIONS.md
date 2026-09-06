# Measurement limitations and subsequent scanner corrections

## Published v2026.08.2 (unchanged)

The release is a record of DNS observations, not a full standards validator or
an assessment of actual message handling. Its sealed metrics and archive have
not been recalculated or replaced.

- DMARC uses the first matching TXT record and extracts selected tags. Duplicate
  tags overwrite earlier values; malformed `pct` defaults to 100. Policy labels
  must not be interpreted as proof of complete syntactic validity or effective
  enforcement. `p=none` does not prove that reporting or monitoring is active.
- The historical DKIM `weak_key` field flags short encoded key material without
  distinguishing RSA from Ed25519. The reported 31.65% is a length-heuristic
  observation among domains with detected selectors, **not a weak-key rate**.
  Legitimate Ed25519 keys can be included. Selector probing is incomplete.
- DNSSEC figures measure DS-record presence, not chain validation.
- The source corpus is the 12 April 2026 snapshot; measurement took place on
  21–23 August. The 142,615 excluded domains need not be a random subset.

## Scanner changes after the published measurement

On 6 September 2026, a tested candidate in `dmarc_scanner/experimental_dkim.py`
was added, restricting the DKIM length heuristic to RSA (including
the default algorithm when `k` is omitted). Ed25519 and unknown algorithms are
not classified by that heuristic. Colon-separated testing flags now recognise
`y` within combinations such as `t=s:y`.

The candidate is **not wired into the current scanner**: the release verifier
requires the historical measurement core's exact bytes. Adoption requires a
new versioned measurement core and fresh provenance before any new run.
Reproducing the historical release requires
its pinned scanner version, not current main. A new measurement would require
a new version and provenance; the original archive remains authoritative for
what was measured then.
