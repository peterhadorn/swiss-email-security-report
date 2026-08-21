# Figure and editorial input contract for v2026.08.2

Figure work starts only after `stage_release` creates `.v2026.08.2.staging`
and `bind_reserved_doi` verifies a separately approved, offline-signed
external reservation attestation. The binding step
adds `doi-reservation.json` and the canonical public Ed25519 key
`doi-approval-public.der`, then changes `release.json` from `staging` to
`doi_reserved`; it does not claim publication. The detached Ed25519 signature
covers every reservation and approval-authority field. Binding, finalization,
and post-seal verification all authenticate that signature against the DER key
and the independently pinned SHA-256 key fingerprint. The production
configuration deliberately remains `UNCONFIGURED` until the release owner
supplies and reviews a real user-owned key; no placeholder key can bind or seal
a release. Figure generation may read only `metrics.json`, `release.json`,
`aggregate-attestation.json`, and `doi-reservation.json`. The DOI in the
reservation is final for every later artifact.

DOI binding copies untouched aggregate staging into a sibling prepared tree,
fully validates that tree, and promotes it by directory rename. The original
tree remains in a sibling backup until the complete prepared tree has been
promoted and cryptographically revalidated. Interruption recovery restores the
original or retains the complete authenticated promotion; it never accepts a
file-by-file partial binding.

## Exact 30-file figure matrix

Each of these five IDs is produced in `de`, `fr`, and `it`, as both SVG and
PNG. Filenames are exactly `figures/{chart_id}.{locale}.{format}`.

| chart_id | family | kind | dimensions | metric_ids | denominator_metric_ids |
| --- | --- | --- | --- | --- | --- |
| `mail-authentication-overview` | `authentication-adoption` | `chart` | 1600×900 | `mx.present`, `spf.present`, `dkim.selector_observed`, `dmarc.detected` | `population.analyzable`, `mx.present`, `mx.present`, `mx.present` |
| `dmarc-policy-observations` | `dmarc-policy` | `chart` | 1600×900 | `dmarc.reject`, `dmarc.quarantine`, `dmarc.none`, `dmarc.no_supported_effective_policy` | four times `mx.present` |
| `dns-transport-signals` | `dns-and-transport` | `chart` | 1600×900 | `ds.record_present`, `tlsa.record_present`, `mta_sts.txt_present`, `tls_rpt.record_present`, `caa.record_present` | `population.analyzable`, then four times `mx.present` |
| `mx-provider-fingerprints` | `mx-provider-fingerprint` | `chart` | 1600×900 | `mx.provider.hostpoint`, `mx.provider.infomaniak`, `mx.provider.microsoft365`, `mx.provider.google_workspace`, `mx.provider.self_hosted`, `mx.provider.other`, `mx.provider.unknown` | seven times `mx.present` |
| `social-report-card` | `report-card` | `social` | 1200×630 | `mx.present`, `spf.present`, `dkim.selector_observed`, `dmarc.detected` | `population.analyzable`, `mx.present`, `mx.present`, `mx.present` |

This is exactly 24 chart files plus six social files. No additional figure is
accepted. The MX-provider chart must say that classifications are hostname
fingerprints, not market share.

## Figure manifest fields

`figures/manifest.json` contains exactly 30 entries. Every entry contains
exactly: `chart_id`, `family`, `path`, `kind`, `format`, `mime_type`, `width`,
`height`, `locale`, `metric_ids`, `denominator_metric_ids`, `title`,
`description`, `caption`, `source_snapshot_date`, `source_snapshot_sha256`,
`source_label`, `measurement_interval`, `release_version`, `license`, `doi`,
`repository`, `methodology_signals`, `caveat_signals`, `sha256`, and `bytes`.

The SVG and PNG in each chart/locale pair share all descriptive fields. Titles,
useful descriptions, captions, source labels, metric labels, and scientific
caveats are native DE, FR, and IT copy. A description may not repeat its title.
Every caption contains the reserved DOI, human metric labels, exact aggregate
numerators and denominators, displayed percentages with an explicit percent
sign, and its chart-specific scientific limitation. Social captions use the
same exact metrics in a compact form. Method and caveat arrays reproduce the
exact method and caveat strings from `metrics.json`; the MX-provider entry
additionally contains
`MX provider classifications are hostname fingerprints, not market-share measurements.`

## Safe assets

SVG uses only the inactive element and attribute allowlist implemented by the
finalizer. It has no scripts, event handlers, `foreignObject`, style or URL
loads, links, images, animation, processing instructions, entities, or external
namespaces. Every SVG uses `role="img"`,
`aria-labelledby="figure-title figure-description"`, localized `<title>` and
`<desc>` nodes with those IDs, and visibly renders the title, caption, source,
and DOI exactly once as local on-canvas text. Required-text ancestry may not
contain a transform, hidden state, transparent paint, non-start anchor, offset,
or off-canvas coordinates. The accessibility title and description are the
first two direct root children and their IDs are unique. One exact full-canvas
`#f8f7f3` background follows. The visible title, the deterministically wrapped
caption lines, source, and DOI form the final direct root-child text layer.
Every line has an exact reviewed x/y position, stays inside the 40-pixel
horizontal inset, uses only the high-contrast `#111111` fill, contains no
`tspan` or coordinate override, and uses a font size from 10 through 96 pixels
(12 pixels by default). Caption wrapping uses the fixed 12-pixel conservative
character bound and 24-pixel line spacing; the source and DOI occupy fixed
lines 60 and 30 pixels above the lower canvas edge. The validator reconstructs
the complete caption from those exact lines and rejects duplicate visible
title, caption, source, or DOI content. This exact structure and layer order
prevents inherited near-zero opacity, background-colour text, right-edge
placement, duplicate ARIA nodes, and later opaque occlusion.

PNG files are RGB or RGBA, exact-size renders of their SVG partner. They must
load successfully under pinned Pillow after both `verify()` and `load()`. PNG
text metadata keys `doi`, `source`, and `caption` exactly match the figure
manifest. Task 7 renderer tests must additionally prove those strings are
drawn in the visible image; the finalizer cannot infer semantic pixel content.

## Required editorial payload

The staging directory must contain these exact filenames before sealing:

- `CITATION.cff`
- `LICENSE` — byte-identical to the repository’s complete MIT licence
- `LICENSE-DATA.md` — byte-identical to the tracked CC BY 4.0 aggregate-data licence
- `README.md`
- `DATA-DICTIONARY.md`
- `METHODOLOGY.md`
- `CORRECTIONS.md`
- `RELEASE-NOTES.md`
- `EDITORIAL-SIGNOFF.json`

All five Markdown documents use these exact metadata fields once:
`Release-Version`, `DOI`, `Source-Snapshot-Date`, `Measurement-Started-At`,
`Measurement-Finished-At`, `Repository`, and `License`.

Exact document titles and H2 markers:

- `README.md`: `# Swiss Email Security Report aggregate release v2026.08.2`;
  `Scope`, `Contents`, `Citation`, `Privacy`, `Licenses`, `Reproduction`.
- `DATA-DICTIONARY.md`: `# Data dictionary`; `File catalogue`, `Metric fields`,
  `Denominators`, `Error handling`, `Figure fields`.
- `METHODOLOGY.md`: `# Methodology`; `Source universe`, `Measurement interval`,
  `Resolver configuration`, `Aggregation`, `Scientific limitations`.
- `CORRECTIONS.md`: `# Corrections policy`; `Contact`, `Required evidence`,
  `Review process`, `Versioning`.
- `RELEASE-NOTES.md`: `# Release notes v2026.08.2`; `Release identity`,
  `Included artifacts`, `Known limitations`, `Corrections`.

`EDITORIAL-SIGNOFF.json` records approved, named, identity- and role-bound,
timestamped signoffs for `scientific`, `privacy`, `de`, `fr`, and `it`, all
after DOI reservation. Its prospective review catalogue binds the exact bytes
of every reviewed non-signoff payload, with `release.json` represented by all
stable semantic fields while derived lifecycle status and inventory are
excluded. This makes `reviewed_artifact_root_sha256` reproducible and identical
before and after sealing. The whole signoff, including reviewer identities,
roles, scope, timestamps, root, and artifact count, is itself signed by the
configured Ed25519 release authority and is reverified after sealing; changing
content and freely recomputing the root is insufficient. `CITATION.cff` must not
include
`date-released`: that date belongs only to the later external publication
record, never to a sealed-but-unpublished bundle.
`CITATION.cff` uses the strict inactive CFF 1.2 YAML subset and includes
`cff-version`, `message`, `title`, `version`, `doi`, `authors`,
`repository-code`, `url`, and `license`.

## Sealing boundary

Figure or documentation work never creates `checksums.sha256` and never changes
the DOI. `finalize_release` revalidates every file, copies each payload to a
fresh inode, creates the complete inventory and whole-tree checksums, sets
status to `sealed`, and seals `v2026.08.2`. Later GitHub or Zenodo publication
uses the sealed bytes as-is and must not modify the bundle.

Before promotion and after sealing, every public text surface is checked against
its file-and-field catalogue. Documentation, CFF, JSON, SVG text, PNG metadata,
manifest values, and checksum filenames reject filesystem paths, private scan
fields, raw DNS records or names (including Unicode IDNs), canonical and encoded
IP addresses, and SHA-like 40/64/96/128-hex values unless the exact public field
and value family is allowlisted. HTML entities, CFF/JSON escapes, slash variants,
case differences, and Unicode compatibility forms are normalized before the
catalogue check. The tracked DE/FR/IT locale catalogues are package data and
must be present when the wheel is installed. CC BY 4.0 remains the mandatory
license for aggregate data and all figures.
