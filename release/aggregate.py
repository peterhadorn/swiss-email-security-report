"""Read-only canonical aggregation for DNS-observation release metrics.

This module deliberately never selects a domain or DNS-record value.  It
accepts only the complete scanner schemas known at release time and produces
immutable aggregate counts suitable for later validation and serialization.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from dmarc_scanner.db import COLUMNS, EXPECTED_COLUMNS, JSON_FIELDS
from dmarc_scanner.providers import MX_PROVIDER_PATTERNS

from release.metric import Metric, display_percentage, high_precision_percentage


TABLE = "dmarc_scan_results"
CANONICAL_COLUMNS = frozenset(EXPECTED_COLUMNS)
LEGACY_COLUMNS = frozenset(
    ("dnssec_signed" if column == "has_ds_record" else "has_tlsa" if column == "has_tlsa_record" else column)
    for column in CANONICAL_COLUMNS
    if column != "query_statuses"
)
LEGACY_ALIASES = {"has_ds_record": "dnssec_signed", "has_tlsa_record": "has_tlsa"}
KNOWN_PROVIDERS = tuple(provider for provider, _ in MX_PROVIDER_PATTERNS) + (
    "self_hosted", "other", "unknown",
)
SUPPORTED_SPF_TERMINALS = ("hardfail", "softfail", "neutral", "pass")
FROZEN_LEGACY_2026_COUNTS = {
    "population.total": 2_459_127, "population.analyzable": 2_324_088, "population.error": 135_039,
    "mx.present": 1_708_618, "mx.absent": 615_470, "ds.record_present": 1_252_199, "ns.answer_present": 2_241_187,
    "published.mx_provider.unassigned_or_possibly_self_hosted": 433_207,
    "published.mx_provider.other_or_unrecognized": 410_893,
    "mx.provider.hostpoint": 348_745, "mx.provider.infomaniak": 179_364,
    "mx.provider.microsoft365": 160_321, "mx.provider.google_workspace": 59_756,
    "spf.present": 1_482_058, "spf.hardfail": 574_101, "spf.softfail": 490_742,
    "spf.neutral": 87_889, "spf.no_terminal_mechanism": 328_967,
    "spf.legacy_rrtype99": 9_954, "spf.no_mx_present": 180_313,
    "dkim.selector_observed": 342_876, "dkim.weak_key_heuristic": 108_768, "dkim.testing_mode": 25_430,
    "dmarc.detected": 731_804, "dmarc.reject": 227_927, "dmarc.quarantine": 283_399,
    "dmarc.none": 219_990, "dmarc.no_supported_effective_policy": 977_302,
    "dmarc.genuine_no_record": 976_814,
    "dmarc.missing_policy": 308,
    "dmarc.unsupported_policy": 180,
    "dmarc.no_detected_enforcement": 1_197_292,
    "dmarc.detected_all": 906_450, "dmarc.partial_pct": 4_435,
    "dmarc.strict_alignment": 109_255, "dmarc.no_mx_detected": 174_646,
    "mx.unresolvable": 38_351, "tlsa.record_present": 654_920,
    "bimi.record_present": 1_324, "mta_sts.txt_present": 2_537,
    "tls_rpt.record_present": 2_728, "caa.record_present": 26_279,
}

# Every query uses values as DB-API parameters; predicates are maintained in
# source as a closed metric catalogue.  This exported constant also enables a
# regression test to make the parameterization contract visible.
AGGREGATE_SQL = (
    "SELECT COUNT(*) FROM dmarc_scan_results WHERE error = ? AND ({predicate})",
    "SELECT COUNT(*) FROM dmarc_scan_results WHERE ({predicate})",
    "SELECT COUNT(*) FROM dmarc_scan_results WHERE ?",
)

class _MetricSpec:
    __slots__ = (
        "metric_id", "category", "predicate", "parameters", "denominator_id",
        "population", "method", "caveat", "precision",
    )

    def __init__(
        self, metric_id: str, category: str, predicate: str, parameters: tuple,
        denominator_id: str | None, population: str, method: str, caveat: str,
        precision: int = 2,
    ) -> None:
        self.metric_id = metric_id
        self.category = category
        self.predicate = predicate
        self.parameters = parameters
        self.denominator_id = denominator_id
        self.population = population
        self.method = method
        self.caveat = caveat
        self.precision = precision


def _schema_columns(conn: sqlite3.Connection) -> frozenset[str]:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = ?", ("table",))}
    if TABLE not in tables:
        raise RuntimeError("database has no dmarc_scan_results table")
    return frozenset(row[1] for row in conn.execute(f"PRAGMA table_info({TABLE})"))


def _resolve_schema(conn: sqlite3.Connection) -> dict[str, str]:
    columns = _schema_columns(conn)
    if columns == CANONICAL_COLUMNS:
        return {}
    if columns == LEGACY_COLUMNS:
        return LEGACY_ALIASES.copy()
    missing_canonical = sorted(CANONICAL_COLUMNS - columns)
    extra = sorted(columns - CANONICAL_COLUMNS)
    raise RuntimeError(
        "unrecognized results schema; refusing aggregate export "
        f"(missing canonical columns: {', '.join(missing_canonical) or 'none'}; "
        f"unexpected columns: {', '.join(extra) or 'none'})"
    )


def _count(conn: sqlite3.Connection, predicate: str = "1 = 1", parameters: tuple = ()) -> int:
    sql = AGGREGATE_SQL[0].format(predicate=predicate)
    return int(conn.execute(sql, ("", *parameters)).fetchone()[0])


def _count_all(conn: sqlite3.Connection, predicate: str, parameters: tuple) -> int:
    """Count all rows for population accounting, including scanner errors."""
    sql = AGGREGATE_SQL[1].format(predicate=predicate)
    return int(conn.execute(sql, parameters).fetchone()[0])


def _assert_closed_categories(conn: sqlite3.Connection, schema: dict[str, str]) -> None:
    canonical_binary_columns = (
        "domain_exists", "has_mx", "has_spf", "has_legacy_spf_rrtype", "has_dkim",
        "dkim_testing_mode", "dkim_weak_key", "has_dmarc", "dmarc_rua", "dmarc_ruf",
        "has_ds_record", "mx_unresolvable", "has_bimi", "has_mta_sts", "has_tlsrpt",
        "has_caa", "has_tlsa_record", "spf_near_limit",
    )
    binary_columns = tuple(schema.get(column, column) for column in canonical_binary_columns)
    binary_predicate = " OR ".join(
        f"typeof({column}) <> ? OR {column} NOT IN (?, ?)" for column in binary_columns
    )
    binary_parameters = tuple(value for _ in binary_columns for value in ("integer", 0, 1))
    if _count_all(conn, binary_predicate, binary_parameters):
        raise RuntimeError("non-binary scanner flag; refusing aggregate export")

    if _count_all(conn, "typeof(spf_lookup_count) <> ? OR spf_lookup_count < ?", ("integer", 0)):
        raise RuntimeError("invalid integer scanner value; refusing aggregate export")
    if _count_all(conn, "typeof(dmarc_pct) <> ?", ("integer",)):
        raise RuntimeError("invalid DMARC pct value; refusing aggregate export")

    json_fields = tuple(field for field in JSON_FIELDS if not (schema and field == "query_statuses"))
    for field in json_fields:
        expected_type = "object" if field == "query_statuses" else "array"
        if _count_all(conn, f"typeof({field}) <> ? OR json_valid({field}) = ? OR json_type({field}) <> ?", ("text", 0, expected_type)):
            raise RuntimeError("invalid JSON storage value; refusing aggregate export")
        if field == "query_statuses":
            invalid_elements = _count_all(
                conn,
                f"EXISTS (SELECT 1 FROM json_each({field}) WHERE type <> ? OR value NOT IN (?, ?, ?, ?))",
                ("text", "ok", "nxdomain", "noanswer", "error"),
            )
        else:
            invalid_elements = _count_all(
                conn, f"EXISTS (SELECT 1 FROM json_each({field}) WHERE type <> ?)", ("text",)
            )
        if invalid_elements:
            raise RuntimeError("invalid JSON element value; refusing aggregate export")

    text_columns = [item.split()[0] for item in COLUMNS if item.split()[1] in {"TEXT", "TIMESTAMP"}]
    for canonical in text_columns:
        if canonical in JSON_FIELDS:
            continue
        column = schema.get(canonical, canonical)
        if _count_all(conn, f"typeof({column}) <> ? OR {column} = ?", ("text", "")) and column in {"domain", "scanned_at"}:
            raise RuntimeError("invalid required text storage value; refusing aggregate export")
        if _count_all(conn, f"typeof({column}) <> ?", ("text",)):
            raise RuntimeError("invalid text storage value; refusing aggregate export")

    if _count_all(conn, "error IS NULL", ()):
        raise RuntimeError("NULL error value; refusing aggregate export")

    if not schema:
        if _count_all(conn, "query_statuses IS NULL OR json_valid(query_statuses) = ? OR json_type(query_statuses) <> ?", (0, "object")):
            raise RuntimeError("invalid query status value; refusing aggregate export")
        if _count_all(conn, "(error = ? AND EXISTS (SELECT 1 FROM json_each(query_statuses) WHERE value = ?)) OR (error <> ? AND NOT EXISTS (SELECT 1 FROM json_each(query_statuses) WHERE value = ?))", ("", "error", "", "error")):
            raise RuntimeError("inconsistent query status and error field; refusing aggregate export")

    provider_placeholders = ", ".join("?" for _ in KNOWN_PROVIDERS)
    unknown_provider_rows = _count_all(
        conn,
        "mx_provider IS NULL OR (has_mx = ? AND mx_provider NOT IN (" + provider_placeholders + ")) "
        "OR (has_mx = ? AND mx_provider <> ?)",
        (1, *KNOWN_PROVIDERS, 0, ""),
    )
    if unknown_provider_rows:
        raise RuntimeError("unrecognized MX provider value; refusing aggregate export")

    unknown_spf_rows = _count_all(
        conn,
        "spf_all_mechanism IS NULL OR (has_spf = ? AND spf_all_mechanism NOT IN (?, ?, ?, ?, ?)) "
        "OR (has_spf = ? AND spf_all_mechanism <> ?)",
        (1, *SUPPORTED_SPF_TERMINALS, "none", 0, ""),
    )
    if unknown_spf_rows:
        raise RuntimeError("unrecognized SPF terminal mechanism; refusing aggregate export")

    if _count_all(conn, "dmarc_policy IS NULL OR dmarc_sp IS NULL", ()):
        raise RuntimeError("NULL DMARC categorical value; refusing aggregate export")


def _specifications(schema: dict[str, str]) -> list[_MetricSpec]:
    ds = schema.get("has_ds_record", "has_ds_record")
    tlsa = schema.get("has_tlsa_record", "has_tlsa_record")
    all_rows = "all analyzable scan rows"
    mx_rows = "analyzable rows with a non-null MX record"
    no_mx_rows = "analyzable rows without a non-null MX record"
    detected_dmarc = "all analyzable rows with a detected DMARC record"
    passive = "Passive DNS observation by the documented scanner and resolver configuration."
    specs = [
        _MetricSpec("population.analyzable", "population", "1 = 1", (), "population.total", all_rows,
                    "Rows with an empty recorded error field.", "An empty error field is not proof that every DNS protocol was validated."),
        _MetricSpec("population.error", "population", "error <> ?", ("",), "population.total", "all scanned rows",
                    "Rows with a recorded scanner error.", "Errors are excluded from descriptive measurement denominators."),
        _MetricSpec("domain.exists", "population", "domain_exists = ?", (1,), "population.analyzable", all_rows,
                    passive, "This is the scanner's DNS existence observation, not a registry-status determination."),
        _MetricSpec("domain.not_exists", "population", "domain_exists = ?", (0,), "population.analyzable", all_rows,
                    passive, "This is the scanner's DNS existence observation, not a registry-status determination."),
        _MetricSpec("mx.present", "mx", "has_mx = ?", (1,), "population.analyzable", all_rows,
                    passive, "A non-null MX answer indicates published mail routing, not successful mail delivery."),
        _MetricSpec("mx.absent", "mx", "has_mx = ?", (0,), "population.analyzable", all_rows,
                    passive, "This includes domains without a non-null MX answer; it does not establish that they never send mail."),
    ]
    for provider in KNOWN_PROVIDERS:
        if provider == "unknown":
            predicate, parameters = "has_mx = ? AND COALESCE(NULLIF(mx_provider, ?), ?) = ?", (1, "", "unknown", "unknown")
        else:
            predicate, parameters = "has_mx = ? AND mx_provider = ?", (1, provider)
        specs.append(_MetricSpec(
            f"mx.provider.{provider}", "mx_provider", predicate, parameters, "mx.present", mx_rows,
            "MX hostname fingerprinting using the documented provider patterns.",
            "Provider classification is a hostname fingerprint, not evidence of a commercial relationship or complete mail infrastructure.",
        ))
    specs.extend([
        _MetricSpec("spf.present", "spf", "has_mx = ? AND has_spf = ?", (1, 1), "mx.present", mx_rows,
                    passive, "SPF presence is a TXT-record observation, not end-to-end SPF evaluation."),
        _MetricSpec("spf.absent", "spf", "has_mx = ? AND has_spf = ?", (1, 0), "mx.present", mx_rows,
                    passive, "Absence is limited to the scanner's TXT observation."),
    ])
    for terminal in SUPPORTED_SPF_TERMINALS:
        specs.append(_MetricSpec(
            f"spf.{terminal}", "spf", "has_mx = ? AND has_spf = ? AND spf_all_mechanism = ?", (1, 1, terminal),
            "mx.present", mx_rows, "Top-level SPF terminal-mechanism parsing.",
            "The scanner does not recursively evaluate include or redirect chains; this is not RFC 7208 policy validation.",
        ))
    specs.extend([
        _MetricSpec("spf.no_terminal_mechanism", "spf", "has_mx = ? AND has_spf = ? AND COALESCE(NULLIF(spf_all_mechanism, ?), ?) = ?", (1, 1, "", "none", "none"), "mx.present", mx_rows,
                    "Top-level SPF terminal-mechanism parsing.", "A published SPF record without a parsed terminal all mechanism is not a security-quality verdict."),
        _MetricSpec("spf.legacy_rrtype99", "spf", "has_legacy_spf_rrtype = ?", (1,), "population.analyzable", all_rows,
                    "Passive query for the obsolete SPF DNS RR type 99.", "This is a record-type observation only; it does not assess SPF correctness."),
        _MetricSpec("spf.no_mx_present", "spf", "has_mx = ? AND has_spf = ?", (0, 1), "mx.absent", no_mx_rows,
                    passive, "This is deliberately reported independently of MX routing."),
        _MetricSpec("dkim.selector_observed", "dkim", "has_mx = ? AND has_dkim = ?", (1, 1), "mx.present", mx_rows,
                    "Provider-aware DKIM selector probes.", "This is a selector lower bound: a domain can use valid selectors that were not probed."),
        _MetricSpec("dkim.selector_not_observed", "dkim", "has_mx = ? AND has_dkim = ?", (1, 0), "mx.present", mx_rows,
                    "Provider-aware DKIM selector probes.", "No observed selector is not evidence that the domain does not use DKIM."),
        _MetricSpec("dkim.weak_key_heuristic", "dkim", "has_mx = ? AND has_dkim = ? AND dkim_weak_key = ?", (1, 1, 1), "dkim.selector_observed", "analyzable MX rows with an observed DKIM selector",
                    "Observed DKIM public-key-value length heuristic.", "This is not a cryptographic key-size measurement or a conclusion about effective key strength."),
        _MetricSpec("dkim.testing_mode", "dkim", "has_mx = ? AND has_dkim = ? AND dkim_testing_mode = ?", (1, 1, 1), "dkim.selector_observed", "analyzable MX rows with an observed DKIM selector",
                    "Observed provider-aware DKIM selector probes.", "Only a found selector is assessed; unprobed selectors can differ."),
        _MetricSpec("dmarc.detected", "dmarc", "has_mx = ? AND has_dmarc = ?", (1, 1), "mx.present", mx_rows,
                    passive, "Detection does not imply that a supported effective policy is present."),
        _MetricSpec("dmarc.reject", "dmarc", "has_mx = ? AND has_dmarc = ? AND dmarc_policy = ?", (1, 1, "reject"), "mx.present", mx_rows,
                    "Parsed DMARC p= tag.", "A published p=reject tag alone does not demonstrate operational enforcement or alignment outcomes."),
        _MetricSpec("dmarc.quarantine", "dmarc", "has_mx = ? AND has_dmarc = ? AND dmarc_policy = ?", (1, 1, "quarantine"), "mx.present", mx_rows,
                    "Parsed DMARC p= tag.", "A published p=quarantine tag alone does not demonstrate operational enforcement or alignment outcomes."),
        _MetricSpec("dmarc.none", "dmarc", "has_mx = ? AND has_dmarc = ? AND dmarc_policy = ?", (1, 1, "none"), "mx.present", mx_rows,
                    "Parsed DMARC p= tag.", "p=none is a monitoring policy, not a detected enforcement policy."),
        _MetricSpec("dmarc.genuine_no_record", "dmarc", "has_mx = ? AND has_dmarc = ?", (1, 0), "mx.present", mx_rows,
                    "DMARC TXT-record detection.", "No record means no DMARC record was detected by the scan; it is not a broad security-quality judgment."),
        _MetricSpec("dmarc.missing_policy", "dmarc", "has_mx = ? AND has_dmarc = ? AND COALESCE(NULLIF(dmarc_policy, ?), ?) = ?", (1, 1, "", "absent", "absent"), "mx.present", mx_rows,
                    "Detected DMARC record with parsed policy state.", "This bucket is distinct from no detected record and means the detected record has no supported p= value."),
        _MetricSpec("dmarc.unsupported_policy", "dmarc", "has_mx = ? AND has_dmarc = ? AND COALESCE(NULLIF(dmarc_policy, ?), ?) NOT IN (?, ?, ?, ?)", (1, 1, "", "absent", "reject", "quarantine", "none", "absent"), "mx.present", mx_rows,
                    "Detected DMARC record with parsed policy state.", "This bucket records an unsupported parsed policy value; it makes no claim about the organisation's security posture."),
        _MetricSpec("dmarc.no_supported_effective_policy", "dmarc", "has_mx = ? AND (has_dmarc = ? OR (has_dmarc = ? AND COALESCE(NULLIF(dmarc_policy, ?), ?) NOT IN (?, ?, ?)))", (1, 0, 1, "", "absent", "reject", "quarantine", "none"), "mx.present", mx_rows,
                    "Reconciliation of no record, missing policy, and unsupported policy observations.", "This is a DNS-observation bucket, not an assessment of actual message handling."),
        _MetricSpec("dmarc.no_detected_enforcement", "dmarc", "has_mx = ? AND (has_dmarc = ? OR (has_dmarc = ? AND COALESCE(NULLIF(dmarc_policy, ?), ?) NOT IN (?, ?)))", (1, 0, 1, "", "absent", "reject", "quarantine"), "mx.present", mx_rows,
                    "Reconciliation of non-enforcing or unsupported DMARC policy observations.", "No detected enforcement is not a determination of actual receiving-mail behaviour."),
        _MetricSpec("dmarc.detected_all", "dmarc", "has_dmarc = ?", (1,), "population.analyzable", detected_dmarc,
                    passive, "This includes records on rows with and without MX."),
        _MetricSpec("dmarc.partial_pct", "dmarc", "has_dmarc = ? AND dmarc_pct >= ? AND dmarc_pct < ?", (1, 0, 100), "dmarc.detected_all", detected_dmarc,
                    "Parsed valid DMARC pct= tag (0–99) across all detected DMARC records.", "The p= tag's pct setting is a published value; it does not demonstrate message-level enforcement. Out-of-range pct values are reported separately."),
        _MetricSpec("dmarc.invalid_pct", "dmarc", "has_dmarc = ? AND (dmarc_pct < ? OR dmarc_pct > ?)", (1, 0, 100), "dmarc.detected_all", detected_dmarc,
                    "Detected DMARC record with a numeric pct= value outside the RFC range 0–100.", "This reports malformed published record content; it is not treated as a partial or effective enforcement setting."),
        _MetricSpec("dmarc.strict_alignment", "dmarc", "has_dmarc = ? AND (dmarc_adkim = ? OR dmarc_aspf = ?)", (1, "s", "s"), "dmarc.detected_all", detected_dmarc,
                    "Parsed DMARC adkim= and aspf= tags across all detected DMARC records.", "Strict alignment tags do not demonstrate that mail flows or aligned identifiers were validated."),
        _MetricSpec("dmarc.invalid_alignment", "dmarc", "has_dmarc = ? AND (dmarc_adkim NOT IN (?, ?) OR dmarc_aspf NOT IN (?, ?))", (1, "r", "s", "r", "s"), "dmarc.detected_all", detected_dmarc,
                    "Detected DMARC record with an adkim= or aspf= value outside the supported r/s values.", "This reports malformed published record content; it is not classified as relaxed or strict alignment."),
        _MetricSpec("dmarc.no_mx_detected", "dmarc", "has_mx = ? AND has_dmarc = ?", (0, 1), "mx.absent", no_mx_rows,
                    passive, "This is deliberately reported independently of MX routing."),
        _MetricSpec("ds.record_present", "dns", f"{ds} = ?", (1,), "population.analyzable", all_rows,
                    "Passive DNS DS-record query.", "A DS record is not proof that DNSSEC validation succeeded."),
        _MetricSpec("ns.answer_present", "dns", "ns_hosts IS NOT NULL AND ns_hosts <> ? AND ns_hosts <> ?", ("", "[]"), "population.analyzable", all_rows,
                    "Passive DNS NS-answer observation.", "An NS answer is not a delegation or DNSSEC-validation quality assessment."),
        _MetricSpec("tlsa.record_present", "tlsa", f"has_mx = ? AND {tlsa} = ?", (1, 1), "mx.present", mx_rows,
                    "Passive TLSA record query for scanned SMTP MX hosts.", "TLSA presence is not validated DANE deployment or proof of mail-transport security."),
        _MetricSpec("bimi.record_present", "emerging", "has_mx = ? AND has_bimi = ?", (1, 1), "mx.present", mx_rows,
                    "Passive BIMI TXT-record query.", "A BIMI TXT record does not demonstrate logo eligibility or validation."),
        _MetricSpec("mta_sts.txt_present", "emerging", "has_mx = ? AND has_mta_sts = ?", (1, 1), "mx.present", mx_rows,
                    "Passive _mta-sts TXT-record query.", "The scanner does not retrieve or validate the HTTPS MTA-STS policy file."),
        _MetricSpec("tls_rpt.record_present", "emerging", "has_mx = ? AND has_tlsrpt = ?", (1, 1), "mx.present", mx_rows,
                    "Passive TLS-RPT TXT-record query.", "Record presence does not demonstrate reporting delivery or policy effectiveness."),
        _MetricSpec("caa.record_present", "emerging", "has_mx = ? AND has_caa = ?", (1, 1), "mx.present", mx_rows,
                    "Passive CAA record query.", "CAA is an X.509 issuance-control signal, not an email-security deployment result."),
        _MetricSpec("mx.unresolvable", "mx", "has_mx = ? AND mx_unresolvable = ?", (1, 1), "mx.present", mx_rows,
                    "A/AAAA follow-up for scanned MX hosts.", "A flag means an MX host had no affirmative A or AAAA answer under the scanner rules; resolver errors are not counted as unresolvable."),
    ])
    return specs


def _total_metric(total: int, measurement_period: str) -> Metric:
    return Metric.counted(
        metric_id="population.total", category="population", numerator=total, denominator=total,
        denominator_metric_id=None, population="all scanned rows", measurement_period=measurement_period,
        method="Count of rows in the private scanner results database.",
        caveat="The released metric contains only an aggregate count; no domains or record values are exported.",
    )


def aggregate_connection(conn: sqlite3.Connection, measurement_period: str) -> tuple[Metric, ...]:
    """Return the complete metric catalogue from an already-open connection.

    The function performs read-only SQL only.  `aggregate_database` should be
    preferred for files because it opens SQLite with ``mode=ro``.
    """
    if not measurement_period:
        raise ValueError("measurement_period is required")
    owns_snapshot = not conn.in_transaction
    if owns_snapshot:
        conn.execute("BEGIN")
    try:
        schema = _resolve_schema(conn)
        _assert_closed_categories(conn, schema)
        total = int(conn.execute(AGGREGATE_SQL[2], (1,)).fetchone()[0])
        error_count = _count_all(conn, "error <> ?", ("",))
        metrics: list[Metric] = [_total_metric(total, measurement_period)]
        values = {metrics[0].metric_id: metrics[0].numerator}
        for spec in _specifications(schema):
            numerator = error_count if spec.metric_id == "population.error" else _count(conn, spec.predicate, spec.parameters)
            try:
                denominator = total if spec.denominator_id is None else values[spec.denominator_id]
            except KeyError as exc:
                raise RuntimeError(f"metric catalogue has unresolved denominator {spec.denominator_id}") from exc
            metric = Metric.counted(
                metric_id=spec.metric_id, category=spec.category, numerator=numerator, denominator=denominator,
                denominator_metric_id=spec.denominator_id, population=spec.population,
                measurement_period=measurement_period, method=spec.method, caveat=spec.caveat,
                precision=spec.precision,
            )
            metrics.append(metric)
            values[metric.metric_id] = metric.numerator
        validate_metrics(metrics)
    except Exception:
        if owns_snapshot:
            conn.execute("ROLLBACK")
        raise
    else:
        if owns_snapshot:
            conn.execute("COMMIT")
        return tuple(metrics)


def aggregate_database(db_path: str | Path, measurement_period: str) -> tuple[Metric, ...]:
    """Open a SQLite database read-only and return canonical aggregates."""
    path = Path(db_path).resolve()
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        return aggregate_connection(conn, measurement_period)
    finally:
        conn.close()


def validate_legacy_expected_counts(counts: dict[str, int]) -> None:
    """Freeze the corrected legacy DMARC arithmetic for release regression."""
    required = set(FROZEN_LEGACY_2026_COUNTS)
    missing = required - counts.keys()
    if missing:
        raise ValueError(f"legacy expected counts missing: {', '.join(sorted(missing))}")
    for metric_id, expected in FROZEN_LEGACY_2026_COUNTS.items():
        if counts[metric_id] != expected:
            raise ValueError(f"legacy frozen count changed for {metric_id}")
    no_supported = (
        counts["dmarc.genuine_no_record"] + counts["dmarc.missing_policy"] + counts["dmarc.unsupported_policy"]
    )
    if counts["dmarc.no_supported_effective_policy"] != no_supported:
        raise ValueError("legacy no-supported-effective-policy reconciliation failed")
    no_enforcement = no_supported + counts["dmarc.none"]
    if counts["dmarc.no_detected_enforcement"] != no_enforcement:
        raise ValueError("legacy no-detected-enforcement reconciliation failed")


def validate_metrics(metrics: Iterable[Metric]) -> None:
    """Fail closed when catalogue arithmetic, denominators, or display changes."""
    catalogue = tuple(metrics)
    values = {metric.metric_id: metric for metric in catalogue}
    if len(values) != len(catalogue):
        raise ValueError("duplicate metric_id")
    for metric in values.values():
        if metric.numerator < 0 or metric.denominator < 0 or metric.numerator > metric.denominator:
            raise ValueError(f"invalid counts for {metric.metric_id}")
        if metric.denominator_metric_id is not None:
            referenced = values.get(metric.denominator_metric_id)
            if referenced is None or metric.denominator != referenced.numerator:
                raise ValueError(f"denominator identity failed for {metric.metric_id}")
        expected_percentage = high_precision_percentage(metric.numerator, metric.denominator)
        if metric.percentage != expected_percentage:
            raise ValueError(f"exact percentage failed for {metric.metric_id}")
        if metric.display_percentage != display_percentage(metric.percentage, metric.precision):
            raise ValueError(f"percentage rounding failed for {metric.metric_id}")

    def count(metric_id: str) -> int:
        return values[metric_id].numerator

    if count("population.total") != count("population.analyzable") + count("population.error"):
        raise ValueError("population reconciliation failed")
    if count("population.analyzable") != count("mx.present") + count("mx.absent"):
        raise ValueError("MX population reconciliation failed")
    if count("population.analyzable") != count("domain.exists") + count("domain.not_exists"):
        raise ValueError("domain-existence reconciliation failed")
    if count("mx.present") != sum(count(f"mx.provider.{provider}") for provider in KNOWN_PROVIDERS):
        raise ValueError("MX provider reconciliation failed")
    if count("spf.present") != sum(count(f"spf.{terminal}") for terminal in SUPPORTED_SPF_TERMINALS) + count("spf.no_terminal_mechanism"):
        raise ValueError("SPF terminal reconciliation failed")
    if count("mx.present") != count("spf.present") + count("spf.absent"):
        raise ValueError("SPF presence reconciliation failed")
    if count("mx.present") != count("dkim.selector_observed") + count("dkim.selector_not_observed"):
        raise ValueError("DKIM selector reconciliation failed")
    if count("dmarc.detected") != (
        count("dmarc.reject") + count("dmarc.quarantine") + count("dmarc.none")
        + count("dmarc.missing_policy") + count("dmarc.unsupported_policy")
    ):
        raise ValueError("DMARC policy reconciliation failed")
    if count("mx.present") != count("dmarc.genuine_no_record") + count("dmarc.detected"):
        raise ValueError("DMARC detection reconciliation failed")
    if count("dmarc.no_supported_effective_policy") != (
        count("dmarc.genuine_no_record") + count("dmarc.missing_policy") + count("dmarc.unsupported_policy")
    ):
        raise ValueError("DMARC no-supported-effective-policy reconciliation failed")
    if count("dmarc.no_detected_enforcement") != count("dmarc.no_supported_effective_policy") + count("dmarc.none"):
        raise ValueError("DMARC no-detected-enforcement reconciliation failed")
