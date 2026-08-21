"""Tests for the privacy-preserving canonical aggregate exporter.

The test rows use opaque synthetic identifiers only.  No observed domains,
DNS records, or domain-level release data are stored in this repository.
"""

from dataclasses import FrozenInstanceError, asdict
from decimal import Decimal
import json
import sqlite3
from pathlib import Path
import re

import pytest

from dmarc_scanner.db import COLUMNS, JSON_FIELDS, create_table, insert_result
from dmarc_scanner.models import DmarcScanResult


def _canonical_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    create_table(conn)
    rows = [
        DmarcScanResult(
            domain="case-01", has_mx=True, mx_provider="google_workspace",
            has_spf=True, spf_all_mechanism="hardfail", has_legacy_spf_rrtype=True,
            has_dkim=True, dkim_testing_mode=True, dkim_weak_key=True,
            has_dmarc=True, dmarc_policy="reject", dmarc_pct=50,
            dmarc_adkim="s", has_ds_record=True, ns_hosts=["ns"],
            mx_unresolvable=True, has_bimi=True, has_mta_sts=True,
            has_tlsrpt=True, has_caa=True, has_tlsa_record=True,
        ),
        DmarcScanResult(
            domain="case-02", has_mx=True, mx_provider="hostpoint",
            has_spf=True, spf_all_mechanism="softfail", has_dmarc=True,
            dmarc_policy="none", ns_hosts=["ns"],
        ),
        DmarcScanResult(
            domain="case-03", has_mx=True, mx_provider="other", has_dmarc=False,
        ),
        DmarcScanResult(
            domain="case-04", has_mx=True, mx_provider="unknown", has_spf=True,
            spf_all_mechanism="neutral", has_dmarc=True, dmarc_policy="absent",
        ),
        DmarcScanResult(
            domain="case-05", has_mx=True, mx_provider="self_hosted",
            has_spf=True, spf_all_mechanism="pass", has_dmarc=True,
            dmarc_policy="unsupported", dmarc_aspf="s",
        ),
        DmarcScanResult(
            domain="case-06", has_mx=False, has_spf=True,
            spf_all_mechanism="hardfail", has_dmarc=True,
            dmarc_policy="quarantine", has_ds_record=True,
        ),
        DmarcScanResult(domain="case-07", domain_exists=False, has_mx=False),
        DmarcScanResult(
            domain="case-08", error="resolver_error", has_mx=True,
            mx_provider="microsoft365", has_dmarc=True, dmarc_policy="reject",
            query_statuses={"MX case-08": "error"},
        ),
    ]
    for row in rows:
        insert_result(conn, row)
    conn.commit()
    return conn


def _legacy_connection() -> sqlite3.Connection:
    """A complete archived schema: aliases only, no query_statuses column."""
    conn = sqlite3.connect(":memory:")
    columns = [
        item.replace("has_ds_record", "dnssec_signed").replace(
            "has_tlsa_record", "has_tlsa"
        )
        for item in COLUMNS
        if not item.startswith("query_statuses ")
    ]
    conn.execute(f"CREATE TABLE dmarc_scan_results ({', '.join(columns)})")
    values = asdict(DmarcScanResult(
        domain="case-legacy", has_mx=True, mx_provider="other", has_spf=True,
        spf_all_mechanism="hardfail", has_dmarc=True, dmarc_policy="reject",
        has_ds_record=True, has_tlsa_record=True,
    ))
    for field in JSON_FIELDS:
        values[field] = json.dumps(values[field])
    values["dnssec_signed"] = values.pop("has_ds_record")
    values["has_tlsa"] = values.pop("has_tlsa_record")
    values.pop("query_statuses")
    names = list(values)
    conn.execute(
        "INSERT INTO dmarc_scan_results (" + ", ".join(names) + ") VALUES (" + ", ".join("?" for _ in names) + ")",
        [values[name] for name in names],
    )
    conn.commit()
    return conn


def _by_id(metrics):
    return {metric.metric_id: metric for metric in metrics}


@pytest.fixture
def canonical_conn():
    conn = _canonical_connection()
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def legacy_conn():
    conn = _legacy_connection()
    try:
        yield conn
    finally:
        conn.close()


def test_aggregate_canonical_schema_uses_exact_decimal_percentages_and_invariants(canonical_conn):
    from release.aggregate import aggregate_connection, validate_metrics

    conn = canonical_conn
    metrics = aggregate_connection(conn, measurement_period="2026-08-17/2026-08-19")
    values = _by_id(metrics)

    assert values["population.total"].numerator == 8
    assert values["population.analyzable"].numerator == 7
    assert values["population.error"].numerator == 1
    assert values["mx.present"].numerator == 5
    assert values["mx.absent"].numerator == 2
    assert values["mx.provider.google_workspace"].numerator == 1
    assert values["mx.provider.unknown"].numerator == 1
    assert values["spf.no_terminal_mechanism"].numerator == 0
    assert values["spf.no_mx_present"].numerator == 1
    assert values["dkim.weak_key_heuristic"].denominator == 1
    assert values["dmarc.genuine_no_record"].numerator == 1
    assert values["dmarc.missing_policy"].numerator == 1
    assert values["dmarc.unsupported_policy"].numerator == 1
    assert values["dmarc.no_supported_effective_policy"].numerator == 3
    assert values["dmarc.no_detected_enforcement"].numerator == 4
    assert values["dmarc.partial_pct"].denominator == 5
    assert values["dmarc.strict_alignment"].numerator == 2
    assert values["ns.answer_present"].numerator == 2
    assert values["tlsa.record_present"].numerator == 1
    assert values["mx.unresolvable"].numerator == 1
    assert str(values["mx.present"].percentage).startswith("71.42857142857142857142857142")
    assert values["mx.present"].display_percentage == "71.43"
    assert validate_metrics(metrics) is None

    with pytest.raises(FrozenInstanceError):
        values["mx.present"].numerator = 0


def test_aggregate_reads_complete_legacy_schema_via_aliases_without_mutation(legacy_conn):
    from release.aggregate import aggregate_connection

    conn = legacy_conn
    metrics = _by_id(aggregate_connection(conn, measurement_period="2026-08"))

    assert metrics["ds.record_present"].numerator == 1
    assert metrics["tlsa.record_present"].numerator == 1
    assert "has_ds_record" not in {row[1] for row in conn.execute("PRAGMA table_info(dmarc_scan_results)")}
    assert "query_statuses" not in {row[1] for row in conn.execute("PRAGMA table_info(dmarc_scan_results)")}


def test_aggregate_fails_closed_for_unknown_schema_and_unexpected_provider():
    from release.aggregate import aggregate_connection

    conn = sqlite3.connect(":memory:")
    known = _canonical_connection()
    try:
        conn.execute("CREATE TABLE dmarc_scan_results (domain TEXT, error TEXT)")
        with pytest.raises(RuntimeError, match="unrecognized results schema"):
            aggregate_connection(conn, measurement_period="2026-08")
        known.execute("UPDATE dmarc_scan_results SET mx_provider = ? WHERE domain = ?", ("new_vendor", "case-01"))
        with pytest.raises(RuntimeError, match="unrecognized MX provider"):
            aggregate_connection(known, measurement_period="2026-08")
    finally:
        conn.close()
        known.close()


def test_aggregate_queries_are_parameterized_and_never_select_private_fields(canonical_conn):
    from release.aggregate import aggregate_connection

    conn = canonical_conn
    statements = []
    conn.set_trace_callback(statements.append)
    aggregate_connection(conn, measurement_period="2026-08")
    selects = [statement.lower() for statement in statements if statement.lower().startswith("select")]
    assert selects
    for statement in selects:
        if statement.startswith("select name from sqlite_master"):
            continue
        assert re.match(r"^select count\(\*\) from dmarc_scan_results where ", statement), statement
        projection = statement.split(" from ", 1)[0]
        assert projection == "select count(*)"
        assert "select *" not in projection
        assert not re.search(r"(?:\.|\"|\[|\s)domain(?:\.|\"|\]|\s|,)", projection), statement
        assert not any(field in projection for field in (
            "query_statuses", "ns_hosts", "mx_hosts", "spf_record", "dkim_selectors",
            "dmarc_record", "rua_domains", "ruf_domains", "bimi_record", "mta_sts_record",
            "tlsrpt_record", "caa_records", "tlsa_hosts",
        )), statement
    assert any("?" in statement for statement in __import__("release.aggregate", fromlist=["AGGREGATE_SQL"]).AGGREGATE_SQL)


def test_frozen_legacy_counts_reconcile_including_corrected_dmarc_buckets():
    from release.aggregate import validate_legacy_expected_counts

    fixture = json.loads(Path("tests/fixtures/release/legacy-2026-expected-counts.json").read_text())
    assert 976_814 + 308 + 180 == 977_302
    assert 977_302 + 219_990 == 1_197_292
    assert validate_legacy_expected_counts(fixture["metrics"]) is None

    invalid = dict(fixture["metrics"])
    invalid["dmarc.no_detected_enforcement"] -= 1
    with pytest.raises(ValueError, match="frozen count changed"):
        validate_legacy_expected_counts(invalid)


def test_metric_schema_and_native_locale_catalogues_cover_every_metric():
    from release.aggregate import _specifications

    metric_ids = {"population.total", *[spec.metric_id for spec in _specifications({})]}
    schema = json.loads(Path("release/schema/metrics.schema.json").read_text())
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert set(schema["$defs"]["metric"]["required"]) >= {
        "metric_id", "percentage", "display_percentage", "precision", "caveat",
    }
    for locale in ("de", "fr", "it"):
        catalogue = json.loads(Path(f"release/locales/{locale}.json").read_text())
        assert catalogue["locale"] == locale
        assert metric_ids <= set(catalogue["labels"])


@pytest.mark.parametrize(
    ("column", "value", "message"),
    [
        ("query_statuses", '{"MX case-01": "error"}', "inconsistent query status"),
        ("has_mx", 2, "binary"),
        ("dmarc_pct", None, "DMARC pct"),
        ("dmarc_pct", 101, "DMARC pct"),
        ("dmarc_adkim", None, "DMARC alignment"),
        ("mx_provider", None, "MX provider"),
        ("query_statuses", "not-json", "invalid query status"),
        ("query_statuses", '{"MX case-01": "unexpected"}', "invalid query status"),
    ],
)
def test_aggregate_rejects_inconclusive_or_invalid_canonical_values(column, value, message, canonical_conn):
    from release.aggregate import aggregate_connection

    conn = canonical_conn
    conn.execute(f"UPDATE dmarc_scan_results SET {column} = ? WHERE domain = ?", (value, "case-01"))
    with pytest.raises(RuntimeError):
        aggregate_connection(conn, measurement_period="2026-08")


def test_aggregate_uses_an_explicit_read_snapshot_transaction(canonical_conn):
    from release.aggregate import aggregate_connection

    conn = canonical_conn
    statements = []
    conn.set_trace_callback(statements.append)
    aggregate_connection(conn, measurement_period="2026-08")
    assert statements[0].upper() == "BEGIN"
    assert statements[-1].upper() == "COMMIT"


def test_aggregate_database_uses_quoted_read_only_uri_for_special_filename(tmp_path):
    from release.aggregate import aggregate_database

    db_path = tmp_path / "results?#.db"
    conn = sqlite3.connect(db_path)
    create_table(conn)
    insert_result(conn, DmarcScanResult(domain="case-file"))
    conn.commit()
    conn.close()

    metrics = aggregate_database(db_path, measurement_period="2026-08")
    assert _by_id(metrics)["population.total"].numerator == 1
    assert not (tmp_path / "results").exists()
    read_only = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    with pytest.raises(sqlite3.OperationalError):
        read_only.execute("CREATE TABLE forbidden (value TEXT)")
    read_only.close()


def test_metrics_json_schema_validates_real_metric_instances():
    import jsonschema
    from release.aggregate import aggregate_connection

    schema = json.loads(Path("release/schema/metrics.schema.json").read_text())
    conn = _canonical_connection()
    try:
        instance = {"metrics": [metric.to_dict() for metric in aggregate_connection(
            conn, measurement_period="2026-08"
        )]}
    finally:
        conn.close()
    jsonschema.Draft202012Validator(schema).validate(instance)
