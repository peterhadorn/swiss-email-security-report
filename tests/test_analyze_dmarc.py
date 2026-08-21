import sqlite3

from analyze_dmarc import analyze
from dmarc_scanner.db import create_table, insert_result
from dmarc_scanner.models import DmarcScanResult


def _seed(db_path):
    conn = sqlite3.connect(db_path)
    create_table(conn)
    rows = [
        DmarcScanResult(domain="nomail.ch", has_mx=False, has_ds_record=False),
        # Even when an errored row contains stale or partial flags, it must
        # affect only the reported error count, never a descriptive metric.
        DmarcScanResult(
            domain="broken.ch", error="mx_query_error", has_mx=True,
            mx_provider="contaminated", has_spf=True, has_dkim=True,
            dkim_weak_key=True, has_dmarc=True, dmarc_policy="reject",
            has_ds_record=True, has_bimi=True, has_mta_sts=True,
            has_tlsrpt=True, has_caa=True, has_tlsa_record=True,
        ),
        DmarcScanResult(
            domain="unprotected.ch", has_mx=True, mx_provider="hostpoint",
            has_spf=True, spf_all_mechanism="softfail",
            has_dmarc=False, dmarc_policy="absent",
        ),
        DmarcScanResult(
            domain="monitoring.ch", has_mx=True, mx_provider="microsoft365",
            has_spf=True, spf_all_mechanism="hardfail",
            has_dmarc=True, dmarc_policy="none", dmarc_rua=True,
        ),
        DmarcScanResult(
            domain="protected.ch", has_mx=True, mx_provider="google_workspace",
            has_spf=True, spf_all_mechanism="hardfail", spf_lookup_count=9,
            spf_near_limit=True, has_dkim=True, dkim_weak_key=True,
            has_dmarc=True, dmarc_policy="reject", dmarc_rua=True, dmarc_ruf=True,
            has_ds_record=True, has_bimi=True, has_mta_sts=True, has_tlsrpt=True,
            has_tlsa_record=True,
        ),
    ]
    for row in rows:
        insert_result(conn, row)
    conn.commit()
    conn.close()


def test_analyze_reports_descriptive_measurement_terms(tmp_path, capsys):
    db_path = str(tmp_path / "dmarc.db")
    _seed(db_path)

    analyze(db_path)

    out = capsys.readouterr().out
    assert "Total rows in DB: 5" in out
    assert "Analyzable domains: 4" in out
    assert "Errored (excluded from descriptive denominators): 1 (20.0%)" in out
    assert "Non-null MX record present: 3 (75.0%)" in out
    assert "DS record present: 1 (25.0%)" in out
    assert "TLSA record present: 1 (33.3%)" in out
    assert "MTA-STS TXT record present: 1 (33.3%)" in out
    assert "DKIM selector observed (provider-aware selector lower bound): 1 (33.3%)" in out
    assert "Observed selector flagged by key-length heuristic: 1 (33.3%)" in out
    assert "Has SPF: 3 (100.0%)" in out
    assert "Has DMARC record: 2 (66.7%)" in out
    assert "BIMI TXT record present: 1 (33.3%)" in out
    assert "Absent or monitoring-only policy" in out
    assert "hostpoint" in out
    assert "contaminated" not in out


def test_analyze_raises_on_missing_db(tmp_path):
    missing = str(tmp_path / "does-not-exist.db")
    try:
        analyze(missing)
        assert False, "expected SystemExit"
    except SystemExit:
        pass
