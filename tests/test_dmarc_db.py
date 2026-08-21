import json
import sqlite3

import pytest

from dmarc_scanner.db import create_table, get_done_domains, insert_result
from dmarc_scanner.models import DmarcScanResult


@pytest.fixture
def conn():
    connection = sqlite3.connect(":memory:")
    yield connection
    connection.close()


def test_create_table_is_idempotent(conn):
    create_table(conn)
    create_table(conn)  # must not raise
    cursor = conn.execute("SELECT COUNT(*) FROM dmarc_scan_results")
    assert cursor.fetchone()[0] == 0


def test_create_table_raises_on_schema_mismatch(conn):
    conn.execute("CREATE TABLE dmarc_scan_results (domain TEXT PRIMARY KEY)")
    conn.commit()
    with pytest.raises(RuntimeError):
        create_table(conn)


def test_insert_and_get_done_domains(conn):
    create_table(conn)
    insert_result(conn, DmarcScanResult(domain="a.ch"))
    insert_result(conn, DmarcScanResult(domain="b.ch"))
    conn.commit()

    assert get_done_domains(conn) == {"a.ch", "b.ch"}


def test_insert_result_replaces_on_conflict(conn):
    create_table(conn)
    insert_result(conn, DmarcScanResult(domain="a.ch", has_mx=False))
    insert_result(conn, DmarcScanResult(domain="a.ch", has_mx=True))
    conn.commit()

    row = conn.execute(
        "SELECT has_mx FROM dmarc_scan_results WHERE domain = 'a.ch'"
    ).fetchone()
    assert row[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM dmarc_scan_results").fetchone()[0] == 1


def test_list_fields_round_trip_as_json(conn):
    create_table(conn)
    result = DmarcScanResult(
        domain="a.ch",
        mx_hosts=["mx1.example.ch", "mx2.example.ch"],
        dkim_selectors_checked=["selector1", "selector2"],
        dkim_selectors_found=["selector1"],
        caa_records=['0 issue "letsencrypt.org"'],
        query_statuses={"MX a.ch": "ok", "DS a.ch": "noanswer"},
    )
    insert_result(conn, result)
    conn.commit()

    row = conn.execute(
        "SELECT mx_hosts, dkim_selectors_checked, dkim_selectors_found, caa_records, query_statuses "
        "FROM dmarc_scan_results WHERE domain = 'a.ch'"
    ).fetchone()
    assert json.loads(row[0]) == ["mx1.example.ch", "mx2.example.ch"]
    assert json.loads(row[1]) == ["selector1", "selector2"]
    assert json.loads(row[2]) == ["selector1"]
    assert json.loads(row[3]) == ['0 issue "letsencrypt.org"']
    assert json.loads(row[4]) == {"MX a.ch": "ok", "DS a.ch": "noanswer"}


def test_dmarc_report_domain_list_fields_round_trip_as_json(conn):
    create_table(conn)
    result = DmarcScanResult(
        domain="a.ch",
        dmarc_rua_domains=["dmarcian.com", "vendor-a.com"],
        dmarc_ruf_domains=["vendor-b.net"],
    )
    insert_result(conn, result)
    conn.commit()

    row = conn.execute(
        "SELECT dmarc_rua_domains, dmarc_ruf_domains FROM dmarc_scan_results WHERE domain = 'a.ch'"
    ).fetchone()
    assert json.loads(row[0]) == ["dmarcian.com", "vendor-a.com"]
    assert json.loads(row[1]) == ["vendor-b.net"]


def test_get_done_domains_excludes_errored_rows(conn):
    # A domain that errored is written to the DB (so the DB reflects every
    # attempt) but must NOT count as "done" — a later run should retry it
    # instead of treating a transient DNS failure as final.
    create_table(conn)
    insert_result(conn, DmarcScanResult(domain="ok.ch"))
    insert_result(conn, DmarcScanResult(domain="broken.ch", error="mx_query_error"))
    conn.commit()

    assert get_done_domains(conn) == {"ok.ch"}


def test_get_done_domains_excludes_rows_with_partial_query_errors(conn):
    create_table(conn)
    insert_result(conn, DmarcScanResult(
        domain="partial.ch",
        query_statuses={"DS partial.ch": "error"},
    ))
    conn.commit()

    assert get_done_domains(conn) == set()
