import sqlite3

import pytest

import dmarc_scan
from dmarc_scan import load_domains, run
from dmarc_scanner.db import get_done_domains
from dmarc_scanner.provenance import manifest_path_for


def test_load_domains_strips_blank_lines_and_trailing_dots(tmp_path):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("a.ch\n\nb.ch.\n  \nc.ch\n")

    assert load_domains(str(domains_file)) == ["a.ch", "b.ch", "c.ch"]


def _fake_query_factory():
    """Every domain: MX -> a self-hosted host, DS -> noanswer, everything
    else -> noanswer. Enough to exercise the full run() path without any
    real network access."""

    def query(name, rdtype):
        if rdtype == "MX":
            base = name
            return "ok", [f"10 mail.{base}."]
        return "noanswer", []

    return query


def test_run_writes_all_domains_to_db(tmp_path):
    db_path = str(tmp_path / "dmarc.db")
    run(["a.ch", "b.ch"], db_path, concurrency=2, query_fn=_fake_query_factory())

    conn = sqlite3.connect(db_path)
    assert get_done_domains(conn) == {"a.ch", "b.ch"}
    conn.close()


def test_run_resumes_and_skips_already_scanned_domains(tmp_path):
    db_path = str(tmp_path / "dmarc.db")

    calls = []

    def counting_query(name, rdtype):
        calls.append((name, rdtype))
        if rdtype == "MX":
            return "ok", [f"10 mail.{name}."]
        return "noanswer", []

    run(["a.ch", "b.ch"], db_path, concurrency=2, query_fn=counting_query)
    calls.clear()

    run(["a.ch", "b.ch", "c.ch"], db_path, concurrency=2, query_fn=counting_query)

    domains_queried_for_mx = {name for name, rdtype in calls if rdtype == "MX"}
    assert domains_queried_for_mx == {"c.ch"}

    conn = sqlite3.connect(db_path)
    assert get_done_domains(conn) == {"a.ch", "b.ch", "c.ch"}
    conn.close()


def test_run_retries_domains_that_previously_errored(tmp_path):
    # Regression test for the resumability fix: a domain that errored on one
    # run must be retried (not silently skipped) on the next.
    db_path = str(tmp_path / "dmarc.db")

    def failing_query(name, rdtype):
        return "error", []

    run(["flaky.ch"], db_path, concurrency=1, query_fn=failing_query)

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT error, has_mx FROM dmarc_scan_results WHERE domain = 'flaky.ch'"
    ).fetchone()
    assert row[0] == "mx_query_error"
    conn.close()

    def succeeding_query(name, rdtype):
        if rdtype == "MX":
            return "ok", [f"10 mail.{name}."]
        return "noanswer", []

    run(["flaky.ch"], db_path, concurrency=1, query_fn=succeeding_query)

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT error, has_mx FROM dmarc_scan_results WHERE domain = 'flaky.ch'"
    ).fetchone()
    assert row[0] == ""
    assert row[1] == 1
    conn.close()


def test_run_records_error_row_when_scan_domain_raises_unexpectedly(tmp_path):
    # Regression test: if scan_domain crashes outright (a bug, not a
    # handled DNS status), the domain must still be written to the DB with
    # an error set — not silently dropped from both the DB and the run's
    # counts. A malformed MX answer with no whitespace makes parse_mx_answer
    # raise ValueError while unpacking, simulating an unanticipated crash.
    db_path = str(tmp_path / "dmarc.db")

    def crashing_query(name, rdtype):
        if rdtype == "MX":
            return "ok", ["malformed-mx-answer-with-no-space"]
        return "noanswer", []

    run(["crash.ch"], db_path, concurrency=1, query_fn=crashing_query)

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT error FROM dmarc_scan_results WHERE domain = 'crash.ch'"
    ).fetchone()
    assert row is not None
    assert row[0].startswith("scan_exception")
    assert get_done_domains(conn) == set()
    conn.close()


def test_run_with_fake_query_fn_never_uses_the_real_query_batch(tmp_path, monkeypatch):
    # Safety property: a caller supplying a fake query_fn but no
    # query_batch_fn must get scan_domain's safe sequential fallback
    # (derived from that same fake), never dmarc_scanner.resolve's real,
    # network-touching query_batch. If run() defaulted query_batch_fn to the
    # real one whenever it's simply unset (rather than only when query_fn is
    # ALSO real), every existing fake-query_fn test above would silently
    # start making real DNS calls through the batch path.
    def exploding_real_batch(pairs):
        raise AssertionError("real query_batch must never run when query_fn is faked")

    monkeypatch.setattr(dmarc_scan, "real_query_batch", exploding_real_batch)

    db_path = str(tmp_path / "dmarc.db")
    run(["a.ch"], db_path, concurrency=1, query_fn=_fake_query_factory())

    conn = sqlite3.connect(db_path)
    assert get_done_domains(conn) == {"a.ch"}
    conn.close()


def test_run_refuses_legacy_output_before_wal_or_fresh_drop_and_removes_manifest(tmp_path):
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE dmarc_scan_results (domain TEXT PRIMARY KEY, dnssec_signed INTEGER, has_tlsa INTEGER, error TEXT)"
    )
    conn.execute("INSERT INTO dmarc_scan_results VALUES ('archived.ch', 1, 1, '')")
    conn.commit()
    conn.close()
    before = db_path.read_bytes()
    manifest_path_for(db_path).write_text('{"stale": true}\n')

    with pytest.raises(RuntimeError, match="legacy output database"):
        run(["new.ch"], str(db_path), concurrency=1, resume=False, query_fn=_fake_query_factory())

    assert db_path.read_bytes() == before
    conn = sqlite3.connect(db_path)
    assert conn.execute("SELECT domain FROM dmarc_scan_results").fetchall() == [("archived.ch",)]
    conn.close()
    assert not manifest_path_for(db_path).exists()


def test_finalize_database_rejects_busy_checkpoint_and_closes_connection(tmp_path):
    db_path = tmp_path / "busy.db"
    writer = sqlite3.connect(db_path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE records (value TEXT)")
    writer.commit()
    reader = sqlite3.connect(db_path)
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM records").fetchall()
    writer.execute("INSERT INTO records VALUES ('uncheckpointed')")
    writer.commit()

    with pytest.raises(RuntimeError, match="checkpoint incomplete"):
        dmarc_scan._finalize_database(writer)

    with pytest.raises(sqlite3.ProgrammingError):
        writer.execute("SELECT 1")
    reader.close()
