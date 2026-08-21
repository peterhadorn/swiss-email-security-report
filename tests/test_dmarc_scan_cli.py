import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import dmarc_scan
from dmarc_scan import load_domains, run
from dmarc_scanner.db import get_done_domains
from dmarc_scanner.provenance import (
    consume_prepared_resume_manifest,
    manifest_archive_path_for,
    manifest_path_for,
    prepare_resume_manifest,
    write_scan_manifest,
)


START = datetime(2026, 8, 21, 10, 0, tzinfo=timezone.utc)
RESOLVERS = {
    "nameservers": ["1.1.1.1"], "rotate": True,
    "timeout_seconds": 4.0, "lifetime_seconds": 6.0,
    "cache_policy": "disabled", "dnspython_version": "2.8.0",
}


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


def _seal_and_prepare_resume(path, source, summary, concurrency):
    runtime_resolvers = dmarc_scan.resolve.resolver_configuration()
    runtime_batch_pool_size = dmarc_scan.resolve.batch_pool_size()
    write_scan_manifest(
        path, source_input_lines=source, planned_input_lines=source,
        run_summary=summary, resume_link=None, scanner_git_revision="a" * 40,
        scanner_git_dirty=False, resolver_configuration=runtime_resolvers,
        started_at=START, finished_at=START + timedelta(minutes=1),
        concurrency=concurrency, batch_pool_size=runtime_batch_pool_size,
        limit=None, shuffle=False, shuffle_seed=None,
    )
    prepared = prepare_resume_manifest(
        path, source_input_lines=source, planned_input_lines=source,
        resolver_configuration=runtime_resolvers, concurrency=concurrency,
        batch_pool_size=runtime_batch_pool_size, limit=None, shuffle=False,
        shuffle_seed=None,
        started_at=START + timedelta(minutes=2),
    )
    consume_prepared_resume_manifest(
        path, prepared, source_input_lines=source, planned_input_lines=source,
        resolver_configuration=runtime_resolvers, concurrency=concurrency,
        batch_pool_size=runtime_batch_pool_size, limit=None, shuffle=False,
        shuffle_seed=None,
    )
    return prepared


def test_run_writes_all_domains_to_db(tmp_path):
    db_path = str(tmp_path / "dmarc.db")
    run(["a.ch", "b.ch"], db_path, concurrency=2, resume=False,
        query_fn=_fake_query_factory())

    conn = sqlite3.connect(db_path)
    assert get_done_domains(conn) == {"a.ch", "b.ch"}
    conn.close()


def test_resume_refuses_a_changed_source_universe(tmp_path):
    db_path = str(tmp_path / "dmarc.db")
    summary = run(["a.ch", "b.ch"], db_path, concurrency=2, resume=False,
                  query_fn=_fake_query_factory())
    write_scan_manifest(
        db_path, source_input_lines=["a.ch", "b.ch"],
        planned_input_lines=["a.ch", "b.ch"], run_summary=summary,
        resume_link=None, scanner_git_revision="a" * 40,
        scanner_git_dirty=False, resolver_configuration=RESOLVERS,
        started_at=START, finished_at=START + timedelta(minutes=1),
        concurrency=2, batch_pool_size=1, limit=None, shuffle=False,
        shuffle_seed=None,
    )
    before = Path(db_path).read_bytes()
    with pytest.raises(RuntimeError, match="universe|rows"):
        prepare_resume_manifest(
            db_path, source_input_lines=["a.ch", "b.ch", "c.ch"],
            planned_input_lines=["a.ch", "b.ch", "c.ch"],
            resolver_configuration=RESOLVERS, concurrency=2,
            batch_pool_size=1, limit=None, shuffle=False, shuffle_seed=None,
            started_at=START + timedelta(minutes=2),
        )
    assert Path(db_path).read_bytes() == before


def test_run_retries_domains_that_previously_errored(tmp_path):
    # Regression test for the resumability fix: a domain that errored on one
    # run must be retried (not silently skipped) on the next.
    db_path = str(tmp_path / "dmarc.db")

    def failing_query(name, rdtype):
        return "error", []

    first = run(["flaky.ch"], db_path, concurrency=1, resume=False,
                query_fn=failing_query)

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

    prepared = _seal_and_prepare_resume(db_path, ["flaky.ch"], first, 1)
    run(["flaky.ch"], db_path, concurrency=1, resume=True,
        query_fn=succeeding_query, prepared_resume=prepared)

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

    run(["crash.ch"], db_path, concurrency=1, resume=False,
        query_fn=crashing_query)

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
    run(["a.ch"], db_path, concurrency=1, resume=False,
        query_fn=_fake_query_factory())

    conn = sqlite3.connect(db_path)
    assert get_done_domains(conn) == {"a.ch"}
    conn.close()


def test_run_refuses_legacy_output_before_wal_or_fresh_drop_and_preserves_manifest(tmp_path):
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

    with pytest.raises(RuntimeError, match="choose a new --output"):
        run(["new.ch"], str(db_path), concurrency=1, resume=False, query_fn=_fake_query_factory())

    assert db_path.read_bytes() == before
    conn = sqlite3.connect(db_path)
    assert conn.execute("SELECT domain FROM dmarc_scan_results").fetchall() == [("archived.ch",)]
    conn.close()
    assert manifest_path_for(db_path).read_text() == '{"stale": true}\n'


def test_run_refuses_unconsumed_active_manifest_before_database_mutation(tmp_path):
    db_path = tmp_path / "active.db"
    run(["a.ch"], str(db_path), concurrency=1, resume=False, query_fn=_fake_query_factory())
    before = db_path.read_bytes()
    manifest_path_for(db_path).write_text('{"active": true}\n')

    with pytest.raises(RuntimeError, match="consumed PreparedResume"):
        run(["a.ch"], str(db_path), concurrency=1, resume=True, query_fn=_fake_query_factory())

    assert db_path.read_bytes() == before
    assert manifest_path_for(db_path).read_text() == '{"active": true}\n'


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


def test_run_revalidates_database_after_consume_immediately_before_wal(tmp_path):
    path = tmp_path / "changed-after-consume.db"
    source = ["a.ch"]
    summary = run(
        source,
        str(path),
        concurrency=1,
        resume=False,
        query_fn=_fake_query_factory(),
    )
    prepared = _seal_and_prepare_resume(path, source, summary, 1)
    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE dmarc_scan_results SET has_mx = 0 WHERE domain = 'a.ch'"
    )
    connection.commit()
    connection.close()
    changed_bytes = path.read_bytes()

    with pytest.raises(RuntimeError, match="database bytes changed"):
        run(
            source,
            str(path),
            concurrency=1,
            resume=True,
            query_fn=_fake_query_factory(),
            prepared_resume=prepared,
        )

    assert path.read_bytes() == changed_bytes
    assert not Path(str(path) + "-wal").exists()
    assert not Path(str(path) + "-shm").exists()


def test_run_rejects_changed_full_plan_after_consume_before_wal(tmp_path):
    path = tmp_path / "changed-plan-after-consume.db"
    source = ["a.ch", "b.ch"]
    summary = run(
        source,
        str(path),
        concurrency=1,
        resume=False,
        query_fn=_fake_query_factory(),
    )
    prepared = _seal_and_prepare_resume(path, source, summary, 1)
    before = path.read_bytes()

    with pytest.raises(RuntimeError, match="plan changed"):
        run(
            [],
            str(path),
            concurrency=1,
            resume=True,
            query_fn=_fake_query_factory(),
            prepared_resume=prepared,
        )

    assert path.read_bytes() == before
    assert not Path(str(path) + "-wal").exists()


def test_run_rejects_concurrency_drift_after_consume_before_wal(tmp_path):
    path = tmp_path / "changed-concurrency-after-consume.db"
    source = ["a.ch"]
    summary = run(
        source,
        str(path),
        concurrency=1,
        resume=False,
        query_fn=_fake_query_factory(),
    )
    prepared = _seal_and_prepare_resume(path, source, summary, 1)
    before = path.read_bytes()

    with pytest.raises(RuntimeError, match="concurrency changed"):
        run(
            source,
            str(path),
            concurrency=2,
            resume=True,
            query_fn=_fake_query_factory(),
            prepared_resume=prepared,
        )

    assert path.read_bytes() == before
    assert not Path(str(path) + "-wal").exists()


@pytest.mark.parametrize("drift", ["resolver", "batch_pool"])
def test_run_rejects_live_resolver_or_batch_pool_drift_before_wal(
    tmp_path, monkeypatch, drift
):
    path = tmp_path / f"changed-{drift}-after-consume.db"
    source = ["a.ch"]
    summary = run(
        source,
        str(path),
        concurrency=1,
        resume=False,
        query_fn=_fake_query_factory(),
    )
    prepared = _seal_and_prepare_resume(path, source, summary, 1)
    before = path.read_bytes()
    if drift == "resolver":
        monkeypatch.setattr(
            dmarc_scan.resolve,
            "QUERY_TIMEOUT",
            dmarc_scan.resolve.QUERY_TIMEOUT + 1.0,
        )
        match = "resolver configuration changed"
    else:
        monkeypatch.setattr(
            dmarc_scan.resolve,
            "_BATCH_POOL_SIZE",
            dmarc_scan.resolve.batch_pool_size() + 1,
        )
        match = "batch pool size changed"

    with pytest.raises(RuntimeError, match=match):
        run(
            source,
            str(path),
            concurrency=1,
            resume=True,
            query_fn=_fake_query_factory(),
            prepared_resume=prepared,
        )

    assert path.read_bytes() == before
    assert not Path(str(path) + "-wal").exists()
    assert not Path(str(path) + "-shm").exists()


def test_cli_negative_limit_preserves_existing_database_and_sidecar(tmp_path, monkeypatch):
    input_path = tmp_path / "domains.txt"
    input_path.write_text("a.ch\n")
    output_path = tmp_path / "existing.db"
    summary = run(
        ["a.ch"],
        str(output_path),
        concurrency=1,
        resume=False,
        query_fn=_fake_query_factory(),
    )
    write_scan_manifest(
        output_path,
        source_input_lines=["a.ch"],
        planned_input_lines=["a.ch"],
        run_summary=summary,
        resume_link=None,
        scanner_git_revision="a" * 40,
        scanner_git_dirty=False,
        resolver_configuration=RESOLVERS,
        started_at=START,
        finished_at=START + timedelta(minutes=1),
        concurrency=1,
        batch_pool_size=1,
        limit=None,
        shuffle=False,
        shuffle_seed=None,
    )
    before_db = output_path.read_bytes()
    before_sidecar = manifest_path_for(output_path).read_bytes()
    monkeypatch.setattr(
        "sys.argv",
        [
            "dmarc_scan.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--limit",
            "-1",
        ],
    )

    with pytest.raises(ValueError, match="limit"):
        dmarc_scan.main()

    assert output_path.read_bytes() == before_db
    assert manifest_path_for(output_path).read_bytes() == before_sidecar


def test_cli_no_resume_refuses_existing_output_and_sidecar_without_changes(
    tmp_path, monkeypatch
):
    input_path = tmp_path / "domains.txt"
    input_path.write_text("a.ch\n")
    output_path = tmp_path / "existing-no-resume.db"
    output_path.write_bytes(b"existing database bytes")
    sidecar = manifest_path_for(output_path)
    sidecar.write_bytes(b"existing sidecar bytes")
    monkeypatch.setattr(
        "sys.argv",
        [
            "dmarc_scan.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--no-resume",
        ],
    )

    with pytest.raises(RuntimeError, match="choose a new --output"):
        dmarc_scan.main()

    assert output_path.read_bytes() == b"existing database bytes"
    assert sidecar.read_bytes() == b"existing sidecar bytes"


def test_cli_rejects_fresh_archive_symlink_before_database_creation(tmp_path, monkeypatch):
    input_path = tmp_path / "domains.txt"
    input_path.write_text("a.ch\n")
    output_path = tmp_path / "new.db"
    archive_target = tmp_path / "elsewhere"
    archive_target.mkdir()
    manifest_archive_path_for(output_path).symlink_to(
        archive_target, target_is_directory=True
    )
    monkeypatch.setattr(
        "sys.argv",
        ["dmarc_scan.py", "--input", str(input_path), "--output", str(output_path)],
    )

    with pytest.raises(RuntimeError, match="manifest archive.*choose a new"):
        dmarc_scan.main()

    assert not output_path.exists()


@pytest.mark.parametrize(
    "option,value,match",
    [
        ("--concurrency", "0", "concurrency"),
        ("--batch-pool-size", "0", "batch-pool-size"),
    ],
)
def test_cli_rejects_nonpositive_worker_settings_before_output_creation(
    tmp_path, monkeypatch, option, value, match
):
    input_path = tmp_path / "domains.txt"
    input_path.write_text("a.ch\n")
    output_path = tmp_path / "new.db"
    monkeypatch.setattr(
        "sys.argv",
        [
            "dmarc_scan.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            option,
            value,
        ],
    )

    with pytest.raises(ValueError, match=match):
        dmarc_scan.main()

    assert not output_path.exists()
