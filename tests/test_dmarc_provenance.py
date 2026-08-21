import hashlib
import json
import sqlite3
from datetime import datetime

import pytest

import dmarc_scan
from analyze_dmarc import analyze
from dmarc_scanner.db import create_table, metric_column
from dmarc_scanner.provenance import (
    SCANNER_REPOSITORY_ROOT,
    manifest_path_for,
    normalized_input,
    scanner_git_provenance,
    write_scan_manifest,
)


def test_normalized_input_is_stable_across_blank_lines_trailing_dots_and_line_endings():
    normalized = normalized_input(["a.ch\r\n", "\n", " b.ch. \n"])

    assert normalized == b"a.ch\nb.ch\n"
    assert hashlib.sha256(normalized).hexdigest() == hashlib.sha256(b"a.ch\nb.ch\n").hexdigest()


def test_write_scan_manifest_records_reproducibility_fields_and_sidecar(tmp_path):
    output = tmp_path / "scan.db"
    output.write_bytes(b"sqlite-output")
    started = datetime.fromisoformat("2026-08-21T10:00:00+00:00")
    finished = datetime.fromisoformat("2026-08-21T10:01:00+00:00")

    path = write_scan_manifest(
        output,
        source_input_lines=["a.ch", "b.ch."],
        effective_input_lines=["b.ch", "a.ch"],
        scanner_git_revision="a" * 40,
        scanner_git_dirty=True,
        resolver_configuration={
            "nameservers": ["1.1.1.1", "8.8.8.8"],
            "rotate": True,
            "timeout_seconds": 4.0,
            "lifetime_seconds": 6.0,
            "cache_policy": "disabled",
            "dnspython_version": "2.8.0",
        },
        started_at=started,
        finished_at=finished,
        concurrency=300,
        batch_pool_size=250,
        retry_resume_mode="resume_retry_partial_errors",
        limit=2,
        shuffle=True,
        shuffle_seed=42,
    )

    assert path == manifest_path_for(output)
    manifest = json.loads(path.read_text())
    assert manifest["source_input_normalized_sha256"] == hashlib.sha256(b"a.ch\nb.ch\n").hexdigest()
    assert manifest["source_input_normalized_line_count"] == 2
    assert manifest["effective_input_normalized_sha256"] == hashlib.sha256(b"b.ch\na.ch\n").hexdigest()
    assert manifest["effective_input_normalized_line_count"] == 2
    assert manifest["scanner_git_revision"] == "a" * 40
    assert manifest["scanner_git_dirty"] is True
    assert manifest["resolver_configuration"]["nameservers"] == ["1.1.1.1", "8.8.8.8"]
    assert manifest["started_at_utc"] == "2026-08-21T10:00:00Z"
    assert manifest["finished_at_utc"] == "2026-08-21T10:01:00Z"
    assert manifest["concurrency"] == 300
    assert manifest["batch_pool_size"] == 250
    assert manifest["retry_resume_mode"] == "resume_retry_partial_errors"
    assert manifest["limit"] == 2
    assert manifest["shuffle"] is True
    assert manifest["shuffle_seed"] == 42
    assert manifest["effective_input_order"] == "seeded_shuffle_then_limit"
    assert manifest["python_version"]
    assert manifest["output_sqlite_sha256"] == hashlib.sha256(b"sqlite-output").hexdigest()
    assert manifest["output_sqlite_size_bytes"] == len(b"sqlite-output")
    assert not list(tmp_path.glob("*.tmp"))


def test_cli_writes_manifest_after_an_empty_scan_without_dns(tmp_path, monkeypatch):
    input_path = tmp_path / "domains.txt"
    output_path = tmp_path / "results.db"
    input_path.write_text("example.ch\n")
    monkeypatch.setattr(
        "sys.argv",
        [
            "dmarc_scan.py", "--input", str(input_path), "--output", str(output_path),
            "--limit", "0", "--no-resume",
        ],
    )

    dmarc_scan.main()

    manifest = json.loads(manifest_path_for(output_path).read_text())
    assert manifest["normalized_input_line_count"] == 1
    assert manifest["effective_input_normalized_line_count"] == 0
    assert manifest["limit"] == 0
    assert manifest["retry_resume_mode"] == "fresh"
    assert output_path.exists()
    assert not (tmp_path / "results.db-wal").exists()


def test_cli_removes_stale_manifest_when_git_provenance_validation_fails(tmp_path, monkeypatch):
    input_path = tmp_path / "domains.txt"
    output_path = tmp_path / "results.db"
    input_path.write_text("example.ch\n")
    manifest_path_for(output_path).write_text('{"stale": true}\n')
    monkeypatch.setattr(
        "sys.argv",
        ["dmarc_scan.py", "--input", str(input_path), "--output", str(output_path), "--limit", "0"],
    )
    monkeypatch.setattr(
        dmarc_scan, "scanner_git_provenance",
        lambda: (_ for _ in ()).throw(RuntimeError("Git SHA-1 unavailable")),
    )

    with pytest.raises(RuntimeError, match="Git SHA-1 unavailable"):
        dmarc_scan.main()

    assert not manifest_path_for(output_path).exists()


def test_scanner_git_provenance_uses_scanner_repo_root_and_fails_closed(monkeypatch):
    calls = []

    def fake_check_output(command, **kwargs):
        calls.append((command, kwargs))
        if command[-1] == "HEAD":
            return "b" * 40 + "\n"
        return " M dmarc_scan.py\n"

    monkeypatch.setattr("dmarc_scanner.provenance.subprocess.check_output", fake_check_output)
    revision, dirty = scanner_git_provenance()

    assert revision == "b" * 40
    assert dirty is True
    assert all(call[1]["cwd"].resolve() == SCANNER_REPOSITORY_ROOT.resolve() for call in calls)


def test_scanner_git_provenance_is_independent_of_checkout_directory_name(monkeypatch, tmp_path):
    arbitrary_checkout = tmp_path / "arbitrary-checkout-name"
    arbitrary_checkout.mkdir()
    calls = []

    def fake_check_output(command, **kwargs):
        calls.append(kwargs["cwd"])
        return "c" * 40 + "\n" if command[-1] == "HEAD" else ""

    monkeypatch.chdir(arbitrary_checkout)
    monkeypatch.setattr("dmarc_scanner.provenance.subprocess.check_output", fake_check_output)

    assert scanner_git_provenance() == ("c" * 40, False)
    assert calls and all(path.resolve() == SCANNER_REPOSITORY_ROOT.resolve() for path in calls)


def test_scanner_git_provenance_rejects_non_commit_revision(monkeypatch):
    monkeypatch.setattr(
        "dmarc_scanner.provenance.subprocess.check_output", lambda *args, **kwargs: "unknown\n"
    )

    with pytest.raises(RuntimeError, match="Git SHA-1"):
        scanner_git_provenance()


def test_legacy_database_metric_columns_are_read_through_explicit_adapter(tmp_path):
    legacy = sqlite3.connect(tmp_path / "legacy.db")
    legacy.execute(
        "CREATE TABLE dmarc_scan_results (domain TEXT PRIMARY KEY, dnssec_signed INTEGER, has_tlsa INTEGER, error TEXT)"
    )

    assert metric_column(legacy, "has_ds_record") == "dnssec_signed"
    assert metric_column(legacy, "has_tlsa_record") == "has_tlsa"
    legacy.close()


def test_analyzer_reads_legacy_presence_columns_without_migrating_them(tmp_path, capsys):
    path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(path)
    legacy.execute(
        "CREATE TABLE dmarc_scan_results ("
        "domain TEXT PRIMARY KEY, error TEXT, has_mx INTEGER, dnssec_signed INTEGER, "
        "has_tlsa INTEGER, mx_provider TEXT, has_spf INTEGER, spf_all_mechanism TEXT, "
        "spf_near_limit INTEGER, has_dkim INTEGER, dkim_weak_key INTEGER, has_dmarc INTEGER, "
        "dmarc_policy TEXT, has_bimi INTEGER, has_mta_sts INTEGER, has_tlsrpt INTEGER, "
        "has_caa INTEGER)"
    )
    legacy.execute(
        "INSERT INTO dmarc_scan_results VALUES "
        "('legacy.ch', '', 1, 1, 1, 'other', 0, '', 0, 0, 0, 0, 'absent', 0, 0, 0, 0)"
    )
    legacy.commit()
    legacy.close()

    analyze(str(path))

    assert "DS record present: 1 (100.0%)" in capsys.readouterr().out
    inspected = sqlite3.connect(path)
    try:
        columns = {row[1] for row in inspected.execute("PRAGMA table_info(dmarc_scan_results)")}
    finally:
        inspected.close()
    assert "has_ds_record" not in columns
    assert "has_tlsa_record" not in columns


def test_new_scans_use_canonical_presence_columns_without_legacy_duplicates(tmp_path):
    conn = sqlite3.connect(tmp_path / "future.db")
    create_table(conn)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(dmarc_scan_results)")}

    assert "has_ds_record" in columns
    assert "has_tlsa_record" in columns
    assert "dnssec_signed" not in columns
    assert "has_tlsa" not in columns
    conn.close()
