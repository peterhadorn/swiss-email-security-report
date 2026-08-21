import hashlib
import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import sqlite3
import stat

import pytest

import dmarc_scan
import dmarc_scanner.provenance as provenance
from analyze_dmarc import analyze
from dmarc_scanner.db import create_table, insert_result, metric_column
from dmarc_scanner.models import DmarcScanResult
from dmarc_scanner.provenance import (
    ACTIVE_V1_ROOT_REVISION,
    FRESH_MODE,
    MEASUREMENT_CORE_FILES,
    RESUME_MODE,
    SCANNER_REPOSITORY_ROOT,
    URI_SAFETY_CORE_TRANSITION,
    DatabaseAccounting,
    RunSummary,
    _framed_measurement_core_digest,
    _immutable_manifest_copy,
    _run_identity,
    consume_prepared_resume_manifest,
    database_accounting,
    manifest_archive_path_for,
    manifest_path_for,
    measurement_core_sha256,
    normalized_input,
    normalized_input_digest,
    planned_domains_from_source,
    prepare_resume_manifest,
    scanner_git_provenance,
    write_scan_manifest,
)


UTC = timezone.utc
START = datetime(2026, 8, 21, 10, 0, tzinfo=UTC)
RESOLVERS = dmarc_scan.resolve.resolver_configuration()


def _digest(lines):
    return normalized_input_digest(lines)[0]


def _make_db(path: Path, results: list[DmarcScanResult]) -> DatabaseAccounting:
    conn = sqlite3.connect(path)
    create_table(conn)
    for result in results:
        insert_result(conn, result)
    conn.commit()
    accounting = database_accounting(conn)
    conn.close()
    return accounting


def _identity(path: Path) -> tuple[str, int]:
    payload = path.read_bytes()
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _write_v1_root(
    path: Path,
    source: list[str],
    *,
    started: datetime = START,
    finished: datetime = START + timedelta(minutes=1),
) -> bytes:
    sha, size = _identity(path)
    source_sha, source_count = normalized_input_digest(source)
    manifest = {
        "normalized_input_sha256": source_sha,
        "normalized_input_line_count": source_count,
        "source_input_normalized_sha256": source_sha,
        "source_input_normalized_line_count": source_count,
        "effective_input_normalized_sha256": source_sha,
        "effective_input_normalized_line_count": source_count,
        "scanner_git_revision": ACTIVE_V1_ROOT_REVISION,
        "scanner_git_dirty": False,
        "resolver_configuration": dict(RESOLVERS),
        "started_at_utc": started.isoformat().replace("+00:00", "Z"),
        "finished_at_utc": finished.isoformat().replace("+00:00", "Z"),
        "concurrency": 120,
        "batch_pool_size": 300,
        "retry_resume_mode": FRESH_MODE,
        "limit": None,
        "shuffle": False,
        "shuffle_seed": None,
        "effective_input_order": "source_order_then_limit",
        "python_version": "3.14.0",
        "output_sqlite_sha256": sha,
        "output_sqlite_size_bytes": size,
    }
    payload = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    manifest_path_for(path).write_bytes(payload)
    manifest_path_for(path).chmod(0o600)
    return payload


def _fresh_v2(
    path: Path,
    source: list[str],
    *,
    started: datetime = START,
    finished: datetime = START + timedelta(minutes=1),
    dirty: bool = False,
    limit=None,
):
    conn = sqlite3.connect(path)
    post = database_accounting(conn)
    conn.close()
    summary = RunSummary(
        FRESH_MODE, len(source), 0, _digest(source), len(source),
        DatabaseAccounting(0, 0, 0), post, len(source),
    )
    return write_scan_manifest(
        path,
        source_input_lines=source,
        planned_input_lines=source,
        run_summary=summary,
        resume_link=None,
        scanner_git_revision="b" * 40,
        scanner_git_dirty=dirty,
        resolver_configuration=RESOLVERS,
        started_at=started,
        finished_at=finished,
        concurrency=120,
        batch_pool_size=300,
        limit=limit,
        shuffle=False,
        shuffle_seed=None,
    )


def _successful_query(name, rdtype):
    if rdtype == "MX":
        return "ok", [f"10 mail.{name}."]
    return "noanswer", []


def _prepare(
    path,
    source,
    *,
    started=START + timedelta(minutes=2),
    limit=None,
    shuffle=False,
):
    planned = planned_domains_from_source(
        source, limit=limit, shuffle=shuffle, shuffle_seed=42 if shuffle else None
    )
    return prepare_resume_manifest(
        path,
        source_input_lines=source,
        planned_input_lines=planned,
        resolver_configuration=RESOLVERS,
        concurrency=120,
        batch_pool_size=300,
        limit=limit,
        shuffle=shuffle,
        shuffle_seed=42 if shuffle else None,
        started_at=started,
    )


def _consume(path, prepared, source, *, limit=None, shuffle=False):
    planned = planned_domains_from_source(
        source, limit=limit, shuffle=shuffle, shuffle_seed=42 if shuffle else None
    )
    consume_prepared_resume_manifest(
        path,
        prepared,
        source_input_lines=source,
        planned_input_lines=planned,
        resolver_configuration=RESOLVERS,
        concurrency=120,
        batch_pool_size=300,
        limit=limit,
        shuffle=shuffle,
        shuffle_seed=42 if shuffle else None,
    )


def _rewrite_v2_manifest(path: Path, mutation) -> dict:
    sidecar = manifest_path_for(path)
    manifest = json.loads(sidecar.read_text())
    mutation(manifest)
    manifest["run_id"] = _run_identity(manifest)
    sidecar.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return manifest


def _write_failed_retry_v2(path: Path, source: list[str], *, from_v1=False) -> dict:
    if from_v1:
        _write_v1_root(path, source)
    else:
        _fresh_v2(path, source)
    link = _prepare(path, source)
    _consume(path, link, source)
    summary = dmarc_scan.run(
        source,
        str(path),
        concurrency=120,
        resume=True,
        query_fn=lambda *_: ("error", []),
        prepared_resume=link,
    )
    write_scan_manifest(
        path,
        source_input_lines=source,
        planned_input_lines=source,
        run_summary=summary,
        resume_link=link,
        scanner_git_revision="e" * 40,
        scanner_git_dirty=False,
        resolver_configuration=RESOLVERS,
        started_at=START + timedelta(minutes=2),
        finished_at=START + timedelta(minutes=3),
        concurrency=120,
        batch_pool_size=300,
        limit=None,
        shuffle=False,
        shuffle_seed=None,
    )
    return json.loads(manifest_path_for(path).read_text())


def test_normalized_input_and_streaming_digest_are_identical():
    values = ["a.ch\r\n", "\n", " b.ch. \n"]
    normalized = normalized_input(values)
    sha, count = normalized_input_digest(iter(values))
    assert normalized == b"a.ch\nb.ch\n"
    assert sha == hashlib.sha256(normalized).hexdigest()
    assert count == 2


def test_measurement_core_digest_binds_relative_names_and_lengths():
    first = _framed_measurement_core_digest([("ab", b"c"), ("d", b"ef")])
    second = _framed_measurement_core_digest([("a", b"bc"), ("de", b"f")])
    assert first != second
    assert measurement_core_sha256() == _framed_measurement_core_digest(
        (name, (SCANNER_REPOSITORY_ROOT / name).read_bytes())
        for name in MEASUREMENT_CORE_FILES
    )


def test_run_summary_is_frozen_and_contains_no_domain_data():
    summary = RunSummary(
        FRESH_MODE, 1, 0, _digest(["secret-example.ch"]), 1,
        DatabaseAccounting(0, 0, 0), DatabaseAccounting(1, 1, 0), 1,
    )
    with pytest.raises(FrozenInstanceError):
        summary.rows_written = 2
    assert "secret-example.ch" not in repr(summary)


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"mode": "unknown"}, "mode"),
        ({"planned_input_count": True}, "integer"),
        ({"attempted_input_sha256": "bad"}, "SHA-256"),
        ({"rows_written": 0}, "rows_written"),
        ({"planned_excluded_count": 1}, "excluded plus attempted"),
        ({"post_database": DatabaseAccounting(3, 3, 0)}, "post total"),
        ({"pre_database": DatabaseAccounting(1, 1, 0)}, "fresh run"),
    ],
)
def test_run_summary_rejects_broken_invariants(kwargs, match):
    values = {
        "mode": FRESH_MODE,
        "planned_input_count": 1,
        "planned_excluded_count": 0,
        "attempted_input_sha256": _digest(["one.ch"]),
        "attempted_input_count": 1,
        "pre_database": DatabaseAccounting(0, 0, 0),
        "post_database": DatabaseAccounting(1, 1, 0),
        "rows_written": 1,
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match=match):
        RunSummary(**values)


def test_fresh_run_summary_requires_one_persisted_row_per_attempt():
    with pytest.raises(ValueError, match="persist one row per attempt"):
        RunSummary(
            FRESH_MODE,
            1,
            0,
            _digest(["a.ch"]),
            1,
            DatabaseAccounting(0, 0, 0),
            DatabaseAccounting(0, 0, 0),
            1,
        )


@pytest.mark.parametrize(
    "kwargs,match",
    [
        (
            {"planned_input_count": 3, "planned_excluded_count": 2},
            "pre-scan total",
        ),
        (
            {
                "attempted_input_count": 0,
                "planned_excluded_count": 2,
                "rows_written": 0,
            },
            "retained error",
        ),
        (
            {
                "post_database": DatabaseAccounting(2, 0, 2),
            },
            "error count",
        ),
    ],
)
def test_resume_run_summary_rejects_full_universe_invariant_failures(kwargs, match):
    values = {
        "mode": RESUME_MODE,
        "planned_input_count": 2,
        "planned_excluded_count": 1,
        "attempted_input_sha256": _digest(["flaky.ch"]),
        "attempted_input_count": 1,
        "pre_database": DatabaseAccounting(2, 1, 1),
        "post_database": DatabaseAccounting(2, 1, 1),
        "rows_written": 1,
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match=match):
        RunSummary(**values)


@pytest.mark.parametrize(
    "values,match",
    [
        ((True, 1, 0), "integer"),
        ((1, -1, 2), "integer"),
        ((2, 2, 1), "partition"),
    ],
)
def test_database_accounting_rejects_non_typed_or_non_partitioned_values(
    values, match
):
    with pytest.raises(ValueError, match=match):
        DatabaseAccounting(*values)


def test_database_accounting_includes_partial_query_error_rows(tmp_path):
    path = tmp_path / "partial.db"
    accounting = _make_db(path, [
        DmarcScanResult(domain="clean.ch"),
        DmarcScanResult(
            domain="partial.ch", query_statuses={"DS partial.ch": "error"}
        ),
    ])
    assert accounting == DatabaseAccounting(2, 1, 1)


def test_run_records_actual_retry_subset_and_clean_exclusion(tmp_path):
    path = tmp_path / "retry.db"
    source = ["clean.ch", "flaky.ch"]
    _make_db(path, [
        DmarcScanResult(domain="clean.ch"),
        DmarcScanResult(domain="flaky.ch", error="mx_query_error"),
    ])
    _fresh_v2(path, source)
    prepared = _prepare(path, source)
    _consume(path, prepared, source)
    summary = dmarc_scan.run(
        source, str(path), concurrency=120, resume=True,
        query_fn=_successful_query, prepared_resume=prepared,
    )
    assert summary.mode == RESUME_MODE
    assert summary.planned_excluded_count == 1
    assert summary.attempted_input_count == 1
    assert summary.attempted_input_sha256 == _digest(["flaky.ch"])
    assert summary.pre_database == DatabaseAccounting(2, 1, 1)
    assert summary.post_database == DatabaseAccounting(2, 2, 0)


def test_zero_attempt_resume_preserves_pre_and_post_accounting(tmp_path):
    path = tmp_path / "zero.db"
    source = ["clean.ch"]
    _make_db(path, [DmarcScanResult(domain="clean.ch")])
    _fresh_v2(path, source)
    prepared = _prepare(path, source)
    _consume(path, prepared, source)
    summary = dmarc_scan.run(
        source, str(path), concurrency=120, resume=True,
        query_fn=lambda *_: pytest.fail("DNS must not run"),
        prepared_resume=prepared,
    )
    assert summary.attempted_input_count == 0
    assert summary.pre_database == summary.post_database == DatabaseAccounting(1, 1, 0)


def test_completed_v2_sidecar_matches_immutable_copy_and_is_private(tmp_path):
    path = tmp_path / "scan.db"
    _make_db(path, [DmarcScanResult(domain="private-name.ch")])
    sidecar = _fresh_v2(path, ["private-name.ch"])
    payload = sidecar.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    archived = manifest_archive_path_for(path) / f"{digest}.json"
    assert archived.read_bytes() == payload
    assert stat.S_IMODE(archived.stat().st_mode) == 0o600
    assert stat.S_IMODE(manifest_archive_path_for(path).stat().st_mode) == 0o700
    assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
    assert b"private-name.ch" not in payload


def test_run_id_is_deterministic_for_same_canonical_identity(tmp_path):
    path = tmp_path / "deterministic.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    sidecar = _fresh_v2(path, ["a.ch"])
    first = json.loads(sidecar.read_text())["run_id"]
    sidecar = _fresh_v2(path, ["a.ch"])
    assert json.loads(sidecar.read_text())["run_id"] == first


def test_manifest_hash_is_taken_after_database_close_and_checkpoint(tmp_path):
    path = tmp_path / "closed.db"
    summary = dmarc_scan.run(
        ["a.ch"], str(path), concurrency=1, resume=False,
        query_fn=_successful_query,
    )
    write_scan_manifest(
        path, source_input_lines=["a.ch"], planned_input_lines=["a.ch"],
        run_summary=summary, resume_link=None, scanner_git_revision="c" * 40,
        scanner_git_dirty=False, resolver_configuration=RESOLVERS,
        started_at=START, finished_at=START + timedelta(minutes=1),
        concurrency=1, batch_pool_size=1, limit=None, shuffle=False,
        shuffle_seed=None,
    )
    manifest = json.loads(manifest_path_for(path).read_text())
    assert (manifest["output_sqlite_sha256"], manifest["output_sqlite_size_bytes"]) == _identity(path)
    assert not Path(str(path) + "-wal").exists()


def test_v1_to_v2_retry_chain_records_explicit_root_attestation(tmp_path):
    path = tmp_path / "v1.db"
    _make_db(path, [
        DmarcScanResult(domain="clean.ch"),
        DmarcScanResult(domain="flaky.ch", error="mx_query_error"),
    ])
    prior = _write_v1_root(path, ["clean.ch", "flaky.ch"])
    source = ["clean.ch", "flaky.ch"]
    link = _prepare(path, source)
    _consume(path, link, source)
    summary = dmarc_scan.run(
        source, str(path), concurrency=120, resume=True,
        query_fn=_successful_query, prepared_resume=link,
    )
    write_scan_manifest(
        path, source_input_lines=["clean.ch", "flaky.ch"],
        planned_input_lines=["clean.ch", "flaky.ch"], run_summary=summary,
        resume_link=link, scanner_git_revision="d" * 40,
        scanner_git_dirty=False, resolver_configuration=RESOLVERS,
        started_at=START + timedelta(minutes=2),
        finished_at=START + timedelta(minutes=3), concurrency=120,
        batch_pool_size=300, limit=None, shuffle=False, shuffle_seed=None,
    )
    manifest = json.loads(manifest_path_for(path).read_text())
    assert manifest["previous_run_manifest_sha256"] == hashlib.sha256(prior).hexdigest()
    assert manifest["root_measurement_core_attestation"]["manifest_schema_version"] == 1
    assert manifest["release_eligible"] is True


def test_active_v1_full_pass_accepts_seeded_shuffle_digest(tmp_path):
    path = tmp_path / "v1-shuffled.db"
    source = ["a.ch", "b.ch"]
    _make_db(path, [
        DmarcScanResult(domain="a.ch"), DmarcScanResult(domain="b.ch")
    ])
    _write_v1_root(path, source)
    manifest = json.loads(manifest_path_for(path).read_text())
    shuffled = planned_domains_from_source(
        source, limit=None, shuffle=True, shuffle_seed=42
    )
    manifest["effective_input_normalized_sha256"] = _digest(shuffled)
    manifest["shuffle"] = True
    manifest["shuffle_seed"] = 42
    manifest["effective_input_order"] = "seeded_shuffle_then_limit"
    manifest_path_for(path).write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    link = _prepare(path, source, shuffle=True)
    assert link.root_attestation["manifest_schema_version"] == 1


def test_v2_to_v2_chain_can_be_prepared_for_another_retry(tmp_path):
    path = tmp_path / "v2.db"
    _make_db(path, [DmarcScanResult(domain="flaky.ch", error="mx_query_error")])
    _fresh_v2(path, ["flaky.ch"])
    source = ["flaky.ch"]
    first = _prepare(path, source)
    _consume(path, first, source)
    summary = dmarc_scan.run(
        source, str(path), concurrency=120, resume=True,
        query_fn=lambda *_: ("error", []), prepared_resume=first,
    )
    write_scan_manifest(
        path, source_input_lines=["flaky.ch"], planned_input_lines=["flaky.ch"],
        run_summary=summary, resume_link=first, scanner_git_revision="e" * 40,
        scanner_git_dirty=False, resolver_configuration=RESOLVERS,
        started_at=START + timedelta(minutes=2),
        finished_at=START + timedelta(minutes=3), concurrency=120,
        batch_pool_size=300, limit=None, shuffle=False, shuffle_seed=None,
    )
    second = _prepare(path, source, started=START + timedelta(minutes=4))
    assert second.root_attestation == first.root_attestation


def test_archived_prior_manifest_survives_a_later_scan_crash(tmp_path):
    path = tmp_path / "crash.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    payload = _fresh_v2(path, ["a.ch"]).read_bytes()
    link = _prepare(path, ["a.ch"])
    _consume(path, link, ["a.ch"])
    with pytest.raises(RuntimeError, match="simulated"):
        raise RuntimeError("simulated scan crash")
    archived = manifest_archive_path_for(path) / f"{hashlib.sha256(payload).hexdigest()}.json"
    assert archived.read_bytes() == payload
    assert not manifest_path_for(path).exists()


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda m: m.update(extra=True), "unsupported fields"),
        (lambda m: m.update(manifest_schema_version=99), "unsupported"),
        (lambda m: m.update(run_id="f" * 64), "run_id"),
        (lambda m: m.update(scanner_git_dirty=1), "run_id|boolean"),
        (lambda m: m["database_post"].update(error_rows=-1), "run_id|integer"),
    ],
)
def test_strict_v2_validation_rejects_tampered_sidecars_before_mutation(
    tmp_path, mutation, match
):
    path = tmp_path / "strict-v2.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    sidecar = _fresh_v2(path, ["a.ch"])
    manifest = json.loads(sidecar.read_text())
    mutation(manifest)
    sidecar.write_text(json.dumps(manifest))
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match=match):
        _prepare(path, ["a.ch"])
    assert path.read_bytes() == before


def test_root_attestation_schema_rejects_boolean_before_membership(tmp_path):
    path = tmp_path / "boolean-root-schema.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _fresh_v2(path, ["a.ch"])
    manifest = json.loads(manifest_path_for(path).read_text())
    manifest["root_measurement_core_attestation"]["manifest_schema_version"] = True
    manifest["run_id"] = _run_identity(manifest)

    with pytest.raises(ValueError, match="root manifest schema.*integer"):
        provenance._validate_v2(manifest)


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda m: m.update(extra=True), "unsupported fields"),
        (lambda m: m.update(scanner_git_dirty="no"), "boolean"),
        (lambda m: m.update(limit=1), "no-limit"),
        (lambda m: m.update(source_input_normalized_line_count=True), "integer"),
        (lambda m: m.update(normalized_input_line_count=True), "normalized input count.*integer"),
        (lambda m: m.update(normalized_input_sha256=1), "normalized input.*SHA-256"),
        (lambda m: m["resolver_configuration"].update(cache_policy="system"), "cache"),
    ],
)
def test_strict_v1_validation_rejects_malformed_roots(tmp_path, mutation, match):
    path = tmp_path / "strict-v1.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    sidecar = manifest_path_for(path)
    _write_v1_root(path, ["a.ch"])
    manifest = json.loads(sidecar.read_text())
    mutation(manifest)
    sidecar.write_text(json.dumps(manifest))
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match=match):
        _prepare(path, ["a.ch"])
    assert path.read_bytes() == before


def test_missing_manifest_is_rejected_before_database_changes(tmp_path):
    path = tmp_path / "missing.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="manifest is missing"):
        _prepare(path, ["a.ch"])
    assert path.read_bytes() == before


def test_malformed_json_manifest_is_rejected_before_database_changes(tmp_path):
    path = tmp_path / "malformed.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    manifest_path_for(path).write_bytes(b"{not-json")
    manifest_path_for(path).chmod(0o600)
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="valid UTF-8 JSON"):
        _prepare(path, ["a.ch"])
    assert path.read_bytes() == before


def test_database_identity_mismatch_is_rejected_before_mutation(tmp_path):
    path = tmp_path / "mismatch.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _write_v1_root(path, ["a.ch"])
    manifest = json.loads(manifest_path_for(path).read_text())
    manifest["output_sqlite_sha256"] = "f" * 64
    manifest_path_for(path).write_text(json.dumps(manifest))
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="does not match"):
        _prepare(path, ["a.ch"])
    assert path.read_bytes() == before


def test_source_universe_change_is_rejected_before_mutation(tmp_path):
    path = tmp_path / "source.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _write_v1_root(path, ["a.ch"])
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="domain universe|source universe"):
        _prepare(path, ["different.ch"])
    assert path.read_bytes() == before


def test_overlapping_resume_timestamp_is_rejected_before_mutation(tmp_path):
    path = tmp_path / "overlap.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _write_v1_root(path, ["a.ch"])
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="before the prior run finished"):
        _prepare(path, ["a.ch"], started=START + timedelta(seconds=30))
    assert path.read_bytes() == before


def test_sidecar_symlink_is_rejected_before_mutation(tmp_path):
    path = tmp_path / "sidecar-symlink.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    real = tmp_path / "real.json"
    payload = _write_v1_root(path, ["a.ch"])
    manifest_path_for(path).unlink()
    real.write_bytes(payload)
    manifest_path_for(path).symlink_to(real)
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="non-symlink"):
        _prepare(path, ["a.ch"])
    assert path.read_bytes() == before


def test_database_symlink_is_rejected_before_mutation(tmp_path):
    real = tmp_path / "real.db"
    _make_db(real, [DmarcScanResult(domain="a.ch")])
    alias = tmp_path / "alias.db"
    alias.symlink_to(real)
    # Build a valid sidecar for the alias using the real database identity.
    real_payload = _write_v1_root(real, ["a.ch"])
    manifest_path_for(alias).write_bytes(real_payload)
    before = real.read_bytes()
    with pytest.raises(RuntimeError, match="non-symlink"):
        _prepare(alias, ["a.ch"])
    assert real.read_bytes() == before


def test_archive_symlink_is_rejected_before_mutation(tmp_path):
    path = tmp_path / "archive-symlink.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _write_v1_root(path, ["a.ch"])
    target = tmp_path / "elsewhere"
    target.mkdir()
    manifest_archive_path_for(path).symlink_to(target, target_is_directory=True)
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="archive.*non-symlink"):
        _prepare(path, ["a.ch"])
    assert path.read_bytes() == before


def test_immutable_copy_collision_with_different_bytes_fails(tmp_path):
    path = tmp_path / "collision.db"
    path.write_bytes(b"db")
    payload = b'{"one":1}\n'
    digest = hashlib.sha256(payload).hexdigest()
    archive = manifest_archive_path_for(path)
    archive.mkdir(mode=0o700)
    target = archive / f"{digest}.json"
    target.write_bytes(b"different")
    target.chmod(0o600)
    with pytest.raises(RuntimeError, match="collision|tampering"):
        _immutable_manifest_copy(path, payload)


def test_tampered_immutable_copy_blocks_resume(tmp_path):
    path = tmp_path / "tampered.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    payload = _fresh_v2(path, ["a.ch"]).read_bytes()
    archived = manifest_archive_path_for(path) / f"{hashlib.sha256(payload).hexdigest()}.json"
    archived.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="collision|tampering"):
        _prepare(path, ["a.ch"])


def test_consume_rejects_sidecar_changed_after_preparation(tmp_path):
    path = tmp_path / "changed.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _fresh_v2(path, ["a.ch"])
    link = _prepare(path, ["a.ch"])
    manifest_path_for(path).write_text("{}")
    with pytest.raises(RuntimeError, match="changed"):
        _consume(path, link, ["a.ch"])


@pytest.mark.parametrize(
    "source,started,match",
    [
        (["different.ch"], START + timedelta(minutes=2), "source universe"),
        (["a.ch"], START + timedelta(seconds=30), "overlaps previous"),
    ],
)
def test_writer_rechecks_source_and_nonoverlap_after_resume_preparation(
    tmp_path, source, started, match
):
    path = tmp_path / "recheck.db"
    accounting = _make_db(path, [DmarcScanResult(domain="a.ch")])
    _fresh_v2(path, ["a.ch"])
    link = _prepare(path, ["a.ch"])
    summary = RunSummary(
        RESUME_MODE, 1, 1, _digest([]), 0, accounting, accounting, 0
    )
    with pytest.raises(ValueError, match=match):
        write_scan_manifest(
            path, source_input_lines=source, planned_input_lines=source,
            run_summary=summary, resume_link=link, scanner_git_revision="a" * 40,
            scanner_git_dirty=False, resolver_configuration=RESOLVERS,
            started_at=started, finished_at=START + timedelta(minutes=3),
            concurrency=120, batch_pool_size=300, limit=None, shuffle=False,
            shuffle_seed=None,
        )


def test_write_manifest_rejects_post_accounting_not_matching_closed_database(tmp_path):
    path = tmp_path / "accounting.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    summary = RunSummary(
        FRESH_MODE, 1, 0, _digest(["a.ch"]), 1,
        DatabaseAccounting(0, 0, 0), DatabaseAccounting(1, 0, 1), 1,
    )
    with pytest.raises(ValueError, match="closed database"):
        write_scan_manifest(
            path, source_input_lines=["a.ch"], planned_input_lines=["a.ch"],
            run_summary=summary, resume_link=None, scanner_git_revision="a" * 40,
            scanner_git_dirty=False, resolver_configuration=RESOLVERS,
            started_at=START, finished_at=START + timedelta(minutes=1),
            concurrency=1, batch_pool_size=1, limit=None, shuffle=False,
            shuffle_seed=None,
        )


def test_write_manifest_rejects_ambiguous_old_api_keywords(tmp_path):
    path = tmp_path / "old-api.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    summary = RunSummary(
        FRESH_MODE, 1, 0, _digest(["a.ch"]), 1,
        DatabaseAccounting(0, 0, 0), DatabaseAccounting(1, 1, 0), 1,
    )
    with pytest.raises(TypeError, match="effective_input_lines"):
        write_scan_manifest(
            path, source_input_lines=["a.ch"], planned_input_lines=["a.ch"],
            effective_input_lines=["a.ch"], run_summary=summary, resume_link=None,
            scanner_git_revision="a" * 40, scanner_git_dirty=False,
            resolver_configuration=RESOLVERS, started_at=START,
            finished_at=START + timedelta(minutes=1), concurrency=1,
            batch_pool_size=1, limit=None, shuffle=False, shuffle_seed=None,
        )


def test_cli_writes_v2_manifest_for_empty_fresh_scan_without_dns(tmp_path, monkeypatch):
    input_path = tmp_path / "domains.txt"
    output_path = tmp_path / "results.db"
    input_path.write_text("example.ch\n")
    monkeypatch.setattr(
        "sys.argv",
        ["dmarc_scan.py", "--input", str(input_path), "--output", str(output_path),
         "--limit", "0", "--no-resume"],
    )
    dmarc_scan.main()
    manifest = json.loads(manifest_path_for(output_path).read_text())
    assert manifest["manifest_schema_version"] == 2
    assert manifest["source_input_normalized_line_count"] == 1
    assert manifest["planned_input_normalized_line_count"] == 0
    assert manifest["attempted_input_normalized_line_count"] == 0
    assert manifest["run_mode"] == FRESH_MODE
    assert manifest["release_eligible"] is False


def test_cli_refuses_stale_sidecar_before_git_or_database_mutation(tmp_path, monkeypatch):
    input_path = tmp_path / "domains.txt"
    output_path = tmp_path / "results.db"
    input_path.write_text("example.ch\n")
    stale = manifest_path_for(output_path)
    stale.write_text('{"stale": true}\n')
    monkeypatch.setattr(
        "sys.argv",
        ["dmarc_scan.py", "--input", str(input_path), "--output", str(output_path),
         "--limit", "0"],
    )
    monkeypatch.setattr(
        dmarc_scan, "scanner_git_provenance",
        lambda: (_ for _ in ()).throw(RuntimeError("Git SHA-1 unavailable")),
    )
    with pytest.raises(RuntimeError, match="choose a new --output"):
        dmarc_scan.main()
    assert stale.read_text() == '{"stale": true}\n'


def test_scanner_git_provenance_uses_repo_root_and_arbitrary_checkout_name(monkeypatch, tmp_path):
    calls = []

    def fake_check_output(command, **kwargs):
        calls.append(kwargs["cwd"])
        return "c" * 40 + "\n" if command[-1] == "HEAD" else ""

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("dmarc_scanner.provenance.subprocess.check_output", fake_check_output)
    assert scanner_git_provenance() == ("c" * 40, False)
    assert calls and all(path.resolve() == SCANNER_REPOSITORY_ROOT.resolve() for path in calls)


def test_scanner_git_provenance_rejects_non_commit_revision(monkeypatch):
    monkeypatch.setattr(
        "dmarc_scanner.provenance.subprocess.check_output",
        lambda *args, **kwargs: "unknown\n",
    )
    with pytest.raises(RuntimeError, match="Git SHA-1"):
        scanner_git_provenance()


def test_legacy_database_metric_columns_use_explicit_adapter(tmp_path):
    legacy = sqlite3.connect(tmp_path / "legacy.db")
    legacy.execute(
        "CREATE TABLE dmarc_scan_results (domain TEXT PRIMARY KEY, "
        "dnssec_signed INTEGER, has_tlsa INTEGER, error TEXT)"
    )
    assert metric_column(legacy, "has_ds_record") == "dnssec_signed"
    assert metric_column(legacy, "has_tlsa_record") == "has_tlsa"
    legacy.close()


def test_analyzer_reads_legacy_presence_columns_without_migration(tmp_path, capsys):
    path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(path)
    legacy.execute(
        "CREATE TABLE dmarc_scan_results (domain TEXT PRIMARY KEY, error TEXT, "
        "has_mx INTEGER, dnssec_signed INTEGER, has_tlsa INTEGER, mx_provider TEXT, "
        "has_spf INTEGER, spf_all_mechanism TEXT, spf_near_limit INTEGER, "
        "has_dkim INTEGER, dkim_weak_key INTEGER, has_dmarc INTEGER, "
        "dmarc_policy TEXT, has_bimi INTEGER, has_mta_sts INTEGER, "
        "has_tlsrpt INTEGER, has_caa INTEGER)"
    )
    legacy.execute(
        "INSERT INTO dmarc_scan_results VALUES "
        "('legacy.ch', '', 1, 1, 1, 'other', 0, '', 0, 0, 0, 0, "
        "'absent', 0, 0, 0, 0)"
    )
    legacy.commit()
    legacy.close()
    analyze(str(path))
    assert "DS record present: 1 (100.0%)" in capsys.readouterr().out
    inspected = sqlite3.connect(path)
    columns = {row[1] for row in inspected.execute("PRAGMA table_info(dmarc_scan_results)")}
    inspected.close()
    assert "has_ds_record" not in columns
    assert "has_tlsa_record" not in columns


def test_new_scan_schema_uses_canonical_presence_columns(tmp_path):
    conn = sqlite3.connect(tmp_path / "future.db")
    create_table(conn)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(dmarc_scan_results)")}
    conn.close()
    assert "has_ds_record" in columns and "has_tlsa_record" in columns
    assert "dnssec_signed" not in columns and "has_tlsa" not in columns


def test_v1_shuffled_root_rejects_digest_not_derived_from_seed_42(tmp_path):
    path = tmp_path / "wrong-shuffle.db"
    source = ["a.ch", "b.ch", "c.ch"]
    _make_db(path, [DmarcScanResult(domain=domain) for domain in source])
    _write_v1_root(path, source)
    manifest = json.loads(manifest_path_for(path).read_text())
    manifest["effective_input_normalized_sha256"] = _digest(list(reversed(source)))
    manifest["shuffle"] = True
    manifest["shuffle_seed"] = 42
    manifest["effective_input_order"] = "seeded_shuffle_then_limit"
    manifest_path_for(path).write_text(json.dumps(manifest))
    before_db = path.read_bytes()
    before_sidecar = manifest_path_for(path).read_bytes()

    with pytest.raises(RuntimeError, match="planned transformation"):
        _prepare(path, source, shuffle=True)

    assert path.read_bytes() == before_db
    assert manifest_path_for(path).read_bytes() == before_sidecar
    assert not manifest_archive_path_for(path).exists()


@pytest.mark.parametrize(
    "source,match",
    [
        (["a.ch", "a.ch."], "unique"),
        (["", "  ", "."], "non-empty"),
    ],
)
def test_resume_rejects_ambiguous_source_before_archive_or_database_mutation(
    tmp_path, source, match
):
    path = tmp_path / "ambiguous-source.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _write_v1_root(path, ["a.ch"])
    before_db = path.read_bytes()
    before_sidecar = manifest_path_for(path).read_bytes()

    with pytest.raises(ValueError, match=match):
        prepare_resume_manifest(
            path,
            source_input_lines=source,
            planned_input_lines=[],
            resolver_configuration=RESOLVERS,
            concurrency=120,
            batch_pool_size=300,
            limit=None,
            shuffle=False,
            shuffle_seed=None,
            started_at=START + timedelta(minutes=2),
        )

    assert path.read_bytes() == before_db
    assert manifest_path_for(path).read_bytes() == before_sidecar
    assert not manifest_archive_path_for(path).exists()


def test_unshuffled_planned_order_must_exactly_match_source_order(tmp_path):
    path = tmp_path / "wrong-plan.db"
    source = ["a.ch", "b.ch"]
    _make_db(path, [DmarcScanResult(domain=domain) for domain in source])
    _write_v1_root(path, source)
    before_db = path.read_bytes()

    with pytest.raises(ValueError, match="exact declared source transformation"):
        prepare_resume_manifest(
            path,
            source_input_lines=source,
            planned_input_lines=list(reversed(source)),
            resolver_configuration=RESOLVERS,
            concurrency=120,
            batch_pool_size=300,
            limit=None,
            shuffle=False,
            shuffle_seed=None,
            started_at=START + timedelta(minutes=2),
        )

    assert path.read_bytes() == before_db
    assert not manifest_archive_path_for(path).exists()


@pytest.mark.parametrize("schema", [1, 2])
def test_strict_json_rejects_duplicate_keys_before_mutation(tmp_path, schema):
    path = tmp_path / f"duplicate-v{schema}.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    if schema == 1:
        _write_v1_root(path, ["a.ch"])
    else:
        _fresh_v2(path, ["a.ch"])
    sidecar = manifest_path_for(path)
    payload = sidecar.read_text()
    sidecar.write_text(payload.replace("{", '{"scanner_git_dirty":false,', 1))
    before_db = path.read_bytes()
    before_sidecar = sidecar.read_bytes()

    with pytest.raises(RuntimeError, match="duplicate JSON keys"):
        _prepare(path, ["a.ch"])

    assert path.read_bytes() == before_db
    assert sidecar.read_bytes() == before_sidecar


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_strict_json_rejects_nonfinite_constants_before_mutation(tmp_path, constant):
    path = tmp_path / f"nonfinite-{constant}.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _write_v1_root(path, ["a.ch"])
    sidecar = manifest_path_for(path)
    sidecar.write_text(
        sidecar.read_text().replace('"timeout_seconds": 4.0', f'"timeout_seconds": {constant}')
    )
    before_db = path.read_bytes()
    before_sidecar = sidecar.read_bytes()

    with pytest.raises(RuntimeError, match="non-finite JSON constant"):
        _prepare(path, ["a.ch"])

    assert path.read_bytes() == before_db
    assert sidecar.read_bytes() == before_sidecar


@pytest.mark.parametrize(
    "field,value",
    [
        ("timeout_seconds", float("nan")),
        ("timeout_seconds", float("inf")),
        ("timeout_seconds", True),
        ("lifetime_seconds", float("nan")),
        ("lifetime_seconds", float("inf")),
        ("lifetime_seconds", False),
    ],
)
def test_runtime_resolver_numbers_must_be_finite_positive_non_booleans(
    tmp_path, field, value
):
    path = tmp_path / f"bad-resolver-{field}.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _write_v1_root(path, ["a.ch"])
    resolver = dict(RESOLVERS)
    resolver[field] = value
    before_db = path.read_bytes()
    before_sidecar = manifest_path_for(path).read_bytes()

    with pytest.raises(ValueError, match=field.replace("_seconds", "")):
        prepare_resume_manifest(
            path,
            source_input_lines=["a.ch"],
            planned_input_lines=["a.ch"],
            resolver_configuration=resolver,
            concurrency=120,
            batch_pool_size=300,
            limit=None,
            shuffle=False,
            shuffle_seed=None,
            started_at=START + timedelta(minutes=2),
        )

    assert path.read_bytes() == before_db
    assert manifest_path_for(path).read_bytes() == before_sidecar


def test_consume_rejects_database_changed_after_prepare_and_preserves_new_bytes(tmp_path):
    path = tmp_path / "changed-after-prepare.db"
    source = ["clean.ch", "flaky.ch"]
    _make_db(path, [
        DmarcScanResult(domain="clean.ch"),
        DmarcScanResult(domain="flaky.ch", error="mx_query_error"),
    ])
    _fresh_v2(path, source)
    link = _prepare(path, source)
    sidecar_before = manifest_path_for(path).read_bytes()
    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE dmarc_scan_results SET has_mx = 1 WHERE domain = 'clean.ch'"
    )
    connection.commit()
    connection.close()
    changed_db = path.read_bytes()

    with pytest.raises(RuntimeError, match="database bytes changed"):
        _consume(path, link, source)

    assert path.read_bytes() == changed_db
    assert manifest_path_for(path).read_bytes() == sidecar_before


def test_consume_rejects_source_plan_changed_after_prepare_before_mutation(tmp_path):
    path = tmp_path / "plan-changed-after-prepare.db"
    source = ["a.ch", "b.ch"]
    _make_db(path, [DmarcScanResult(domain=domain) for domain in source])
    _fresh_v2(path, source)
    link = _prepare(path, source)
    before_db = path.read_bytes()
    before_sidecar = manifest_path_for(path).read_bytes()

    with pytest.raises(RuntimeError, match="source changed|plan changed"):
        consume_prepared_resume_manifest(
            path,
            link,
            source_input_lines=list(reversed(source)),
            planned_input_lines=list(reversed(source)),
            resolver_configuration=RESOLVERS,
            concurrency=120,
            batch_pool_size=300,
            limit=None,
            shuffle=False,
            shuffle_seed=None,
        )

    assert path.read_bytes() == before_db
    assert manifest_path_for(path).read_bytes() == before_sidecar


def test_consume_rejects_resolver_drift_after_prepare_before_mutation(tmp_path):
    path = tmp_path / "resolver-changed-after-prepare.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _fresh_v2(path, ["a.ch"])
    link = _prepare(path, ["a.ch"])
    changed_resolver = dict(RESOLVERS)
    changed_resolver["timeout_seconds"] = 5.0
    before_db = path.read_bytes()
    before_sidecar = manifest_path_for(path).read_bytes()

    with pytest.raises(RuntimeError, match="configuration changed"):
        consume_prepared_resume_manifest(
            path,
            link,
            source_input_lines=["a.ch"],
            planned_input_lines=["a.ch"],
            resolver_configuration=changed_resolver,
            concurrency=120,
            batch_pool_size=300,
            limit=None,
            shuffle=False,
            shuffle_seed=None,
        )

    assert path.read_bytes() == before_db
    assert manifest_path_for(path).read_bytes() == before_sidecar


def test_prepared_resume_deep_freezes_bound_resolver_configuration(tmp_path):
    path = tmp_path / "frozen-resolver.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _fresh_v2(path, ["a.ch"])
    link = _prepare(path, ["a.ch"])

    with pytest.raises(TypeError):
        link.resolver_configuration["timeout_seconds"] = 5.0
    with pytest.raises(AttributeError):
        link.resolver_configuration["nameservers"].append("9.9.9.9")

    _consume(path, link, ["a.ch"])


def test_consume_rejects_archive_mode_changed_after_prepare_before_mutation(tmp_path):
    path = tmp_path / "archive-mode-changed.db"
    _make_db(path, [DmarcScanResult(domain="a.ch")])
    _fresh_v2(path, ["a.ch"])
    link = _prepare(path, ["a.ch"])
    archive = manifest_archive_path_for(path)
    archive.chmod(0o755)
    before_db = path.read_bytes()
    before_sidecar = manifest_path_for(path).read_bytes()

    with pytest.raises(RuntimeError, match="permissions are unsafe"):
        _consume(path, link, ["a.ch"])

    assert path.read_bytes() == before_db
    assert manifest_path_for(path).read_bytes() == before_sidecar


def test_immutable_copy_race_rejects_same_bytes_with_unsafe_mode(tmp_path, monkeypatch):
    path = tmp_path / "race.db"
    path.write_bytes(b"db")
    payload = b'{"manifest":"same bytes"}\n'

    def race_link(_source, target):
        Path(target).write_bytes(payload)
        Path(target).chmod(0o644)
        raise FileExistsError

    monkeypatch.setattr(provenance.os, "link", race_link)
    with pytest.raises(RuntimeError, match="unsafe permissions"):
        _immutable_manifest_copy(path, payload)


def test_uri_safety_transition_reconstructs_exact_attested_old_db_file():
    transition = URI_SAFETY_CORE_TRANSITION
    current = (SCANNER_REPOSITORY_ROOT / transition["changed_file"]).read_text()
    new_line = "sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)"
    old_line = 'sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)'
    assert current.count(new_line) == 1
    assert old_line not in current
    assert hashlib.sha256(current.encode()).hexdigest() == transition["new_file_sha256"]
    reconstructed = current.replace(new_line, old_line)
    assert hashlib.sha256(reconstructed.encode()).hexdigest() == transition["old_file_sha256"]


@pytest.mark.parametrize("changed_file", ["dmarc_scanner/db.py", "dmarc_scanner/models.py"])
def test_uri_safety_transition_rejects_any_other_measurement_core_file_drift(
    tmp_path, monkeypatch, changed_file
):
    for relative_name in MEASUREMENT_CORE_FILES:
        destination = tmp_path / relative_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SCANNER_REPOSITORY_ROOT / relative_name, destination)
    with (tmp_path / changed_file).open("ab") as changed:
        changed.write(b"\n# unregistered drift\n")
    monkeypatch.setattr(provenance, "SCANNER_REPOSITORY_ROOT", tmp_path)

    with pytest.raises(ValueError, match="changed|target bytes"):
        provenance._validated_uri_safety_transition(
            URI_SAFETY_CORE_TRANSITION["from_measurement_core_sha256"],
            URI_SAFETY_CORE_TRANSITION["to_measurement_core_sha256"],
            URI_SAFETY_CORE_TRANSITION,
        )


def test_v1_to_v2_manifest_records_exact_uri_safety_transition(tmp_path):
    path = tmp_path / "transition.db"
    source = ["flaky.ch"]
    _make_db(path, [DmarcScanResult(domain="flaky.ch", error="mx_query_error")])
    manifest = _write_failed_retry_v2(path, source, from_v1=True)
    assert manifest["measurement_core_transition"] == URI_SAFETY_CORE_TRANSITION
    assert manifest["measurement_core_sha256"] == URI_SAFETY_CORE_TRANSITION[
        "to_measurement_core_sha256"
    ]


def test_v1_to_v2_manifest_rejects_tampered_transition_attestation(tmp_path):
    path = tmp_path / "tampered-transition.db"
    source = ["flaky.ch"]
    _make_db(path, [DmarcScanResult(domain="flaky.ch", error="mx_query_error")])
    _write_failed_retry_v2(path, source, from_v1=True)

    def tamper(manifest):
        manifest["measurement_core_transition"]["reason"] = "some other change"

    _rewrite_v2_manifest(path, tamper)
    before_db = path.read_bytes()
    with pytest.raises(RuntimeError, match="attestation is not exact"):
        _prepare(path, source, started=START + timedelta(minutes=4))
    assert path.read_bytes() == before_db


def test_v2_chain_rejects_repeated_uri_safety_transition(tmp_path):
    path = tmp_path / "repeated-transition.db"
    source = ["flaky.ch"]
    _make_db(path, [DmarcScanResult(domain="flaky.ch", error="mx_query_error")])
    _write_failed_retry_v2(path, source, from_v1=True)
    second = _prepare(path, source, started=START + timedelta(minutes=4))
    _consume(path, second, source)
    summary = dmarc_scan.run(
        source,
        str(path),
        concurrency=120,
        resume=True,
        query_fn=lambda *_: ("error", []),
        prepared_resume=second,
    )
    write_scan_manifest(
        path,
        source_input_lines=source,
        planned_input_lines=source,
        run_summary=summary,
        resume_link=second,
        scanner_git_revision="f" * 40,
        scanner_git_dirty=False,
        resolver_configuration=RESOLVERS,
        started_at=START + timedelta(minutes=4),
        finished_at=START + timedelta(minutes=5),
        concurrency=120,
        batch_pool_size=300,
        limit=None,
        shuffle=False,
        shuffle_seed=None,
    )
    _rewrite_v2_manifest(
        path,
        lambda manifest: manifest.update(
            measurement_core_transition=dict(URI_SAFETY_CORE_TRANSITION)
        ),
    )
    before_db = path.read_bytes()

    with pytest.raises(RuntimeError, match="only once"):
        _prepare(path, source, started=START + timedelta(minutes=6))

    assert path.read_bytes() == before_db


def test_v2_chain_rejects_unregistered_measurement_core_drift(tmp_path):
    path = tmp_path / "core-drift.db"
    source = ["flaky.ch"]
    _make_db(path, [DmarcScanResult(domain="flaky.ch", error="mx_query_error")])
    _write_failed_retry_v2(path, source)
    _rewrite_v2_manifest(
        path,
        lambda manifest: manifest.update(measurement_core_sha256="0" * 64),
    )
    before_db = path.read_bytes()

    with pytest.raises(RuntimeError, match="transition is not registered"):
        _prepare(path, source, started=START + timedelta(minutes=4))

    assert path.read_bytes() == before_db


def test_v2_chain_rejects_resolver_configuration_drift(tmp_path):
    path = tmp_path / "chain-resolver-drift.db"
    source = ["flaky.ch"]
    _make_db(path, [DmarcScanResult(domain="flaky.ch", error="mx_query_error")])
    _write_failed_retry_v2(path, source)
    changed_resolver = dict(RESOLVERS)
    changed_resolver["timeout_seconds"] = 5.0
    _rewrite_v2_manifest(
        path,
        lambda manifest: manifest.update(resolver_configuration=changed_resolver),
    )
    before_db = path.read_bytes()

    with pytest.raises(RuntimeError, match="configuration changed: resolver_configuration"):
        prepare_resume_manifest(
            path,
            source_input_lines=source,
            planned_input_lines=source,
            resolver_configuration=changed_resolver,
            concurrency=120,
            batch_pool_size=300,
            limit=None,
            shuffle=False,
            shuffle_seed=None,
            started_at=START + timedelta(minutes=4),
        )

    assert path.read_bytes() == before_db


def test_v2_chain_rejects_overlapping_archived_timestamps(tmp_path):
    path = tmp_path / "chain-overlap.db"
    source = ["flaky.ch"]
    _make_db(path, [DmarcScanResult(domain="flaky.ch", error="mx_query_error")])
    _write_failed_retry_v2(path, source)
    _rewrite_v2_manifest(
        path,
        lambda manifest: manifest.update(
            started_at_utc=(START + timedelta(seconds=30)).isoformat().replace(
                "+00:00", "Z"
            )
        ),
    )
    before_db = path.read_bytes()

    with pytest.raises(RuntimeError, match="timestamps overlap"):
        _prepare(path, source, started=START + timedelta(minutes=4))

    assert path.read_bytes() == before_db


@pytest.mark.parametrize("mutation_name", ["attempted_subset", "increased_errors"])
def test_v2_retry_manifest_rejects_full_universe_accounting_invariant_failures(
    tmp_path, mutation_name
):
    path = tmp_path / f"retry-invariant-{mutation_name}.db"
    source = ["clean.ch", "flaky.ch"]
    _make_db(path, [
        DmarcScanResult(domain="clean.ch"),
        DmarcScanResult(domain="flaky.ch", error="mx_query_error"),
    ])
    _write_failed_retry_v2(path, source)

    def mutate(manifest):
        if mutation_name == "attempted_subset":
            manifest["attempted_input_normalized_line_count"] = 0
            manifest["planned_excluded_count"] = 2
            manifest["rows_written"] = 0
        else:
            manifest["database_post"] = {
                "total_rows": 2,
                "analyzable_rows": 0,
                "error_rows": 2,
            }

    manifest = _rewrite_v2_manifest(path, mutate)
    invariant_match = (
        "every retained" if mutation_name == "attempted_subset"
        else "error count cannot increase"
    )
    with pytest.raises(ValueError, match=invariant_match):
        provenance._validate_v2(manifest)
    before_db = path.read_bytes()

    with pytest.raises(RuntimeError, match="manifest validation failed"):
        _prepare(path, source, started=START + timedelta(minutes=4))

    assert path.read_bytes() == before_db
