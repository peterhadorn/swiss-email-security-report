"""Release staging/sealing tests use synthetic aggregate-only identifiers."""

from __future__ import annotations

import hashlib
import html
import base64
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import textwrap
import tomllib
import zipfile

import pytest
from PIL import Image, PngImagePlugin

from dmarc_scanner.db import create_table, insert_result
from dmarc_scanner.models import DmarcScanResult
from dmarc_scanner.provenance import (
    ACTIVE_V1_ROOT_REVISION,
    MEASUREMENT_CORE_ALGORITHM,
    MEASUREMENT_CORE_FILES,
    URI_SAFETY_CORE_TRANSITION,
    V1_ROOT_CORE_ATTESTATIONS,
    _run_identity,
    normalized_input,
)


RESOLVERS = {
    "nameservers": ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"],
    "rotate": True,
    "timeout_seconds": 4.0,
    "lifetime_seconds": 6.0,
    "cache_policy": "disabled",
    "dnspython_version": "2.8.0",
}
SOURCE_BYTES = normalized_input(["case-01", "case-02", "case-03"])
SOURCE_SHA = hashlib.sha256(SOURCE_BYTES).hexdigest()
ROOT_CORE_SHA = V1_ROOT_CORE_ATTESTATIONS[ACTIVE_V1_ROOT_REVISION]
FINAL_CORE_SHA = URI_SAFETY_CORE_TRANSITION["to_measurement_core_sha256"]


def _identity(path: Path) -> tuple[str, int]:
    return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size


def _private_database(tmp_path: Path, name: str = "synthetic?#.db") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    database = tmp_path / name
    conn = sqlite3.connect(database)
    create_table(conn)
    for row in (
        DmarcScanResult(
            domain="case-01", has_mx=True, mx_provider="hostpoint",
            has_spf=True, spf_all_mechanism="hardfail", has_dkim=True,
            has_dmarc=True, dmarc_policy="reject", has_ds_record=True,
            ns_hosts=["case-ns"], has_mta_sts=True,
        ),
        DmarcScanResult(
            domain="case-02", has_mx=False, has_spf=True,
            spf_all_mechanism="none",
        ),
        DmarcScanResult(
            domain="case-03", error="case-private-error",
            query_statuses={"MX case-03": "error"},
        ),
    ):
        insert_result(conn, row)
    conn.commit()
    conn.close()
    return database


def _write_manifest(path: Path, payload: dict) -> tuple[Path, str]:
    content = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()
    path.write_bytes(content)
    return path, hashlib.sha256(content).hexdigest()


def _v2_manifest(
    *, previous_hash: str, input_identity: tuple[str, int],
    output_identity: tuple[str, int], root_hash: str,
    started: str, finished: str, pre: tuple[int, int, int],
    post: tuple[int, int, int], revision: str,
    transition: dict | None,
) -> dict:
    pre_total, pre_analyzable, pre_error = pre
    post_total, post_analyzable, post_error = post
    manifest = {
        "manifest_schema_version": 2,
        "run_id": "0" * 64,
        "previous_run_manifest_sha256": previous_hash,
        "input_sqlite_sha256": input_identity[0],
        "input_sqlite_size_bytes": input_identity[1],
        "output_sqlite_sha256": output_identity[0],
        "output_sqlite_size_bytes": output_identity[1],
        "source_input_normalized_sha256": SOURCE_SHA,
        "source_input_normalized_line_count": 3,
        "planned_input_normalized_sha256": SOURCE_SHA,
        "planned_input_normalized_line_count": 3,
        "attempted_input_normalized_sha256": hashlib.sha256(
            f"attempt-{started}".encode()
        ).hexdigest(),
        "attempted_input_normalized_line_count": pre_error,
        "planned_excluded_count": pre_analyzable,
        "rows_written": pre_error,
        "database_pre": {
            "total_rows": pre_total, "analyzable_rows": pre_analyzable,
            "error_rows": pre_error,
        },
        "database_post": {
            "total_rows": post_total, "analyzable_rows": post_analyzable,
            "error_rows": post_error,
        },
        "scanner_git_revision": revision,
        "scanner_git_dirty": False,
        "resolver_configuration": RESOLVERS,
        "started_at_utc": started,
        "finished_at_utc": finished,
        "concurrency": 120,
        "batch_pool_size": 300,
        "run_mode": "resume_retry_partial_errors",
        "limit": None,
        "shuffle": True,
        "shuffle_seed": 42,
        "planned_input_order": "seeded_shuffle_then_limit",
        "python_version": "3.14.0",
        "measurement_core_algorithm": MEASUREMENT_CORE_ALGORITHM,
        "measurement_core_files": list(MEASUREMENT_CORE_FILES),
        "measurement_core_sha256": FINAL_CORE_SHA,
        "measurement_core_transition": transition,
        "root_measurement_core_attestation": {
            "root_identifier_kind": "manifest_sha256",
            "root_identifier": root_hash,
            "manifest_schema_version": 1,
            "scanner_git_revision": ACTIVE_V1_ROOT_REVISION,
            "measurement_core_sha256": ROOT_CORE_SHA,
            "attestation_method": "explicit_revision_to_measurement_core_v1",
        },
        "release_eligible": True,
    }
    manifest["run_id"] = _run_identity(manifest)
    return manifest


def _private_chain(tmp_path: Path) -> tuple[Path, list[Path]]:
    database = _private_database(tmp_path)
    root_output = ("1" * 64, 111)
    root = {
        "normalized_input_sha256": SOURCE_SHA,
        "normalized_input_line_count": 3,
        "source_input_normalized_sha256": SOURCE_SHA,
        "source_input_normalized_line_count": 3,
        "effective_input_normalized_sha256": SOURCE_SHA,
        "effective_input_normalized_line_count": 3,
        "scanner_git_revision": ACTIVE_V1_ROOT_REVISION,
        "scanner_git_dirty": False,
        "resolver_configuration": RESOLVERS,
        "started_at_utc": "2026-08-21T00:00:00Z",
        "finished_at_utc": "2026-08-21T00:01:00Z",
        "concurrency": 120,
        "batch_pool_size": 300,
        "retry_resume_mode": "fresh",
        "limit": None,
        "shuffle": True,
        "shuffle_seed": 42,
        "effective_input_order": "seeded_shuffle_then_limit",
        "python_version": "3.14.0",
        "output_sqlite_sha256": root_output[0],
        "output_sqlite_size_bytes": root_output[1],
    }
    root_path, root_hash = _write_manifest(tmp_path / "01-root?#.json", root)
    retry_one_output = ("2" * 64, 222)
    retry_one = _v2_manifest(
        previous_hash=root_hash, input_identity=root_output,
        output_identity=retry_one_output, root_hash=root_hash,
        started="2026-08-21T00:02:00Z", finished="2026-08-21T00:03:00Z",
        pre=(3, 1, 2), post=(3, 2, 1), revision="a" * 40,
        transition=dict(URI_SAFETY_CORE_TRANSITION),
    )
    retry_one_path, retry_one_hash = _write_manifest(tmp_path / "02-retry.json", retry_one)
    retry_two = _v2_manifest(
        previous_hash=retry_one_hash, input_identity=retry_one_output,
        output_identity=_identity(database), root_hash=root_hash,
        started="2026-08-21T00:04:00Z", finished="2026-08-21T00:05:00Z",
        pre=(3, 2, 1), post=(3, 2, 1), revision="b" * 40,
        transition=None,
    )
    retry_two_path, _ = _write_manifest(tmp_path / "03-retry.json", retry_two)
    return database, [root_path, retry_one_path, retry_two_path]


@pytest.fixture
def release_module(monkeypatch):
    import release.build_release as bundle

    config = {
        "release_version": bundle.RELEASE_VERSION,
        "doi_approval_key_fingerprint": "UNCONFIGURED",
        "source_snapshot_date": "2026-04-12",
        "source_input_normalized_sha256": SOURCE_SHA,
        "source_input_normalized_line_count": 3,
        "root_scanner_git_revision": ACTIVE_V1_ROOT_REVISION,
        "measurement_core_algorithm": MEASUREMENT_CORE_ALGORITHM,
        "measurement_core_files": list(MEASUREMENT_CORE_FILES),
        "root_measurement_core_sha256": ROOT_CORE_SHA,
        "final_measurement_core_sha256": FINAL_CORE_SHA,
        "measurement_core_transition": dict(URI_SAFETY_CORE_TRANSITION),
        "resolver_configuration": RESOLVERS,
        "root_run": {"mode": "fresh", "input_order": "seeded_shuffle_then_limit"},
        "retry_run": {"mode": "resume_retry_partial_errors"},
        "execution": {
            "limit": None, "shuffle": True, "shuffle_seed": 42,
            "concurrency": 120, "batch_pool_size": 300,
        },
    }
    monkeypatch.setattr(bundle, "_load_official_config", lambda: config)
    return bundle


def _stage(tmp_path: Path, release_module) -> tuple[Path, Path, list[Path]]:
    database, manifests = _private_chain(tmp_path)
    staging = release_module.stage_release(
        database=database, manifest_paths=manifests,
        output_directory=tmp_path / "public",
    )
    return staging, database, manifests


def test_official_configuration_and_schema_pin_every_release_identity():
    import release.build_release as bundle

    config = bundle._load_official_config()
    assert config["release_version"] == "v2026.08.2"
    assert config["source_snapshot_date"] == "2026-04-12"
    assert config["source_input_normalized_line_count"] == 2_459_127
    assert config["source_input_normalized_sha256"] == "be742a42b89dbac80b5296316d35a2d245383e31d15d5df0b1242af8ec9e07c8"
    assert config["root_scanner_git_revision"] == ACTIVE_V1_ROOT_REVISION
    assert config["root_measurement_core_sha256"] == ROOT_CORE_SHA
    assert config["final_measurement_core_sha256"] == FINAL_CORE_SHA
    assert config["measurement_core_transition"] == URI_SAFETY_CORE_TRANSITION
    assert config["resolver_configuration"] == RESOLVERS
    assert config["execution"] == {
        "limit": None, "shuffle": True, "shuffle_seed": 42,
        "concurrency": 120, "batch_pool_size": 300,
    }
    assert config["root_run"] == {"mode": "resume_retry_partial_errors", "input_order": "seeded_shuffle_then_limit"}
    assert config["retry_run"] == {"mode": "resume_retry_partial_errors"}
    assert config["doi_approval_key_fingerprint"] == "8794791863b0cb5c5fe2d7ce5de80b05aacdb4759d92829e7b4e322803d6ab62"
    assert bundle._configured_doi_approval_fingerprint() == config["doi_approval_key_fingerprint"]


@pytest.mark.parametrize(("field", "value"), [
    ("source_snapshot_date", "2026-04-13"),
    ("source_input_normalized_sha256", "0" * 64),
    ("root_scanner_git_revision", "0" * 40),
    ("doi_approval_key_fingerprint", "not-a-pinned-key"),
])
def test_official_configuration_schema_rejects_identity_drift(field, value):
    import release.build_release as bundle

    config = json.loads(bundle.CONFIG_PATH.read_text())
    config[field] = value
    with pytest.raises(ValueError, match="schema validation"):
        bundle._validate_instance(
            bundle.CONFIG_SCHEMA_PATH, config, "release configuration",
        )


@pytest.mark.parametrize("payload", [b'{"a": 1, "a": 2}', b'{"a": NaN}'])
def test_public_json_loader_rejects_duplicates_and_nonfinite_values(
    tmp_path, release_module, payload,
):
    path = tmp_path / "unsafe.json"
    path.write_bytes(payload)
    with pytest.raises(ValueError, match="duplicate|non-finite"):
        release_module._load_json(path, "unsafe fixture")


def test_exact_v1_v2_v2_chain_and_public_interval(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    release = json.loads((staging / "release.json").read_text())
    assert release["status"] == "staging"
    assert release["measurement_interval"] == {
        "started_at_utc": "2026-08-21T00:00:00Z",
        "finished_at_utc": "2026-08-21T00:05:00Z",
    }
    assert [run["manifest_schema_version"] for run in release["run_chain"]] == [1, 2, 2]
    assert [run["attempted_input_count"] for run in release["run_chain"]] == [3, 2, 1]
    assert [run["measurement_core_sha256"] for run in release["run_chain"]] == [
        ROOT_CORE_SHA, FINAL_CORE_SHA, FINAL_CORE_SHA,
    ]
    assert release["measurement_core"] == {
        "algorithm": MEASUREMENT_CORE_ALGORITHM,
        "files": list(MEASUREMENT_CORE_FILES),
        "root_sha256": ROOT_CORE_SHA,
        "final_sha256": FINAL_CORE_SHA,
        "transition": URI_SAFETY_CORE_TRANSITION,
    }
    assert release["source_universe"]["snapshot_date"] == "2026-04-12"
    assert "doi" not in release and "inventory" not in release
    assert not (staging / "checksums.sha256").exists()
    assert stat.S_IMODE(staging.stat().st_mode) == 0o700


def test_staging_is_deterministic_and_aggregate_only(tmp_path, release_module):
    database, manifests = _private_chain(tmp_path)
    first = release_module.stage_release(
        database=database, manifest_paths=manifests, output_directory=tmp_path / "one",
    )
    second = release_module.stage_release(
        database=database, manifest_paths=list(reversed(manifests)), output_directory=tmp_path / "two",
    )
    assert {path.name for path in first.iterdir()} == {
        "metrics.json", "metrics.csv", "aggregate-attestation.json", "release.json",
    }
    for name in ("metrics.json", "metrics.csv", "aggregate-attestation.json", "release.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    rendered = "\n".join(path.read_text() for path in first.iterdir())
    for forbidden in ("case-01", "case-02", "case-03", "case-ns", "case-private-error"):
        assert forbidden not in rendered


def test_manifest_directory_input_and_question_hash_filenames(tmp_path, release_module):
    database, manifests = _private_chain(tmp_path)
    directory = tmp_path / "manifest-directory"
    directory.mkdir()
    for manifest in manifests:
        manifest.rename(directory / manifest.name)
    staging = release_module.stage_release(
        database=database, manifest_directory=directory,
        output_directory=tmp_path / "output",
    )
    assert staging.is_dir()
    assert database.name == "synthetic?#.db"
    assert not (tmp_path / "synthetic").exists()
    conn = release_module._read_only_connection(database)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM dmarc_scan_results")
    finally:
        conn.close()
    assert not Path(f"{database}-wal").exists()
    assert not Path(f"{database}-shm").exists()
    assert not (tmp_path / "synthetic").exists()


def test_one_run_only_and_v2_only_chains_are_rejected(tmp_path, release_module):
    database, manifests = _private_chain(tmp_path)
    with pytest.raises(ValueError, match="at least one v2 retry"):
        release_module.validate_manifest_chain(database=database, manifest_paths=manifests[:1])
    with pytest.raises(ValueError, match="v1 root"):
        release_module.validate_manifest_chain(database=database, manifest_paths=manifests[1:])


@pytest.mark.parametrize(("manifest_index", "field", "value", "message"), [
    (0, "scanner_git_revision", "c" * 40, "attestation|official"),
    (0, "concurrency", 119, "concurrency"),
    (0, "shuffle_seed", 43, "shuffle_seed"),
    (1, "batch_pool_size", 299, "batch_pool_size"),
    (1, "resolver_configuration", {**RESOLVERS, "nameservers": list(reversed(RESOLVERS["nameservers"]))}, "resolver"),
    (1, "measurement_core_sha256", "d" * 64, "measurement.core|run_id|release_eligible"),
])
def test_official_manifest_pin_failures(
    tmp_path, release_module, manifest_index, field, value, message,
):
    database, manifests = _private_chain(tmp_path)
    payload = json.loads(manifests[manifest_index].read_text())
    payload[field] = value
    if manifest_index:
        payload["run_id"] = _run_identity(payload)
    _write_manifest(manifests[manifest_index], payload)
    with pytest.raises(ValueError, match=message):
        release_module.validate_manifest_chain(database=database, manifest_paths=manifests)


def test_stale_v1_effective_schema_and_exact_byte_link_fail_closed(tmp_path, release_module):
    database, manifests = _private_chain(tmp_path)
    payload = json.loads(manifests[0].read_text())
    payload["effective_input_normalized_line_count"] = 2
    _write_manifest(manifests[0], payload)
    with pytest.raises(ValueError, match="full source-universe"):
        release_module.validate_manifest_chain(database=database, manifest_paths=manifests)


@pytest.mark.parametrize(("manifest_index", "mutation", "message"), [
    (1, "missing_transition", "transition"),
    (2, "repeated_transition", "transition"),
    (1, "altered_transition", "transition"),
    (2, "changed_plan", "planned_sha256"),
])
def test_core_transition_occurs_exactly_once_and_plan_never_changes(
    tmp_path, release_module, manifest_index, mutation, message,
):
    database, manifests = _private_chain(tmp_path)
    payload = json.loads(manifests[manifest_index].read_text())
    if mutation == "missing_transition":
        payload["measurement_core_transition"] = None
    elif mutation == "repeated_transition":
        payload["measurement_core_transition"] = dict(URI_SAFETY_CORE_TRANSITION)
    elif mutation == "altered_transition":
        payload["measurement_core_transition"]["reason"] = "different"
    else:
        payload["planned_input_normalized_sha256"] = "f" * 64
    payload["run_id"] = _run_identity(payload)
    _write_manifest(manifests[manifest_index], payload)
    with pytest.raises(ValueError, match=message):
        release_module.validate_manifest_chain(
            database=database, manifest_paths=manifests,
        )

    database, manifests = _private_chain(tmp_path / "second")
    manifests[0].write_bytes(manifests[0].read_bytes() + b" \n")
    with pytest.raises(ValueError, match="exact prior manifest bytes"):
        release_module.validate_manifest_chain(database=database, manifest_paths=manifests)


def test_chain_rejects_overlap_bad_attempt_accounting_and_final_identity(tmp_path, release_module):
    database, manifests = _private_chain(tmp_path)
    payload = json.loads(manifests[2].read_text())
    payload["started_at_utc"] = "2026-08-21T00:02:30Z"
    payload["run_id"] = _run_identity(payload)
    _write_manifest(manifests[2], payload)
    with pytest.raises(ValueError, match="overlap"):
        release_module.validate_manifest_chain(database=database, manifest_paths=manifests)

    database, manifests = _private_chain(tmp_path / "attempt")
    payload = json.loads(manifests[2].read_text())
    payload["attempted_input_normalized_line_count"] = 0
    payload["planned_excluded_count"] = 3
    payload["rows_written"] = 0
    payload["run_id"] = _run_identity(payload)
    _write_manifest(manifests[2], payload)
    with pytest.raises(ValueError, match="attempted count|attempt every retained error"):
        release_module.validate_manifest_chain(database=database, manifest_paths=manifests)

    database, manifests = _private_chain(tmp_path / "identity")
    with database.open("ab") as target:
        target.write(b"mutation")
    with pytest.raises(ValueError, match="final manifest output identity"):
        release_module.validate_manifest_chain(database=database, manifest_paths=manifests)


def test_stage_rejects_final_manifest_accounting_that_differs_from_database_aggregate(
    tmp_path, release_module,
):
    database, manifests = _private_chain(tmp_path)
    final_manifest = json.loads(manifests[-1].read_text())
    final_manifest["database_post"] = {
        "total_rows": 3, "analyzable_rows": 3, "error_rows": 0,
    }
    final_manifest["run_id"] = _run_identity(final_manifest)
    _write_manifest(manifests[-1], final_manifest)

    with pytest.raises(ValueError, match="final run accounting.*aggregate"):
        release_module.stage_release(
            database=database, manifest_paths=manifests,
            output_directory=tmp_path / "public",
        )
    assert not (tmp_path / "public").exists()


def test_live_sqlite_companion_is_never_aggregated(tmp_path, release_module):
    database, manifests = _private_chain(tmp_path)
    Path(f"{database}-wal").write_bytes(b"synthetic companion")
    with pytest.raises(ValueError, match="companion"):
        release_module.stage_release(
            database=database, manifest_paths=manifests,
            output_directory=tmp_path / "output",
        )
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("moment", ["after_first_hash", "between_passes", "after_snapshot"])
def test_toctou_mutation_at_every_boundary_fails_and_cleans_output(
    tmp_path, release_module, monkeypatch, moment,
):
    database, manifests = _private_chain(tmp_path)

    def mutate():
        with database.open("ab") as target:
            target.write(moment.encode())

    if moment == "after_first_hash":
        original = release_module._read_only_connection
        def changed(path):
            mutate()
            return original(path)
        monkeypatch.setattr(release_module, "_read_only_connection", changed)
    elif moment == "between_passes":
        original = release_module.aggregate_connection
        def changed(conn, period):
            metrics = original(conn, period)
            mutate()
            return metrics
        monkeypatch.setattr(release_module, "aggregate_connection", changed)
    else:
        original = release_module.independent_count_reconciliation_connection
        def changed(conn, metrics):
            original(conn, metrics)
            mutate()
        monkeypatch.setattr(release_module, "independent_count_reconciliation_connection", changed)
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="changed during|changed after"):
        release_module.stage_release(
            database=database, manifest_paths=manifests, output_directory=output,
        )
    assert not output.exists()


def test_late_database_mutation_during_metric_serialization_fails_and_cleans_output(
    tmp_path, release_module, monkeypatch,
):
    database, manifests = _private_chain(tmp_path)
    original = release_module._metric_payload

    def mutate_after_snapshot(metrics):
        payload = original(metrics)
        with database.open("ab") as target:
            target.write(b"late mutation")
        return payload

    monkeypatch.setattr(release_module, "_metric_payload", mutate_after_snapshot)
    output = tmp_path / "public"
    with pytest.raises(ValueError, match="changed after aggregate serialization"):
        release_module.stage_release(
            database=database, manifest_paths=manifests, output_directory=output,
        )
    assert not output.exists()


def test_both_count_catalogues_share_one_explicit_snapshot(tmp_path, release_module, monkeypatch):
    database, manifests = _private_chain(tmp_path)
    seen = []
    original_aggregate = release_module.aggregate_connection
    original_independent = release_module.independent_count_reconciliation_connection
    def aggregate(conn, period):
        seen.append((id(conn), conn.in_transaction, "canonical"))
        return original_aggregate(conn, period)
    def independent(conn, metrics):
        seen.append((id(conn), conn.in_transaction, "independent"))
        return original_independent(conn, metrics)
    monkeypatch.setattr(release_module, "aggregate_connection", aggregate)
    monkeypatch.setattr(release_module, "independent_count_reconciliation_connection", independent)
    release_module.stage_release(
        database=database, manifest_paths=manifests, output_directory=tmp_path / "output",
    )
    assert seen[0][0] == seen[1][0]
    assert seen == [(seen[0][0], True, "canonical"), (seen[0][0], True, "independent")]


@pytest.mark.parametrize("statement", [
    "SELECT * FROM dmarc_scan_results",
    "SELECT domain FROM dmarc_scan_results",
    'SELECT d."domain" FROM dmarc_scan_results AS d',
    "SELECT query_statuses FROM dmarc_scan_results",
])
def test_sql_privacy_allowlist_rejects_raw_or_qualified_projections(release_module, statement):
    with pytest.raises(ValueError, match="projection|domain"):
        release_module._validate_count_only_trace([statement])


def test_output_roots_and_manifest_inputs_reject_symlinks_and_nonempty_state(tmp_path, release_module):
    database, manifests = _private_chain(tmp_path)
    output = tmp_path / "nonempty"
    output.mkdir()
    (output / "keep").write_text("keep")
    with pytest.raises(FileExistsError, match="nonempty"):
        release_module.stage_release(database=database, manifest_paths=manifests, output_directory=output)

    link = tmp_path / "manifest-link.json"
    link.symlink_to(manifests[0])
    with pytest.raises(ValueError, match="non-symlink"):
        release_module.validate_manifest_chain(
            database=database, manifest_paths=[link, *manifests[1:]],
        )

    with pytest.raises(ValueError, match="parent traversal"):
        release_module.stage_release(
            database=database, manifest_paths=manifests,
            output_directory=tmp_path / "unused" / ".." / "escaped",
        )


def _reservation(doi: str = "10.5281/zenodo.1234567") -> dict:
    record_id = int(doi.rsplit(".", 1)[1])
    return {
        "provider": "zenodo",
        "record_id": record_id,
        "doi": doi,
        "doi_url": f"https://doi.org/{doi}",
        "reserved_at_utc": "2026-08-21T06:00:00Z",
        "release_version": "v2026.08.2",
    }


def _reserve_staging(staging: Path, release_module, doi: str) -> None:
    private_key = staging.parent.parent / "doi-approval-private.pem"
    public_key = staging.parent.parent / "doi-approval-public.pem"
    if not private_key.exists():
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private_key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], check=True, capture_output=True)
    reservation = _reservation(doi)
    reservation["external_verification"] = {
        "verification_version": 1, "authority_name": "WebEvolve Release Authority",
        "approver_name": "Peter Hadorn", "approver_identity": "staff:peter.hadorn",
        "approver_role": "release-owner", "scope": "offline-zenodo-reservation-verification-v1",
        "signature_algorithm": "ed25519-openssl-pkeyutl-raw-v1",
        "public_key_fingerprint_sha256": release_module._public_key_fingerprint(public_key),
    }
    release_module._load_official_config()["doi_approval_key_fingerprint"] = reservation["external_verification"]["public_key_fingerprint_sha256"]
    unsigned = release_module._reservation_signed_bytes(reservation)
    payload = staging.parent.parent / "doi-approval-payload"
    signature = staging.parent.parent / "doi-approval-signature"
    payload.write_bytes(unsigned)
    subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key), "-in", str(payload), "-out", str(signature)], check=True, capture_output=True)
    reservation["external_verification"]["signature_base64"] = base64.b64encode(signature.read_bytes()).decode()
    release_module.bind_reserved_doi(
        staging_directory=staging, reservation_attestation=reservation,
        approval_public_key=public_key,
        approved_key_fingerprint=reservation["external_verification"]["public_key_fingerprint_sha256"],
    )


def _png_bytes(width: int, height: int, *, doi: str, source: str, caption: str) -> bytes:
    image = Image.new("RGB", (width, height), (248, 247, 243))
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("doi", doi)
    metadata.add_text("source", source)
    metadata.add_text("caption", caption)
    output = BytesIO()
    image.save(output, format="PNG", pnginfo=metadata)
    return output.getvalue()


def _svg_bytes(
    width: int, height: int, *, title: str, description: str,
    doi: str, source: str, caption: str,
) -> bytes:
    raw_values = {
        "title": title, "description": description, "doi": doi,
        "source": source, "caption": caption,
    }
    values = {key: html.escape(value) for key, value in raw_values.items()}
    import release.build_release as bundle

    font_family = bundle.FIGURE_FONT_FAMILY
    font_style = bundle._svg_font_face_declaration()
    max_characters = (width - 80) // 12
    caption_lines = textwrap.wrap(
        " ".join(caption.split()), width=max_characters,
        break_long_words=False, break_on_hyphens=False,
    )
    caption_nodes = "".join(
        f'<text x="40" y="{140 + index * 24}" fill="#111111" '
        f'font-family="{font_family}">'
        f'{html.escape(line)}</text>'
        for index, line in enumerate(caption_lines)
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        'aria-labelledby="figure-title figure-description">'
        f'<title id="figure-title">{values["title"]}</title>'
        f'<desc id="figure-description">{values["description"]}</desc>'
        f'<style type="text/css">{font_style}</style>'
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#f8f7f3"/>'
        f'<text x="40" y="80" fill="#111111" font-family="{font_family}">{values["title"]}</text>'
        f'{caption_nodes}'
        f'<text x="40" y="{height - 60}" fill="#111111" font-family="{font_family}">{values["source"]}</text>'
        f'<text x="40" y="{height - 30}" fill="#111111" font-family="{font_family}">{values["doi"]}</text>'
        '</svg>'
    ).encode()


def _document_text(name: str, release_module, doi: str, interval: dict) -> str:
    title, headings = release_module.DOCUMENT_CONTRACTS[name]
    metadata = (
        f"# {title}\n\n"
        f"Release-Version: {release_module.RELEASE_VERSION}\n"
        f"DOI: {doi}\n"
        f"Source-Snapshot-Date: 2026-04-12\n"
        f"Measurement-Started-At: {interval['started_at_utc']}\n"
        f"Measurement-Finished-At: {interval['finished_at_utc']}\n"
        f"Repository: {release_module.CANONICAL_REPOSITORY_URL}\n"
        "License: CC BY 4.0\n"
    )
    sections = "".join(
        f"\n## {heading}\n\nReviewed aggregate release information for {heading.lower()}, "
        "including scientific limitations, privacy boundaries, denominators, and correction handling.\n"
        for heading in headings
    )
    return metadata + sections


def _complete_staging(staging: Path, release_module, doi: str = "10.5281/zenodo.1234567") -> None:
    release = json.loads((staging / "release.json").read_text())
    if release["status"] == "staging":
        _reserve_staging(staging, release_module, doi)
        release = json.loads((staging / "release.json").read_text())
    (staging / "figures").mkdir()
    interval = release["measurement_interval"]
    metrics = {
        item["metric_id"]: item
        for item in json.loads((staging / "metrics.json").read_text())["metrics"]
    }
    figures = []
    for chart_id, specification in release_module.FIGURE_SPECS.items():
        for locale in release_module.FIGURE_LOCALES:
            source = release_module.FIGURE_SOURCE_LABELS[locale]
            copy = release_module._approved_figure_copy(chart_id, locale, tuple(
                release_module._metric_objects(json.loads((staging / "metrics.json").read_text())),
            ), release, doi)
            title, description, caption = copy["title"], copy["description"], copy["caption"]
            for fmt in ("svg", "png"):
                width, height = specification["dimensions"]
                name = f"{chart_id}.{locale}.{fmt}"
                path = staging / "figures" / name
                if fmt == "svg":
                    content = _svg_bytes(
                        width, height, title=title, description=description,
                        doi=doi, source=source, caption=caption,
                    )
                    mime = "image/svg+xml"
                else:
                    content = _png_bytes(
                        width, height, doi=doi, source=source, caption=caption,
                    )
                    mime = "image/png"
                path.write_bytes(content)
                digest, size = _identity(path)
                metric_ids = list(specification["metric_ids"])
                caveats = list(dict.fromkeys(metrics[item]["caveat"] for item in metric_ids))
                if specification.get("required_caveat"):
                    caveats.append(specification["required_caveat"])
                figures.append({
                    "chart_id": chart_id, "family": specification["family"],
                    "path": f"figures/{name}", "kind": specification["kind"],
                    "format": fmt, "mime_type": mime, "width": width, "height": height,
                    "locale": locale, "metric_ids": metric_ids,
                    "denominator_metric_ids": list(specification["denominator_metric_ids"]),
                    "title": title, "description": description, "caption": caption,
                    "source_snapshot_date": "2026-04-12",
                    "source_snapshot_sha256": release["source_universe"]["normalized_sha256"],
                    "source_label": source, "measurement_interval": interval,
                    "release_version": release_module.RELEASE_VERSION,
                    "license": "CC BY 4.0", "doi": doi,
                    "repository": release_module.CANONICAL_REPOSITORY_URL,
                    "methodology_signals": list(dict.fromkeys(metrics[item]["method"] for item in metric_ids)),
                    "caveat_signals": caveats, "sha256": digest, "bytes": size,
                })
    (staging / "figures" / "manifest.json").write_text(json.dumps({
        "manifest_version": 1, "release_version": "v2026.08.2", "figures": figures,
    }, sort_keys=True, indent=2) + "\n")
    (staging / "CITATION.cff").write_text(
        'cff-version: "1.2.0"\n'
        'message: "Please cite this aggregate research release."\n'
        'title: "Swiss Email Security Report aggregate data"\n'
        'version: "v2026.08.2"\n'
        f'doi: "{doi}"\n'
        'authors:\n'
        '  - family-names: "Hadorn"\n'
        '    given-names: "Peter"\n'
        f'repository-code: "{release_module.CANONICAL_REPOSITORY_URL}"\n'
        f'url: "https://doi.org/{doi}"\n'
        'license: "CC-BY-4.0"\n'
    )
    (staging / "LICENSE").write_bytes(release_module.CODE_LICENSE_PATH.read_bytes())
    (staging / "LICENSE-DATA.md").write_bytes(release_module.DATA_LICENSE_PATH.read_bytes())
    for name in release_module.DOCUMENT_CONTRACTS:
        (staging / name).write_text(_document_text(name, release_module, doi, interval))
    signoffs = {
        role: {
            "approved": True, "reviewer_name": "Peter Hadorn",
            "reviewer_identity": f"staff:peter.{role}",
            "reviewer_role": {
                "scientific": "scientific-methods-reviewer", "privacy": "privacy-reviewer",
                "de": "german-language-editor", "fr": "french-language-editor", "it": "italian-language-editor",
            }[role],
            "signed_at_utc": "2026-08-21T07:00:00Z",
        }
        for role in ("scientific", "privacy", "de", "fr", "it")
    }
    reviewed_files = {
        path.relative_to(staging).as_posix(): path
        for path in staging.rglob("*") if path.is_file()
    }
    reservation = json.loads((staging / "doi-reservation.json").read_text())
    authority = reservation["external_verification"]
    signoff_payload = {
        "signoff_version": 1, "release_version": release_module.RELEASE_VERSION,
        "doi": doi, "signed_at_utc": "2026-08-21T07:00:00Z",
        "reviewed_scope": release_module.EDITORIAL_REVIEW_SCOPE,
        "reviewed_artifact_count": len(release_module._reviewed_artifact_entries(reviewed_files)),
        "reviewed_artifact_root_sha256": release_module._reviewed_artifact_root(reviewed_files),
        "signoffs": signoffs,
        "external_verification": {
            "verification_version": 1,
            "authority_name": authority["authority_name"],
            "approver_name": authority["approver_name"],
            "approver_identity": authority["approver_identity"],
            "approver_role": authority["approver_role"],
            "scope": "prospective-editorial-review-v1",
            "signature_algorithm": "ed25519-openssl-pkeyutl-raw-v1",
            "public_key_fingerprint_sha256": authority["public_key_fingerprint_sha256"],
        },
    }
    signed_payload = staging.parent.parent / "editorial-approval-payload"
    signed_output = staging.parent.parent / "editorial-approval-signature"
    signed_payload.write_bytes(release_module._editorial_signoff_signed_bytes(signoff_payload))
    subprocess.run([
        "openssl", "pkeyutl", "-sign", "-rawin",
        "-inkey", str(staging.parent.parent / "doi-approval-private.pem"),
        "-in", str(signed_payload), "-out", str(signed_output),
    ], check=True, capture_output=True)
    signoff_payload["external_verification"]["signature_base64"] = base64.b64encode(
        signed_output.read_bytes(),
    ).decode()
    (staging / "EDITORIAL-SIGNOFF.json").write_text(
        json.dumps(signoff_payload, sort_keys=True, indent=2) + "\n",
    )


def test_reserved_doi_lifecycle_is_explicit_strict_and_not_published(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    invalid = _reservation()
    invalid["doi"] = "pending"
    with pytest.raises(ValueError, match="reservation|DOI|schema"):
        release_module.bind_reserved_doi(
            staging_directory=staging, reservation_attestation=invalid,
        )
    assert json.loads((staging / "release.json").read_text())["status"] == "staging"

    doi = "10.5281/zenodo.1234567"
    _reserve_staging(staging, release_module, doi)
    release = json.loads((staging / "release.json").read_text())
    reservation = json.loads((staging / "doi-reservation.json").read_text())
    assert release["status"] == "doi_reserved" and release["doi"] == doi
    assert reservation["doi"] == doi and "external_verification" in reservation
    assert "published" not in (staging / "release.json").read_text()


def test_doi_binding_rejects_self_asserted_reservation_and_svg_hidden_caption(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    with pytest.raises(ValueError, match="reservation|external_verification"):
        release_module.bind_reserved_doi(
            staging_directory=staging, reservation_attestation=_reservation(),
        )
    _complete_staging(staging, release_module)
    manifest_path = staging / "figures" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    entry = next(item for item in manifest["figures"] if item["format"] == "svg")
    path = staging / entry["path"]
    path.write_text(path.read_text().replace('x="40" y="140"', 'x="-1" y="140"', 1))
    entry["sha256"], entry["bytes"] = _identity(path)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    with pytest.raises(ValueError, match="visible"):
        release_module.finalize_release(staging_directory=staging)


def test_finalizer_requires_reserved_doi_and_complete_reviewed_payload(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    with pytest.raises(ValueError, match="reservation|doi_reserved|missing required"):
        release_module.finalize_release(staging_directory=staging)
    _reserve_staging(staging, release_module, "10.5281/zenodo.1234567")
    with pytest.raises(ValueError, match="missing required"):
        release_module.finalize_release(staging_directory=staging)
    release = json.loads((staging / "release.json").read_text())
    assert release["status"] == "doi_reserved" and "inventory" not in release


def test_finalizer_refuses_unexpected_output_root_state(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    (staging.parent / "unreviewed").write_text("unexpected")
    with pytest.raises(FileExistsError, match="unexpected state"):
        release_module.finalize_release(staging_directory=staging)


def test_finalizer_seals_complete_inventory_and_checksums(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    doi = "10.5281/zenodo.1234567"
    _complete_staging(staging, release_module, doi)
    source_inodes = {
        path.relative_to(staging).as_posix(): path.stat().st_ino
        for path in staging.rglob("*") if path.is_file()
    }
    final = release_module.finalize_release(staging_directory=staging)
    assert final == tmp_path / "public" / "v2026.08.2"
    assert not staging.exists()
    release = json.loads((final / "release.json").read_text())
    assert release["status"] == "sealed" and release["doi"] == doi
    assert "published" not in (final / "release.json").read_text()
    assert all(
        (final / name).stat().st_ino != inode
        for name, inode in source_inodes.items()
    )
    regular = {
        path.relative_to(final).as_posix() for path in final.rglob("*") if path.is_file()
    }
    assert {item["name"] for item in release["inventory"]} == regular - {
        "release.json", "checksums.sha256",
    }
    checksum_names = {
        row.split("  ", 1)[1]
        for row in (final / "checksums.sha256").read_text().splitlines()
    }
    assert checksum_names == regular - {"checksums.sha256"}
    assert "release.json" in checksum_names and "figures/manifest.json" in checksum_names
    assert stat.S_IMODE(final.stat().st_mode) == 0o555
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in final.rglob("*") if path.is_file())
    assert all(path.stat().st_nlink == 1 for path in final.rglob("*") if path.is_file())


def test_exact_30_figure_contract_is_pinned(release_module):
    assert tuple(release_module.FIGURE_SPECS) == (
        "mail-authentication-overview", "dmarc-policy-observations",
        "dns-transport-signals", "mx-provider-fingerprints",
        "social-report-card",
    )
    assert release_module.FIGURE_SPECS["mx-provider-fingerprints"]["required_caveat"] == (
        "MX provider classifications are hostname fingerprints, not market-share measurements."
    )
    assert release_module.FIGURE_SPECS["mail-authentication-overview"]["metric_ids"] == (
        "mx.present", "spf.present", "dkim.selector_observed", "dmarc.detected",
    )
    assert release_module.FIGURE_SPECS["dmarc-policy-observations"]["metric_ids"] == (
        "dmarc.reject", "dmarc.quarantine", "dmarc.none",
        "dmarc.no_supported_effective_policy",
    )
    assert release_module.FIGURE_SPECS["dns-transport-signals"]["metric_ids"] == (
        "tlsa.record_present", "bimi.record_present", "mta_sts.txt_present",
        "tls_rpt.record_present",
    )
    assert release_module.FIGURE_SPECS["social-report-card"]["dimensions"] == (1200, 630)
    assert all(
        specification["dimensions"] == (1600, 900)
        for chart_id, specification in release_module.FIGURE_SPECS.items()
        if chart_id != "social-report-card"
    )
    assert release_module.EXPECTED_FIGURE_COUNT == 30


def test_finalize_refuses_citation_or_figure_doi_tampering(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    doi = "10.5281/zenodo.1234567"
    _complete_staging(staging, release_module, doi)
    (staging / "CITATION.cff").write_text(
        (staging / "CITATION.cff").read_text().replace(doi, "10.5281/zenodo.9999999")
    )
    with pytest.raises(ValueError, match="CITATION|DOI"):
        release_module.finalize_release(staging_directory=staging)
    assert staging.exists() and not (staging.parent / "v2026.08.2").exists()

    (staging / "CITATION.cff").write_text(
        (staging / "CITATION.cff").read_text().replace("9999999", "1234567")
    )
    manifest_path = staging / "figures" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["figures"][0]["doi"] = "10.5281/zenodo.9999999"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    with pytest.raises(ValueError, match="figure.*DOI|reservation"):
        release_module.finalize_release(staging_directory=staging)


def test_svg_allowlist_rejects_onload_even_with_updated_manifest_hash(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    manifest_path = staging / "figures" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    entry = next(item for item in manifest["figures"] if item["format"] == "svg")
    figure = staging / entry["path"]
    figure.write_bytes(figure.read_bytes().replace(b"<svg ", b'<svg onload="alert(1)" ', 1))
    entry["sha256"], entry["bytes"] = _identity(figure)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    with pytest.raises(ValueError, match="SVG.*attribute|onload|inactive"):
        release_module.finalize_release(staging_directory=staging)


@pytest.mark.parametrize("mutation", ["truncated", "one-pixel", "wrong-mode"])
def test_png_validation_uses_pillow_and_exact_contract(
    tmp_path, release_module, mutation,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    manifest_path = staging / "figures" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    entry = next(item for item in manifest["figures"] if item["format"] == "png")
    figure = staging / entry["path"]
    if mutation == "truncated":
        figure.write_bytes(figure.read_bytes()[:-20])
    else:
        mode = "L" if mutation == "wrong-mode" else "RGB"
        dimensions = (entry["width"], entry["height"]) if mutation == "wrong-mode" else (1, 1)
        image = Image.new(mode, dimensions)
        image.save(figure, format="PNG")
    entry["sha256"], entry["bytes"] = _identity(figure)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    with pytest.raises(ValueError, match="PNG|dimensions|mode|metadata|truncated"):
        release_module.finalize_release(staging_directory=staging)


@pytest.mark.parametrize(("name", "content", "message"), [
    ("private.db", b"private", "database"),
    ("notes.bak", b"backup", "backup"),
    ("README.md", b"private material: query_statuses\n", "private scanner material"),
])
def test_finalizer_privacy_and_file_allowlists_fail_closed(
    tmp_path, release_module, name, content, message,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    (staging / name).write_bytes(content)
    with pytest.raises(ValueError, match=message):
        release_module.finalize_release(staging_directory=staging)


def test_finalizer_rejects_symlink_and_figure_path_traversal(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    (staging / "linked").symlink_to(staging / "README.md")
    with pytest.raises(ValueError, match="symlink"):
        release_module.finalize_release(staging_directory=staging)
    (staging / "linked").unlink()
    manifest = json.loads((staging / "figures" / "manifest.json").read_text())
    manifest["figures"][0]["path"] = "figures/../README.md"
    (staging / "figures" / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="schema|unsafe"):
        release_module.finalize_release(staging_directory=staging)


def test_finalizer_rejects_hardlinked_staging_payload(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    external = tmp_path / "external-readme"
    os.link(staging / "README.md", external)
    with pytest.raises(ValueError, match="hard.?link"):
        release_module.finalize_release(staging_directory=staging)


def test_metric_tamper_and_existing_final_are_rejected(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    metrics = json.loads((staging / "metrics.json").read_text())
    metrics["metrics"][0]["numerator"] += 1
    (staging / "metrics.json").write_text(json.dumps(metrics))
    with pytest.raises(ValueError, match="counts|aggregate file|percentage"):
        release_module.finalize_release(staging_directory=staging)

    # Restore by restaging in a separate root, then prove overwrite refusal.
    second_root = tmp_path / "second"
    second_staging, _database, _manifests = _stage(second_root, release_module)
    _complete_staging(second_staging, release_module)
    (second_staging.parent / "v2026.08.2").mkdir()
    with pytest.raises(FileExistsError, match="existing final"):
        release_module.finalize_release(staging_directory=second_staging)


@pytest.mark.parametrize(
    "target", ["release-chain", "attestation-link", "source-pin", "final-accounting"],
)
def test_finalizer_rejects_cross_reference_tampering(tmp_path, release_module, target):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    doi = "10.5281/zenodo.1234567"
    _complete_staging(staging, release_module, doi)
    if target == "release-chain":
        path = staging / "release.json"
        payload = json.loads(path.read_text())
        payload["run_chain"][1]["attempted_input_count"] = 0
    elif target == "final-accounting":
        path = staging / "release.json"
        payload = json.loads(path.read_text())
        payload["run_chain"][-1]["database_post"] = {
            "total": 3, "analyzable": 3, "error": 0,
        }
    elif target == "attestation-link":
        path = staging / "aggregate-attestation.json"
        payload = json.loads(path.read_text())
        payload["final_run_identifier"] = "f" * 64
        path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
    else:
        attestation_path = staging / "aggregate-attestation.json"
        attestation = json.loads(attestation_path.read_text())
        attestation["source_input_normalized_sha256"] = "f" * 64
        attestation_path.write_text(json.dumps(attestation, sort_keys=True, indent=2) + "\n")
        path = staging / "release.json"
        payload = json.loads(path.read_text())
        payload["source_universe"]["normalized_sha256"] = "f" * 64
        identity = _identity(attestation_path)
        aggregate = next(
            item for item in payload["aggregate_files"]
            if item["name"] == "aggregate-attestation.json"
        )
        aggregate["sha256"], aggregate["bytes"] = identity
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")

    with pytest.raises(
        ValueError,
        match="chain invariants|attestation differs|pinned source|final run accounting",
    ):
        release_module.finalize_release(staging_directory=staging)
    assert staging.exists() and not (staging.parent / "v2026.08.2").exists()


def test_checksum_verifier_detects_post_seal_tampering(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    final = release_module.finalize_release(staging_directory=staging)
    os.chmod(final, 0o755)
    os.chmod(final / "README.md", 0o644)
    (final / "README.md").write_text("tampered public documentation")
    with pytest.raises(ValueError, match="checksum verification"):
        release_module._verify_checksums(final)


def test_cff_safe_parser_licenses_documents_and_signoffs_fail_closed(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    (staging / "CITATION.cff").write_text(
        '!!python/object/apply:os.system ["echo unsafe"]\n'
    )
    with pytest.raises(ValueError, match="CITATION|YAML|schema"):
        release_module.finalize_release(staging_directory=staging)

    staging, _database, _manifests = _stage(tmp_path / "license", release_module)
    _complete_staging(staging, release_module)
    (staging / "LICENSE-DATA.md").write_text("CC BY 4.0")
    with pytest.raises(ValueError, match="canonical data license"):
        release_module.finalize_release(staging_directory=staging)

    staging, _database, _manifests = _stage(tmp_path / "license-link", release_module)
    _complete_staging(staging, release_module)
    (staging / "LICENSE-DATA.md").write_text(
        "CC BY 4.0: https://creativecommons.org/licenses/by/4.0/legalcode\n"
    )
    with pytest.raises(ValueError, match="canonical data license"):
        release_module.finalize_release(staging_directory=staging)

    staging, _database, _manifests = _stage(tmp_path / "docs", release_module)
    _complete_staging(staging, release_module)
    (staging / "METHODOLOGY.md").write_text("# METHODOLOGY\n\nTBD\n")
    with pytest.raises(ValueError, match="METHODOLOGY|placeholder|heading|field"):
        release_module.finalize_release(staging_directory=staging)

    staging, _database, _manifests = _stage(tmp_path / "signoff", release_module)
    _complete_staging(staging, release_module)
    signoff = json.loads((staging / "EDITORIAL-SIGNOFF.json").read_text())
    signoff["signoffs"]["fr"]["approved"] = False
    (staging / "EDITORIAL-SIGNOFF.json").write_text(json.dumps(signoff))
    with pytest.raises(ValueError, match="signoff|approved"):
        release_module.finalize_release(staging_directory=staging)


def test_cli_has_stage_reservation_and_finalize_operations(release_module):
    with pytest.raises(SystemExit):
        release_module.main(["stage", "--doi", "10.5281/zenodo.1234567"])
    with pytest.raises(SystemExit):
        release_module.main(["bind-doi", "--staging-directory", "missing"])
    with pytest.raises(SystemExit):
        release_module.main([
            "finalize", "--staging-directory", "missing", "--doi",
            "10.5281/zenodo.1234567",
        ])


@pytest.mark.parametrize("boundary", ["original-move", "promotion"])
def test_doi_binding_recovers_from_post_rename_interruption(
    tmp_path, release_module, monkeypatch, boundary,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    original = {
        path.relative_to(staging).as_posix(): path.read_bytes()
        for path in staging.rglob("*") if path.is_file()
    }
    real_replace = release_module.os.replace
    injected = False

    def interrupted_replace(source, destination):
        nonlocal injected
        source_path, destination_path = Path(source), Path(destination)
        is_boundary = (
            boundary == "original-move"
            and source_path == staging
            and destination_path.name.endswith("doi-backup")
        ) or (
            boundary == "promotion"
            and source_path.name.endswith("doi-prepared")
            and destination_path == staging
        )
        result = real_replace(source, destination)
        if is_boundary and not injected:
            injected = True
            raise KeyboardInterrupt(f"fault after {boundary}")
        return result

    monkeypatch.setattr(release_module.os, "replace", interrupted_replace)
    with pytest.raises(KeyboardInterrupt, match="fault after"):
        _reserve_staging(staging, release_module, "10.5281/zenodo.1234567")
    assert injected
    assert {entry.name for entry in staging.parent.iterdir()} == {
        release_module.STAGING_DIRECTORY_NAME,
    }
    current = {
        path.relative_to(staging).as_posix(): path.read_bytes()
        for path in staging.rglob("*") if path.is_file()
    }
    status = json.loads((staging / "release.json").read_text())["status"]
    if status == "staging":
        assert current == original
    else:
        assert status == "doi_reserved"
        assert set(current) == release_module.RESERVED_STAGING_FILES
    _reserve_staging(staging, release_module, "10.5281/zenodo.1234567")
    assert json.loads((staging / "release.json").read_text())["status"] == "doi_reserved"
    assert {
        path.relative_to(staging).as_posix()
        for path in staging.rglob("*") if path.is_file()
    } == release_module.RESERVED_STAGING_FILES


def test_doi_binding_copy_interruption_leaves_only_byte_identical_original(
    tmp_path, release_module, monkeypatch,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    original = {
        path.relative_to(staging).as_posix(): path.read_bytes()
        for path in staging.rglob("*") if path.is_file()
    }
    real_copy = release_module.shutil.copy2
    injected = False

    def interrupted_copy(source, destination, *args, **kwargs):
        nonlocal injected
        result = real_copy(source, destination, *args, **kwargs)
        if not injected:
            injected = True
            raise KeyboardInterrupt("fault during sibling preparation")
        return result

    monkeypatch.setattr(release_module.shutil, "copy2", interrupted_copy)
    with pytest.raises(KeyboardInterrupt, match="sibling preparation"):
        _reserve_staging(staging, release_module, "10.5281/zenodo.1234567")

    assert injected
    assert {entry.name for entry in staging.parent.iterdir()} == {
        release_module.STAGING_DIRECTORY_NAME,
    }
    assert {
        path.relative_to(staging).as_posix(): path.read_bytes()
        for path in staging.rglob("*") if path.is_file()
    } == original


def test_doi_binding_is_idempotent_only_for_the_same_signed_reservation(
    tmp_path, release_module,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    doi = "10.5281/zenodo.1234567"
    _reserve_staging(staging, release_module, doi)
    before = {
        path.relative_to(staging).as_posix(): path.read_bytes()
        for path in staging.rglob("*") if path.is_file()
    }
    reservation = json.loads((staging / "doi-reservation.json").read_text())
    public_key = staging.parent.parent / "doi-approval-public.pem"
    fingerprint = reservation["external_verification"]["public_key_fingerprint_sha256"]
    release_module.bind_reserved_doi(
        staging_directory=staging, reservation_attestation=reservation,
        approval_public_key=public_key, approved_key_fingerprint=fingerprint,
    )
    after = {
        path.relative_to(staging).as_posix(): path.read_bytes()
        for path in staging.rglob("*") if path.is_file()
    }
    assert after == before

    changed = json.loads(json.dumps(reservation))
    changed["external_verification"]["authority_name"] = "Another Release Authority"
    with pytest.raises(ValueError, match="signature|different reservation"):
        release_module.bind_reserved_doi(
            staging_directory=staging, reservation_attestation=changed,
            approval_public_key=public_key, approved_key_fingerprint=fingerprint,
        )
    assert {
        path.relative_to(staging).as_posix(): path.read_bytes()
        for path in staging.rglob("*") if path.is_file()
    } == before


def test_interrupted_doi_recovery_authenticates_promoted_tree_before_deleting_backup(
    tmp_path, release_module,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    root = staging.parent
    backup = root / f"{release_module.STAGING_DIRECTORY_NAME}.doi-backup"
    shutil.copytree(staging, backup)
    (staging / "doi-reservation.json").write_text("{}\n")
    (staging / "doi-approval-public.der").write_bytes(b"not-an-ed25519-key")
    original_backup = {
        path.relative_to(backup).as_posix(): path.read_bytes()
        for path in backup.rglob("*") if path.is_file()
    }

    with pytest.raises(ValueError, match="status|schema|Ed25519|reservation"):
        _reserve_staging(staging, release_module, "10.5281/zenodo.1234567")

    assert backup.exists()
    assert {
        path.relative_to(backup).as_posix(): path.read_bytes()
        for path in backup.rglob("*") if path.is_file()
    } == original_backup


def test_doi_binding_rejects_non_ed25519_approval_key(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    private_key = tmp_path / "rsa-private.pem"
    public_key = tmp_path / "rsa-public.pem"
    subprocess.run([
        "openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", str(private_key),
    ], check=True, capture_output=True)
    der = subprocess.run([
        "openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER",
    ], check=True, capture_output=True).stdout
    subprocess.run([
        "openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key),
    ], check=True, capture_output=True)
    fingerprint = hashlib.sha256(der).hexdigest()
    release_module._load_official_config()["doi_approval_key_fingerprint"] = fingerprint
    reservation = _reservation()
    reservation["external_verification"] = {
        "verification_version": 1, "authority_name": "WebEvolve Release Authority",
        "approver_name": "Peter Hadorn", "approver_identity": "staff:peter.hadorn",
        "approver_role": "release-owner", "scope": "offline-zenodo-reservation-verification-v1",
        "signature_algorithm": "ed25519-openssl-pkeyutl-raw-v1",
        "public_key_fingerprint_sha256": fingerprint,
        "signature_base64": base64.b64encode(b"x" * 64).decode(),
    }
    with pytest.raises(ValueError, match="Ed25519"):
        release_module.bind_reserved_doi(
            staging_directory=staging, reservation_attestation=reservation,
            approval_public_key=public_key, approved_key_fingerprint=fingerprint,
        )


def test_public_text_catalogue_allows_only_declared_hash_ip_and_domain_fields(
    tmp_path, release_module,
):
    release_path = tmp_path / "release.json"
    safe = {
        "source_universe": {"normalized_sha256": "a" * 64},
        "resolver_configuration": {"nameservers": ["1.1.1.1", "8.8.8.8"]},
        "canonical_repository_url": release_module.CANONICAL_REPOSITORY_URL,
    }
    release_path.write_text(json.dumps(safe))
    release_module._assert_public_content_safe({"release.json": release_path})

    for field, value in (
        ("unreviewed_hash", "b" * 64),
        ("unreviewed_ip", "82.21.4.94"),
        ("unreviewed_domain", "private-example.ch"),
        ("unreviewed_known_domain", "github.com"),
    ):
        unsafe = dict(safe)
        unsafe[field] = value
        release_path.write_text(json.dumps(unsafe))
        with pytest.raises(ValueError, match="unapproved|raw hash|IP|domain"):
            release_module._assert_public_content_safe({"release.json": release_path})

    unsafe = dict(safe)
    unsafe["canonical_repository_url"] = "https://private-example.ch/release"
    release_path.write_text(json.dumps(unsafe))
    with pytest.raises(ValueError, match="unapproved|domain"):
        release_module._assert_public_content_safe({"release.json": release_path})


@pytest.mark.parametrize("payload", [
    "Private host private-example.ch must not ship.",
    "Private address 82.21.4.94 must not ship.",
    f"Private digest {'b' * 64} must not ship.",
])
def test_every_public_text_family_rejects_unapproved_identifiers(
    tmp_path, release_module, payload,
):
    files = {}
    for name in ("README.md", "CITATION.cff", "figures/example.svg"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload)
        files[name] = path
    with pytest.raises(ValueError, match="unapproved|raw hash|IP|domain"):
        release_module._assert_public_content_safe(files)


@pytest.mark.parametrize("leak", [
    "/private/tmp/release.db", "/etc/passwd", "/root", "/opt/private",
    "/Volumes/Scanner/private", r"\private\tmp\release.db",
    r"C:\Users\Peter\private_scan", "&#47;etc&#47;passwd",
    "%2Fetc%2Fpasswd", "file:///private/tmp/release.db",
    "／private／tmp／release.db",
])
def test_public_text_rejects_general_absolute_and_rendered_paths(
    release_module, leak,
):
    with pytest.raises(ValueError, match="path|private|unapproved"):
        release_module._assert_safe_public_text(
            f"Do not publish {leak}", "reviewed Markdown",
        )


@pytest.mark.parametrize("length", [40, 64, 96, 128])
def test_public_text_rejects_every_sha_like_hex_length(release_module, length):
    with pytest.raises(ValueError, match="hash|hex"):
        release_module._assert_safe_public_text(
            f"unreviewed digest {'a' * length}", "reviewed Markdown",
        )


@pytest.mark.parametrize("domain", [
    "kundendaten.中国", "kundendaten.xn--fiqs8s", "kundendaten。中国",
    "secret%2eexample%2ech",
])
def test_public_text_rejects_unicode_and_punycode_domains(release_module, domain):
    with pytest.raises(ValueError, match="domain"):
        release_module._assert_safe_public_text(domain, "reviewed Markdown")


@pytest.mark.parametrize("encoded", [
    "192.168.001.001", "3232235777", "0xc0a80101", "030052000401",
    "0xc0.0xa8.0x01.0x01", "http://127.1/private",
    "http://0x7f.0.0.1/private", "http://0177.0.0.1/private",
    "http://127.0.1/private",
])
def test_public_text_rejects_noncanonical_ipv4_encodings(release_module, encoded):
    with pytest.raises(ValueError, match="IP|address|encoding"):
        release_module._assert_safe_public_text(encoded, "reviewed Markdown")


@pytest.mark.parametrize("record", [
    "v=spf1 include:private.example -all",
    "v=DMARC1; p=reject; rua=mailto:security@example.com",
    "v=DKIM1; p=AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
    "v=BIMI1; l=https://private.example/logo.svg",
    "v=STSv1; id=private-policy",
    "v=TLSRPTv1; rua=mailto:security@example.com",
])
def test_public_text_rejects_raw_dns_record_payloads(release_module, record):
    with pytest.raises(ValueError, match="DNS record|record payload"):
        release_module._assert_safe_public_text(record, "reviewed Markdown")


def test_private_field_vocabulary_is_casefolded_and_entity_decoded(
    tmp_path, release_module,
):
    for index, payload in enumerate((
        "MX_HOSTS must never ship", "DMARC_RECORD must never ship",
        "private&#46;example", "&#47;etc&#47;passwd",
    )):
        path = tmp_path / f"README-{index}.md"
        path.write_text(payload)
        with pytest.raises(ValueError, match="private|domain|path"):
            release_module._assert_public_content_safe({path.name: path})
    private_json = tmp_path / "release.json"
    private_json.write_text(json.dumps({"MX_HOSTS": ["hidden"]}))
    with pytest.raises(ValueError, match="private scanner field vocabulary"):
        release_module._assert_public_content_safe({"release.json": private_json})

    encoded_ip_json = tmp_path / "metrics.json"
    encoded_ip_json.write_text(json.dumps({"unreviewed_integer": 3232235777}))
    with pytest.raises(ValueError, match="decimal IP"):
        release_module._assert_public_content_safe({"metrics.json": encoded_ip_json})


def test_reviewed_semantic_json_integer_is_not_misclassified_as_ipv4(
    tmp_path, release_module,
):
    reservation = tmp_path / "doi-reservation.json"
    reservation.write_text(json.dumps({"record_id": 2_112_345_678}))
    release_module._assert_public_content_safe({"doi-reservation.json": reservation})


@pytest.mark.parametrize(("escaped", "message"), [
    (r"private\u002eexample", "domain"),
    (r"\u002fetc\u002fpasswd", "path"),
])
def test_cff_decoded_scalar_privacy_scan_rejects_unicode_escape(
    tmp_path, release_module, escaped, message,
):
    citation = tmp_path / "CITATION.cff"
    citation.write_text(
        'cff-version: "1.2.0"\n'
        f'message: "Please cite {escaped} for this aggregate release"\n'
        'title: "Swiss email security aggregate report"\n'
        'version: "v2026.08.2"\n'
        'doi: "10.5281/zenodo.1234567"\n'
        'authors:\n'
        '  - family-names: "Hadorn"\n'
        '    given-names: "Peter"\n'
        f'repository-code: "{release_module.CANONICAL_REPOSITORY_URL}"\n'
        'url: "https://doi.org/10.5281/zenodo.1234567"\n'
        'license: "CC-BY-4.0"\n'
    )
    with pytest.raises(ValueError, match=message):
        release_module._assert_public_content_safe({"CITATION.cff": citation})


def test_svg_decoded_entity_privacy_scan_rejects_rendered_domain(
    tmp_path, release_module,
):
    svg = tmp_path / "figure.svg"
    svg.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<text>private&#46;example</text></svg>',
    )
    with pytest.raises(ValueError, match="domain"):
        release_module._assert_public_content_safe({"figures/example.svg": svg})


@pytest.mark.parametrize("leak", ["private-example.ch", "82.21.4.94", "b" * 64])
def test_png_metadata_privacy_catalogue_rejects_unapproved_identifiers(
    release_module, leak,
):
    item = {
        "width": 1200, "height": 630, "doi": "10.5281/zenodo.1234567",
        "source_label": "Source text without identifiers.",
        "caption": f"Reviewed aggregate caption with forbidden value {leak}",
        "metric_ids": ["mx.present"],
        "denominator_metric_ids": ["population.analyzable"],
    }
    content = _png_bytes(
        1200, 630, doi=item["doi"], source=item["source_label"],
        caption=item["caption"],
    )
    with pytest.raises(ValueError, match="unapproved|raw hash|IP|domain"):
        release_module._validate_png(content, item)


@pytest.mark.parametrize("mutation", ["translated", "identity", "timestamp"])
def test_finalize_reverifies_every_signed_doi_semantic_field(
    tmp_path, release_module, mutation,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    reservation_path = staging / "doi-reservation.json"
    reservation = json.loads(reservation_path.read_text())
    if mutation == "translated":
        reservation["external_verification"]["authority_name"] = "Independent Release Authority"
    elif mutation == "identity":
        reservation["external_verification"]["approver_identity"] = "staff:another.owner"
    else:
        reservation["reserved_at_utc"] = "2026-08-21T06:00:01Z"
    reservation_path.write_text(json.dumps(reservation, sort_keys=True, separators=(",", ":")) + "\n")
    release_path = staging / "release.json"
    release = json.loads(release_path.read_text())
    digest, size = _identity(reservation_path)
    release["doi_reservation_file"]["sha256"] = digest
    release["doi_reservation_file"]["bytes"] = size
    release_path.write_text(json.dumps(release, sort_keys=True, separators=(",", ":")) + "\n")
    signoff_path = staging / "EDITORIAL-SIGNOFF.json"
    signoff = json.loads(signoff_path.read_text())
    signoff["reviewed_artifact_root_sha256"] = release_module._reviewed_artifact_root({
        path.relative_to(staging).as_posix(): path
        for path in staging.rglob("*") if path.is_file()
    })
    signoff_path.write_text(json.dumps(signoff, sort_keys=True, indent=2) + "\n")
    with pytest.raises(ValueError, match="DOI approval signature"):
        release_module.finalize_release(staging_directory=staging)


@pytest.mark.parametrize("mutation", [
    "transform", "suffix", "end-anchor", "right-edge", "tiny-font",
    "background-fill", "ancestor-opacity", "occlusion", "duplicate-aria",
    "duplicate-required", "alternate-caption-duplicate",
])
def test_svg_required_text_must_be_exact_and_locally_on_canvas(
    tmp_path, release_module, mutation,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    manifest_path = staging / "figures" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    entry = next(item for item in manifest["figures"] if item["format"] == "svg")
    figure = staging / entry["path"]
    content = figure.read_text()
    caption_line = release_module._svg_caption_lines(entry["caption"], entry["width"])[0]
    exact = (
        f'<text x="40" y="140" fill="#111111" '
        f'font-family="{release_module.FIGURE_FONT_FAMILY}">'
        f'{html.escape(caption_line)}</text>'
    )
    if mutation == "transform":
        replacement = f'<g transform="translate(-5000 0)">{exact}</g>'
    elif mutation == "suffix":
        replacement = exact.replace("</text>", " extra unreviewed words</text>")
    elif mutation == "end-anchor":
        replacement = exact.replace('<text ', '<text text-anchor="end" x="0" ').replace('x="40" ', "", 1)
    elif mutation == "right-edge":
        replacement = exact.replace('x="40"', 'x="1599.999"')
    elif mutation == "tiny-font":
        replacement = exact.replace('<text ', '<text font-size="0.000001" ')
    elif mutation == "background-fill":
        replacement = exact.replace('fill="#111111"', 'fill="#f8f7f3"')
    elif mutation == "ancestor-opacity":
        replacement = f'<g opacity="0.000001">{exact}</g>'
    else:
        replacement = exact
    assert exact in content
    content = content.replace(exact, replacement, 1)
    if mutation == "occlusion":
        content = content.replace(
            "</svg>",
            '<rect x="0" y="0" width="1600" height="900" fill="#f8f7f3"/></svg>',
        )
    elif mutation == "duplicate-aria":
        content = content.replace(
            '<rect x="0"',
            '<g><title id="figure-title">duplicate</title>'
            '<desc id="figure-description">duplicate</desc></g><rect x="0"',
            1,
        )
    elif mutation == "duplicate-required":
        duplicate = (
            f'<text x="40" y="110" fill="#111111" '
            f'font-family="{release_module.FIGURE_FONT_FAMILY}">'
            f'{html.escape(entry["doi"])}</text>'
        )
        background = (
            f'<rect x="0" y="0" width="{entry["width"]}" '
            f'height="{entry["height"]}" fill="#f8f7f3"/>'
        )
        content = content.replace(background, f'{background}{duplicate}', 1)
    elif mutation == "alternate-caption-duplicate":
        words = " ".join(entry["caption"].split()).split()
        split_at = len(words) // 2
        duplicate = "".join((
            f'<text x="40" y="400" fill="#111111" '
            f'font-family="{release_module.FIGURE_FONT_FAMILY}">'
            f'{html.escape(" ".join(words[:split_at]))}</text>',
            f'<text x="40" y="424" fill="#111111" '
            f'font-family="{release_module.FIGURE_FONT_FAMILY}">'
            f'{html.escape(" ".join(words[split_at:]))}</text>',
        ))
        background = (
            f'<rect x="0" y="0" width="{entry["width"]}" '
            f'height="{entry["height"]}" fill="#f8f7f3"/>'
        )
        content = content.replace(background, f'{background}{duplicate}', 1)
    figure.write_text(content)
    entry["sha256"], entry["bytes"] = _identity(figure)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    signoff_path = staging / "EDITORIAL-SIGNOFF.json"
    signoff = json.loads(signoff_path.read_text())
    signoff["reviewed_artifact_root_sha256"] = release_module._reviewed_artifact_root({
        path.relative_to(staging).as_posix(): path
        for path in staging.rglob("*") if path.is_file()
    })
    signoff_path.write_text(json.dumps(signoff, sort_keys=True, indent=2) + "\n")
    with pytest.raises(
        ValueError,
        match="visible|exact|transform|canvas|accessibility|ARIA|layer|positions",
    ):
        release_module.finalize_release(staging_directory=staging)


def test_svg_required_text_accepts_only_a_sane_font_size(release_module):
    item = {
        "width": 1600, "height": 900,
        "title": "Reviewed title", "description": "Useful reviewed description",
        "caption": "Reviewed aggregate caption with exact values and a limitation.",
        "source_label": "Reviewed source label", "doi": "10.5281/zenodo.1234567",
        "metric_ids": ["mx.present"],
        "denominator_metric_ids": ["population.analyzable"],
    }
    content = _svg_bytes(
        item["width"], item["height"], title=item["title"],
        description=item["description"], doi=item["doi"],
        source=item["source_label"], caption=item["caption"],
    ).replace(b'<text x="40" y="80"', b'<text font-size="10" x="40" y="80"')
    assert release_module._validate_svg(content, item) == (1600, 900)


@pytest.mark.parametrize("mutation", [None, "extra-rule", "changed-font", "external-url"])
def test_svg_embedded_font_declaration_is_exactly_pinned_and_inactive(
    release_module, mutation,
):
    item = {
        "width": 1600, "height": 900,
        "title": "Reviewed title", "description": "Useful reviewed description",
        "caption": "Reviewed aggregate caption with exact values and a limitation.",
        "source_label": "Reviewed source label", "doi": "10.5281/zenodo.1234567",
        "metric_ids": ["mx.present"],
        "denominator_metric_ids": ["population.analyzable"],
    }
    content = _svg_bytes(
        item["width"], item["height"], title=item["title"],
        description=item["description"], doi=item["doi"],
        source=item["source_label"], caption=item["caption"],
    ).decode()
    declaration = release_module._svg_font_face_declaration()
    encoded = base64.b64encode(Path("figures/fonts/DMSans-Variable.ttf").read_bytes()).decode()
    if mutation == "extra-rule":
        declaration += "text{opacity:0}"
    elif mutation == "changed-font":
        declaration = declaration.replace(encoded[20], "A" if encoded[20] != "A" else "B", 1)
    elif mutation == "external-url":
        declaration = "@import url('https://private.example/font.css');" + declaration
    content = content.replace(release_module._svg_font_face_declaration(), declaration, 1)
    if mutation is None:
        assert release_module._validate_svg(content.encode(), item) == (1600, 900)
    else:
        with pytest.raises(ValueError, match="font|style|inactive|allowlisted"):
            release_module._validate_svg(content.encode(), item)


def test_svg_realistic_long_caption_uses_exact_visible_multiline_layout(release_module):
    caption = (
        "MX-Eintrag vorhanden: 99,4 % (1328299/1336314) · SPF-Eintrag vorhanden: "
        "65,3 % (867831/1328299) · DKIM-Selector beobachtet: 42,1 % "
        "(559223/1328299) · DMARC-Eintrag erkannt: 49,7 % (660142/1328299). "
        "Passive DNS-Beobachtung; die DKIM-Kennzahl ist eine selectorabhängige "
        "Untergrenze. Messzeitraum: 2026-04-12T00:00:00Z–2026-04-12T23:59:59Z. "
        "Quelle: Snapshot der SWITCH-Zone .ch vom 12.04.2026. CC BY 4.0. "
        "DOI: 10.5281/zenodo.1234567."
    )
    item = {
        "width": 1600, "height": 900,
        "title": "Überblick E-Mail-Authentifizierung",
        "description": "Vier passive Beobachtungen mit den jeweils gültigen Nennern.",
        "caption": caption,
        "source_label": "Quelle: Snapshot der SWITCH-Zone .ch vom 12.04.2026.",
        "doi": "10.5281/zenodo.1234567", "metric_ids": ["mx.present"],
        "denominator_metric_ids": ["population.analyzable"],
    }
    assert len(release_module._svg_caption_lines(caption, 1600)) >= 3
    content = _svg_bytes(
        item["width"], item["height"], title=item["title"],
        description=item["description"], doi=item["doi"],
        source=item["source_label"], caption=item["caption"],
    )
    assert release_module._validate_svg(content, item) == (1600, 900)


def test_editorial_signoff_cannot_be_mutated_or_freely_recomputed(
    tmp_path, release_module,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    signoff_path = staging / "EDITORIAL-SIGNOFF.json"
    signoff = json.loads(signoff_path.read_text())
    signoff["signoffs"]["fr"]["reviewer_name"] = "Mallory Smith"
    signoff["reviewed_artifact_root_sha256"] = release_module._reviewed_artifact_root({
        path.relative_to(staging).as_posix(): path
        for path in staging.rglob("*") if path.is_file()
    })
    signoff_path.write_text(json.dumps(signoff, sort_keys=True, indent=2) + "\n")
    with pytest.raises(ValueError, match="editorial signoff signature"):
        release_module.finalize_release(staging_directory=staging)


def test_editorial_root_is_prospective_and_stable_after_sealing(
    tmp_path, release_module,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    signoff = json.loads((staging / "EDITORIAL-SIGNOFF.json").read_text())
    assert signoff["reviewed_scope"] == release_module.EDITORIAL_REVIEW_SCOPE
    final = release_module.finalize_release(staging_directory=staging)
    sealed_files = {
        path.relative_to(final).as_posix(): path
        for path in final.rglob("*") if path.is_file()
    }
    assert release_module._reviewed_artifact_root(sealed_files) == signoff["reviewed_artifact_root_sha256"]


@pytest.mark.parametrize("target", ["doi", "editorial"])
def test_postseal_verifier_rechecks_doi_and_editorial_signatures(
    tmp_path, release_module, target,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    final = release_module.finalize_release(staging_directory=staging)
    for path in [final, *final.rglob("*")]:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    target_path = final / (
        "doi-reservation.json" if target == "doi" else "EDITORIAL-SIGNOFF.json"
    )
    target_payload = json.loads(target_path.read_text())
    target_payload["external_verification"]["signature_base64"] = base64.b64encode(b"x" * 64).decode()
    target_path.write_text(json.dumps(target_payload, sort_keys=True, separators=(",", ":")) + "\n")
    if target == "editorial":
        release_path = final / "release.json"
        release = json.loads(release_path.read_text())
        entry = next(
            item for item in release["inventory"]
            if item["name"] == "EDITORIAL-SIGNOFF.json"
        )
        entry["sha256"], entry["bytes"] = _identity(target_path)
        release_path.write_text(json.dumps(release, sort_keys=True, separators=(",", ":")) + "\n")
    checksum = final / "checksums.sha256"
    names = sorted(
        path.relative_to(final).as_posix() for path in final.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    )
    checksum.write_text("\n".join(
        f"{_identity(final / name)[0]}  {name}" for name in names
    ) + "\n")
    with pytest.raises(ValueError, match="DOI approval signature|editorial signoff signature"):
        release_module._verify_checksums(final)


def test_postseal_verifier_rejects_recomputed_inventory_envelope(
    tmp_path, release_module,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    final = release_module.finalize_release(staging_directory=staging)
    for path in [final, *final.rglob("*")]:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    release_path = final / "release.json"
    release = json.loads(release_path.read_text())
    release["inventory"][0]["media_type"] = "application/octet-stream"
    release_path.write_text(json.dumps(release, sort_keys=True, separators=(",", ":")) + "\n")
    names = sorted(
        path.relative_to(final).as_posix() for path in final.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    )
    (final / "checksums.sha256").write_text("\n".join(
        f"{_identity(final / name)[0]}  {name}" for name in names
    ) + "\n")
    with pytest.raises(ValueError, match="inventory"):
        release_module._verify_checksums(final)


def test_signoff_signature_binds_every_reviewed_byte(tmp_path, release_module):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    _complete_staging(staging, release_module)
    readme = staging / "README.md"
    readme.write_text(readme.read_text() + "\nReviewed clarification without private identifiers.\n")
    signoff_path = staging / "EDITORIAL-SIGNOFF.json"
    signoff = json.loads(signoff_path.read_text())
    signoff["reviewed_artifact_root_sha256"] = release_module._reviewed_artifact_root({
        path.relative_to(staging).as_posix(): path
        for path in staging.rglob("*") if path.is_file()
    })
    signoff_path.write_text(json.dumps(signoff, sort_keys=True, indent=2) + "\n")
    with pytest.raises(ValueError, match="editorial signoff signature"):
        release_module.finalize_release(staging_directory=staging)


def test_localized_figure_copy_uses_human_labels_native_caveats_and_exact_values(
    tmp_path, release_module,
):
    staging, _database, _manifests = _stage(tmp_path, release_module)
    release = json.loads((staging / "release.json").read_text())
    metrics = release_module._metric_objects(json.loads((staging / "metrics.json").read_text()))
    native_markers = {
        "de": "beobacht", "fr": "observ", "it": "osserv",
    }
    for chart_id, specification in release_module.FIGURE_SPECS.items():
        for locale in release_module.FIGURE_LOCALES:
            copy = release_module._approved_figure_copy(
                chart_id, locale, metrics, release, "10.5281/zenodo.1234567",
            )
            assert copy["description"] != copy["title"]
            assert native_markers[locale].casefold() in (
                copy["description"] + " " + copy["caption"]
            ).casefold()
            assert "%" in copy["caption"]
            assert all(metric_id not in copy["caption"] for metric_id in specification["metric_ids"])
            for metric_id in specification["metric_ids"]:
                metric = next(item for item in metrics if item.metric_id == metric_id)
                assert str(metric.numerator) in copy["caption"]
                assert str(metric.denominator) in copy["caption"]
            if chart_id == "social-report-card":
                assert len(copy["caption"]) < 700


def test_installed_wheel_contains_and_loads_locale_catalogues(tmp_path):
    """Build a minimal wheel from the declared setuptools package catalogue."""
    repository = Path(__file__).resolve().parents[1]
    configuration = tomllib.loads((repository / "pyproject.toml").read_text())
    setuptools_configuration = configuration["tool"]["setuptools"]
    package_data = setuptools_configuration["package-data"]
    assert "locales/*.json" in package_data["release"]

    wheel_root = tmp_path / "wheel-root"
    wheel_root.mkdir()
    included: list[tuple[str, bytes]] = []
    for package in setuptools_configuration["packages"]:
        package_root = repository / package
        for source in sorted(package_root.glob("*.py")):
            included.append((source.relative_to(repository).as_posix(), source.read_bytes()))
        for pattern in package_data.get(package, []):
            for source in sorted(package_root.glob(pattern)):
                if source.is_file():
                    included.append((source.relative_to(repository).as_posix(), source.read_bytes()))

    dist_info = "swiss_email_security_report-0.0.0.dist-info"
    included.extend((
        (f"{dist_info}/METADATA", (
            "Metadata-Version: 2.1\nName: swiss-email-security-report\n"
            "Version: 0.0.0\nRequires-Python: >=3.12\n\n"
        ).encode()),
        (f"{dist_info}/WHEEL", (
            "Wheel-Version: 1.0\nGenerator: release-package-regression\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n\n"
        ).encode()),
    ))
    record_rows = []
    for name, content in included:
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        record_rows.append(f"{name},sha256={digest},{len(content)}")
    record_rows.append(f"{dist_info}/RECORD,,")
    included.append((f"{dist_info}/RECORD", ("\n".join(record_rows) + "\n").encode()))

    wheel = tmp_path / "swiss_email_security_report-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in included:
            archive.writestr(name, content)
    installed = tmp_path / "installed"
    subprocess.run([
        sys.executable, "-m", "pip", "install", "--quiet", "--no-deps",
        "--no-compile", "--target", str(installed), str(wheel),
    ], check=True, cwd=tmp_path, capture_output=True, text=True)
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    result = subprocess.run([
        sys.executable, "-c",
        "import pathlib,sys; sys.path.insert(0, sys.argv[1]); "
        "import release.build_release as bundle; "
        "assert pathlib.Path(bundle.__file__).is_relative_to(pathlib.Path(sys.argv[1])); "
        "print(bundle._locale_payload('fr')['labels']['mx.present'])",
        str(installed),
    ], check=True, cwd=tmp_path, env=environment, capture_output=True, text=True)
    assert result.stdout.strip() == "Enregistrement MX non nul présent"
