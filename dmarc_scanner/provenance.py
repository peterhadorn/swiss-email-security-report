"""Reproducibility metadata for private scanner outputs."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile


SCANNER_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")


def normalized_input(lines) -> bytes:
    """Normalize scanner input exactly as the CLI does, without blank lines."""
    domains = []
    for line in lines:
        domain = str(line).strip().rstrip(".")
        if domain:
            domains.append(domain)
    return ("\n".join(domains) + ("\n" if domains else "")).encode("utf-8")


def manifest_path_for(output_path) -> Path:
    output = Path(output_path)
    return output.with_name(f"{output.name}.manifest.json")


def scanner_git_provenance() -> tuple[str, bool]:
    """Return the scanner repository's exact revision and dirty state.

    Provenance must never silently refer to a caller's unrelated repository.
    A missing or malformed revision aborts manifest creation instead of using a
    placeholder that cannot be independently verified.
    """
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=SCANNER_REPOSITORY_ROOT,
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
        dirty = bool(subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=SCANNER_REPOSITORY_ROOT,
            text=True, stderr=subprocess.DEVNULL,
        ).strip())
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("scanner Git SHA-1 is unavailable") from exc
    if not _GIT_SHA1.fullmatch(revision):
        raise RuntimeError("scanner Git SHA-1 is unavailable or invalid")
    return revision, dirty


def scanner_git_revision() -> str:
    """Compatibility accessor for the validated scanner repository revision."""
    return scanner_git_provenance()[0]


def _sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as output:
        for chunk in iter(lambda: output.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("scan timestamps must be timezone-aware UTC values")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def write_scan_manifest(
    output_path,
    *,
    source_input_lines,
    effective_input_lines,
    scanner_git_revision: str,
    scanner_git_dirty: bool,
    resolver_configuration: dict,
    started_at: datetime,
    finished_at: datetime,
    concurrency: int,
    batch_pool_size: int,
    retry_resume_mode: str,
    limit: int | None,
    shuffle: bool,
    shuffle_seed: int | None,
) -> Path:
    """Atomically write a sidecar after the SQLite connection is closed."""
    output = Path(output_path)
    if not _GIT_SHA1.fullmatch(scanner_git_revision):
        raise RuntimeError("scanner Git SHA-1 is unavailable or invalid")
    source_normalized = normalized_input(source_input_lines)
    effective_normalized = normalized_input(effective_input_lines)
    output_sha256, output_size = _sha256_and_size(output)
    manifest = {
        # These aliases preserve manifest-reader compatibility; canonical
        # fields below distinguish source population from transformed input.
        "normalized_input_sha256": hashlib.sha256(source_normalized).hexdigest(),
        "normalized_input_line_count": source_normalized.count(b"\n"),
        "source_input_normalized_sha256": hashlib.sha256(source_normalized).hexdigest(),
        "source_input_normalized_line_count": source_normalized.count(b"\n"),
        "effective_input_normalized_sha256": hashlib.sha256(effective_normalized).hexdigest(),
        "effective_input_normalized_line_count": effective_normalized.count(b"\n"),
        "scanner_git_revision": scanner_git_revision,
        "scanner_git_dirty": scanner_git_dirty,
        "resolver_configuration": resolver_configuration,
        "started_at_utc": _utc_timestamp(started_at),
        "finished_at_utc": _utc_timestamp(finished_at),
        "concurrency": concurrency,
        "batch_pool_size": batch_pool_size,
        "retry_resume_mode": retry_resume_mode,
        "limit": limit,
        "shuffle": shuffle,
        "shuffle_seed": shuffle_seed,
        "effective_input_order": (
            "seeded_shuffle_then_limit" if shuffle else "source_order_then_limit"
        ),
        "python_version": platform.python_version(),
        "output_sqlite_sha256": output_sha256,
        "output_sqlite_size_bytes": output_size,
    }
    destination = manifest_path_for(output)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as manifest_file:
            json.dump(manifest, manifest_file, sort_keys=True, indent=2)
            manifest_file.write("\n")
            manifest_file.flush()
            os.fsync(manifest_file.fileno())
        os.replace(temporary, destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination
