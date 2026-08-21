"""Durable, privacy-preserving provenance for private scanner outputs.

Manifest version 2 describes one database mutation. A resume may start only
after the exact prior sidecar and database identity have been validated and
the sidecar bytes durably archived. Manifests contain aggregate accounting
and digests only; raw domain names never leave private inputs/databases.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import random
import sqlite3
import stat
import subprocess
import tempfile
from types import MappingProxyType
from typing import Any, Iterable, Mapping


SCANNER_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PYTHON_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[A-Za-z0-9.+-]*)?$")

MANIFEST_SCHEMA_VERSION = 2
FRESH_MODE = "fresh"
RESUME_MODE = "resume_retry_partial_errors"
MEASUREMENT_CORE_ALGORITHM = "sha256-length-prefixed-path-and-content-v1"
MEASUREMENT_CORE_FILES = (
    "dmarc_scanner/db.py",
    "dmarc_scanner/models.py",
    "dmarc_scanner/parsers.py",
    "dmarc_scanner/providers.py",
    "dmarc_scanner/resolve.py",
    "dmarc_scanner/scan.py",
)

# The active full pass started before v2 existed. Its v1 sidecar cannot carry
# a core digest, so only this explicit clean revision -> framed-core
# attestation may anchor a release-eligible v2 retry chain.
ACTIVE_V1_ROOT_REVISION = "48eba50b7b2e50d9c16abf4a7807a3ff4d693611"
V1_ROOT_CORE_ATTESTATIONS: dict[str, str] = {
    ACTIVE_V1_ROOT_REVISION: "c464dbd2e1698685d95b8b45390b8e863abf0e1dc8bb3e86de56411d17fa0486",
}

URI_SAFETY_TRANSITION_ID = "5ff4b49ac61ed6b1e3c5246748a8657681359ce7c457530d751b4e295031171f"
URI_SAFETY_CORE_TRANSITION: dict[str, Any] = {
    "attestation_id": URI_SAFETY_TRANSITION_ID,
    "from_measurement_core_sha256": "c464dbd2e1698685d95b8b45390b8e863abf0e1dc8bb3e86de56411d17fa0486",
    "to_measurement_core_sha256": "ffcef30fd2b9c82b59d44af43ac9c3052196199bdff6f3be6ffef78b700b4a18",
    "changed_file": "dmarc_scanner/db.py",
    "old_file_sha256": "8e93ca54f9460ed29d05d6387f3c6b1a1fe57eb57cd660642f46de1d9f934cec",
    "new_file_sha256": "2a40ee7fb6ffc7ef313364fce1bba4f4f156165e51353931c51499be9634e031",
    "reason": "read-only SQLite URI safety fix in validate_output_path only",
}
_UNCHANGED_TRANSITION_FILE_SHA256 = {
    "dmarc_scanner/models.py": "cc8647e7c379a87d254a95b0355863c1c5d064c24a8bf373df7ce1faa58fee53",
    "dmarc_scanner/parsers.py": "152c0f90d7cbd6481bd58643c789ec0d4ffac330a6ca8bf8514d55bb797d60a4",
    "dmarc_scanner/providers.py": "2b5843e060c66da1d795dad8a4da1b6cf3ef038e4032c321c9df66bf7e6d741f",
    "dmarc_scanner/resolve.py": "370e08dd87b7cf500bacca05bdaa309aa9556fdd04c14d3aa89843eb200d1b0f",
    "dmarc_scanner/scan.py": "570d3196cfd4c021bebc257c10716f7089201329bce90d500a43cd1e5f3c243f",
}


def normalized_input(lines: Iterable[object]) -> bytes:
    """Normalize input exactly as the CLI does, omitting blank lines."""
    domains = []
    for line in lines:
        domain = str(line).strip().rstrip(".")
        if domain:
            domains.append(domain)
    return ("\n".join(domains) + ("\n" if domains else "")).encode("utf-8")


def normalized_input_digest(lines: Iterable[object]) -> tuple[str, int]:
    """Stream the normalized digest/count without retaining normalized bytes."""
    digest = hashlib.sha256()
    count = 0
    for line in lines:
        domain = str(line).strip().rstrip(".")
        if domain:
            digest.update(domain.encode("utf-8"))
            digest.update(b"\n")
            count += 1
    return digest.hexdigest(), count


def normalized_domain_list(
    lines: Iterable[object], *, require_nonempty: bool = True
) -> list[str]:
    """Return normalized domains, rejecting ambiguous release populations."""
    domains = []
    seen = set()
    for line in lines:
        domain = str(line).strip().rstrip(".")
        if not domain:
            continue
        if domain in seen:
            raise ValueError("normalized source domains must be unique")
        seen.add(domain)
        domains.append(domain)
    if require_nonempty and not domains:
        raise ValueError("source domain universe must be non-empty")
    return domains


def planned_domains_from_source(
    source_input_lines: Iterable[object],
    *,
    limit: int | None,
    shuffle: bool,
    shuffle_seed: int | None,
) -> list[str]:
    """Apply the one supported, exactly reproducible source transformation."""
    source = normalized_domain_list(source_input_lines)
    if limit is not None:
        _require_exact_int(limit, "limit")
    if type(shuffle) is not bool:
        raise ValueError("shuffle must be boolean")
    if shuffle:
        if shuffle_seed != 42:
            raise ValueError("shuffled scans require deterministic seed 42")
        planned = list(source)
        random.Random(42).shuffle(planned)
    else:
        if shuffle_seed is not None:
            raise ValueError("unshuffled runs cannot have a shuffle seed")
        planned = list(source)
    if limit is not None:
        planned = planned[:limit]
    return planned


def validate_planned_transformation(
    source_input_lines: Iterable[object],
    planned_input_lines: Iterable[object],
    *,
    limit: int | None,
    shuffle: bool,
    shuffle_seed: int | None,
) -> tuple[list[str], list[str]]:
    source = normalized_domain_list(source_input_lines)
    planned = normalized_domain_list(planned_input_lines, require_nonempty=False)
    expected = planned_domains_from_source(
        source, limit=limit, shuffle=shuffle, shuffle_seed=shuffle_seed
    )
    if planned != expected:
        raise ValueError("planned input is not the exact declared source transformation")
    return source, planned


def manifest_path_for(output_path: os.PathLike[str] | str) -> Path:
    output = Path(output_path)
    return output.with_name(f"{output.name}.manifest.json")


def manifest_archive_path_for(output_path: os.PathLike[str] | str) -> Path:
    output = Path(output_path)
    return output.with_name(f"{output.name}.run-manifests")


def scanner_git_provenance() -> tuple[str, bool]:
    """Return the scanner repository's exact revision and dirty state."""
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
    return scanner_git_provenance()[0]


def _sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _framed_measurement_core_digest(entries: Iterable[tuple[str, bytes]]) -> str:
    """Hash relative names and contents with unambiguous length framing."""
    digest = hashlib.sha256()
    digest.update(b"swiss-email-security-measurement-core\x00v1\x00")
    for relative_name, content in entries:
        name = relative_name.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def measurement_core_sha256(root: Path | None = None) -> str:
    repository_root = SCANNER_REPOSITORY_ROOT if root is None else Path(root)
    return _framed_measurement_core_digest(
        (name, (repository_root / name).read_bytes()) for name in MEASUREMENT_CORE_FILES
    )


def _validated_uri_safety_transition(
    from_core: str, to_core: str, value: object | None = None
) -> dict[str, Any]:
    """Validate the single attested, non-measurement v1→v2 core transition."""
    expected = dict(URI_SAFETY_CORE_TRANSITION)
    if value is not None and value != expected:
        raise ValueError("measurement-core transition attestation is not exact")
    if (
        from_core != expected["from_measurement_core_sha256"]
        or to_core != expected["to_measurement_core_sha256"]
    ):
        raise ValueError("measurement-core transition is not registered")
    db_path = SCANNER_REPOSITORY_ROOT / expected["changed_file"]
    db_bytes = db_path.read_bytes()
    if hashlib.sha256(db_bytes).hexdigest() != expected["new_file_sha256"]:
        raise ValueError("attested db.py transition target bytes changed")
    old_line = b'sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)'
    new_line = b"sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)"
    if db_bytes.count(new_line) != 1 or old_line in db_bytes:
        raise ValueError("attested validate_output_path URI change is not exact")
    reconstructed_old_bytes = db_bytes.replace(new_line, old_line, 1)
    if (
        hashlib.sha256(reconstructed_old_bytes).hexdigest()
        != expected["old_file_sha256"]
    ):
        raise ValueError("attested db.py differs by more than the exact URI construction")
    for relative_name, expected_sha in _UNCHANGED_TRANSITION_FILE_SHA256.items():
        actual_sha = hashlib.sha256(
            (SCANNER_REPOSITORY_ROOT / relative_name).read_bytes()
        ).hexdigest()
        if actual_sha != expected_sha:
            raise ValueError("a non-attested measurement-core file changed")
    if measurement_core_sha256() != to_core:
        raise ValueError("attested measurement-core transition target is not current")
    return expected


def _require_plain_regular_file(path: Path, description: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise RuntimeError(f"{description} is missing") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise RuntimeError(f"{description} must be a regular non-symlink file")


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_private_archive_directory(output: Path) -> Path:
    directory = manifest_archive_path_for(output)
    if directory.exists() or directory.is_symlink():
        mode = directory.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise RuntimeError("manifest archive must be a regular non-symlink directory")
        if stat.S_IMODE(mode) != 0o700:
            raise RuntimeError("manifest archive permissions are unsafe")
    else:
        directory.mkdir(mode=0o700)
        _fsync_directory(directory.parent)
    return directory


def _immutable_manifest_copy(output: Path, payload: bytes) -> str:
    """Durably archive exact manifest bytes under their SHA-256 identity."""
    digest = hashlib.sha256(payload).hexdigest()
    directory = _ensure_private_archive_directory(output)
    target = directory / f"{digest}.json"
    if target.exists() or target.is_symlink():
        _require_plain_regular_file(target, "immutable manifest copy")
        if target.read_bytes() != payload:
            raise RuntimeError("immutable manifest collision or tampering detected")
        if stat.S_IMODE(target.stat().st_mode) != 0o600:
            raise RuntimeError("immutable manifest copy has unsafe permissions")
        return digest

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{digest}.", suffix=".tmp", dir=directory
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as temporary_file:
            temporary_file.write(payload)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        try:
            # A hard link publishes the already-fsynced temp inode with
            # O_EXCL-like collision behavior; unlike os.replace(), it can
            # never overwrite a concurrently created immutable identity.
            os.link(temporary, target)
        except FileExistsError:  # race protection
            _require_plain_regular_file(target, "immutable manifest copy")
            if target.read_bytes() != payload:
                raise RuntimeError("immutable manifest collision or tampering detected")
            if stat.S_IMODE(target.stat().st_mode) != 0o600:
                raise RuntimeError("immutable manifest copy has unsafe permissions")
        temporary.unlink()
        _fsync_directory(directory)
    finally:
        if temporary.exists():
            temporary.unlink()
    return digest


def _atomic_write_private(destination: Path, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as destination_file:
            destination_file.write(payload)
            destination_file.flush()
            os.fsync(destination_file.fileno())
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _require_exact_int(value: object, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def _require_sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256")
    return value


def _require_git_sha1(value: object, name: str) -> str:
    if not isinstance(value, str) or not _GIT_SHA1.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase Git SHA-1")
    return value


def _require_exact_keys(value: object, keys: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{name} has missing or unsupported fields")
    return value


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("scan timestamps must be timezone-aware values")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc_timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{name} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{name} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{name} must be UTC")
    return parsed


def _validate_resolver_configuration(value: object) -> Mapping[str, Any]:
    resolver = _require_exact_keys(value, {
        "nameservers", "rotate", "timeout_seconds", "lifetime_seconds",
        "cache_policy", "dnspython_version",
    }, "resolver_configuration")
    nameservers = resolver["nameservers"]
    if not isinstance(nameservers, list) or not nameservers or any(
        not isinstance(item, str) for item in nameservers
    ):
        raise ValueError("resolver nameservers must be a non-empty string list")
    try:
        for item in nameservers:
            ipaddress.ip_address(item)
    except ValueError as exc:
        raise ValueError("resolver nameservers must be IP addresses") from exc
    if type(resolver["rotate"]) is not bool:
        raise ValueError("resolver rotate must be boolean")
    for field in ("timeout_seconds", "lifetime_seconds"):
        number = resolver[field]
        if (
            type(number) not in (int, float)
            or isinstance(number, bool)
            or not math.isfinite(number)
            or number <= 0
        ):
            raise ValueError(f"resolver {field} must be positive")
    if resolver["cache_policy"] != "disabled":
        raise ValueError("resolver cache policy must be disabled")
    if not isinstance(resolver["dnspython_version"], str) or not resolver["dnspython_version"]:
        raise ValueError("dnspython version must be non-empty")
    return resolver


def _resolver_configuration_identity(value: object) -> dict[str, Any]:
    """Return a deeply immutable-comparable resolver identity."""
    resolver = dict(_validate_resolver_configuration(value))
    resolver["nameservers"] = tuple(resolver["nameservers"])
    return resolver


@dataclass(frozen=True)
class DatabaseAccounting:
    total_rows: int
    analyzable_rows: int
    error_rows: int

    def __post_init__(self) -> None:
        for name, value in (
            ("total_rows", self.total_rows),
            ("analyzable_rows", self.analyzable_rows),
            ("error_rows", self.error_rows),
        ):
            _require_exact_int(value, name)
        if self.total_rows != self.analyzable_rows + self.error_rows:
            raise ValueError("database accounting must partition total rows")

    def as_dict(self) -> dict[str, int]:
        return {
            "total_rows": self.total_rows,
            "analyzable_rows": self.analyzable_rows,
            "error_rows": self.error_rows,
        }


@dataclass(frozen=True)
class RunSummary:
    """Actual, domain-free accounting returned by :func:`dmarc_scan.run`."""

    mode: str
    planned_input_count: int
    planned_excluded_count: int
    attempted_input_sha256: str
    attempted_input_count: int
    pre_database: DatabaseAccounting
    post_database: DatabaseAccounting
    rows_written: int

    def __post_init__(self) -> None:
        if self.mode not in (FRESH_MODE, RESUME_MODE):
            raise ValueError("unsupported run mode")
        for name, value in (
            ("planned_input_count", self.planned_input_count),
            ("planned_excluded_count", self.planned_excluded_count),
            ("attempted_input_count", self.attempted_input_count),
            ("rows_written", self.rows_written),
        ):
            _require_exact_int(value, name)
        _require_sha256(self.attempted_input_sha256, "attempted_input_sha256")
        if not isinstance(self.pre_database, DatabaseAccounting):
            raise ValueError("pre_database must be DatabaseAccounting")
        if not isinstance(self.post_database, DatabaseAccounting):
            raise ValueError("post_database must be DatabaseAccounting")
        if self.rows_written != self.attempted_input_count:
            raise ValueError("rows_written must equal attempted input count")
        if self.planned_excluded_count + self.attempted_input_count != self.planned_input_count:
            raise ValueError("excluded plus attempted must equal planned input")
        if not (
            self.pre_database.total_rows <= self.post_database.total_rows
            <= self.pre_database.total_rows + self.attempted_input_count
        ):
            raise ValueError("post total is inconsistent with attempted rows")
        if self.attempted_input_count == 0 and self.post_database != self.pre_database:
            raise ValueError("zero-attempt run must not change database accounting")
        if self.mode == FRESH_MODE:
            if self.pre_database != DatabaseAccounting(0, 0, 0):
                raise ValueError("fresh run must have zero pre-scan accounting")
            if self.planned_excluded_count != 0:
                raise ValueError("fresh run cannot exclude planned rows")
            if self.planned_input_count != self.attempted_input_count:
                raise ValueError("fresh run must attempt all planned rows")
            if self.post_database.total_rows != self.attempted_input_count:
                raise ValueError("fresh run must persist one row per attempt")
        else:
            if self.planned_input_count != self.pre_database.total_rows:
                raise ValueError("retry plan must equal the complete pre-scan total")
            if self.attempted_input_count != self.pre_database.error_rows:
                raise ValueError("retry must attempt every retained error row")
            if self.planned_excluded_count != self.pre_database.analyzable_rows:
                raise ValueError("retry must exclude every analyzable pre-scan row")
            if self.post_database.total_rows != self.pre_database.total_rows:
                raise ValueError("retry must preserve the database row total")
            if self.post_database.error_rows > self.pre_database.error_rows:
                raise ValueError("retry error count cannot increase")


@dataclass(frozen=True)
class PreparedResume:
    previous_run_manifest_sha256: str
    input_sqlite_sha256: str
    input_sqlite_size_bytes: int
    source_input_sha256: str
    source_input_count: int
    planned_input_sha256: str
    planned_input_count: int
    expected_attempted_input_sha256: str
    expected_attempted_input_count: int
    previous_finished_at_utc: str
    previous_measurement_core_sha256: str
    runtime_measurement_core_sha256: str
    measurement_core_transition: Mapping[str, Any] | None
    input_database: DatabaseAccounting
    resolver_configuration: Mapping[str, Any]
    concurrency: int
    batch_pool_size: int
    limit: int | None
    shuffle: bool
    shuffle_seed: int | None
    planned_input_order: str
    archive_directory_mode: int
    archive_manifest_mode: int
    root_attestation: Mapping[str, Any]
    root_release_eligible: bool

    def __post_init__(self) -> None:
        _require_sha256(self.previous_run_manifest_sha256, "previous manifest")
        _require_sha256(self.input_sqlite_sha256, "input SQLite")
        _require_exact_int(self.input_sqlite_size_bytes, "input SQLite size")
        _require_sha256(self.source_input_sha256, "source input")
        _require_exact_int(self.source_input_count, "source input count")
        _require_sha256(self.planned_input_sha256, "planned input")
        _require_exact_int(self.planned_input_count, "planned input count")
        _require_sha256(self.expected_attempted_input_sha256, "expected attempted input")
        _require_exact_int(self.expected_attempted_input_count, "expected attempted input count")
        _parse_utc_timestamp(self.previous_finished_at_utc, "previous finish")
        _require_sha256(self.previous_measurement_core_sha256, "previous measurement core")
        _require_sha256(self.runtime_measurement_core_sha256, "runtime measurement core")
        if not isinstance(self.input_database, DatabaseAccounting):
            raise ValueError("input_database must be DatabaseAccounting")
        resolver = _resolver_configuration_identity(self.resolver_configuration)
        object.__setattr__(self, "resolver_configuration", MappingProxyType(resolver))
        _require_exact_int(self.concurrency, "concurrency", minimum=1)
        _require_exact_int(self.batch_pool_size, "batch_pool_size", minimum=1)
        if self.limit is not None:
            _require_exact_int(self.limit, "limit")
        if type(self.shuffle) is not bool:
            raise ValueError("shuffle must be boolean")
        expected_order = (
            "seeded_shuffle_then_limit" if self.shuffle else "source_order_then_limit"
        )
        if self.planned_input_order != expected_order:
            raise ValueError("prepared input order is inconsistent")
        if self.shuffle and self.shuffle_seed != 42:
            raise ValueError("prepared shuffled input requires seed 42")
        if not self.shuffle and self.shuffle_seed is not None:
            raise ValueError("prepared unshuffled input cannot have a seed")
        if self.archive_directory_mode != 0o700 or self.archive_manifest_mode != 0o600:
            raise ValueError("prepared archive permissions are unsafe")
        root = dict(_validate_root_attestation(self.root_attestation))
        root_core = root["measurement_core_sha256"]
        if root_core != self.previous_measurement_core_sha256:
            _validated_uri_safety_transition(root_core, self.previous_measurement_core_sha256)
        if self.previous_measurement_core_sha256 == self.runtime_measurement_core_sha256:
            if self.measurement_core_transition is not None:
                raise ValueError("prepared resume repeats a measurement-core transition")
        else:
            if self.measurement_core_transition is None:
                raise ValueError("prepared resume is missing its measurement-core transition")
            transition = _validated_uri_safety_transition(
                self.previous_measurement_core_sha256,
                self.runtime_measurement_core_sha256,
                self.measurement_core_transition,
            )
            object.__setattr__(
                self, "measurement_core_transition", MappingProxyType(transition)
            )
        object.__setattr__(self, "root_attestation", MappingProxyType(root))
        if type(self.root_release_eligible) is not bool:
            raise ValueError("root release eligibility must be boolean")


# Compatibility for code written against the short-lived first v2 prototype.
ResumeLink = PreparedResume


def database_accounting(conn: sqlite3.Connection) -> DatabaseAccounting:
    """Count rows with the same partial-error rule as resume filtering."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(dmarc_scan_results)")}
    if not columns:
        return DatabaseAccounting(0, 0, 0)
    error_predicate = "error <> ''"
    if "query_statuses" in columns:
        error_predicate += " OR query_statuses LIKE '%\"error\"%'"
    total = conn.execute("SELECT COUNT(*) FROM dmarc_scan_results").fetchone()[0]
    errors = conn.execute(
        f"SELECT COUNT(*) FROM dmarc_scan_results WHERE {error_predicate}"
    ).fetchone()[0]
    return DatabaseAccounting(total, total - errors, errors)


def _database_accounting_read_only(path: Path) -> DatabaseAccounting:
    try:
        # The scanner has already checkpointed/closed the DB. ``immutable=1``
        # prevents a read-only verification from creating fresh -wal/-shm
        # companions after the output identity was hashed.
        conn = sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True
        )
    except sqlite3.Error as exc:
        raise RuntimeError("resume database cannot be inspected read-only") from exc
    try:
        return database_accounting(conn)
    finally:
        conn.close()


def _inspect_retry_database(
    path: Path, source_domains: list[str], planned_domains: list[str]
) -> tuple[DatabaseAccounting, str, int]:
    """Bind the exact retry subset without returning or recording raw names."""
    try:
        conn = sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True
        )
    except sqlite3.Error as exc:
        raise RuntimeError("resume database cannot be inspected read-only") from exc
    try:
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(dmarc_scan_results)")
        }
        if "domain" not in columns or "error" not in columns:
            raise RuntimeError("resume database schema cannot derive retry subset")
        error_predicate = "error <> ''"
        if "query_statuses" in columns:
            error_predicate += " OR query_statuses LIKE '%\"error\"%'"
        rows = conn.execute(
            f"SELECT domain, CASE WHEN {error_predicate} THEN 1 ELSE 0 END "
            "FROM dmarc_scan_results"
        ).fetchall()
    finally:
        conn.close()
    if len(rows) != len(source_domains):
        raise RuntimeError("resume database domain universe differs from source")
    error_by_domain = {domain: bool(is_error) for domain, is_error in rows}
    if set(error_by_domain) != set(source_domains):
        raise RuntimeError("resume database domain universe differs from source")
    error_count = sum(error_by_domain.values())
    accounting = DatabaseAccounting(len(rows), len(rows) - error_count, error_count)
    attempted = (domain for domain in planned_domains if error_by_domain[domain])
    attempted_sha, attempted_count = normalized_input_digest(attempted)
    if attempted_count != error_count:
        raise RuntimeError("retry plan does not cover every retained error row")
    return accounting, attempted_sha, attempted_count


def _validate_output_parent(output: Path) -> None:
    parent = output.parent
    try:
        mode = parent.lstat().st_mode
    except FileNotFoundError as exc:
        raise RuntimeError("output parent directory is missing") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise RuntimeError("output parent must be a regular non-symlink directory")


def _reject_sqlite_companions(output: Path) -> None:
    for suffix in ("-wal", "-shm"):
        companion = Path(f"{output}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise RuntimeError(
                f"SQLite companion {companion.name} exists; output is not checkpoint-clean"
            )


def validate_fresh_output_preflight(output_path: os.PathLike[str] | str) -> None:
    """Require an entirely new output identity for a destructive fresh scan."""
    output = Path(output_path)
    _validate_output_parent(output)
    _reject_sqlite_companions(output)
    for path, description in (
        (output, "fresh output database"),
        (manifest_path_for(output), "fresh output sidecar"),
        (manifest_archive_path_for(output), "fresh output manifest archive"),
    ):
        if path.exists() or path.is_symlink():
            raise RuntimeError(
                f"{description} already exists; choose a new --output path"
            )


def validate_resume_output_preflight(output_path: os.PathLike[str] | str) -> None:
    """Reject unsafe resume paths before hashing, archiving, or SQLite access."""
    output = Path(output_path)
    _validate_output_parent(output)
    _reject_sqlite_companions(output)
    _require_plain_regular_file(output, "resume database")
    sidecar = manifest_path_for(output)
    _require_plain_regular_file(sidecar, "resume manifest")
    if stat.S_IMODE(sidecar.stat().st_mode) != 0o600:
        raise RuntimeError("resume manifest has unsafe permissions")
    archive = manifest_archive_path_for(output)
    if archive.exists() or archive.is_symlink():
        mode = archive.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise RuntimeError("manifest archive must be a regular non-symlink directory")
        if stat.S_IMODE(mode) != 0o700:
            raise RuntimeError("manifest archive permissions are unsafe")


def validate_consumed_resume_preflight(output_path: os.PathLike[str] | str) -> None:
    """Validate state seen by run() after a PreparedResume is consumed."""
    output = Path(output_path)
    _validate_output_parent(output)
    _reject_sqlite_companions(output)
    _require_plain_regular_file(output, "resume database")
    sidecar = manifest_path_for(output)
    if sidecar.exists() or sidecar.is_symlink():
        raise RuntimeError("prepared resume sidecar was not consumed")
    archive = manifest_archive_path_for(output)
    mode = archive.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != 0o700:
        raise RuntimeError("prepared resume archive is unsafe")


def revalidate_consumed_prepared_resume(
    output_path: os.PathLike[str] | str,
    prepared: PreparedResume,
    *,
    planned_input_lines: Iterable[object],
    concurrency: int,
    resolver_configuration: Mapping[str, Any],
    batch_pool_size: int,
) -> None:
    """Recheck a consumed resume immediately before SQLite enables WAL.

    ``prepare_resume_manifest`` binds the active sidecar and database, while
    ``consume_prepared_resume_manifest`` removes that sidecar only after a
    second validation. This final read-only check closes the public API gap
    where callers could otherwise change the database or full plan between
    consume and :func:`dmarc_scan.run`.
    """
    if not isinstance(prepared, PreparedResume):
        raise ValueError("prepared must be PreparedResume")
    validate_consumed_resume_preflight(output_path)
    output = Path(output_path)
    planned_domains = normalized_domain_list(
        planned_input_lines, require_nonempty=False
    )
    planned_sha, planned_count = normalized_input_digest(planned_domains)
    if (planned_sha, planned_count) != (
        prepared.planned_input_sha256,
        prepared.planned_input_count,
    ):
        raise RuntimeError("consumed prepared resume plan changed before SQLite")
    _require_exact_int(concurrency, "concurrency", minimum=1)
    if concurrency != prepared.concurrency:
        raise RuntimeError("consumed prepared resume concurrency changed before SQLite")
    current_resolver = _resolver_configuration_identity(resolver_configuration)
    if current_resolver != dict(prepared.resolver_configuration):
        raise RuntimeError(
            "consumed prepared resume resolver configuration changed before SQLite"
        )
    _require_exact_int(batch_pool_size, "batch_pool_size", minimum=1)
    if batch_pool_size != prepared.batch_pool_size:
        raise RuntimeError(
            "consumed prepared resume batch pool size changed before SQLite"
        )
    if measurement_core_sha256() != prepared.runtime_measurement_core_sha256:
        raise RuntimeError(
            "consumed prepared resume measurement core changed before SQLite"
        )

    archive = manifest_archive_path_for(output)
    archived = archive / f"{prepared.previous_run_manifest_sha256}.json"
    _require_plain_regular_file(archived, "consumed prepared archived manifest")
    if (
        stat.S_IMODE(archive.lstat().st_mode) != prepared.archive_directory_mode
        or stat.S_IMODE(archived.lstat().st_mode) != prepared.archive_manifest_mode
    ):
        raise RuntimeError(
            "consumed prepared resume archive permissions changed before SQLite"
        )
    archived_payload = archived.read_bytes()
    if hashlib.sha256(archived_payload).hexdigest() != (
        prepared.previous_run_manifest_sha256
    ):
        raise RuntimeError("consumed prepared archived manifest changed before SQLite")

    identity_before = _sha256_and_size(output)
    accounting, expected_sha, expected_count = _inspect_retry_database(
        output, planned_domains, planned_domains
    )
    identity_after = _sha256_and_size(output)
    bound_identity = (
        prepared.input_sqlite_sha256,
        prepared.input_sqlite_size_bytes,
    )
    if identity_before != bound_identity or identity_after != bound_identity:
        raise RuntimeError("consumed prepared resume database bytes changed before SQLite")
    if accounting != prepared.input_database:
        raise RuntimeError(
            "consumed prepared resume database accounting changed before SQLite"
        )
    if (expected_sha, expected_count) != (
        prepared.expected_attempted_input_sha256,
        prepared.expected_attempted_input_count,
    ):
        raise RuntimeError("consumed prepared resume retry subset changed before SQLite")


_V1_KEYS = {
    "normalized_input_sha256", "normalized_input_line_count",
    "source_input_normalized_sha256", "source_input_normalized_line_count",
    "effective_input_normalized_sha256", "effective_input_normalized_line_count",
    "scanner_git_revision", "scanner_git_dirty", "resolver_configuration",
    "started_at_utc", "finished_at_utc", "concurrency", "batch_pool_size",
    "retry_resume_mode", "limit", "shuffle", "shuffle_seed",
    "effective_input_order", "python_version", "output_sqlite_sha256",
    "output_sqlite_size_bytes",
}
_ACCOUNTING_KEYS = {"total_rows", "analyzable_rows", "error_rows"}
_ROOT_ATTESTATION_KEYS = {
    "root_identifier_kind", "root_identifier", "manifest_schema_version",
    "scanner_git_revision", "measurement_core_sha256", "attestation_method",
}
_V2_KEYS = {
    "manifest_schema_version", "run_id", "previous_run_manifest_sha256",
    "input_sqlite_sha256", "input_sqlite_size_bytes", "output_sqlite_sha256",
    "output_sqlite_size_bytes", "source_input_normalized_sha256",
    "source_input_normalized_line_count", "planned_input_normalized_sha256",
    "planned_input_normalized_line_count", "attempted_input_normalized_sha256",
    "attempted_input_normalized_line_count", "planned_excluded_count",
    "rows_written", "database_pre", "database_post", "scanner_git_revision",
    "scanner_git_dirty", "resolver_configuration", "started_at_utc",
    "finished_at_utc", "concurrency", "batch_pool_size", "run_mode", "limit",
    "shuffle", "shuffle_seed", "planned_input_order", "python_version",
    "measurement_core_algorithm", "measurement_core_files",
    "measurement_core_sha256", "measurement_core_transition",
    "root_measurement_core_attestation",
    "release_eligible",
}


def _accounting_from_manifest(value: object, name: str) -> DatabaseAccounting:
    item = _require_exact_keys(value, _ACCOUNTING_KEYS, name)
    return DatabaseAccounting(
        _require_exact_int(item["total_rows"], f"{name}.total_rows"),
        _require_exact_int(item["analyzable_rows"], f"{name}.analyzable_rows"),
        _require_exact_int(item["error_rows"], f"{name}.error_rows"),
    )


def _validate_common_parameters(
    manifest: Mapping[str, Any], *, order_key: str
) -> tuple[datetime, datetime]:
    _require_git_sha1(manifest["scanner_git_revision"], "scanner_git_revision")
    if type(manifest["scanner_git_dirty"]) is not bool:
        raise ValueError("scanner_git_dirty must be boolean")
    _validate_resolver_configuration(manifest["resolver_configuration"])
    started = _parse_utc_timestamp(manifest["started_at_utc"], "started_at_utc")
    finished = _parse_utc_timestamp(manifest["finished_at_utc"], "finished_at_utc")
    if finished < started:
        raise ValueError("scan finish precedes scan start")
    _require_exact_int(manifest["concurrency"], "concurrency", minimum=1)
    _require_exact_int(manifest["batch_pool_size"], "batch_pool_size", minimum=1)
    if manifest["limit"] is not None:
        _require_exact_int(manifest["limit"], "limit")
    if type(manifest["shuffle"]) is not bool:
        raise ValueError("shuffle must be boolean")
    if manifest["shuffle"]:
        _require_exact_int(manifest["shuffle_seed"], "shuffle_seed")
        expected_order = "seeded_shuffle_then_limit"
    else:
        if manifest["shuffle_seed"] is not None:
            raise ValueError("unshuffled runs cannot have a shuffle seed")
        expected_order = "source_order_then_limit"
    if manifest[order_key] != expected_order:
        raise ValueError("input order metadata is inconsistent")
    if not isinstance(manifest["python_version"], str) or not _PYTHON_VERSION.fullmatch(
        manifest["python_version"]
    ):
        raise ValueError("python_version is invalid")
    return started, finished


def _root_attestation_for_v1(
    manifest: Mapping[str, Any], manifest_sha256: str
) -> dict[str, Any]:
    revision = manifest["scanner_git_revision"]
    try:
        core_digest = V1_ROOT_CORE_ATTESTATIONS[revision]
    except KeyError as exc:
        raise ValueError(
            "v1 root revision has no explicit measurement-core attestation"
        ) from exc
    _require_sha256(core_digest, "v1 root measurement core attestation")
    return {
        "root_identifier_kind": "manifest_sha256",
        "root_identifier": manifest_sha256,
        "manifest_schema_version": 1,
        "scanner_git_revision": revision,
        "measurement_core_sha256": core_digest,
        "attestation_method": "explicit_revision_to_measurement_core_v1",
    }


def _validate_root_attestation(value: object) -> Mapping[str, Any]:
    item = _require_exact_keys(value, _ROOT_ATTESTATION_KEYS, "root attestation")
    if item["root_identifier_kind"] not in ("manifest_sha256", "run_id"):
        raise ValueError("unsupported root identifier kind")
    _require_sha256(item["root_identifier"], "root identifier")
    root_schema = _require_exact_int(
        item["manifest_schema_version"], "root manifest schema", minimum=1
    )
    if root_schema not in (1, 2):
        raise ValueError("unsupported root manifest schema")
    _require_git_sha1(item["scanner_git_revision"], "root scanner revision")
    _require_sha256(item["measurement_core_sha256"], "root measurement core")
    expected_method = (
        "explicit_revision_to_measurement_core_v1"
        if root_schema == 1
        else "embedded_measurement_core_v2"
    )
    if item["attestation_method"] != expected_method:
        raise ValueError("root core attestation method is inconsistent")
    if root_schema == 1:
        if item["root_identifier_kind"] != "manifest_sha256":
            raise ValueError("v1 root must be identified by manifest SHA-256")
        expected = V1_ROOT_CORE_ATTESTATIONS.get(item["scanner_git_revision"])
        if expected != item["measurement_core_sha256"]:
            raise ValueError("v1 root core attestation is not registered")
    elif item["root_identifier_kind"] != "run_id":
        raise ValueError("v2 root must be identified by run ID")
    return item


def _run_identity(manifest: Mapping[str, Any]) -> str:
    """Derive a stable identity, normalizing a fresh root's self-reference."""
    identity = dict(manifest)
    identity.pop("run_id", None)
    root = identity.get("root_measurement_core_attestation")
    if identity.get("run_mode") == FRESH_MODE and isinstance(root, dict):
        root = dict(root)
        root["root_identifier"] = None
        identity["root_measurement_core_attestation"] = root
    payload = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(b"swiss-email-security-run-v2\x00" + payload).hexdigest()


def _validate_v1_root(
    manifest: object,
    manifest_sha256: str,
    *,
    actual_output_identity: tuple[str, int] | None,
    actual_accounting: DatabaseAccounting | None,
) -> dict[str, Any]:
    item = _require_exact_keys(manifest, _V1_KEYS, "v1 manifest")
    source_sha = _require_sha256(
        item["source_input_normalized_sha256"], "source input"
    )
    source_count = _require_exact_int(
        item["source_input_normalized_line_count"], "source count"
    )
    if source_count == 0:
        raise ValueError("source domain universe must be non-empty")
    normalized_alias_sha = _require_sha256(
        item["normalized_input_sha256"], "normalized input"
    )
    normalized_alias_count = _require_exact_int(
        item["normalized_input_line_count"], "normalized input count"
    )
    if normalized_alias_sha != source_sha or normalized_alias_count != source_count:
        raise ValueError("v1 normalized-input aliases disagree")
    effective_sha = _require_sha256(
        item["effective_input_normalized_sha256"], "effective input"
    )
    effective_count = _require_exact_int(
        item["effective_input_normalized_line_count"], "effective count"
    )
    if effective_count != source_count:
        raise ValueError("v1 root is not a full source-universe pass")
    _require_sha256(item["output_sqlite_sha256"], "v1 output SQLite")
    _require_exact_int(item["output_sqlite_size_bytes"], "v1 output SQLite size")
    _validate_common_parameters(item, order_key="effective_input_order")
    if not item["shuffle"] and effective_sha != source_sha:
        raise ValueError("unshuffled v1 effective input differs from its source")
    if item["retry_resume_mode"] != FRESH_MODE or item["limit"] is not None:
        raise ValueError("v1 root must be a no-limit fresh run")
    if item["scanner_git_dirty"]:
        raise ValueError("v1 release root must be from a clean checkout")
    if actual_output_identity is not None and actual_output_identity != (
        item["output_sqlite_sha256"], item["output_sqlite_size_bytes"]
    ):
        raise ValueError("v1 manifest does not match the resume database")
    if actual_accounting is not None and actual_accounting.total_rows != source_count:
        raise ValueError("v1 root database row count does not match source universe")
    attestation = _root_attestation_for_v1(item, manifest_sha256)
    return {
        "schema": 1,
        "source_sha256": source_sha,
        "source_count": source_count,
        "planned_sha256": effective_sha,
        "planned_count": effective_count,
        "output_sha256": item["output_sqlite_sha256"],
        "output_size": item["output_sqlite_size_bytes"],
        "started_at": item["started_at_utc"],
        "finished_at": item["finished_at_utc"],
        "measurement_core_sha256": attestation["measurement_core_sha256"],
        "root_attestation": attestation,
        "release_eligible": True,
        "resolver_configuration": dict(item["resolver_configuration"]),
        "concurrency": item["concurrency"],
        "batch_pool_size": item["batch_pool_size"],
        "limit": item["limit"],
        "shuffle": item["shuffle"],
        "shuffle_seed": item["shuffle_seed"],
        "planned_input_order": item["effective_input_order"],
    }


def _validate_v2(
    manifest: object,
    *,
    actual_output_identity: tuple[str, int] | None = None,
    actual_accounting: DatabaseAccounting | None = None,
) -> dict[str, Any]:
    item = _require_exact_keys(manifest, _V2_KEYS, "v2 manifest")
    if item["manifest_schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ValueError("unsupported manifest schema version")
    run_id = _require_sha256(item["run_id"], "run_id")
    if _run_identity(item) != run_id:
        raise ValueError("v2 run_id does not match canonical run identity")
    source_sha = _require_sha256(
        item["source_input_normalized_sha256"], "source input"
    )
    source_count = _require_exact_int(
        item["source_input_normalized_line_count"], "source count"
    )
    if source_count == 0:
        raise ValueError("source domain universe must be non-empty")
    _require_sha256(item["planned_input_normalized_sha256"], "planned input")
    planned_count = _require_exact_int(
        item["planned_input_normalized_line_count"], "planned count"
    )
    attempted_sha = _require_sha256(
        item["attempted_input_normalized_sha256"], "attempted input"
    )
    attempted_count = _require_exact_int(
        item["attempted_input_normalized_line_count"], "attempted count"
    )
    excluded_count = _require_exact_int(
        item["planned_excluded_count"], "planned excluded count"
    )
    rows_written = _require_exact_int(item["rows_written"], "rows written")
    pre = _accounting_from_manifest(item["database_pre"], "database_pre")
    post = _accounting_from_manifest(item["database_post"], "database_post")
    summary = RunSummary(
        item["run_mode"], planned_count, excluded_count, attempted_sha,
        attempted_count, pre, post, rows_written,
    )
    _require_sha256(item["output_sqlite_sha256"], "output SQLite")
    _require_exact_int(item["output_sqlite_size_bytes"], "output SQLite size")
    _validate_common_parameters(item, order_key="planned_input_order")
    if planned_count > source_count:
        raise ValueError("planned input cannot exceed source universe")
    expected_planned_count = (
        source_count if item["limit"] is None
        else min(source_count, item["limit"])
    )
    if planned_count != expected_planned_count:
        raise ValueError("planned input count is inconsistent with limit")
    if item["measurement_core_algorithm"] != MEASUREMENT_CORE_ALGORITHM:
        raise ValueError("unsupported measurement-core algorithm")
    if item["measurement_core_files"] != list(MEASUREMENT_CORE_FILES):
        raise ValueError("measurement-core file set is not canonical")
    core_sha = _require_sha256(item["measurement_core_sha256"], "measurement core")
    root = _validate_root_attestation(item["root_measurement_core_attestation"])
    transition = item["measurement_core_transition"]
    if transition is not None:
        transition = _validated_uri_safety_transition(
            root["measurement_core_sha256"], core_sha, transition
        )
    if type(item["release_eligible"]) is not bool:
        raise ValueError("release_eligible must be boolean")
    if actual_output_identity is not None and actual_output_identity != (
        item["output_sqlite_sha256"], item["output_sqlite_size_bytes"]
    ):
        raise ValueError("v2 manifest does not match the resume database")
    if actual_accounting is not None and actual_accounting != post:
        raise ValueError("v2 post accounting does not match the resume database")

    if summary.mode == FRESH_MODE:
        if transition is not None:
            raise ValueError("fresh root cannot contain a core transition")
        if item["previous_run_manifest_sha256"] is not None:
            raise ValueError("fresh manifest cannot link a previous run")
        if (
            item["input_sqlite_sha256"] is not None
            or item["input_sqlite_size_bytes"] is not None
        ):
            raise ValueError("fresh manifest cannot identify an input database")
        if root["manifest_schema_version"] != 2 or root["root_identifier"] != run_id:
            raise ValueError("fresh v2 root attestation does not identify this run")
        if (
            root["scanner_git_revision"] != item["scanner_git_revision"]
            or root["measurement_core_sha256"] != core_sha
        ):
            raise ValueError("fresh v2 root attestation disagrees with the run")
        expected_release = (
            item["limit"] is None
            and not item["scanner_git_dirty"]
            and planned_count == source_count
            and attempted_count == source_count
            and post.total_rows == source_count
        )
    else:
        _require_sha256(item["previous_run_manifest_sha256"], "previous manifest")
        _require_sha256(item["input_sqlite_sha256"], "input SQLite")
        _require_exact_int(item["input_sqlite_size_bytes"], "input SQLite size")
        if item["limit"] is not None or planned_count != source_count:
            raise ValueError("retry must plan the complete no-limit source universe")
        if pre.total_rows != source_count:
            raise ValueError("retry pre-scan rows must equal the source universe")
        if attempted_count != pre.error_rows:
            raise ValueError("retry must attempt every and only retained error row")
        if excluded_count != pre.analyzable_rows:
            raise ValueError("retry exclusions must equal pre-scan analyzable rows")
        if post.total_rows != pre.total_rows or post.error_rows > pre.error_rows:
            raise ValueError("retry post accounting cannot add rows or errors")
        core_is_allowed = core_sha == root["measurement_core_sha256"]
        if not core_is_allowed:
            _validated_uri_safety_transition(root["measurement_core_sha256"], core_sha)
            core_is_allowed = True
        expected_release = (
            item["limit"] is None
            and not item["scanner_git_dirty"]
            and source_count > 0
            and planned_count == source_count
            and core_is_allowed
            and pre.total_rows == source_count
            and post.total_rows == source_count
        )
    if item["release_eligible"] != expected_release:
        raise ValueError("release_eligible is inconsistent with manifest facts")
    return {
        "schema": 2,
        "source_sha256": source_sha,
        "source_count": source_count,
        "planned_sha256": item["planned_input_normalized_sha256"],
        "planned_count": planned_count,
        "output_sha256": item["output_sqlite_sha256"],
        "output_size": item["output_sqlite_size_bytes"],
        "input_sha256": item["input_sqlite_sha256"],
        "input_size": item["input_sqlite_size_bytes"],
        "started_at": item["started_at_utc"],
        "finished_at": item["finished_at_utc"],
        "measurement_core_sha256": core_sha,
        "measurement_core_transition": transition,
        "root_attestation": dict(root),
        "release_eligible": item["release_eligible"],
        "mode": summary.mode,
        "pre_database": pre,
        "post_database": post,
        "previous_manifest_sha256": item["previous_run_manifest_sha256"],
        "resolver_configuration": dict(item["resolver_configuration"]),
        "concurrency": item["concurrency"],
        "batch_pool_size": item["batch_pool_size"],
        "limit": item["limit"],
        "shuffle": item["shuffle"],
        "shuffle_seed": item["shuffle_seed"],
        "planned_input_order": item["planned_input_order"],
    }


def _load_manifest_bytes(payload: bytes, description: str) -> object:
    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{description} contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_nonfinite_constant(value):
        raise ValueError(f"{description} contains non-finite JSON constant {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{description} is not valid UTF-8 JSON") from exc


def _validate_archived_chain(
    output: Path,
    current_info: Mapping[str, Any],
) -> None:
    """Walk a v2 chain to its fresh v1/v2 root using archived exact bytes."""
    child_info = current_info
    seen: set[str] = set()
    archive = manifest_archive_path_for(output)
    if archive.exists() or archive.is_symlink():
        mode = archive.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ValueError("manifest archive is unsafe")
        if stat.S_IMODE(mode) != 0o700:
            raise ValueError("manifest archive permissions are unsafe")
    while child_info["schema"] == 2 and child_info["mode"] == RESUME_MODE:
        previous_sha = child_info["previous_manifest_sha256"]
        if previous_sha in seen:
            raise ValueError("manifest chain contains a cycle")
        seen.add(previous_sha)
        previous_path = archive / f"{previous_sha}.json"
        _require_plain_regular_file(previous_path, "previous immutable manifest")
        if stat.S_IMODE(previous_path.stat().st_mode) != 0o600:
            raise ValueError("previous immutable manifest permissions are unsafe")
        previous_payload = previous_path.read_bytes()
        if hashlib.sha256(previous_payload).hexdigest() != previous_sha:
            raise ValueError("previous immutable manifest filename/hash mismatch")
        previous_manifest = _load_manifest_bytes(
            previous_payload, "previous immutable manifest"
        )
        if (
            isinstance(previous_manifest, dict)
            and previous_manifest.get("manifest_schema_version") == 2
        ):
            previous_info = _validate_v2(previous_manifest)
        elif (
            isinstance(previous_manifest, dict)
            and "manifest_schema_version" not in previous_manifest
        ):
            previous_info = _validate_v1_root(
                previous_manifest, previous_sha,
                actual_output_identity=None, actual_accounting=None,
            )
        else:
            raise ValueError("unsupported previous manifest schema version")
        if (previous_info["output_sha256"], previous_info["output_size"]) != (
            child_info["input_sha256"], child_info["input_size"]
        ):
            raise ValueError("manifest chain database identities do not link")
        if (previous_info["source_sha256"], previous_info["source_count"]) != (
            child_info["source_sha256"], child_info["source_count"]
        ):
            raise ValueError("manifest chain source universe changed")
        for field in (
            "planned_sha256", "planned_count", "resolver_configuration",
            "concurrency", "batch_pool_size", "limit", "shuffle",
            "shuffle_seed", "planned_input_order",
        ):
            if previous_info[field] != child_info[field]:
                raise ValueError(f"manifest chain configuration changed: {field}")
        if previous_info["schema"] == 2 and (
            previous_info["post_database"] != child_info["pre_database"]
        ):
            raise ValueError("manifest chain pre/post accounting does not link")
        if _parse_utc_timestamp(
            child_info["started_at"], "child start"
        ) < _parse_utc_timestamp(previous_info["finished_at"], "previous finish"):
            raise ValueError("manifest chain run timestamps overlap")
        if previous_info["root_attestation"] != child_info["root_attestation"]:
            raise ValueError("manifest chain root attestation changed")
        if previous_info["measurement_core_sha256"] == child_info["measurement_core_sha256"]:
            if child_info["measurement_core_transition"] is not None:
                raise ValueError("measurement-core transition may occur only once")
        else:
            if previous_info["schema"] != 1:
                raise ValueError("measurement core changed after the first v2 retry")
            if child_info["measurement_core_transition"] is None:
                raise ValueError("v1→v2 measurement-core transition is missing")
            _validated_uri_safety_transition(
                previous_info["measurement_core_sha256"],
                child_info["measurement_core_sha256"],
                child_info["measurement_core_transition"],
            )
        child_info = previous_info

    if child_info["schema"] == 2 and child_info["mode"] != FRESH_MODE:
        raise ValueError("manifest chain does not end in a fresh root")
    if not child_info["release_eligible"]:
        raise ValueError("manifest chain root is not release eligible")


def prepare_resume_manifest(
    output_path: os.PathLike[str] | str,
    *,
    source_input_lines: Iterable[object],
    planned_input_lines: Iterable[object],
    resolver_configuration: Mapping[str, Any],
    concurrency: int,
    batch_pool_size: int,
    limit: int | None,
    shuffle: bool,
    shuffle_seed: int | None,
    started_at: datetime,
) -> PreparedResume:
    """Validate and durably archive the exact prior sidecar before mutation."""
    output = Path(output_path)
    sidecar = manifest_path_for(output)
    validate_resume_output_preflight(output)
    source_domains, planned_domains = validate_planned_transformation(
        source_input_lines,
        planned_input_lines,
        limit=limit,
        shuffle=shuffle,
        shuffle_seed=shuffle_seed,
    )
    source_input_sha256, source_input_count = normalized_input_digest(source_domains)
    planned_input_sha256, planned_input_count = normalized_input_digest(planned_domains)
    current_resolver = dict(_validate_resolver_configuration(resolver_configuration))
    _require_exact_int(concurrency, "concurrency", minimum=1)
    _require_exact_int(batch_pool_size, "batch_pool_size", minimum=1)
    current_started = _parse_utc_timestamp(_utc_timestamp(started_at), "current start")
    payload = sidecar.read_bytes()
    manifest_sha = hashlib.sha256(payload).hexdigest()
    actual_identity = _sha256_and_size(output)
    try:
        manifest = _load_manifest_bytes(payload, "resume manifest")
        actual_accounting, expected_attempted_sha, expected_attempted_count = (
            _inspect_retry_database(output, source_domains, planned_domains)
        )
        if (
            isinstance(manifest, dict)
            and manifest.get("manifest_schema_version") == 2
        ):
            info = _validate_v2(
                manifest,
                actual_output_identity=actual_identity,
                actual_accounting=actual_accounting,
            )
            _validate_archived_chain(output, info)
        elif isinstance(manifest, dict) and "manifest_schema_version" not in manifest:
            info = _validate_v1_root(
                manifest, manifest_sha,
                actual_output_identity=actual_identity,
                actual_accounting=actual_accounting,
            )
        else:
            raise ValueError("unsupported manifest schema version")
    except (ValueError, sqlite3.Error) as exc:
        raise RuntimeError(f"resume manifest validation failed: {exc}") from exc
    if (info["source_sha256"], info["source_count"]) != (
        source_input_sha256, source_input_count
    ):
        raise RuntimeError("resume source universe does not match prior manifest")
    if (info["planned_sha256"], info["planned_count"]) != (
        planned_input_sha256, planned_input_count
    ):
        raise RuntimeError("resume planned transformation does not match prior manifest")
    current_configuration = {
        "resolver_configuration": current_resolver,
        "concurrency": concurrency,
        "batch_pool_size": batch_pool_size,
        "limit": limit,
        "shuffle": shuffle,
        "shuffle_seed": shuffle_seed,
        "planned_input_order": (
            "seeded_shuffle_then_limit" if shuffle else "source_order_then_limit"
        ),
    }
    for field, value in current_configuration.items():
        if info[field] != value:
            raise RuntimeError(f"resume configuration differs from prior manifest: {field}")
    if limit is not None or planned_input_count != source_input_count:
        raise RuntimeError("resume retry requires the complete no-limit source universe")
    if actual_accounting.total_rows != source_input_count:
        raise RuntimeError("resume database rows do not equal the source universe")
    if current_started < _parse_utc_timestamp(info["finished_at"], "previous finish"):
        raise RuntimeError("resume run starts before the prior run finished")
    current_core = measurement_core_sha256()
    next_core_transition = None
    if info["measurement_core_sha256"] != current_core:
        if info["schema"] != 1:
            raise RuntimeError("resume measurement core changed after the first v2 retry")
        try:
            next_core_transition = _validated_uri_safety_transition(
                info["measurement_core_sha256"], current_core
            )
        except ValueError as exc:
            raise RuntimeError("resume measurement core differs from the root scan") from exc

    archived_sha = _immutable_manifest_copy(output, payload)
    if archived_sha != manifest_sha:
        raise RuntimeError("archived manifest identity changed")
    archive = manifest_archive_path_for(output)
    archived = archive / f"{manifest_sha}.json"
    return PreparedResume(
        previous_run_manifest_sha256=manifest_sha,
        input_sqlite_sha256=actual_identity[0],
        input_sqlite_size_bytes=actual_identity[1],
        source_input_sha256=info["source_sha256"],
        source_input_count=info["source_count"],
        planned_input_sha256=planned_input_sha256,
        planned_input_count=planned_input_count,
        expected_attempted_input_sha256=expected_attempted_sha,
        expected_attempted_input_count=expected_attempted_count,
        previous_finished_at_utc=info["finished_at"],
        previous_measurement_core_sha256=info["measurement_core_sha256"],
        runtime_measurement_core_sha256=current_core,
        measurement_core_transition=next_core_transition,
        input_database=actual_accounting,
        resolver_configuration=current_resolver,
        concurrency=concurrency,
        batch_pool_size=batch_pool_size,
        limit=limit,
        shuffle=shuffle,
        shuffle_seed=shuffle_seed,
        planned_input_order=current_configuration["planned_input_order"],
        archive_directory_mode=stat.S_IMODE(archive.stat().st_mode),
        archive_manifest_mode=stat.S_IMODE(archived.stat().st_mode),
        root_attestation=info["root_attestation"],
        root_release_eligible=info["release_eligible"],
    )


def consume_prepared_resume_manifest(
    output_path: os.PathLike[str] | str,
    prepared: PreparedResume,
    *,
    source_input_lines: Iterable[object],
    planned_input_lines: Iterable[object],
    resolver_configuration: Mapping[str, Any],
    concurrency: int,
    batch_pool_size: int,
    limit: int | None,
    shuffle: bool,
    shuffle_seed: int | None,
) -> None:
    """Revalidate every bound fact, then consume the sidecar before mutation."""
    if not isinstance(prepared, PreparedResume):
        raise ValueError("prepared must be PreparedResume")
    output = Path(output_path)
    validate_resume_output_preflight(output)
    sidecar = manifest_path_for(output)
    source_domains, planned_domains = validate_planned_transformation(
        source_input_lines, planned_input_lines, limit=limit, shuffle=shuffle,
        shuffle_seed=shuffle_seed,
    )
    source_sha, source_count = normalized_input_digest(source_domains)
    planned_sha, planned_count = normalized_input_digest(planned_domains)
    current_resolver = dict(_validate_resolver_configuration(resolver_configuration))
    _require_exact_int(concurrency, "concurrency", minimum=1)
    _require_exact_int(batch_pool_size, "batch_pool_size", minimum=1)
    if (source_sha, source_count) != (
        prepared.source_input_sha256, prepared.source_input_count
    ):
        raise RuntimeError("prepared resume source changed before mutation")
    if (planned_sha, planned_count) != (
        prepared.planned_input_sha256, prepared.planned_input_count
    ):
        raise RuntimeError("prepared resume plan changed before mutation")
    current_order = "seeded_shuffle_then_limit" if shuffle else "source_order_then_limit"
    if (
        _resolver_configuration_identity(current_resolver)
        != dict(prepared.resolver_configuration)
        or concurrency != prepared.concurrency
        or batch_pool_size != prepared.batch_pool_size
        or limit != prepared.limit
        or shuffle != prepared.shuffle
        or shuffle_seed != prepared.shuffle_seed
        or current_order != prepared.planned_input_order
    ):
        raise RuntimeError("prepared resume configuration changed before mutation")
    if measurement_core_sha256() != prepared.runtime_measurement_core_sha256:
        raise RuntimeError("prepared resume measurement core changed before mutation")

    current_identity = _sha256_and_size(output)
    current_accounting, expected_sha, expected_count = _inspect_retry_database(
        output, source_domains, planned_domains
    )
    if current_identity != (
        prepared.input_sqlite_sha256, prepared.input_sqlite_size_bytes
    ):
        raise RuntimeError("prepared resume database bytes changed before mutation")
    if current_accounting != prepared.input_database:
        raise RuntimeError("prepared resume database accounting changed before mutation")
    if (expected_sha, expected_count) != (
        prepared.expected_attempted_input_sha256,
        prepared.expected_attempted_input_count,
    ):
        raise RuntimeError("prepared resume retry subset changed before mutation")

    sidecar_payload = sidecar.read_bytes()
    if hashlib.sha256(sidecar_payload).hexdigest() != (
        prepared.previous_run_manifest_sha256
    ):
        raise RuntimeError("prepared resume manifest changed before mutation")
    archive = manifest_archive_path_for(output)
    archived = archive / f"{prepared.previous_run_manifest_sha256}.json"
    _require_plain_regular_file(archived, "prepared archived manifest")
    if (
        stat.S_IMODE(archive.stat().st_mode) != prepared.archive_directory_mode
        or stat.S_IMODE(archived.stat().st_mode) != prepared.archive_manifest_mode
    ):
        raise RuntimeError("prepared resume archive permissions changed before mutation")
    if archived.read_bytes() != sidecar_payload:
        raise RuntimeError("prepared archived manifest bytes changed before mutation")
    sidecar.unlink()
    _fsync_directory(sidecar.parent)


def write_scan_manifest(
    output_path: os.PathLike[str] | str,
    *,
    source_input_lines: Iterable[object],
    planned_input_lines: Iterable[object],
    run_summary: RunSummary,
    resume_link: PreparedResume | None,
    scanner_git_revision: str,
    scanner_git_dirty: bool,
    resolver_configuration: Mapping[str, Any],
    started_at: datetime,
    finished_at: datetime,
    concurrency: int,
    batch_pool_size: int,
    limit: int | None,
    shuffle: bool,
    shuffle_seed: int | None,
) -> Path:
    """Write a completed v2 sidecar and identical immutable copy durably."""
    output = Path(output_path)
    _require_plain_regular_file(output, "completed scan database")
    if not isinstance(run_summary, RunSummary):
        raise ValueError("run_summary must be an immutable RunSummary")
    revision = _require_git_sha1(scanner_git_revision, "scanner_git_revision")
    if type(scanner_git_dirty) is not bool:
        raise ValueError("scanner_git_dirty must be boolean")
    _validate_resolver_configuration(resolver_configuration)
    source_domains, planned_domains = validate_planned_transformation(
        source_input_lines, planned_input_lines, limit=limit, shuffle=shuffle,
        shuffle_seed=shuffle_seed,
    )
    source_sha, source_count = normalized_input_digest(source_domains)
    planned_sha, planned_count = normalized_input_digest(planned_domains)
    if planned_count != run_summary.planned_input_count:
        raise ValueError("planned input count does not match run summary")
    if run_summary.mode == FRESH_MODE:
        if resume_link is not None:
            raise ValueError("fresh manifest cannot have a resume link")
    elif not isinstance(resume_link, PreparedResume):
        raise ValueError("resume manifest requires a validated PreparedResume")
    if resume_link is not None and (source_sha, source_count) != (
        resume_link.source_input_sha256, resume_link.source_input_count
    ):
        raise ValueError("resume source universe changed after validation")
    if resume_link is not None and run_summary.pre_database != resume_link.input_database:
        raise ValueError("resume pre-scan accounting differs from validated input")
    if resume_link is not None and (
        run_summary.attempted_input_sha256,
        run_summary.attempted_input_count,
    ) != (
        resume_link.expected_attempted_input_sha256,
        resume_link.expected_attempted_input_count,
    ):
        raise ValueError("run summary does not match the prepared retry subset")

    started_text = _utc_timestamp(started_at)
    finished_text = _utc_timestamp(finished_at)
    started_value = _parse_utc_timestamp(started_text, "started_at_utc")
    finished_value = _parse_utc_timestamp(finished_text, "finished_at_utc")
    if finished_value < started_value:
        raise ValueError("scan finish precedes scan start")
    if resume_link is not None and started_value < _parse_utc_timestamp(
        resume_link.previous_finished_at_utc, "previous finish"
    ):
        raise ValueError("resume run overlaps previous run")
    _require_exact_int(concurrency, "concurrency", minimum=1)
    _require_exact_int(batch_pool_size, "batch_pool_size", minimum=1)
    if limit is not None:
        _require_exact_int(limit, "limit")
    if type(shuffle) is not bool:
        raise ValueError("shuffle must be boolean")
    if shuffle:
        if shuffle_seed != 42:
            raise ValueError("shuffled scans require deterministic seed 42")
        order = "seeded_shuffle_then_limit"
    else:
        if shuffle_seed is not None:
            raise ValueError("unshuffled runs cannot have a seed")
        order = "source_order_then_limit"

    core_sha = measurement_core_sha256()
    if resume_link is not None and core_sha != resume_link.runtime_measurement_core_sha256:
        raise ValueError("measurement core changed since resume preparation")
    if resume_link is not None and (
        _resolver_configuration_identity(resolver_configuration)
        != dict(resume_link.resolver_configuration)
        or concurrency != resume_link.concurrency
        or batch_pool_size != resume_link.batch_pool_size
        or limit != resume_link.limit
        or shuffle != resume_link.shuffle
        or shuffle_seed != resume_link.shuffle_seed
        or order != resume_link.planned_input_order
        or (planned_sha, planned_count) != (
            resume_link.planned_input_sha256, resume_link.planned_input_count
        )
    ):
        raise ValueError("resume configuration changed after preparation")
    if resume_link is not None:
        if limit is not None or planned_count != source_count:
            raise ValueError("retry must use the complete no-limit source universe")
        if run_summary.pre_database.total_rows != source_count:
            raise ValueError("retry pre-scan rows must equal source count")
        if run_summary.attempted_input_count != run_summary.pre_database.error_rows:
            raise ValueError("retry must attempt every retained error row")
        if run_summary.planned_excluded_count != run_summary.pre_database.analyzable_rows:
            raise ValueError("retry exclusions must equal analyzable pre-scan rows")
        if (
            run_summary.post_database.total_rows != run_summary.pre_database.total_rows
            or run_summary.post_database.error_rows > run_summary.pre_database.error_rows
        ):
            raise ValueError("retry cannot add rows or errors")
    output_sha, output_size = _sha256_and_size(output)
    actual_post_database = _database_accounting_read_only(output)
    if actual_post_database != run_summary.post_database:
        raise ValueError("post-scan accounting does not match the closed database")
    core_is_release_attested = core_sha == (
        core_sha if resume_link is None
        else resume_link.root_attestation["measurement_core_sha256"]
    )
    if resume_link is not None and not core_is_release_attested:
        _validated_uri_safety_transition(
            resume_link.root_attestation["measurement_core_sha256"], core_sha
        )
        core_is_release_attested = True
    release_eligible = (
        limit is None
        and not scanner_git_dirty
        and planned_count == source_count
        and core_is_release_attested
        and (
            run_summary.post_database.total_rows == source_count
            if run_summary.mode == FRESH_MODE
            else bool(
                resume_link
                and resume_link.root_release_eligible
                and run_summary.pre_database.total_rows == source_count
                and run_summary.post_database.total_rows == source_count
            )
        )
    )

    root_attestation = (
        {
            "root_identifier_kind": "run_id",
            "root_identifier": "0" * 64,
            "manifest_schema_version": 2,
            "scanner_git_revision": revision,
            "measurement_core_sha256": core_sha,
            "attestation_method": "embedded_measurement_core_v2",
        }
        if resume_link is None else dict(resume_link.root_attestation)
    )
    manifest: dict[str, Any] = {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": "0" * 64,
        "previous_run_manifest_sha256": (
            None if resume_link is None else resume_link.previous_run_manifest_sha256
        ),
        "input_sqlite_sha256": None if resume_link is None else resume_link.input_sqlite_sha256,
        "input_sqlite_size_bytes": (
            None if resume_link is None else resume_link.input_sqlite_size_bytes
        ),
        "output_sqlite_sha256": output_sha,
        "output_sqlite_size_bytes": output_size,
        "source_input_normalized_sha256": source_sha,
        "source_input_normalized_line_count": source_count,
        "planned_input_normalized_sha256": planned_sha,
        "planned_input_normalized_line_count": planned_count,
        "attempted_input_normalized_sha256": run_summary.attempted_input_sha256,
        "attempted_input_normalized_line_count": run_summary.attempted_input_count,
        "planned_excluded_count": run_summary.planned_excluded_count,
        "rows_written": run_summary.rows_written,
        "database_pre": run_summary.pre_database.as_dict(),
        "database_post": run_summary.post_database.as_dict(),
        "scanner_git_revision": revision,
        "scanner_git_dirty": scanner_git_dirty,
        "resolver_configuration": dict(resolver_configuration),
        "started_at_utc": started_text,
        "finished_at_utc": finished_text,
        "concurrency": concurrency,
        "batch_pool_size": batch_pool_size,
        "run_mode": run_summary.mode,
        "limit": limit,
        "shuffle": shuffle,
        "shuffle_seed": shuffle_seed,
        "planned_input_order": order,
        "python_version": platform.python_version(),
        "measurement_core_algorithm": MEASUREMENT_CORE_ALGORITHM,
        "measurement_core_files": list(MEASUREMENT_CORE_FILES),
        "measurement_core_sha256": core_sha,
        "measurement_core_transition": (
            None if resume_link is None or resume_link.measurement_core_transition is None
            else dict(resume_link.measurement_core_transition)
        ),
        "root_measurement_core_attestation": root_attestation,
        "release_eligible": release_eligible,
    }
    manifest["run_id"] = _run_identity(manifest)
    if resume_link is None:
        manifest["root_measurement_core_attestation"]["root_identifier"] = manifest["run_id"]

    # Self-validate the run and its exact archived ancestry before these bytes
    # become authoritative. This also prevents a caller from forging a
    # PreparedResume that repeats the one permitted v1→v2 core transition.
    validated_info = _validate_v2(
        manifest, actual_output_identity=(output_sha, output_size)
    )
    if resume_link is not None:
        _validate_archived_chain(output, validated_info)
    payload = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
    # Immutable copy first: a crash cannot leave an authoritative sidecar
    # whose exact history bytes were not made durable.
    _immutable_manifest_copy(output, payload)
    destination = manifest_path_for(output)
    _atomic_write_private(destination, payload)
    return destination
