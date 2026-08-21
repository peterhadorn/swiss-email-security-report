"""SQLite storage for dmarc_scan_results — a sibling DB, not a table in
the existing results.db."""

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from dmarc_scanner.models import DmarcScanResult

COLUMNS = [
    "domain TEXT PRIMARY KEY",
    "domain_exists INTEGER",
    "has_mx INTEGER", "mx_hosts TEXT", "mx_provider TEXT",
    "has_spf INTEGER", "spf_record TEXT", "spf_all_mechanism TEXT",
    "spf_lookup_count INTEGER", "spf_near_limit INTEGER", "has_legacy_spf_rrtype INTEGER",
    "dkim_selectors_checked TEXT", "dkim_selectors_found TEXT", "has_dkim INTEGER",
    "dkim_testing_mode INTEGER", "dkim_weak_key INTEGER",
    "has_dmarc INTEGER", "dmarc_record TEXT", "dmarc_policy TEXT",
    "dmarc_rua INTEGER", "dmarc_ruf INTEGER",
    "dmarc_pct INTEGER", "dmarc_sp TEXT", "dmarc_adkim TEXT", "dmarc_aspf TEXT",
    "dmarc_rua_domains TEXT", "dmarc_ruf_domains TEXT",
    "has_ds_record INTEGER",
    "ns_hosts TEXT",
    "mx_hosts_unresolvable TEXT", "mx_unresolvable INTEGER",
    "has_bimi INTEGER", "bimi_record TEXT",
    "has_mta_sts INTEGER", "mta_sts_record TEXT",
    "has_tlsrpt INTEGER", "tlsrpt_record TEXT",
    "has_caa INTEGER", "caa_records TEXT",
    "has_tlsa_record INTEGER", "tlsa_hosts_checked TEXT", "tlsa_hosts_found TEXT",
    "query_statuses TEXT",
    "error TEXT",
    "scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
]

EXPECTED_COLUMNS = {col.split()[0] for col in COLUMNS}
JSON_FIELDS = {
    "mx_hosts", "dkim_selectors_checked", "dkim_selectors_found", "caa_records",
    "dmarc_rua_domains", "dmarc_ruf_domains", "mx_hosts_unresolvable",
    "tlsa_hosts_checked", "tlsa_hosts_found", "ns_hosts", "query_statuses",
}

# New scans store scientifically specific observations. The archived 2026
# database is intentionally immutable, so readers select its legacy columns
# through this adapter rather than adding ambiguous duplicate columns to it.
LEGACY_METRIC_COLUMNS = {
    "has_ds_record": "dnssec_signed",
    "has_tlsa_record": "has_tlsa",
}


def _get_existing_columns(conn: sqlite3.Connection) -> set:
    cursor = conn.execute("PRAGMA table_info(dmarc_scan_results)")
    return {row[1] for row in cursor}


def validate_output_path(db_path: str) -> None:
    """Refuse to mutate a legacy or unknown existing results schema.

    The inspection opens an existing file read-only and happens before WAL
    mode, drops, table creation, or any other scanner mutation.
    """
    path = Path(db_path)
    if not path.exists():
        return
    try:
        conn = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise RuntimeError(f"cannot inspect existing output database {path}") from exc
    try:
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )}
        if "dmarc_scan_results" not in tables:
            return
        columns = _get_existing_columns(conn)
        if set(LEGACY_METRIC_COLUMNS.values()) & columns:
            raise RuntimeError(
                "refusing legacy output database; choose a new --output path"
            )
        if columns != EXPECTED_COLUMNS:
            raise RuntimeError(
                "refusing existing output database with an unknown schema; "
                "choose a new --output path"
            )
    finally:
        conn.close()


def metric_column(conn: sqlite3.Connection, canonical_name: str) -> str:
    """Return the physical column for a canonical presence observation.

    This is a read/export compatibility adapter for archived result databases.
    It never alters an existing database and always prefers the future-scan
    canonical column when present.
    """
    columns = _get_existing_columns(conn)
    if canonical_name in columns:
        return canonical_name
    legacy_name = LEGACY_METRIC_COLUMNS.get(canonical_name)
    if legacy_name and legacy_name in columns:
        return legacy_name
    raise RuntimeError(f"Database has no column for canonical metric {canonical_name!r}")


def create_table(conn: sqlite3.Connection):
    """Create results table if not exists, fail fast on schema mismatch."""
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS dmarc_scan_results ({', '.join(COLUMNS)})"
    )
    conn.commit()

    existing = _get_existing_columns(conn)
    if existing != EXPECTED_COLUMNS:
        missing = EXPECTED_COLUMNS - existing
        extra = existing - EXPECTED_COLUMNS
        parts = []
        if missing:
            parts.append(f"missing columns: {', '.join(sorted(missing))}")
        if extra:
            parts.append(f"unexpected columns: {', '.join(sorted(extra))}")
        raise RuntimeError(
            f"Schema mismatch in dmarc_scan_results ({'; '.join(parts)}). "
            f"Back up the DB and re-create it, or migrate manually."
        )


def get_done_domains(conn: sqlite3.Connection) -> set:
    """Domains considered done for resume purposes.

    Excludes rows that recorded a query error — a transient DNS failure
    should be retried on the next run, not treated as permanently scanned.
    """
    columns = _get_existing_columns(conn)
    where = "error = ''"
    if "query_statuses" in columns:
        # Keep this independent guard as protection for rows written by a
        # future caller that retained detailed statuses but omitted error.
        where += " AND query_statuses NOT LIKE '%\"error\"%'"
    cursor = conn.execute(f"SELECT domain FROM dmarc_scan_results WHERE {where}")
    return {row[0] for row in cursor}


def insert_result(conn: sqlite3.Connection, result: DmarcScanResult):
    d = asdict(result)
    for key in JSON_FIELDS:
        if isinstance(d[key], (list, dict)):
            d[key] = json.dumps(d[key])
    columns = ", ".join(d.keys())
    placeholders = ", ".join(["?"] * len(d))
    conn.execute(
        f"INSERT OR REPLACE INTO dmarc_scan_results ({columns}) VALUES ({placeholders})",
        list(d.values()),
    )
