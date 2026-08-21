"""Swiss email-security scanner — passive DNS-only entry point.

Usage:
    python3 dmarc_scan.py --input data/ch_domains.txt --output data/dmarc_scan_results.db --limit 100
    python3 dmarc_scan.py --input data/ch_domains.txt --output data/dmarc_scan_results.db --concurrency 300
"""

import argparse
import concurrent.futures
import json
import logging
import random
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from dmarc_scanner import resolve
from dmarc_scanner.db import create_table, get_done_domains, insert_result, validate_output_path
from dmarc_scanner.models import DmarcScanResult
from dmarc_scanner.provenance import (
    manifest_path_for,
    scanner_git_provenance,
    write_scan_manifest,
)
from dmarc_scanner.resolve import query as real_query, query_batch as real_query_batch
from dmarc_scanner.scan import scan_domain

logger = logging.getLogger(__name__)

BATCH_SIZE = 2000
REPORT_EVERY = 2000


def _health_path_for(db_path: str) -> str:
    path = Path(db_path)
    return str(path.with_name(f"{path.stem}_health.json"))


def _finalize_database(conn: sqlite3.Connection) -> None:
    """Commit and checkpoint before closing so a sidecar can hash final bytes."""
    try:
        conn.commit()
        rows = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        if len(rows) != 1:
            raise RuntimeError("checkpoint incomplete: SQLite returned no checkpoint status")
        busy, log_frames, checkpointed_frames = rows[0]
        if busy != 0 or log_frames != checkpointed_frames or log_frames != 0:
            raise RuntimeError(
                "checkpoint incomplete: WAL remains pending "
                f"(busy={busy}, log={log_frames}, checkpointed={checkpointed_frames})"
            )
    finally:
        conn.close()


def run(
    domains: list,
    db_path: str,
    concurrency: int = 300,
    resume: bool = True,
    query_fn=None,
    query_batch_fn=None,
):
    """Scan all domains with a thread-pool concurrency limit, write to SQLite."""
    # Only default to the real, network-touching query_batch when query_fn
    # is ALSO defaulting to the real resolver — a caller supplying a fake
    # query_fn (every test) but no query_batch_fn must get scan_domain's own
    # safe sequential fallback (derived from that same fake), never the real
    # one, or a "just fake the query" test would silently start making real
    # DNS calls through the batch path.
    using_real_query = query_fn is None
    query_fn = real_query if using_real_query else query_fn
    if query_batch_fn is None and using_real_query:
        query_batch_fn = real_query_batch

    # A stale sidecar can never be allowed to describe an output about to be
    # changed, including a run that subsequently fails.
    manifest_path_for(db_path).unlink(missing_ok=True)
    validate_output_path(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    if not resume:
        conn.execute("DROP TABLE IF EXISTS dmarc_scan_results")
        conn.commit()
        logger.info("Starting fresh: cleared existing dmarc_scan_results table")
    create_table(conn)

    db_total_scanned = conn.execute("SELECT COUNT(*) FROM dmarc_scan_results").fetchone()[0]

    if resume:
        done = get_done_domains(conn)
        before = len(domains)
        domains = [d for d in domains if d not in done]
        logger.info(f"Resume: {len(done)} done, {len(domains)} remaining (of {before})")

    total = len(domains)
    if total == 0:
        logger.info("Nothing to scan.")
        _finalize_database(conn)
        return

    scanned = 0
    mx_found = 0
    errors = 0
    start_time = time.monotonic()
    health_path = _health_path_for(db_path)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        i = 0
        while i < total:
            batch = domains[i:i + BATCH_SIZE]
            futures = {
                pool.submit(scan_domain, d, query_fn, query_batch_fn): d for d in batch
            }

            for future in concurrent.futures.as_completed(futures):
                domain = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    # scan_domain crashed outright (a bug, not a handled DNS
                    # error) — record it as an errored row instead of
                    # silently dropping the domain, so it still shows up in
                    # analyze_dmarc.py's error count and gets retried on the
                    # next run via get_done_domains' error != '' exclusion.
                    logger.warning(f"Failed {domain}: {exc}")
                    result = DmarcScanResult(domain=domain, error=f"scan_exception: {exc}")

                insert_result(conn, result)
                scanned += 1
                if result.has_mx:
                    mx_found += 1
                if result.error:
                    errors += 1

                if scanned % REPORT_EVERY == 0:
                    elapsed = time.monotonic() - start_time
                    rate = scanned / elapsed if elapsed > 0 else 0
                    eta_min = (total - scanned) / rate / 60 if rate > 0 else 0
                    total_scanned = db_total_scanned + scanned
                    logger.info(
                        f"{scanned}/{total} ({scanned/total*100:.1f}%) "
                        f"mx_found={mx_found} rate={rate:.0f}/s ETA={eta_min:.0f}m errors={errors}"
                    )
                    with open(health_path, "w") as hf:
                        json.dump({
                            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            "scanned": total_scanned,
                            "total": total + db_total_scanned,
                            "mx_found": mx_found,
                            "errors": errors,
                            "rate": round(rate, 1),
                            "eta_min": round(eta_min),
                        }, hf)
                    conn.commit()

            conn.commit()
            i += BATCH_SIZE

    _finalize_database(conn)

    elapsed = time.monotonic() - start_time
    logger.info(
        f"Done: {scanned} domains in {elapsed/60:.1f}m. "
        f"MX found: {mx_found} ({mx_found/max(scanned,1)*100:.1f}%) Errors: {errors}"
    )


def load_domains(path: str) -> list:
    """Load domains from file, strip trailing dots and blank lines."""
    domains = []
    with open(path) as f:
        for line in f:
            d = line.strip().rstrip(".")
            if d:
                domains.append(d)
    return domains


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Swiss Email Security Scanner (passive DNS-only)")
    parser.add_argument("--input", required=True, help="Domain list file")
    parser.add_argument("--output", default="data/dmarc_scan_results.db", help="SQLite output")
    parser.add_argument("--concurrency", type=int, default=300)
    parser.add_argument(
        "--batch-pool-size", type=int, default=None,
        help="Override the shared within-domain query-batch pool size "
             "(default: dmarc_scanner.resolve's own default). Tune this "
             "together with --concurrency, not independently — see "
             "resolve.py's _BATCH_POOL_SIZE comment.",
    )
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--shuffle", action="store_true", help="Randomize domain order (seed=42)")
    parser.add_argument(
        "--limit", type=int,
        help="Scan at most N normalized input domains; 0 intentionally writes an empty scan.",
    )

    args = parser.parse_args()

    # Clear an old sidecar before any configuration, input, Git, or database
    # failure path. A manifest must never survive the attempt it no longer
    # describes.
    manifest_path_for(args.output).unlink(missing_ok=True)

    if args.batch_pool_size is not None:
        resolve.configure_batch_pool_size(args.batch_pool_size)

    input_domains = load_domains(args.input)
    domains = list(input_domains)
    if args.shuffle:
        random.seed(42)
        random.shuffle(domains)
    if args.limit is not None:
        domains = domains[:args.limit]

    logger.info(
        f"Loaded {len(domains)} domains, concurrency={args.concurrency}, "
        f"batch_pool_size={args.batch_pool_size or 'default'}"
    )

    scanner_revision, scanner_dirty = scanner_git_provenance()
    started_at = datetime.now(timezone.utc)
    run(
        domains,
        args.output,
        concurrency=args.concurrency,
        resume=not args.no_resume,
    )
    finished_at = datetime.now(timezone.utc)
    manifest_path = write_scan_manifest(
        args.output,
        source_input_lines=input_domains,
        effective_input_lines=domains,
        scanner_git_revision=scanner_revision,
        scanner_git_dirty=scanner_dirty,
        resolver_configuration=resolve.resolver_configuration(),
        started_at=started_at,
        finished_at=finished_at,
        concurrency=args.concurrency,
        batch_pool_size=resolve.batch_pool_size(),
        retry_resume_mode=("fresh" if args.no_resume else "resume_retry_partial_errors"),
        limit=args.limit,
        shuffle=args.shuffle,
        shuffle_seed=42 if args.shuffle else None,
    )
    logger.info("Wrote private scan manifest: %s", manifest_path)


if __name__ == "__main__":
    main()
