"""Swiss email-security scanner — passive DNS-only entry point.

Usage:
    python3 dmarc_scan.py --input data/ch_domains.txt --output data/dmarc_scan_results.db --limit 100
    python3 dmarc_scan.py --input data/ch_domains.txt --output data/dmarc_scan_results.db --concurrency 300
"""

import argparse
import concurrent.futures
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from dmarc_scanner import resolve
from dmarc_scanner.db import create_table, get_done_domains, insert_result, validate_output_path
from dmarc_scanner.models import DmarcScanResult
from dmarc_scanner.provenance import (
    FRESH_MODE,
    PreparedResume,
    RESUME_MODE,
    RunSummary,
    consume_prepared_resume_manifest,
    database_accounting,
    manifest_path_for,
    normalized_input_digest,
    normalized_domain_list,
    planned_domains_from_source,
    prepare_resume_manifest,
    revalidate_consumed_prepared_resume,
    scanner_git_provenance,
    validate_fresh_output_preflight,
    validate_resume_output_preflight,
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
    prepared_resume: PreparedResume | None = None,
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

    if type(concurrency) is not int or concurrency <= 0:
        raise ValueError("concurrency must be an integer > 0")
    planned = normalized_domain_list(domains, require_nonempty=False)
    if planned != list(domains):
        raise ValueError("run domains must already be uniquely normalized")
    if resume:
        if not isinstance(prepared_resume, PreparedResume):
            raise RuntimeError("resume run requires a consumed PreparedResume")
        revalidate_consumed_prepared_resume(
            db_path,
            prepared_resume,
            planned_input_lines=planned,
            concurrency=concurrency,
            resolver_configuration=resolve.resolver_configuration(),
            batch_pool_size=resolve.batch_pool_size(),
        )
    else:
        if prepared_resume is not None:
            raise ValueError("fresh run cannot receive a PreparedResume")
        validate_fresh_output_preflight(db_path)
    validate_output_path(db_path)
    active_manifest = manifest_path_for(db_path)
    if active_manifest.exists() or active_manifest.is_symlink():
        raise RuntimeError(
            "active scan manifest must be validated/consumed before database mutation"
        )
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    if not resume:
        logger.info("Starting fresh in a new output database")
    create_table(conn)

    pre_database = database_accounting(conn)
    db_total_scanned = pre_database.total_rows
    excluded_count = 0
    planned_count = len(domains)
    if resume:
        done = get_done_domains(conn)
        before = len(domains)
        domains = [d for d in domains if d not in done]
        excluded_count = before - len(domains)
        logger.info(f"Resume: {len(done)} done, {len(domains)} remaining (of {before})")

    total = len(domains)
    attempted_sha256, attempted_count = normalized_input_digest(domains)
    if prepared_resume is not None and (
        attempted_sha256, attempted_count
    ) != (
        prepared_resume.expected_attempted_input_sha256,
        prepared_resume.expected_attempted_input_count,
    ):
        _finalize_database(conn)
        raise RuntimeError("runtime retry subset differs from PreparedResume")
    if total == 0:
        logger.info("Nothing to scan.")
        post_database = database_accounting(conn)
        _finalize_database(conn)
        return RunSummary(
            RESUME_MODE if resume else FRESH_MODE,
            planned_count,
            excluded_count,
            attempted_sha256,
            attempted_count,
            pre_database,
            post_database,
            0,
        )

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

    post_database = database_accounting(conn)
    _finalize_database(conn)

    elapsed = time.monotonic() - start_time
    logger.info(
        f"Done: {scanned} domains in {elapsed/60:.1f}m. "
        f"MX found: {mx_found} ({mx_found/max(scanned,1)*100:.1f}%) Errors: {errors}"
    )
    return RunSummary(
        RESUME_MODE if resume else FRESH_MODE,
        planned_count,
        excluded_count,
        attempted_sha256,
        attempted_count,
        pre_database,
        post_database,
        scanned,
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

    input_domains = load_domains(args.input)
    domains = planned_domains_from_source(
        input_domains,
        limit=args.limit,
        shuffle=args.shuffle,
        shuffle_seed=42 if args.shuffle else None,
    )
    if type(args.concurrency) is not int or args.concurrency <= 0:
        raise ValueError("--concurrency must be an integer > 0")
    effective_batch_pool_size = (
        args.batch_pool_size
        if args.batch_pool_size is not None else resolve.batch_pool_size()
    )
    if type(effective_batch_pool_size) is not int or effective_batch_pool_size <= 0:
        raise ValueError("--batch-pool-size must be an integer > 0")
    output = Path(args.output)
    output_present = output.exists() or output.is_symlink()
    resume_requested = not args.no_resume and output_present
    if resume_requested:
        validate_resume_output_preflight(output)
    else:
        validate_fresh_output_preflight(output)

    if args.batch_pool_size is not None:
        resolve.configure_batch_pool_size(args.batch_pool_size)

    logger.info(
        f"Loaded {len(domains)} domains, concurrency={args.concurrency}, "
        f"batch_pool_size={args.batch_pool_size or 'default'}"
    )

    scanner_revision, scanner_dirty = scanner_git_provenance()
    started_at = datetime.now(timezone.utc)
    resume_link = (
        prepare_resume_manifest(
            args.output,
            source_input_lines=input_domains,
            planned_input_lines=domains,
            resolver_configuration=resolve.resolver_configuration(),
            concurrency=args.concurrency,
            batch_pool_size=resolve.batch_pool_size(),
            limit=args.limit,
            shuffle=args.shuffle,
            shuffle_seed=42 if args.shuffle else None,
            started_at=started_at,
        )
        if resume_requested else None
    )
    if resume_link is not None:
        consume_prepared_resume_manifest(
            args.output,
            resume_link,
            source_input_lines=input_domains,
            planned_input_lines=domains,
            resolver_configuration=resolve.resolver_configuration(),
            concurrency=args.concurrency,
            batch_pool_size=resolve.batch_pool_size(),
            limit=args.limit,
            shuffle=args.shuffle,
            shuffle_seed=42 if args.shuffle else None,
        )
    summary = run(
        domains,
        args.output,
        concurrency=args.concurrency,
        resume=resume_requested,
        prepared_resume=resume_link,
    )
    finished_at = datetime.now(timezone.utc)
    manifest_path = write_scan_manifest(
        args.output,
        source_input_lines=input_domains,
        planned_input_lines=domains,
        run_summary=summary,
        resume_link=resume_link,
        scanner_git_revision=scanner_revision,
        scanner_git_dirty=scanner_dirty,
        resolver_configuration=resolve.resolver_configuration(),
        started_at=started_at,
        finished_at=finished_at,
        concurrency=args.concurrency,
        batch_pool_size=resolve.batch_pool_size(),
        limit=args.limit,
        shuffle=args.shuffle,
        shuffle_seed=42 if args.shuffle else None,
    )
    logger.info("Wrote private scan manifest: %s", manifest_path)


if __name__ == "__main__":
    main()
