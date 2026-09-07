"""Real DNS resolution — public resolvers only, never the domain's own servers.

One `dns.resolver.Resolver` per thread (thread-local): dnspython Resolver
objects are not safe to share a cache across threads under this concurrency
model, so each worker thread lazily builds and reuses its own.
"""

import concurrent.futures
import threading

import dns.exception
import dns.resolver
import dns.version

PUBLIC_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"]
QUERY_TIMEOUT = 4.0   # per-nameserver-attempt timeout, seconds
QUERY_LIFETIME = 6.0  # total budget across nameserver retries, seconds

_thread_local = threading.local()


def _make_resolver() -> "dns.resolver.Resolver":
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(PUBLIC_NAMESERVERS)
    # Spread queries across all 5 resolvers instead of hammering the first
    # one in the list — dnspython defaults to trying nameservers in a fixed
    # order otherwise.
    resolver.rotate = True
    resolver.timeout = QUERY_TIMEOUT
    resolver.lifetime = QUERY_LIFETIME
    resolver.cache = None
    return resolver


def _get_thread_resolver():
    resolver = getattr(_thread_local, "resolver", None)
    if resolver is None:
        resolver = _make_resolver()
        _thread_local.resolver = resolver
    return resolver


def _txt_to_text(rdata) -> str:
    return b"".join(rdata.strings).decode("utf-8", errors="replace")


def query(name: str, rdtype: str) -> tuple:
    """Run one DNS query. Returns (status, answers).

    status: "ok" | "nxdomain" | "noanswer" | "error"
    answers: list of plain strings (TXT segments already joined), [] unless "ok"
    """
    resolver = _get_thread_resolver()
    try:
        answer = resolver.resolve(name, rdtype, raise_on_no_answer=True)
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        return "noanswer", []
    except Exception:
        return "error", []

    if rdtype == "TXT":
        return "ok", [_txt_to_text(r) for r in answer]
    return "ok", [str(r) for r in answer]


# One domain's full set of DNS-record checks previously ran as a sequential
# chain of ~10-27 blocking round-trips inside a single worker thread — the
# real bottleneck at scale wasn't outer thread count (tested and confirmed:
# raising it made things worse) but each domain's own critical path. This
# shared, bounded pool lets independent queries WITHIN one domain's scan run
# concurrently instead.
#
# Sizing this is NOT independent of --concurrency (dmarc_scan.py's outer
# thread count): once most of a domain's queries route through this pool
# (roughly 21 of ~27 today — everything except MX, MX-host A/AAAA, and
# TLSA), aggregate scan throughput follows Little's Law against the
# AVERAGE in-flight query count, which becomes governed by this pool's
# size, not by --concurrency. Pairing a small pool with a large outer
# --concurrency silently caps throughput below what --concurrency alone
# used to provide. Empirically: outer concurrency 700 alone already
# triggered a resolver-side error-rate spike, so this should stay near
# that same total in-flight ceiling (~300), not be raised independently —
# tune both together, not one in isolation.
_BATCH_POOL_SIZE = 300
_batch_pool = None
_batch_pool_lock = threading.Lock()


def configure_batch_pool_size(size: int) -> None:
    """Override the shared batch pool's worker count before first use.

    Must be called before any query_batch() call in this process — the pool
    is created lazily on first use and cannot be resized afterward.
    """
    global _BATCH_POOL_SIZE
    if _batch_pool is not None:
        raise RuntimeError("batch pool already created — call this before any query_batch()")
    _BATCH_POOL_SIZE = size


def batch_pool_size() -> int:
    """Return the configured shared within-domain query-batch pool size."""
    return _BATCH_POOL_SIZE


def resolver_configuration() -> dict:
    """Return all resolver settings that materially affect a scan."""
    return {
        "nameservers": list(PUBLIC_NAMESERVERS),
        "rotate": True,
        "timeout_seconds": QUERY_TIMEOUT,
        "lifetime_seconds": QUERY_LIFETIME,
        "cache_policy": "disabled",
        "dnspython_version": dns.version.version,
    }


def _get_batch_pool() -> "concurrent.futures.ThreadPoolExecutor":
    global _batch_pool
    if _batch_pool is None:
        with _batch_pool_lock:
            if _batch_pool is None:
                _batch_pool = concurrent.futures.ThreadPoolExecutor(
                    max_workers=_BATCH_POOL_SIZE
                )
    return _batch_pool


def query_batch(pairs: list) -> dict:
    """Run multiple independent DNS queries concurrently.

    pairs: list of (name, rdtype) tuples, must be unique — a duplicate pair
    fires twice concurrently and the dict keeps whichever result lands last,
    which is not what the sequential fallback in scan.py would do (it would
    just call query() twice, keeping the last call's result too, but
    deterministically). Returns {(name, rdtype): (status, answers)}, same
    per-pair result shape as query(). Empty input returns {} without
    touching the pool.
    """
    if not pairs:
        return {}
    pool = _get_batch_pool()
    futures = {pool.submit(query, name, rdtype): (name, rdtype) for name, rdtype in pairs}
    results = {}
    for future in concurrent.futures.as_completed(futures):
        pair = futures[future]
        try:
            results[pair] = future.result()
        except Exception:
            # A per-future failure is a DNS-query error for this exact pair,
            # not a reason to discard every other completed query.
            results[pair] = ("error", [])
    return results
