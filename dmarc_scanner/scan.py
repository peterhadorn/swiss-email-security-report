"""Per-domain orchestration: combine DNS lookups into one DmarcScanResult.

`query` is injected — this module never touches the network directly.
Production wiring (dmarc_scan.py) passes dmarc_scanner.resolve.query; tests
pass a fake. SPF, the legacy SPF RR-type-99 check, and DMARC are checked for
every domain that exists in DNS, regardless of MX — a domain that sends no
mail can still be spoofed unless it explicitly locks that down. DKIM, BIMI,
MTA-STS, TLS-RPT, CAA, and TLSA (DANE for SMTP, per MX host) are only
checked for domains that have MX, since they're meaningless without a mail
server to protect. DNSSEC and NS are checked for every domain that exists
in DNS, since neither is mail-specific either.

`query_batch` is also injected, optionally: it runs a list of independent
(name, rdtype) pairs concurrently instead of one at a time, cutting each
domain's wall-clock time without changing what gets checked. When not
provided, a safe sequential fallback is derived from `query` itself — same
calls, same order, same results — so callers that only know about `query`
(most existing tests) see identical behavior.
"""

from dmarc_scanner.models import DmarcScanResult
from dmarc_scanner.parsers import (
    find_first, is_bimi_record, is_dkim_record, is_dmarc_record,
    is_mta_sts_record, is_spf_record, is_tlsrpt_record,
    parse_dkim, parse_dmarc, parse_mx_answer, parse_spf,
)
from dmarc_scanner.providers import dkim_selectors_for_provider, fingerprint_mx_provider


def scan_domain(domain: str, query, query_batch=None) -> DmarcScanResult:
    if query_batch is None:
        query_batch = lambda pairs: {(n, r): query(n, r) for n, r in pairs}

    result = DmarcScanResult(domain=domain)

    mx_status, mx_answers = query(domain, "MX")
    if mx_status == "nxdomain":
        result.domain_exists = False
        return result
    if mx_status == "error":
        result.error = "mx_query_error"
        return result

    result.domain_exists = True

    if mx_status == "ok" and mx_answers:
        # Sort by preference (RFC 5321 §5.1: clients MUST try MX hosts in
        # numerical preference order) so mx_hosts[0] is always the domain's
        # actual primary mail server — DNS response order is not guaranteed
        # to match preference order, and provider fingerprinting depends on
        # this. RFC 7505 null MX ("0 .", parses to an empty host) means the
        # domain explicitly accepts no mail — filtered out after sorting.
        parsed = sorted(
            (parse_mx_answer(raw) for raw in mx_answers), key=lambda pair: pair[0]
        )
        hosts = [host for _, host in parsed if host]
        if hosts:
            result.has_mx = True
            result.mx_hosts = hosts
            result.mx_provider = fingerprint_mx_provider(hosts, domain)

    # DNSSEC, NS, SPF, the legacy SPF RR type, and DMARC are all mutually
    # independent (none needs another's result) and all run regardless of
    # MX — batched into one concurrent round instead of 5 sequential ones.
    group_a = query_batch([
        (domain, "DS"),
        (domain, "NS"),
        (domain, "TXT"),
        (domain, "SPF"),
        (f"_dmarc.{domain}", "TXT"),
    ])

    ds_status, ds_answers = group_a[(domain, "DS")]
    result.dnssec_signed = ds_status == "ok" and bool(ds_answers)

    ns_status, ns_answers = group_a[(domain, "NS")]
    if ns_status == "ok":
        result.ns_hosts = sorted(h.rstrip(".").lower() for h in ns_answers)

    txt_status, txt_answers = group_a[(domain, "TXT")]
    if txt_status == "ok":
        spf_raw = find_first(txt_answers, is_spf_record)
        if spf_raw:
            result.has_spf = True
            result.spf_record = spf_raw
            spf = parse_spf(spf_raw)
            result.spf_all_mechanism = spf["all_mechanism"]
            result.spf_lookup_count = spf["lookup_count"]
            result.spf_near_limit = spf["near_limit"]

    legacy_spf_status, legacy_spf_answers = group_a[(domain, "SPF")]
    result.has_legacy_spf_rrtype = legacy_spf_status == "ok" and bool(legacy_spf_answers)

    dmarc_status, dmarc_answers = group_a[(f"_dmarc.{domain}", "TXT")]
    dmarc_raw = find_first(dmarc_answers, is_dmarc_record) if dmarc_status == "ok" else None
    if dmarc_raw:
        result.has_dmarc = True
        result.dmarc_record = dmarc_raw
        dmarc = parse_dmarc(dmarc_raw)
        result.dmarc_policy = dmarc["policy"]
        result.dmarc_rua = dmarc["has_rua"]
        result.dmarc_ruf = dmarc["has_ruf"]
        result.dmarc_pct = dmarc["pct"]
        result.dmarc_sp = dmarc["sp"]
        result.dmarc_adkim = dmarc["adkim"]
        result.dmarc_aspf = dmarc["aspf"]
        result.dmarc_rua_domains = dmarc["rua_domains"]
        result.dmarc_ruf_domains = dmarc["ruf_domains"]
    else:
        # No DMARC record found at all — same "not protected" bucket as a
        # record present but missing its p= tag (parse_dmarc's "absent").
        result.dmarc_policy = "absent"

    if not result.has_mx:
        return result

    # "error" (a transient resolver failure) is deliberately NOT treated as
    # confirmation of non-existence — only "nxdomain" (the name genuinely
    # doesn't exist) or a clean "noanswer" on both A and AAAA (the name
    # exists but has no address record) are affirmative dangling-MX
    # findings. An error on either lookup leaves that host's resolvability
    # inconclusive, and is silently skipped rather than flagged — the same
    # spirit as the rest of the scanner never turning a query error into an
    # affirmative security claim.
    for host in result.mx_hosts:
        a_status, a_answers = query(host, "A")
        if a_status == "ok" and a_answers:
            continue
        if a_status == "nxdomain":
            result.mx_hosts_unresolvable.append(host)
            continue
        if a_status == "error":
            continue
        aaaa_status, aaaa_answers = query(host, "AAAA")
        if aaaa_status == "ok" and aaaa_answers:
            continue
        if aaaa_status == "error":
            continue
        result.mx_hosts_unresolvable.append(host)
    result.mx_unresolvable = bool(result.mx_hosts_unresolvable)

    selectors = dkim_selectors_for_provider(result.mx_provider)
    result.dkim_selectors_checked = selectors
    dkim_results = query_batch(
        [(f"{selector}._domainkey.{domain}", "TXT") for selector in selectors]
    )
    found_selectors = []
    weak_key_found = False
    testing_mode_found = False
    for selector in selectors:
        dkim_status, dkim_answers = dkim_results[(f"{selector}._domainkey.{domain}", "TXT")]
        if dkim_status != "ok":
            continue
        dkim_raw = find_first(dkim_answers, is_dkim_record)
        if not dkim_raw:
            continue
        found_selectors.append(selector)
        dkim_info = parse_dkim(dkim_raw)
        if dkim_info["testing_mode"]:
            testing_mode_found = True
        if dkim_info["weak_key"]:
            weak_key_found = True
    result.dkim_selectors_found = found_selectors
    result.has_dkim = bool(found_selectors)
    result.dkim_testing_mode = testing_mode_found
    result.dkim_weak_key = weak_key_found

    # BIMI, MTA-STS, TLS-RPT, and CAA are four mutually independent checks —
    # none depends on another's result, so batch them into one round too.
    group_c = query_batch([
        (f"default._bimi.{domain}", "TXT"),
        (f"_mta-sts.{domain}", "TXT"),
        (f"_smtp._tls.{domain}", "TXT"),
        (domain, "CAA"),
    ])

    bimi_status, bimi_answers = group_c[(f"default._bimi.{domain}", "TXT")]
    if bimi_status == "ok":
        bimi_raw = find_first(bimi_answers, is_bimi_record)
        if bimi_raw:
            result.has_bimi = True
            result.bimi_record = bimi_raw

    mta_status, mta_answers = group_c[(f"_mta-sts.{domain}", "TXT")]
    if mta_status == "ok":
        mta_raw = find_first(mta_answers, is_mta_sts_record)
        if mta_raw:
            result.has_mta_sts = True
            result.mta_sts_record = mta_raw

    tlsrpt_status, tlsrpt_answers = group_c[(f"_smtp._tls.{domain}", "TXT")]
    if tlsrpt_status == "ok":
        tlsrpt_raw = find_first(tlsrpt_answers, is_tlsrpt_record)
        if tlsrpt_raw:
            result.has_tlsrpt = True
            result.tlsrpt_record = tlsrpt_raw

    caa_status, caa_answers = group_c[(domain, "CAA")]
    if caa_status == "ok" and caa_answers:
        result.has_caa = True
        result.caa_records = caa_answers

    tlsa_checked = []
    tlsa_found = []
    for host in result.mx_hosts:
        tlsa_checked.append(host)
        tlsa_status, tlsa_answers = query(f"_25._tcp.{host}", "TLSA")
        if tlsa_status == "ok" and tlsa_answers:
            tlsa_found.append(host)
    result.tlsa_hosts_checked = tlsa_checked
    result.tlsa_hosts_found = tlsa_found
    result.has_tlsa = bool(tlsa_found)

    return result
