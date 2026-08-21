from dmarc_scanner.scan import scan_domain


class RecordingQuery:
    """Fake query() that returns canned (status, answers) by (name, rdtype)
    and records every call, so tests can assert which lookups did/didn't run.
    """

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, name, rdtype):
        self.calls.append((name, rdtype))
        return self.responses.get((name, rdtype), ("noanswer", []))


def test_nxdomain_domain_skips_everything():
    query = RecordingQuery({("dead.ch", "MX"): ("nxdomain", [])})
    result = scan_domain("dead.ch", query)

    assert result.domain_exists is False
    assert result.has_mx is False
    assert query.calls == [("dead.ch", "MX")]


def test_mx_query_error_skips_everything_and_records_error():
    query = RecordingQuery({("flaky.ch", "MX"): ("error", [])})
    result = scan_domain("flaky.ch", query)

    assert result.error == "mx_query_error"
    assert query.calls == [("flaky.ch", "MX")]


def test_domain_exists_without_mx_checks_dnssec_ns_spf_and_dmarc_but_not_dkim_or_caa():
    query = RecordingQuery({
        ("noemail.ch", "MX"): ("noanswer", []),
        ("noemail.ch", "DS"): ("ok", ["12345 8 2 ABCDEF"]),
        ("noemail.ch", "NS"): ("ok", ["ns2.example.ch.", "ns1.example.ch."]),
        ("noemail.ch", "TXT"): ("ok", ["v=spf1 -all"]),
        ("noemail.ch", "SPF"): ("noanswer", []),
        ("_dmarc.noemail.ch", "TXT"): ("ok", ["v=DMARC1; p=reject"]),
    })
    result = scan_domain("noemail.ch", query)

    assert result.domain_exists is True
    assert result.has_mx is False
    assert result.has_ds_record is True
    assert result.ns_hosts == ["ns1.example.ch", "ns2.example.ch"]
    assert result.has_spf is True
    assert result.spf_all_mechanism == "hardfail"
    assert result.has_legacy_spf_rrtype is False
    assert result.has_dmarc is True
    assert result.dmarc_policy == "reject"
    assert result.has_dkim is False
    assert result.has_caa is False
    assert query.calls == [
        ("noemail.ch", "MX"), ("noemail.ch", "DS"), ("noemail.ch", "NS"),
        ("noemail.ch", "TXT"), ("noemail.ch", "SPF"), ("_dmarc.noemail.ch", "TXT"),
    ]


def test_legacy_spf_rrtype_detected_when_present():
    # RFC 7208 obsoleted the dedicated SPF RR type (99) in favor of TXT-only
    # — a domain that still has one is using a deprecated record format and
    # should be told to drop it.
    domain = "old-style.ch"
    query = RecordingQuery({
        (domain, "MX"): ("noanswer", []),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        (domain, "SPF"): ("ok", ["v=spf1 -all"]),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
    })
    result = scan_domain(domain, query)

    assert result.has_legacy_spf_rrtype is True


def test_null_mx_is_treated_as_no_mail():
    # RFC 7505: "0 ." means the domain explicitly declares it accepts no
    # mail — must NOT be treated as has_mx=True. SPF/legacy-SPF/DMARC still
    # run (now unconditional), DKIM/CAA/etc do not (still MX-gated).
    query = RecordingQuery({
        ("nomail-declared.ch", "MX"): ("ok", ["0 ."]),
        ("nomail-declared.ch", "DS"): ("noanswer", []),
    })
    result = scan_domain("nomail-declared.ch", query)

    assert result.has_mx is False
    assert result.mx_hosts == []
    assert query.calls == [
        ("nomail-declared.ch", "MX"), ("nomail-declared.ch", "DS"),
        ("nomail-declared.ch", "NS"), ("nomail-declared.ch", "TXT"),
        ("nomail-declared.ch", "SPF"), ("_dmarc.nomail-declared.ch", "TXT"),
    ]


def test_mx_hosts_are_sorted_by_preference_not_dns_response_order():
    # RFC 5321 §5.1: clients MUST try MX hosts in numerical preference
    # order. DNS servers don't guarantee response order matches preference,
    # so mx_hosts must be sorted here rather than trusting query() order —
    # provider fingerprinting (dmarc_scanner/providers.py) depends on
    # mx_hosts[0] being the true primary.
    domain = "multi-mx.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["20 backup.example.net.", "10 primary.example.net."]),
        (domain, "DS"): ("noanswer", []),
    })
    result = scan_domain(domain, query)

    assert result.mx_hosts == ["primary.example.net", "backup.example.net"]


def test_full_domain_with_every_record_present():
    domain = "secure.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 secure-ch.mail.protection.outlook.com."]),
        (domain, "DS"): ("ok", ["12345 8 2 ABCDEF"]),
        (domain, "TXT"): ("ok", [
            "google-site-verification=abc123",
            "v=spf1 include:spf.protection.outlook.com -all",
        ]),
        (f"selector1._domainkey.{domain}", "TXT"): (
            "ok", ["v=DKIM1; k=rsa; p=" + "A" * 392]),
        (f"selector2._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("ok", [
            "v=DMARC1; p=reject; rua=mailto:d@dmarcian.com; ruf=mailto:f@secure.ch; "
            "pct=50; sp=quarantine; adkim=s; aspf=s",
        ]),
        (f"default._bimi.{domain}", "TXT"): ("ok", ["v=BIMI1; l=https://secure.ch/logo.svg;"]),
        (f"_mta-sts.{domain}", "TXT"): ("ok", ["v=STSv1; id=20260101000000Z;"]),
        (f"_smtp._tls.{domain}", "TXT"): ("ok", ["v=TLSRPTv1;rua=mailto:tls@secure.ch"]),
        (domain, "CAA"): ("ok", ['0 issue "letsencrypt.org"']),
    })

    result = scan_domain(domain, query)

    assert result.domain_exists is True
    assert result.has_mx is True
    assert result.mx_hosts == ["secure-ch.mail.protection.outlook.com"]
    assert result.mx_provider == "microsoft365"
    assert result.has_ds_record is True

    assert result.has_spf is True
    assert result.spf_all_mechanism == "hardfail"
    assert result.spf_lookup_count == 1
    assert result.spf_near_limit is False

    assert result.dkim_selectors_checked == ["selector1", "selector2"]
    assert result.dkim_selectors_found == ["selector1"]
    assert result.has_dkim is True
    assert result.dkim_testing_mode is False
    assert result.dkim_weak_key is False

    assert result.has_dmarc is True
    assert result.dmarc_policy == "reject"
    assert result.dmarc_rua is True
    assert result.dmarc_ruf is True
    assert result.dmarc_pct == 50
    assert result.dmarc_sp == "quarantine"
    assert result.dmarc_adkim == "s"
    assert result.dmarc_aspf == "s"
    assert result.dmarc_rua_domains == ["dmarcian.com"]
    assert result.dmarc_ruf_domains == ["secure.ch"]

    assert result.has_bimi is True
    assert result.has_mta_sts is True
    assert result.has_tlsrpt is True
    assert result.has_caa is True
    assert result.caa_records == ['0 issue "letsencrypt.org"']


def test_dkim_with_empty_p_tag_is_not_treated_as_found():
    domain = "revoked.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 mail.somehost.example."]),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        ("default._domainkey." + domain, "TXT"): ("ok", ["v=DKIM1; k=rsa; p="]),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
    })

    result = scan_domain(domain, query)

    assert result.dkim_selectors_found == []
    assert result.has_dkim is False


def test_mx_with_no_downstream_records_leaves_everything_else_false():
    domain = "bare.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 mail.somehost.example."]),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        ("default._domainkey." + domain, "TXT"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
    })

    result = scan_domain(domain, query)

    assert result.mx_provider == "other"
    assert result.dkim_selectors_checked == [
        "default", "selector1", "selector2", "google", "k1", "s1", "s2",
        "mail", "dkim", "smtp", "key1", "mx",
    ]
    assert result.has_spf is False
    assert result.has_dkim is False
    assert result.has_dmarc is False
    assert result.dmarc_policy == "absent"
    assert result.has_bimi is False
    assert result.has_mta_sts is False
    assert result.has_tlsrpt is False
    assert result.has_caa is False


def test_google_workspace_domain_checks_google_selector_only():
    domain = "gws.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["1 aspmx.l.google.com."]),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        (f"google._domainkey.{domain}", "TXT"): (
            "ok", ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB"]),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
    })

    result = scan_domain(domain, query)

    assert result.mx_provider == "google_workspace"
    assert result.dkim_selectors_checked == ["google"]
    assert result.has_dkim is True
    dkim_calls = [c for c in query.calls if "_domainkey" in c[0]]
    assert dkim_calls == [(f"google._domainkey.{domain}", "TXT")]


def test_dkim_weak_key_and_testing_mode_flagged_when_any_selector_shows_them():
    domain = "sloppy-dkim.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 mail.somehost.example."]),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        (domain, "SPF"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        ("default._domainkey." + domain, "TXT"): (
            "ok", ["v=DKIM1; t=y; k=rsa; p=" + "A" * 216]),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
    })
    result = scan_domain(domain, query)

    assert result.has_dkim is True
    assert result.dkim_testing_mode is True
    assert result.dkim_weak_key is True


def test_dkim_accumulator_across_multiple_selectors():
    # Regression test: ensures "ANY selector" accumulation logic (not last-write-wins).
    # Dirty selector (weak key, testing mode) is processed FIRST; clean selector
    # (strong key, no testing mode) is processed LAST. A buggy overwrite
    # (testing_mode_found = dkim_info["testing_mode"] per iteration) would end
    # up with False/False (clean selector's values overwrite), while correct
    # accumulation (if dkim_info[X]: found = True) preserves True from the first.
    domain = "mixed-dkim.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 mail.somehost.example."]),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        (domain, "SPF"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        # Selector 1 (processed first): problematic (weak key, testing mode)
        (f"default._domainkey.{domain}", "TXT"): (
            "ok", ["v=DKIM1; t=y; k=rsa; p=" + "A" * 216]),
        # Selector 2 (processed second/last of the two that resolve): clean
        (f"selector1._domainkey.{domain}", "TXT"): (
            "ok", ["v=DKIM1; k=rsa; p=" + "A" * 392]),
        # Remaining selectors for "other" provider fallback
        (f"selector2._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"google._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"k1._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"s1._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"s2._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"mail._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"dkim._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"smtp._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"key1._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"mx._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
    })
    result = scan_domain(domain, query)

    # Both selectors resolve (default and selector1, in that processing order)
    assert result.has_dkim is True
    assert result.dkim_selectors_found == ["default", "selector1"]
    # Correct accumulation: both issues are True (dirty selector set them first)
    # Buggy overwrite would end up False/False (clean selector, processed last, would overwrite)
    assert result.dkim_testing_mode is True
    assert result.dkim_weak_key is True


def test_dangling_mx_host_is_flagged_unresolvable():
    domain = "abandoned-relay.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 mail.gone-forever.example."]),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        (domain, "SPF"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        ("mail.gone-forever.example", "A"): ("nxdomain", []),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
    })
    result = scan_domain(domain, query)

    assert result.mx_hosts_unresolvable == ["mail.gone-forever.example"]
    assert result.mx_unresolvable is True


def test_ipv6_only_mx_host_is_resolvable_via_aaaa():
    domain = "ipv6-only.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 mail.ipv6only.example."]),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        (domain, "SPF"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        ("mail.ipv6only.example", "A"): ("noanswer", []),
        ("mail.ipv6only.example", "AAAA"): ("ok", ["2001:db8::1"]),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
    })
    result = scan_domain(domain, query)

    assert result.mx_hosts_unresolvable == []
    assert result.mx_unresolvable is False


def test_transient_dns_error_on_mx_host_is_not_flagged_as_dangling():
    # A resolver timeout/error is NOT the same as confirmed non-existence.
    # Treating "error" the same as "nxdomain" would turn ordinary transient
    # DNS failures into false-positive "abandoned mail infra" security
    # findings — especially likely at 2.46M-domain scan concurrency, which
    # is exactly the failure mode the existing error/retry mechanism
    # (dmarc_scanner/db.py's get_done_domains) exists to handle elsewhere.
    domain = "flaky-resolver.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 mail.flaky-resolver.ch."]),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        (domain, "SPF"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        ("mail.flaky-resolver.ch", "A"): ("error", []),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
    })
    result = scan_domain(domain, query)

    assert result.mx_hosts_unresolvable == []
    assert result.mx_unresolvable is False


def test_transient_dns_error_on_aaaa_after_noanswer_a_is_not_flagged_as_dangling():
    # Same principle, the A-noanswer-then-AAAA-fallback path: an error on
    # the AAAA lookup is inconclusive, not confirmation of non-existence.
    domain = "flaky-resolver-aaaa.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 mail.flaky-resolver-aaaa.ch."]),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        (domain, "SPF"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        ("mail.flaky-resolver-aaaa.ch", "A"): ("noanswer", []),
        ("mail.flaky-resolver-aaaa.ch", "AAAA"): ("error", []),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
    })
    result = scan_domain(domain, query)

    assert result.mx_hosts_unresolvable == []
    assert result.mx_unresolvable is False
    assert result.query_statuses["AAAA mail.flaky-resolver-aaaa.ch"] == "error"
    assert result.error == "query_errors: AAAA mail.flaky-resolver-aaaa.ch"


def test_whole_batch_failure_marks_each_check_as_error():
    domain = "batch-failure.ch"

    def query(name, rdtype):
        return ("ok", ["10 mail.batch-failure.ch."]) if rdtype == "MX" else ("noanswer", [])

    def failed_batch(_pairs):
        raise RuntimeError("pool failed")

    result = scan_domain(domain, query, failed_batch)

    assert result.query_statuses["DS batch-failure.ch"] == "error"
    assert result.query_statuses["TXT _dmarc.batch-failure.ch"] == "error"
    assert "DS batch-failure.ch" in result.error


def test_missing_or_malformed_batch_results_are_persisted_as_query_errors():
    domain = "bad-batch.ch"

    def query(name, rdtype):
        return ("ok", ["10 mail.bad-batch.ch."]) if rdtype == "MX" else ("noanswer", [])

    def malformed_batch(pairs):
        return {pairs[0]: "not a DNS response"}

    result = scan_domain(domain, query, malformed_batch)

    assert result.query_statuses["DS bad-batch.ch"] == "error"
    assert result.query_statuses["NS bad-batch.ch"] == "error"
    assert result.query_statuses["TXT _dmarc.bad-batch.ch"] == "error"


def test_non_mapping_batch_result_marks_every_affected_check_as_error():
    domain = "non-mapping-batch.ch"

    def query(name, rdtype):
        return ("ok", ["10 mail.non-mapping-batch.ch."]) if rdtype == "MX" else ("noanswer", [])

    result = scan_domain(domain, query, lambda pairs: [])

    assert result.query_statuses["DS non-mapping-batch.ch"] == "error"
    assert result.query_statuses["TXT _dmarc.non-mapping-batch.ch"] == "error"


def test_tlsa_found_for_mx_host():
    domain = "dane-enabled.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 mail.dane-enabled.ch."]),
        (domain, "DS"): ("ok", ["12345 8 2 ABCDEF"]),
        (domain, "TXT"): ("noanswer", []),
        (domain, "SPF"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        ("mail.dane-enabled.ch", "A"): ("ok", ["203.0.113.5"]),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
        ("_25._tcp.mail.dane-enabled.ch", "TLSA"): ("ok", ["3 1 1 abc123"]),
    })
    result = scan_domain(domain, query)

    assert result.tlsa_hosts_checked == ["mail.dane-enabled.ch"]
    assert result.tlsa_hosts_found == ["mail.dane-enabled.ch"]
    assert result.has_tlsa_record is True


def test_tlsa_absent_when_no_tlsa_record():
    domain = "no-dane.ch"
    query = RecordingQuery({
        (domain, "MX"): ("ok", ["10 mail.no-dane.ch."]),
        (domain, "DS"): ("noanswer", []),
        (domain, "TXT"): ("noanswer", []),
        (domain, "SPF"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("noanswer", []),
        ("mail.no-dane.ch", "A"): ("ok", ["203.0.113.9"]),
        (f"default._bimi.{domain}", "TXT"): ("noanswer", []),
        (f"_mta-sts.{domain}", "TXT"): ("noanswer", []),
        (f"_smtp._tls.{domain}", "TXT"): ("noanswer", []),
        (domain, "CAA"): ("noanswer", []),
        ("_25._tcp.mail.no-dane.ch", "TLSA"): ("noanswer", []),
    })
    result = scan_domain(domain, query)

    assert result.tlsa_hosts_checked == ["mail.no-dane.ch"]
    assert result.tlsa_hosts_found == []
    assert result.has_tlsa_record is False


# --- query_batch integration ---------------------------------------------

def test_scan_domain_uses_provided_query_batch_for_dkim_selectors():
    # When a query_batch is supplied, scan_domain must actually call it for
    # the DKIM selector group (not silently fall back to sequential query()
    # calls for it) — this is the whole point of the parallelization.
    domain = "batch-test.ch"
    query = RecordingQuery({(domain, "MX"): ("ok", ["10 mail.somehost.example."])})
    dkim_batch_calls = []

    def fake_query_batch(pairs):
        result = {}
        for name, rdtype in pairs:
            if "_domainkey." in name:
                dkim_batch_calls.append((name, rdtype))
            result[(name, rdtype)] = ("noanswer", [])
        return result

    scan_domain(domain, query, fake_query_batch)

    expected_selectors = [
        "default", "selector1", "selector2", "google", "k1", "s1", "s2",
        "mail", "dkim", "smtp", "key1", "mx",
    ]
    assert dkim_batch_calls == [
        (f"{s}._domainkey.{domain}", "TXT") for s in expected_selectors
    ]


def test_scan_domain_default_query_batch_derived_from_query_matches_provided_batch_results():
    # Regression: the no-query_batch-provided fallback and an explicit
    # equivalent batch function must produce identical DmarcScanResult
    # objects for the same fixture — the fallback is not a separate code
    # path with separate behavior, just a different execution strategy.
    domain = "secure.ch"
    responses = {
        (domain, "MX"): ("ok", ["10 secure-ch.mail.protection.outlook.com."]),
        (domain, "DS"): ("ok", ["12345 8 2 ABCDEF"]),
        (domain, "TXT"): ("ok", [
            "google-site-verification=abc123",
            "v=spf1 include:spf.protection.outlook.com -all",
        ]),
        (f"selector1._domainkey.{domain}", "TXT"): (
            "ok", ["v=DKIM1; k=rsa; p=" + "A" * 392]),
        (f"selector2._domainkey.{domain}", "TXT"): ("noanswer", []),
        (f"_dmarc.{domain}", "TXT"): ("ok", [
            "v=DMARC1; p=reject; rua=mailto:d@secure.ch; ruf=mailto:f@secure.ch",
        ]),
        (f"default._bimi.{domain}", "TXT"): ("ok", ["v=BIMI1; l=https://secure.ch/logo.svg;"]),
        (f"_mta-sts.{domain}", "TXT"): ("ok", ["v=STSv1; id=20260101000000Z;"]),
        (f"_smtp._tls.{domain}", "TXT"): ("ok", ["v=TLSRPTv1;rua=mailto:tls@secure.ch"]),
        (domain, "CAA"): ("ok", ['0 issue "letsencrypt.org"']),
        ("secure-ch.mail.protection.outlook.com", "A"): ("ok", ["203.0.113.1"]),
        ("_25._tcp.secure-ch.mail.protection.outlook.com", "TLSA"): ("ok", ["3 1 1 abc"]),
    }

    result_no_batch = scan_domain(domain, RecordingQuery(dict(responses)))

    def explicit_batch(pairs):
        q = RecordingQuery(dict(responses))
        return {(n, r): q(n, r) for n, r in pairs}

    result_with_batch = scan_domain(
        domain, RecordingQuery(dict(responses)), explicit_batch
    )

    assert result_no_batch == result_with_batch
