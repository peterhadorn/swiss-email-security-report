from dmarc_scanner.providers import dkim_selectors_for_provider, fingerprint_mx_provider


def test_fingerprint_microsoft365():
    hosts = ["example-ch.mail.protection.outlook.com"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "microsoft365"


def test_fingerprint_google_workspace():
    hosts = ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "google_workspace"


def test_fingerprint_hostpoint():
    hosts = ["mx.hostpoint.ch"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "hostpoint"


def test_fingerprint_infomaniak():
    hosts = ["mail.infomaniak.com"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "infomaniak"


def test_fingerprint_cyon():
    hosts = ["mx1.cyon.ch"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "cyon"


def test_fingerprint_vtx_base_domain():
    hosts = ["mx2.vtx.ch"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "vtx"


def test_fingerprint_swizzonic():
    hosts = ["mx.swizzonic.email"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "swizzonic"


def test_fingerprint_netzone():
    hosts = ["mx.netzone.ch", "mx2.netzone.ch"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "netzone"


def test_fingerprint_iway():
    hosts = ["elba.iway.ch", "malta.iway.ch"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "iway"


def test_fingerprint_hosttech():
    hosts = ["mail1.hosttech.eu", "mail2.hosttech.eu"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "hosttech"


def test_fingerprint_tophost():
    hosts = ["mx01.tophost.ch", "mx02.tophost.ch"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "tophost"


def test_fingerprint_is_case_insensitive():
    hosts = ["EXAMPLE-CH.MAIL.PROTECTION.OUTLOOK.COM"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "microsoft365"


def test_fingerprint_self_hosted_when_mx_is_subdomain_of_own_domain():
    hosts = ["mail.example.ch"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "self_hosted"


def test_fingerprint_self_hosted_when_mx_equals_domain():
    hosts = ["example.ch"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "self_hosted"


def test_fingerprint_other_for_unrecognized_third_party():
    hosts = ["mx.somehost.example"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "other"


def test_fingerprint_uses_first_matching_host_in_list():
    hosts = ["mx.somehost.example", "aspmx.l.google.com"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "google_workspace"


def test_fingerprint_does_not_false_positive_on_unrelated_substring_match():
    # "green.ch" must not match "evergreen.ch", "cyon.ch" must not match
    # "halcyon.ch" — matching requires an exact host or a dot-bounded suffix.
    assert fingerprint_mx_provider(["mail.evergreen.ch"], "example.ch") == "other"
    assert fingerprint_mx_provider(["mail.halcyon.ch"], "example.ch") == "other"


def test_fingerprint_prioritizes_primary_mx_over_pattern_table_order():
    # Regression test: mx_hosts must be classified by the primary (first,
    # highest-priority) host, not by whichever provider happens to appear
    # earliest in MX_PROVIDER_PATTERNS. Here the domain's real provider is
    # hostpoint; the Microsoft 365 host is only a secondary/backup relay,
    # and "microsoft365" sits earlier in the table — a naive
    # table-order-first implementation would wrongly return "microsoft365".
    hosts = ["mx1.hostpoint.ch", "mail-relay.mail.protection.outlook.com"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "hostpoint"


def test_fingerprint_self_hosted_primary_outranks_third_party_backup():
    # Same principle, self-hosted case: the domain's own primary MX outranks
    # a third-party backup MX later in the (caller-supplied, priority-order)
    # host list.
    hosts = ["mail.example.ch", "aspmx.l.google.com"]
    assert fingerprint_mx_provider(hosts, "example.ch") == "self_hosted"


def test_dkim_selectors_microsoft365():
    assert dkim_selectors_for_provider("microsoft365") == ["selector1", "selector2"]


def test_dkim_selectors_google_workspace():
    assert dkim_selectors_for_provider("google_workspace") == ["google"]


def test_dkim_selectors_fallback_checks_common_selectors_for_unrecognized_providers():
    common = [
        "default", "selector1", "selector2", "google", "k1", "s1", "s2",
        "mail", "dkim", "smtp", "key1", "mx",
    ]
    assert dkim_selectors_for_provider("hostpoint") == common
    assert dkim_selectors_for_provider("self_hosted") == common
    assert dkim_selectors_for_provider("other") == common
    assert dkim_selectors_for_provider("") == common


def test_dkim_selectors_microsoft365_and_google_unaffected_by_fallback_expansion():
    assert dkim_selectors_for_provider("microsoft365") == ["selector1", "selector2"]
    assert dkim_selectors_for_provider("google_workspace") == ["google"]
