from dmarc_scanner.parsers import (
    find_first, is_bimi_record, is_dkim_record, is_dmarc_record,
    is_mta_sts_record, is_spf_record, is_tlsrpt_record,
    parse_dkim, parse_dmarc, parse_mx_answer, parse_spf,
)


# --- record-type identification -------------------------------------------

def test_is_spf_record():
    assert is_spf_record("v=spf1 -all") is True
    assert is_spf_record("V=SPF1 include:_spf.google.com ~all") is True
    assert is_spf_record("google-site-verification=abc123") is False


def test_is_dmarc_record():
    assert is_dmarc_record("v=DMARC1; p=reject;") is True
    assert is_dmarc_record("v=dmarc1;p=none") is True
    assert is_dmarc_record("v=spf1 -all") is False


def test_is_bimi_record():
    assert is_bimi_record("v=BIMI1; l=https://example.ch/logo.svg;") is True
    assert is_bimi_record("v=spf1 -all") is False


def test_is_mta_sts_record():
    assert is_mta_sts_record("v=STSv1; id=20260101000000Z;") is True
    assert is_mta_sts_record("v=spf1 -all") is False


def test_is_tlsrpt_record():
    assert is_tlsrpt_record("v=TLSRPTv1;rua=mailto:tls-reports@example.ch") is True
    assert is_tlsrpt_record("v=spf1 -all") is False


# --- DKIM: requires a non-empty p= tag (RFC 6376 §3.6.1 — an empty p=
# means the key was revoked, and the v= tag itself is only RECOMMENDED,
# not required, so we can't key off "v=DKIM1" alone) ------------------------

def test_is_dkim_record_true_with_key_material():
    assert is_dkim_record("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB") is True


def test_is_dkim_record_true_without_v_tag():
    assert is_dkim_record("k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB") is True


def test_is_dkim_record_false_when_p_tag_empty_revoked_key():
    assert is_dkim_record("v=DKIM1; k=rsa; p=") is False


def test_is_dkim_record_false_when_p_tag_missing():
    assert is_dkim_record("v=DKIM1; k=rsa") is False


# --- find_first -------------------------------------------------------------

def test_find_first_returns_matching_record_among_others():
    records = [
        "google-site-verification=abc123",
        "v=spf1 include:_spf.google.com ~all",
        "some-other-txt-record",
    ]
    assert find_first(records, is_spf_record) == "v=spf1 include:_spf.google.com ~all"


def test_find_first_returns_none_when_no_match():
    assert find_first(["google-site-verification=abc123"], is_spf_record) is None


# --- parse_mx_answer ---------------------------------------------------------

def test_parse_mx_answer_strips_trailing_dot_and_lowercases():
    assert parse_mx_answer("10 mail.Example.ch.") == (10, "mail.example.ch")


def test_parse_mx_answer_without_trailing_dot():
    assert parse_mx_answer("20 mx2.example.ch") == (20, "mx2.example.ch")


def test_parse_mx_answer_null_mx_yields_empty_host():
    # RFC 7505 null MX: "0 ." — the domain explicitly declares it accepts no
    # mail. Callers (dmarc_scanner/scan.py) must treat an empty host as "no
    # real mail server", not as has_mx=True.
    assert parse_mx_answer("0 .") == (0, "")


# --- parse_spf: all-mechanism strength ---------------------------------------

def test_parse_spf_hardfail():
    assert parse_spf("v=spf1 include:_spf.google.com -all")["all_mechanism"] == "hardfail"


def test_parse_spf_softfail():
    assert parse_spf("v=spf1 include:_spf.google.com ~all")["all_mechanism"] == "softfail"


def test_parse_spf_neutral():
    assert parse_spf("v=spf1 include:_spf.google.com ?all")["all_mechanism"] == "neutral"


def test_parse_spf_pass_all_is_weak():
    assert parse_spf("v=spf1 include:_spf.google.com +all")["all_mechanism"] == "pass"


def test_parse_spf_bare_all_means_pass():
    assert parse_spf("v=spf1 all")["all_mechanism"] == "pass"


def test_parse_spf_no_all_mechanism():
    assert parse_spf("v=spf1 include:_spf.google.com")["all_mechanism"] == "none"


# --- parse_spf: lookup counting ----------------------------------------------

def test_parse_spf_counts_include():
    r = parse_spf("v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all")
    assert r["lookup_count"] == 2


def test_parse_spf_counts_bare_a_and_mx():
    r = parse_spf("v=spf1 a mx -all")
    assert r["lookup_count"] == 2


def test_parse_spf_counts_a_and_mx_with_domain_or_cidr():
    r = parse_spf("v=spf1 a:mail.example.ch mx:example.ch a/24 -all")
    assert r["lookup_count"] == 3


def test_parse_spf_counts_exists_and_redirect():
    r = parse_spf("v=spf1 exists:%{i}._spf.example.ch redirect=_spf.example.ch")
    assert r["lookup_count"] == 2


def test_parse_spf_ip4_ip6_do_not_count():
    r = parse_spf("v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 -all")
    assert r["lookup_count"] == 0


def test_parse_spf_counts_qualified_mechanisms():
    # RFC 7208 §4.6.2: every mechanism may carry a leading qualifier
    # (+ - ~ ?). A qualified mechanism still costs a lookup.
    r = parse_spf(
        "v=spf1 +a -mx +include:_spf.example.ch "
        "~include:spf.protection.outlook.com -all"
    )
    assert r["lookup_count"] == 4


def test_parse_spf_near_limit_flag():
    below = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(7)) + " -all"
    at = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(8)) + " -all"
    assert parse_spf(below)["near_limit"] is False
    assert parse_spf(at)["near_limit"] is True


# --- parse_dmarc --------------------------------------------------------------

def test_parse_dmarc_reject_with_rua_and_ruf():
    r = parse_dmarc("v=DMARC1; p=reject; rua=mailto:d@example.ch; ruf=mailto:f@example.ch")
    assert r["policy"] == "reject"
    assert r["has_rua"] is True
    assert r["has_ruf"] is True


def test_parse_dmarc_none_without_reporting():
    r = parse_dmarc("v=DMARC1; p=none;")
    assert r["policy"] == "none"
    assert r["has_rua"] is False
    assert r["has_ruf"] is False


def test_parse_dmarc_quarantine_case_insensitive_tag():
    r = parse_dmarc("v=DMARC1; P=Quarantine; RUA=mailto:d@example.ch")
    assert r["policy"] == "quarantine"
    assert r["has_rua"] is True


def test_parse_dmarc_missing_policy_tag_is_absent():
    r = parse_dmarc("v=DMARC1; rua=mailto:d@example.ch")
    assert r["policy"] == "absent"


def test_parse_dmarc_pct_defaults_to_100_when_absent():
    r = parse_dmarc("v=DMARC1; p=reject")
    assert r["pct"] == 100


def test_parse_dmarc_pct_parses_explicit_value():
    r = parse_dmarc("v=DMARC1; p=reject; pct=25")
    assert r["pct"] == 25


def test_parse_dmarc_pct_falls_back_to_100_on_garbage_value():
    r = parse_dmarc("v=DMARC1; p=reject; pct=not-a-number")
    assert r["pct"] == 100


def test_parse_dmarc_sp_defaults_to_empty_when_absent():
    r = parse_dmarc("v=DMARC1; p=reject")
    assert r["sp"] == ""


def test_parse_dmarc_sp_parses_explicit_value():
    r = parse_dmarc("v=DMARC1; p=quarantine; sp=reject")
    assert r["sp"] == "reject"


def test_parse_dmarc_alignment_defaults_to_relaxed():
    r = parse_dmarc("v=DMARC1; p=reject")
    assert r["adkim"] == "r"
    assert r["aspf"] == "r"


def test_parse_dmarc_alignment_parses_strict():
    r = parse_dmarc("v=DMARC1; p=reject; adkim=s; aspf=s")
    assert r["adkim"] == "s"
    assert r["aspf"] == "s"


def test_parse_dmarc_extracts_single_rua_domain():
    r = parse_dmarc("v=DMARC1; p=reject; rua=mailto:d@dmarcian.com")
    assert r["rua_domains"] == ["dmarcian.com"]


def test_parse_dmarc_extracts_multiple_rua_domains_and_strips_size_suffix():
    # RFC 7489 §6.2: a reporting URI may carry an optional "!<size>" cap
    # (e.g. "!10m") that must not leak into the extracted domain.
    r = parse_dmarc(
        "v=DMARC1; p=reject; rua=mailto:a@vendor-a.com!10m,mailto:b@example.ch"
    )
    assert r["rua_domains"] == ["vendor-a.com", "example.ch"]


def test_parse_dmarc_extracts_ruf_domain():
    r = parse_dmarc("v=DMARC1; p=reject; ruf=mailto:forensics@vendor-b.net")
    assert r["ruf_domains"] == ["vendor-b.net"]


def test_parse_dmarc_report_domains_empty_when_no_reporting_tags():
    r = parse_dmarc("v=DMARC1; p=none")
    assert r["rua_domains"] == []
    assert r["ruf_domains"] == []


# --- parse_dkim ---------------------------------------------------------

def test_parse_dkim_testing_mode_flag():
    r = parse_dkim("v=DKIM1; t=y; k=rsa; p=" + "A" * 216)
    assert r["testing_mode"] is True


def test_parse_dkim_not_testing_mode_when_tag_absent():
    r = parse_dkim("v=DKIM1; k=rsa; p=" + "A" * 216)
    assert r["testing_mode"] is False


def test_parse_dkim_1024_bit_length_key_flagged_weak():
    # Empirically measured in this session: a 1024-bit RSA
    # SubjectPublicKeyInfo base64-encodes to 216 characters.
    r = parse_dkim("v=DKIM1; k=rsa; p=" + "A" * 216)
    assert r["weak_key"] is True


def test_parse_dkim_2048_bit_length_key_not_flagged_weak():
    # Empirically measured in this session: a 2048-bit RSA
    # SubjectPublicKeyInfo base64-encodes to 392 characters.
    r = parse_dkim("v=DKIM1; k=rsa; p=" + "A" * 392)
    assert r["weak_key"] is False
