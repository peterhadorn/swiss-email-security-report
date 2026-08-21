from dmarc_scanner.models import DmarcScanResult
import pytest


def test_default_result_has_safe_defaults():
    result = DmarcScanResult(domain="example.ch")

    assert result.domain == "example.ch"
    assert result.domain_exists is True
    assert result.has_mx is False
    assert result.mx_hosts == []
    assert result.mx_provider == ""
    assert result.has_spf is False
    assert result.spf_record == ""
    assert result.spf_all_mechanism == ""
    assert result.spf_lookup_count == 0
    assert result.spf_near_limit is False
    assert result.has_legacy_spf_rrtype is False
    assert result.dkim_selectors_checked == []
    assert result.dkim_selectors_found == []
    assert result.has_dkim is False
    assert result.dkim_testing_mode is False
    assert result.dkim_weak_key is False
    assert result.has_dmarc is False
    assert result.dmarc_record == ""
    assert result.dmarc_policy == ""
    assert result.dmarc_rua is False
    assert result.dmarc_ruf is False
    assert result.dmarc_pct == 100
    assert result.dmarc_sp == ""
    assert result.dmarc_adkim == "r"
    assert result.dmarc_aspf == "r"
    assert result.dmarc_rua_domains == []
    assert result.dmarc_ruf_domains == []
    assert result.has_ds_record is False
    assert result.ns_hosts == []
    assert result.has_bimi is False
    assert result.bimi_record == ""
    assert result.has_mta_sts is False
    assert result.mta_sts_record == ""
    assert result.has_tlsrpt is False
    assert result.tlsrpt_record == ""
    assert result.has_caa is False
    assert result.caa_records == []
    assert result.has_tlsa_record is False
    assert result.tlsa_hosts_checked == []
    assert result.tlsa_hosts_found == []
    assert result.error == ""
    assert result.mx_hosts_unresolvable == []
    assert result.mx_unresolvable is False
    assert result.query_statuses == {}


def test_legacy_constructor_names_are_not_silently_translated():
    with pytest.raises(TypeError, match="dnssec_signed"):
        DmarcScanResult(domain="example.ch", dnssec_signed=True)

    with pytest.raises(TypeError, match="has_tlsa"):
        DmarcScanResult(domain="example.ch", has_tlsa=True)
