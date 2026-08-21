import dns.exception
import dns.resolver
import pytest

import dmarc_scanner.resolve as resolve_module
from dmarc_scanner.resolve import configure_batch_pool_size, query, query_batch


class FakeTxtRdata:
    """Mimics dnspython TXT rdata: `.strings` is a tuple of byte segments."""

    def __init__(self, *segments):
        self.strings = tuple(s.encode() for s in segments)


class FakeRdata:
    """Mimics any other rdtype: str()'s to the record's text form."""

    def __init__(self, text):
        self._text = text

    def __str__(self):
        return self._text


class FakeResolver:
    def __init__(self, effect):
        self._effect = effect

    def resolve(self, name, rdtype, raise_on_no_answer=True):
        return self._effect(name, rdtype)


def _patch_resolver(monkeypatch, effect):
    monkeypatch.setattr(resolve_module, "_get_thread_resolver", lambda: FakeResolver(effect))


def test_query_ok_txt_joins_multi_segment_strings(monkeypatch):
    _patch_resolver(monkeypatch, lambda name, rdtype: [FakeTxtRdata("v=spf1 ", "~all")])
    status, answers = query("example.ch", "TXT")
    assert status == "ok"
    assert answers == ["v=spf1 ~all"]


def test_query_ok_mx_returns_string_form(monkeypatch):
    _patch_resolver(monkeypatch, lambda name, rdtype: [FakeRdata("10 mail.example.ch.")])
    status, answers = query("example.ch", "MX")
    assert status == "ok"
    assert answers == ["10 mail.example.ch."]


def test_query_nxdomain(monkeypatch):
    def effect(name, rdtype):
        raise dns.resolver.NXDOMAIN()
    _patch_resolver(monkeypatch, effect)
    status, answers = query("does-not-exist.ch", "MX")
    assert status == "nxdomain"
    assert answers == []


def test_query_noanswer(monkeypatch):
    def effect(name, rdtype):
        raise dns.resolver.NoAnswer()
    _patch_resolver(monkeypatch, effect)
    status, answers = query("example.ch", "MX")
    assert status == "noanswer"
    assert answers == []


def test_query_timeout_is_error(monkeypatch):
    def effect(name, rdtype):
        raise dns.exception.Timeout()
    _patch_resolver(monkeypatch, effect)
    status, answers = query("example.ch", "MX")
    assert status == "error"
    assert answers == []


def test_query_unexpected_exception_degrades_to_error(monkeypatch):
    def effect(name, rdtype):
        raise RuntimeError("boom")
    _patch_resolver(monkeypatch, effect)
    status, answers = query("example.ch", "MX")
    assert status == "error"
    assert answers == []


def test_make_resolver_enables_rotation_across_nameservers():
    # Without rotate=True, dnspython always tries nameservers[0] first, so
    # ~all traffic hits one public resolver (1.1.1.1) instead of spreading
    # across the configured list — a self-inflicted rate-limit risk at
    # 250-400 concurrent threads.
    resolver = resolve_module._make_resolver()
    assert resolver.rotate is True


# --- query_batch --------------------------------------------------------

def test_query_batch_empty_list_returns_empty_dict():
    assert query_batch([]) == {}


def test_query_batch_runs_multiple_queries_and_returns_dict_keyed_by_pair(monkeypatch):
    def effect(name, rdtype):
        if rdtype == "MX":
            return [FakeRdata(f"10 mail.{name}.")]
        return [FakeTxtRdata(f"v=spf1 for {name}")]
    _patch_resolver(monkeypatch, effect)

    results = query_batch([("a.ch", "MX"), ("b.ch", "TXT")])

    assert results[("a.ch", "MX")] == ("ok", ["10 mail.a.ch."])
    assert results[("b.ch", "TXT")] == ("ok", ["v=spf1 for b.ch"])


def test_query_batch_preserves_per_pair_status_independently(monkeypatch):
    def effect(name, rdtype):
        if name == "exists.ch":
            return [FakeRdata("10 mail.exists.ch.")]
        raise dns.resolver.NXDOMAIN()
    _patch_resolver(monkeypatch, effect)

    results = query_batch([("exists.ch", "MX"), ("missing.ch", "MX")])

    assert results[("exists.ch", "MX")] == ("ok", ["10 mail.exists.ch."])
    assert results[("missing.ch", "MX")] == ("nxdomain", [])


def test_configure_batch_pool_size_updates_before_pool_created(monkeypatch):
    monkeypatch.setattr(resolve_module, "_batch_pool", None)
    original_size = resolve_module._BATCH_POOL_SIZE
    try:
        configure_batch_pool_size(123)
        assert resolve_module._BATCH_POOL_SIZE == 123
    finally:
        resolve_module._BATCH_POOL_SIZE = original_size


def test_configure_batch_pool_size_raises_once_pool_already_created(monkeypatch):
    monkeypatch.setattr(resolve_module, "_batch_pool", object())
    with pytest.raises(RuntimeError):
        configure_batch_pool_size(456)


def test_query_batch_runs_concurrently_not_sequentially(monkeypatch):
    # If each query blocked for 0.2s and query_batch ran them sequentially,
    # 20 queries would take >=4s. Concurrent execution keeps it well under
    # that — this is the actual behavior query_batch exists to provide.
    import time

    def effect(name, rdtype):
        time.sleep(0.2)
        return [FakeRdata("10 mail.example.ch.")]
    _patch_resolver(monkeypatch, effect)

    pairs = [(f"selector{i}.example.ch", "MX") for i in range(20)]
    start = time.monotonic()
    results = query_batch(pairs)
    elapsed = time.monotonic() - start

    assert len(results) == 20
    assert elapsed < 2.0
