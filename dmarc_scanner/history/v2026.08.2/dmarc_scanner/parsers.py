"""Pure parsing helpers for SPF/DMARC/BIMI/MTA-STS/TLS-RPT/DKIM TXT records.

No network I/O. Operates on already-fetched raw TXT/MX record strings.
"""

from typing import Callable, Optional


def _normalized(text: str) -> str:
    return text.strip().lower().replace(" ", "")


def _parse_tags(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def is_spf_record(text: str) -> bool:
    return text.strip().lower().startswith("v=spf1")


def is_dmarc_record(text: str) -> bool:
    return _normalized(text).startswith("v=dmarc1")


def is_bimi_record(text: str) -> bool:
    return _normalized(text).startswith("v=bimi1")


def is_mta_sts_record(text: str) -> bool:
    return _normalized(text).startswith("v=stsv1")


def is_tlsrpt_record(text: str) -> bool:
    return _normalized(text).startswith("v=tlsrptv1")


def is_dkim_record(text: str) -> bool:
    """True only if a non-empty p= (public key) tag is present.

    The v=DKIM1 tag is RECOMMENDED but not required (RFC 6376 §3.6.1), so we
    can't key off it alone. An empty p= means the key was explicitly revoked
    and must NOT be treated as "DKIM found".
    """
    return bool(_parse_tags(text).get("p"))


# RSA SubjectPublicKeyInfo DER-encodes to a fixed size per key size,
# measured empirically: 1024-bit -> 216 base64 characters, 2048-bit -> 392.
# A p= value shorter than this threshold (comfortably between the two) is
# almost certainly <=1024-bit, below today's minimum-recommended DKIM key
# size. This is a length heuristic, not exact bit-counting — the project's
# existing "rough estimate" pattern (see spf_lookup_count).
_WEAK_DKIM_KEY_B64_THRESHOLD = 250


def parse_dkim(record: str) -> dict:
    """Depth analysis of an already-confirmed DKIM record.

    Callers must have already run is_dkim_record (guarantees a non-empty
    p= tag) before calling this — an empty p= means a revoked key, a
    different concept from "weak key" and out of scope here.
    """
    tags = _parse_tags(record)
    p_value = tags.get("p", "")
    return {
        "testing_mode": tags.get("t", "").lower() == "y",
        "weak_key": 0 < len(p_value) < _WEAK_DKIM_KEY_B64_THRESHOLD,
    }


def find_first(records: list, predicate: Callable[[str], bool]) -> Optional[str]:
    for record in records:
        if predicate(record):
            return record
    return None


def parse_mx_answer(raw: str) -> tuple:
    """'10 mail.Example.ch.' -> (10, 'mail.example.ch')

    RFC 7505 null MX ('0 .') yields an empty host string after stripping the
    trailing dot — callers must treat that as "no real mail server".
    """
    preference_str, host = raw.split(None, 1)
    return int(preference_str), host.rstrip(".").lower()


_ALL_MECHANISMS = {
    "-all": "hardfail",
    "~all": "softfail",
    "?all": "neutral",
    "+all": "pass",
    "all": "pass",
}

_QUALIFIER_CHARS = "+-~?"

# Mechanisms that cost one DNS lookup under RFC 7208 §4.6.4: include, a, mx,
# ptr, exists, and the redirect modifier. ip4/ip6 never do. Every mechanism
# may carry a leading qualifier (+/-/~/?, RFC 7208 §4.6.2), so lookup
# counting strips it before matching.
_LOOKUP_PREFIXES = ("include:", "exists:", "redirect=", "a:", "a/", "mx:", "mx/", "ptr:")
_LOOKUP_BARE_TOKENS = {"a", "mx", "ptr"}


def parse_spf(record: str) -> dict:
    tokens = record.split()
    all_mechanism = "none"
    lookup_count = 0

    for token in tokens:
        tl = token.lower()
        if tl in _ALL_MECHANISMS:
            all_mechanism = _ALL_MECHANISMS[tl]
            continue
        bare = tl[1:] if tl[:1] in _QUALIFIER_CHARS else tl
        if bare in _LOOKUP_BARE_TOKENS or bare.startswith(_LOOKUP_PREFIXES):
            lookup_count += 1

    return {
        "all_mechanism": all_mechanism,
        "lookup_count": lookup_count,
        "near_limit": lookup_count >= 8,
    }


def _extract_report_domains(tag_value: str) -> list:
    """'mailto:a@vendor.com,mailto:b@x.ch!10m' -> ['vendor.com', 'x.ch']

    RFC 7489 §6.2: rua=/ruf= values are comma-separated URIs, each optionally
    suffixed with "!<size>" (a report-size cap) that must be stripped before
    extracting the domain. Handles mailto: (the overwhelming majority in
    practice) and any other scheme://host URI form.
    """
    domains = []
    for uri in tag_value.split(","):
        uri = uri.strip().split("!", 1)[0]
        if uri.lower().startswith("mailto:"):
            addr = uri[len("mailto:"):]
            if "@" in addr:
                domains.append(addr.rsplit("@", 1)[1].lower())
        elif "://" in uri:
            after_scheme = uri.split("://", 1)[1]
            host = after_scheme.split("/", 1)[0]
            if host:
                domains.append(host.lower())
    return domains


def parse_dmarc(record: str) -> dict:
    tags = _parse_tags(record)
    policy = tags.get("p", "").lower() or "absent"
    pct_raw = tags.get("pct", "")
    try:
        pct = int(pct_raw)
    except ValueError:
        pct = 100
    return {
        "policy": policy,
        "has_rua": bool(tags.get("rua")),
        "has_ruf": bool(tags.get("ruf")),
        "pct": pct,
        "sp": tags.get("sp", "").lower(),
        "adkim": tags.get("adkim", "r").lower(),
        "aspf": tags.get("aspf", "r").lower(),
        "rua_domains": _extract_report_domains(tags.get("rua", "")),
        "ruf_domains": _extract_report_domains(tags.get("ruf", "")),
    }
