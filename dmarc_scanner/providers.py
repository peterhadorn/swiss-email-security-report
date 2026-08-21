"""MX-hostname provider fingerprinting and DKIM selector strategy.

The MX_PROVIDER_PATTERNS table is best-effort: Microsoft 365 and Google
Workspace MX hostnames are standardized and match reliably; the Swiss
hosting-provider entries are educated guesses at commonly seen MX hostnames
and may need extending once real full-scan data shows which "other"-bucket
hostnames are actually common. mx_hosts is stored raw in the DB precisely so
that reclassification later doesn't require a re-scan.

Matching requires an exact host or a dot-bounded suffix (e.g. "cyon.ch"
matches "mx1.cyon.ch" but not "mail.halcyon.ch") — plain substring matching
would misclassify unrelated hosts that happen to contain a pattern.
"""

# (provider_key, [substrings to match against a lowercased MX hostname])
MX_PROVIDER_PATTERNS = [
    ("microsoft365", ["mail.protection.outlook.com"]),
    ("google_workspace", [
        "aspmx.l.google.com", "aspmx2.googlemail.com", "aspmx3.googlemail.com",
        "aspmx4.googlemail.com", "aspmx5.googlemail.com",
        "alt1.aspmx.l.google.com", "alt2.aspmx.l.google.com",
        "alt3.aspmx.l.google.com", "alt4.aspmx.l.google.com",
        "smtp.google.com",
    ]),
    ("hostpoint", ["hostpoint.ch"]),
    ("infomaniak", ["infomaniak.ch", "infomaniak.com"]),
    ("cyon", ["cyon.ch", "cyon.net"]),
    ("swisscom", ["swisscom.ch", "bluewin.ch"]),
    ("init7", ["init7.net"]),
    ("greench", ["green.ch"]),
    ("vtx", ["vtxmail.ch", "vtxnet.ch", "vtx.ch"]),
    ("metanet", ["metanet.ch"]),
    ("protonmail", ["protonmail.ch", "proton.me"]),
    ("mailbox_org", ["mailbox.org"]),
    ("gmx", ["gmx.net", "gmx.ch"]),
    ("ovh", ["mx.ovh.net", "mx.ovh.com", "mx.ovh.ca"]),
    ("mimecast", ["mimecast.com"]),
    ("proofpoint", ["pphosted.com"]),
    ("barracuda", ["barracudanetworks.com"]),
    ("swizzonic", ["swizzonic.ch", "swizzonic.email"]),
    ("netzone", ["netzone.ch"]),
    ("iway", ["iway.ch"]),
    ("hosttech", ["hosttech.ch", "hosttech.eu"]),
    ("tophost", ["tophost.ch"]),
]

# Best-effort, commonly-observed DKIM selector names across mail systems in
# general (cPanel/Plesk defaults, popular ESPs) — used as the fallback for
# every provider without a verified, documented selector convention of its
# own (i.e. everything except microsoft365/google_workspace below, whose
# selectors are standardized and genuinely known, not guessed). Not
# exhaustive: a domain can use any selector name it wants, and this list
# only catches what's common in practice. Checking N selectors costs N DNS
# queries per domain instead of 1 — see this plan's Global Constraints for
# the query-volume tradeoff at full-scan scale.
_COMMON_DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "k1", "s1", "s2",
    "mail", "dkim", "smtp", "key1", "mx",
]

_DKIM_SELECTORS_BY_PROVIDER = {
    "microsoft365": ["selector1", "selector2"],
    "google_workspace": ["google"],
}


def _host_matches(host: str, pattern: str) -> bool:
    return host == pattern or host.endswith("." + pattern)


def fingerprint_mx_provider(mx_hosts: list, domain: str) -> str:
    """Classify by the highest-priority MX host that matches anything.

    Callers must pass mx_hosts already sorted by MX preference (lowest
    number first) — this trusts host order as priority order and does not
    re-sort. Checking hosts in priority order (not MX_PROVIDER_PATTERNS'
    table order) matters: a domain's primary MX determines its real
    provider, and a secondary/backup MX (a spam-filtering gateway, a
    failover relay) must not outrank it just because that provider happens
    to appear earlier in the table.
    """
    hosts_lower = [h.lower().rstrip(".") for h in mx_hosts]
    domain_lower = domain.lower().rstrip(".")

    for host in hosts_lower:
        for provider, patterns in MX_PROVIDER_PATTERNS:
            if any(_host_matches(host, pattern) for pattern in patterns):
                return provider
        if host == domain_lower or host.endswith(f".{domain_lower}"):
            return "self_hosted"

    return "other"


def dkim_selectors_for_provider(mx_provider: str) -> list:
    return _DKIM_SELECTORS_BY_PROVIDER.get(mx_provider, _COMMON_DKIM_SELECTORS)
