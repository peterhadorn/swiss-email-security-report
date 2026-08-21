"""Data model for the passive DNS email-security scan."""

from dataclasses import dataclass, field


@dataclass
class DmarcScanResult:
    domain: str

    # Existence / MX
    domain_exists: bool = True
    has_mx: bool = False
    mx_hosts: list = field(default_factory=list)
    mx_provider: str = ""  # microsoft365, google_workspace, hostpoint, infomaniak,
                            # cyon, self_hosted, other, "" (no MX)
    # Which mx_hosts entries have neither an A nor an AAAA record — abandoned
    # mail infra and a potential subdomain-takeover surface, not just an
    # adoption stat.
    mx_hosts_unresolvable: list = field(default_factory=list)
    mx_unresolvable: bool = False  # True if mx_hosts_unresolvable is non-empty

    # SPF
    has_spf: bool = False
    spf_record: str = ""
    spf_all_mechanism: str = ""  # hardfail, softfail, neutral, pass, none
    # Top-level mechanism count only — does NOT recursively resolve include:/
    # redirect= chains, so a domain can exceed the real RFC 7208 10-lookup
    # limit while spf_near_limit stays False. Rough estimate, by design.
    spf_lookup_count: int = 0
    spf_near_limit: bool = False  # True if spf_lookup_count >= 8
    # RFC 7208 obsoleted the dedicated SPF RR type (99) in favor of TXT-only
    # — True means the domain still publishes the deprecated format.
    has_legacy_spf_rrtype: bool = False

    # DKIM (provider-aware selector guess only)
    dkim_selectors_checked: list = field(default_factory=list)
    dkim_selectors_found: list = field(default_factory=list)
    has_dkim: bool = False
    # True if ANY found selector shows the issue — a domain can have
    # multiple valid selectors, and "at least one problem exists somewhere"
    # matches the security-audit framing of the rest of this scanner.
    dkim_testing_mode: bool = False
    dkim_weak_key: bool = False

    # DMARC
    has_dmarc: bool = False
    dmarc_record: str = ""
    # none, quarantine, reject, or "absent" — "absent" covers both "no DMARC
    # record found at all" and "record found but missing its p= tag".
    dmarc_policy: str = ""
    dmarc_rua: bool = False
    dmarc_ruf: bool = False
    dmarc_pct: int = 100  # RFC 7489 default when pct= is absent
    dmarc_sp: str = ""  # subdomain policy; "" means "inherits p=" (tag absent)
    dmarc_adkim: str = "r"  # DKIM alignment mode: r=relaxed (default), s=strict
    dmarc_aspf: str = "r"  # SPF alignment mode: r=relaxed (default), s=strict
    dmarc_rua_domains: list = field(default_factory=list)  # domains rua= reports go to
    dmarc_ruf_domains: list = field(default_factory=list)  # domains ruf= reports go to

    # DNSSEC
    dnssec_signed: bool = False

    # Nameservers — checked unconditionally like DNSSEC, since neither is
    # mail-specific. Stored raw; reclassify by provider later via UPDATE,
    # same "store raw, no re-scan needed" philosophy as mx_hosts.
    ns_hosts: list = field(default_factory=list)

    # BIMI / MTA-STS / TLS-RPT
    has_bimi: bool = False
    bimi_record: str = ""
    has_mta_sts: bool = False
    mta_sts_record: str = ""
    has_tlsrpt: bool = False
    tlsrpt_record: str = ""

    # CAA
    has_caa: bool = False
    caa_records: list = field(default_factory=list)

    # TLSA / DANE for SMTP — checked at _25._tcp.<mx_host> for each MX host.
    # The DNSSEC-anchored sibling of MTA-STS (same goal: enforce TLS on
    # inbound mail), fully passive-DNS-checkable unlike MTA-STS's *mode*
    # (which needs an HTTPS fetch and stays out of scope).
    has_tlsa: bool = False
    tlsa_hosts_checked: list = field(default_factory=list)
    tlsa_hosts_found: list = field(default_factory=list)

    # Error — non-empty means a DNS query failed for this domain; excluded
    # from the resume "done" set (see dmarc_scanner/db.py) so it gets retried.
    error: str = ""
