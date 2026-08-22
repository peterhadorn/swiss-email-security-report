"""Stage and seal the aggregate-only v2026.08.2 research release.

This module is the audited boundary between private scanner state and public
artifacts. Staging validates a pinned manifest chain and reads the final
SQLite database exactly once, inside one explicit read snapshot. Finalizing
is separate and requires reviewed figures, documents, licences, citation
metadata, and a registered DOI.
"""

from __future__ import annotations

import argparse
import base64
import csv
from dataclasses import dataclass
from decimal import Decimal
from functools import cache
import hashlib
import html
import ipaddress
from io import BytesIO
import json
import mimetypes
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
from typing import Any, Iterable, Mapping, Sequence
import unicodedata
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

from jsonschema import Draft202012Validator, FormatChecker
from PIL import Image, UnidentifiedImageError

from dmarc_scanner.db import EXPECTED_COLUMNS
from dmarc_scanner.provenance import (
    ACTIVE_V1_ROOT_REVISION,
    FRESH_MODE,
    MANIFEST_SCHEMA_VERSION,
    MEASUREMENT_CORE_ALGORITHM,
    MEASUREMENT_CORE_FILES,
    RESUME_MODE,
    URI_SAFETY_CORE_TRANSITION,
    V1_ROOT_CORE_ATTESTATIONS,
    _load_manifest_bytes,
    _parse_utc_timestamp,
    _validate_v1_root,
    _validate_v2,
)
from release.aggregate import KNOWN_PROVIDERS, aggregate_connection, validate_metrics
from release.metric import Metric


RELEASE_VERSION = "v2026.08.2"
CANONICAL_REPOSITORY_URL = "https://github.com/peterhadorn/swiss-email-security-report"
CORRECTION_POLICY_URL = "https://ki-barometer.ch/datasets/ch-email-security-2026/corrections/"
EDITORIAL_REVIEW_SCOPE = "all-reviewed-public-content-and-stable-release-semantics-v1"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
RESULTS_TABLE = "dmarc_scan_results"

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config" / f"{RELEASE_VERSION}.json"
SCHEMA_DIRECTORY = HERE / "schema"
FIGURE_FONT_PATH = HERE.parent / "figures" / "fonts" / "DMSans-Variable.ttf"
FIGURE_FONT_SHA256 = "8cd08d97e89c24d0aa92edd2f0f4c8ee6195eee9b7c9f154865a58b02f0c1c0d"
FIGURE_FONT_FAMILY = "DMSansEmbedded"
CONFIG_SCHEMA_PATH = SCHEMA_DIRECTORY / "release-config.schema.json"
METRICS_SCHEMA_PATH = SCHEMA_DIRECTORY / "metrics.schema.json"
ATTESTATION_SCHEMA_PATH = SCHEMA_DIRECTORY / "aggregate-attestation.schema.json"
RELEASE_SCHEMA_PATH = SCHEMA_DIRECTORY / "release.schema.json"
FIGURES_SCHEMA_PATH = SCHEMA_DIRECTORY / "figures-manifest.schema.json"
DOI_RESERVATION_SCHEMA_PATH = SCHEMA_DIRECTORY / "doi-reservation.schema.json"
CITATION_SCHEMA_PATH = SCHEMA_DIRECTORY / "citation-cff.schema.json"
EDITORIAL_SIGNOFF_SCHEMA_PATH = SCHEMA_DIRECTORY / "editorial-signoff.schema.json"
CODE_LICENSE_PATH = HERE.parent / "LICENSE"
DATA_LICENSE_PATH = HERE / "LICENSE-DATA.md"

STAGING_DIRECTORY_NAME = f".{RELEASE_VERSION}.staging"
FINAL_DIRECTORY_NAME = RELEASE_VERSION
STAGING_FILES = frozenset({
    "metrics.json", "metrics.csv", "aggregate-attestation.json", "release.json",
})
RESERVED_STAGING_FILES = STAGING_FILES | {"doi-reservation.json", "doi-approval-public.der"}
REQUIRED_FINAL_FILES = frozenset({
    "metrics.json", "metrics.csv", "aggregate-attestation.json", "release.json",
    "doi-reservation.json", "doi-approval-public.der", "figures/manifest.json", "CITATION.cff", "LICENSE",
    "LICENSE-DATA.md", "DATA-DICTIONARY.md", "METHODOLOGY.md", "CORRECTIONS.md",
    "README.md", "RELEASE-NOTES.md", "EDITORIAL-SIGNOFF.json",
})
PRIVATE_EXTENSIONS = frozenset({".db", ".sqlite", ".sqlite3", ".wal", ".journal"})
PUBLIC_METRIC_FIELDS = frozenset({
    "metric_id", "category", "numerator", "denominator", "denominator_metric_id",
    "percentage", "display_percentage", "precision", "population", "unit",
    "measurement_period", "method", "caveat",
})

FIGURE_LOCALES = ("de", "fr", "it")
FIGURE_SOURCE_LABELS = {
    "de": "Quelle: Snapshot der SWITCH-Zone .ch vom 12.04.2026.",
    "fr": "Source : instantané de la zone .ch de SWITCH du 12.04.2026.",
    "it": "Fonte: istantanea della zona .ch di SWITCH del 12.04.2026.",
}
# Kept as a deterministic compatibility label for non-localized catalogue text.
FIGURE_SOURCE_LABEL = FIGURE_SOURCE_LABELS["de"]
PROVIDER_FINGERPRINT_CAVEAT = (
    "MX provider classifications are hostname fingerprints, not market-share measurements."
)
FIGURE_SPECS: dict[str, dict[str, Any]] = {
    "mail-authentication-overview": {
        "family": "authentication-adoption", "kind": "chart", "dimensions": (1600, 900),
        "metric_ids": ("mx.present", "spf.present", "dkim.selector_observed", "dmarc.detected"),
        "denominator_metric_ids": ("population.analyzable", "mx.present", "mx.present", "mx.present"),
        "caption_signal": "Passive DNS observations; presence is not end-to-end validation.",
    },
    "dmarc-policy-observations": {
        "family": "dmarc-policy", "kind": "chart", "dimensions": (1600, 900),
        "metric_ids": ("dmarc.reject", "dmarc.quarantine", "dmarc.none", "dmarc.no_supported_effective_policy"),
        "denominator_metric_ids": ("mx.present", "mx.present", "mx.present", "mx.present"),
        "caption_signal": "Published DMARC tags do not prove operational enforcement.",
    },
    "dns-transport-signals": {
        "family": "dns-and-transport", "kind": "chart", "dimensions": (1600, 900),
        "metric_ids": ("tlsa.record_present", "bimi.record_present", "mta_sts.txt_present", "tls_rpt.record_present"),
        "denominator_metric_ids": ("mx.present", "mx.present", "mx.present", "mx.present"),
        "caption_signal": "Record presence is not DANE, BIMI, MTA-STS, or TLS-RPT validation.",
    },
    "mx-provider-fingerprints": {
        "family": "mx-provider-fingerprint", "kind": "chart", "dimensions": (1600, 900),
        "metric_ids": (
            "mx.provider.hostpoint", "mx.provider.infomaniak", "mx.provider.microsoft365",
            "mx.provider.google_workspace", "mx.provider.self_hosted", "mx.provider.other",
            "mx.provider.unknown",
        ),
        "denominator_metric_ids": ("mx.present",) * 7,
        "caption_signal": "MX hostname fingerprints, not market share.",
        "required_caveat": PROVIDER_FINGERPRINT_CAVEAT,
    },
    "social-report-card": {
        "family": "report-card", "kind": "social", "dimensions": (1200, 630),
        "metric_ids": ("mx.present", "spf.present", "dkim.selector_observed", "dmarc.detected"),
        "denominator_metric_ids": ("population.analyzable", "mx.present", "mx.present", "mx.present"),
        "caption_signal": "Aggregate observations with metric-specific denominators and caveats.",
    },
}
EXPECTED_FIGURE_COUNT = len(FIGURE_SPECS) * len(FIGURE_LOCALES) * 2

# These are deliberately reviewable templates, rather than free-form figure
# copy.  Values are injected only from the validated aggregate payload.
APPROVED_FIGURE_TITLES = {
    "mail-authentication-overview": {"de": "Überblick E-Mail-Authentifizierung", "fr": "Vue d’ensemble de l’authentification e-mail", "it": "Panoramica dell’autenticazione e-mail"},
    "dmarc-policy-observations": {"de": "Beobachtete DMARC-Richtlinien", "fr": "Politiques DMARC observées", "it": "Politiche DMARC osservate"},
    "dns-transport-signals": {"de": "DNS- und Transport-Signale", "fr": "Signaux DNS et transport", "it": "Segnali DNS e trasporto"},
    "mx-provider-fingerprints": {"de": "MX-Provider-Fingerprints", "fr": "Empreintes des fournisseurs MX", "it": "Impronte dei fornitori MX"},
    "social-report-card": {"de": "Schweizer E-Mail-Sicherheitsbericht", "fr": "Rapport suisse sur la sécurité e-mail", "it": "Rapporto svizzero sulla sicurezza e-mail"},
}
APPROVED_FIGURE_DESCRIPTIONS = {
    "mail-authentication-overview": {
        "de": "Vier passive Beobachtungen zur E-Mail-Authentifizierung, jeweils mit dem für die Kennzahl gültigen Nenner.",
        "fr": "Quatre observations passives de l’authentification e-mail, chacune avec le dénominateur propre à l’indicateur.",
        "it": "Quattro osservazioni passive sull’autenticazione e-mail, ciascuna con il denominatore specifico dell’indicatore.",
    },
    "dmarc-policy-observations": {
        "de": "Beobachtete DMARC-Richtlinien bei auswertbaren Domains mit einem nicht-null MX-Eintrag.",
        "fr": "Politiques DMARC observées parmi les domaines analysables dotés d’un enregistrement MX non nul.",
        "it": "Politiche DMARC osservate tra i domini analizzabili con un record MX non nullo.",
    },
    "dns-transport-signals": {
        "de": "Beobachtung ausgewählter TLSA-, BIMI-, MTA-STS- und TLS-RPT-Einträge ohne Ende-zu-Ende-Validierung.",
        "fr": "Observation d’enregistrements TLSA, BIMI, MTA-STS et TLS-RPT sélectionnés, sans validation de bout en bout.",
        "it": "Osservazione di record TLSA, BIMI, MTA-STS e TLS-RPT selezionati, senza validazione end-to-end.",
    },
    "mx-provider-fingerprints": {
        "de": "Beobachtete MX-Hostname-Fingerprints; keine Messung von Marktanteilen oder Kundenbeziehungen.",
        "fr": "Observation d’empreintes de noms d’hôtes MX, sans mesure des parts de marché ni des relations commerciales.",
        "it": "Osservazione delle impronte dei nomi host MX, senza misurare quote di mercato o rapporti commerciali.",
    },
    "social-report-card": {
        "de": "Kompakte Übersicht über vier aggregierte Beobachtungen des Schweizer E-Mail-Sicherheitsberichts.",
        "fr": "Aperçu compact de quatre observations agrégées du rapport suisse sur la sécurité e-mail.",
        "it": "Sintesi compatta di quattro osservazioni aggregate del rapporto svizzero sulla sicurezza e-mail.",
    },
}
APPROVED_FIGURE_CAVEATS = {
    "mail-authentication-overview": {
        "de": "Passive DNS-Beobachtung; die DKIM-Kennzahl ist eine selectorabhängige Untergrenze.",
        "fr": "Observation DNS passive ; l’indicateur DKIM est une borne inférieure dépendante des sélecteurs testés.",
        "it": "Osservazione DNS passiva; l’indicatore DKIM è un limite inferiore dipendente dai selettori verificati.",
    },
    "dmarc-policy-observations": {
        "de": "Veröffentlichte DMARC-Tags belegen keine tatsächliche operative Durchsetzung.",
        "fr": "Les balises DMARC publiées ne prouvent pas une application opérationnelle effective.",
        "it": "I tag DMARC pubblicati non dimostrano un’applicazione operativa effettiva.",
    },
    "dns-transport-signals": {
        "de": "Die Präsenz eines Eintrags ist kein Nachweis für DANE-, BIMI-, MTA-STS- oder TLS-RPT-Funktionalität.",
        "fr": "La présence d’un enregistrement ne valide ni DANE, ni BIMI, ni le fonctionnement de MTA-STS ou TLS-RPT.",
        "it": "La presenza di un record non convalida DANE, BIMI o il funzionamento di MTA-STS o TLS-RPT.",
    },
    "mx-provider-fingerprints": {
        "de": "Hostname-Fingerprints sind keine Marktanteils- oder Vertragsmessung.",
        "fr": "Les empreintes de noms d’hôtes ne mesurent ni les parts de marché ni les relations contractuelles.",
        "it": "Le impronte dei nomi host non misurano quote di mercato o rapporti contrattuali.",
    },
    "social-report-card": {
        "de": "Aggregierte Beobachtungen mit kennzahlspezifischen Nennern; keine Ende-zu-Ende-Validierung.",
        "fr": "Observations agrégées avec dénominateurs propres à chaque indicateur ; aucune validation de bout en bout.",
        "it": "Osservazioni aggregate con denominatori specifici per indicatore; nessuna validazione end-to-end.",
    },
}
APPROVED_LOCALIZED_INTERVAL = {
    "de": "Messzeitraum", "fr": "Période de mesure", "it": "Periodo di misurazione",
}
SAFE_PUBLIC_DOMAINS = frozenset({
    "github.com", "doi.org", "creativecommons.org", "ki-barometer.ch", "www.w3.org",
})
APPROVED_PUBLIC_IPS = frozenset({"1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"})
UNICODE_DOMAIN_RE = re.compile(
    r"(?<![\w-])(?:[^\W_](?:[\w-]{0,61}[^\W_])?\.)+"
    r"[^\W_](?:[\w-]{0,61}[^\W_])?(?![\w-])",
    re.UNICODE,
)
ASCII_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
ASCII_DNS_TLD_RE = re.compile(r"^(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})$", re.I)
SHA_LIKE_HEX_RE = re.compile(
    r"(?<![0-9a-f])(?:[0-9a-f]{128}|[0-9a-f]{96}|[0-9a-f]{64}|[0-9a-f]{40})(?![0-9a-f])",
    re.I,
)
IP_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9A-Fa-f:.])"
    r"|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
ENCODED_IPV4_RE = re.compile(
    r"(?<![0-9A-Za-z.])(?:0x[0-9a-f]{8}|0[0-7]{10,11})(?![0-9A-Za-z.])"
    r"|(?<![0-9A-Za-z.])(?:0x[0-9a-f]{1,2}\.){3}0x[0-9a-f]{1,2}(?![0-9A-Za-z.])",
    re.I,
)
DECIMAL_IPV4_RE = re.compile(r"(?<![0-9A-Za-z.])[1-9][0-9]{7,9}(?![0-9A-Za-z.])")
ABSOLUTE_POSIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9:/.])/{1,}(?:[A-Za-z0-9._~-]+(?:/{1,}[A-Za-z0-9._~-]+)*)",
)
ABSOLUTE_WINDOWS_PATH_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]+[^\s<>\"']+")
FILE_URI_RE = re.compile(r"\bfile\s*:[\\/]+", re.I)
RAW_DNS_RECORD_RE = re.compile(
    r"(?:\bv\s*=\s*(?:spf1|dmarc1|dkim1|bimi1|stsv1|tlsrptv1)\b"
    r"|\bversion\s*:\s*stsv1\b|\bru[af]\s*=\s*(?:mailto:|https?://))",
    re.I,
)
PRIVATE_FIELD_RE = re.compile(
    r"(?:query_statuses|ns_hosts|mx_hosts|spf_record|dkim_selectors|dmarc_record|"
    r"rua_domains|ruf_domains|bimi_record|mta_sts_record|tlsrpt_record|caa_records|tlsa_hosts)",
    re.I,
)


def _normalize_public_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    for _attempt in range(4):
        decoded = html.unescape(unquote(normalized))
        if decoded == normalized:
            break
        normalized = decoded
    normalized = normalized.translate(str.maketrans({
        "∕": "/", "⁄": "/", "。": ".", "．": ".", "｡": ".",
    }))
    normalized = re.sub(r"\\+([/])", r"\1", normalized)
    return normalized


def _domain_like_values(value: str) -> Iterable[tuple[str, str]]:
    normalized = _normalize_public_text(value)
    for match in UNICODE_DOMAIN_RE.finditer(normalized):
        raw = match.group(0)
        try:
            labels = [label.encode("idna").decode("ascii").casefold() for label in raw.split(".")]
        except UnicodeError:
            continue
        if (
            len(".".join(labels)) <= 253
            and all(ASCII_DNS_LABEL_RE.fullmatch(label) for label in labels[:-1])
            and ASCII_DNS_TLD_RE.fullmatch(labels[-1])
        ):
            yield raw, ".".join(labels)


def _numeric_ipv4_component(value: str) -> int:
    if value.casefold().startswith("0x"):
        return int(value[2:], 16)
    if len(value) > 1 and value.startswith("0"):
        return int(value, 8)
    return int(value, 10)


def _is_noncanonical_ipv4_host(host: str) -> bool:
    if re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", host):
        try:
            return str(ipaddress.ip_address(host)) != host
        except ValueError:
            return True
    if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){1,3}", host, re.I):
        parts = host.split(".")
        try:
            values = [_numeric_ipv4_component(part) for part in parts]
        except ValueError:
            return False
        limits = {
            2: (0xFF, 0xFFFFFF),
            3: (0xFF, 0xFF, 0xFFFF),
            4: (0xFF, 0xFF, 0xFF, 0xFF),
        }.get(len(values))
        return limits is not None and all(value <= limit for value, limit in zip(values, limits, strict=True))
    return False


def _encoded_ipv4_url_host(value: str) -> str | None:
    for candidate in re.findall(r"https?://[^\s<>\"']+", value, re.I):
        try:
            host = urlsplit(candidate).hostname
        except ValueError:
            continue
        if host and _is_noncanonical_ipv4_host(host):
            return host
    return None


def _locale_payload(locale: str) -> Mapping[str, Any]:
    payload = _load_json(HERE / "locales" / f"{locale}.json", f"{locale} figure locale")
    if set(payload) != {"locale", "categories", "labels"} or payload["locale"] != locale:
        raise ValueError("figure locale catalogue structure differs from the reviewed contract")
    if not isinstance(payload["labels"], dict) or not all(
        isinstance(key, str) and isinstance(value, str) and value.strip()
        for key, value in payload["labels"].items()
    ):
        raise ValueError("figure locale catalogue contains an invalid metric label")
    return payload


def _localized_number(value: str | int, locale: str) -> str:
    rendered = str(value)
    if locale in FIGURE_LOCALES:
        rendered = rendered.replace(".", ",")
    return rendered


def _approved_figure_copy(
    chart_id: str, locale: str, metrics: Sequence[Metric], release: Mapping[str, Any], doi: str,
) -> dict[str, str]:
    specification = FIGURE_SPECS[chart_id]
    selected = [next(metric for metric in metrics if metric.metric_id == metric_id) for metric_id in specification["metric_ids"]]
    title = APPROVED_FIGURE_TITLES[chart_id][locale]
    description = APPROVED_FIGURE_DESCRIPTIONS[chart_id][locale]
    labels = _locale_payload(locale)["labels"]
    values = " · ".join(
        f"{labels[metric.metric_id]}: {_localized_number(metric.display_percentage, locale)} % "
        f"({metric.numerator}/{metric.denominator})"
        for metric in selected
    )
    caveat = APPROVED_FIGURE_CAVEATS[chart_id][locale]
    source = FIGURE_SOURCE_LABELS[locale]
    interval = release["measurement_interval"]
    if chart_id == "social-report-card":
        caption = f"{values}. {caveat} {source} DOI: {doi}."
    else:
        caption = (
            f"{values}. {caveat} {APPROVED_LOCALIZED_INTERVAL[locale]}: "
            f"{interval['started_at_utc']}–{interval['finished_at_utc']}. "
            f"{source} CC BY 4.0. DOI: {doi}."
        )
    return {"title": title, "description": description, "caption": caption}


def _assert_safe_public_text(
    value: str, description: str, *, allowed_domain_like: Iterable[str] = (),
    allowed_hash_lengths: Iterable[int] = (), allowed_ips: Iterable[str] = (),
    allow_decimal_integer: bool = False,
) -> None:
    normalized = _normalize_public_text(value)
    if PRIVATE_FIELD_RE.search(normalized):
        raise ValueError(f"{description} contains private scanner material")
    if RAW_DNS_RECORD_RE.search(normalized):
        raise ValueError(f"{description} contains a raw DNS record payload")
    if (
        FILE_URI_RE.search(normalized)
        or ABSOLUTE_WINDOWS_PATH_RE.search(normalized)
        or ABSOLUTE_POSIX_PATH_RE.search(normalized.replace("\\", "/"))
    ):
        raise ValueError(f"{description} contains an absolute filesystem path")
    permitted_hash_lengths = frozenset(allowed_hash_lengths)
    if SHA_LIKE_HEX_RE.search(normalized) and not (
        len(normalized) in permitted_hash_lengths
        and re.fullmatch(rf"[0-9a-f]{{{len(normalized)}}}", normalized)
    ):
        raise ValueError(f"{description} contains a raw hash (SHA-like hex) outside an approved field")
    permitted = {
        ascii_domain
        for item in allowed_domain_like
        for _raw, ascii_domain in _domain_like_values(item)
    }
    for domain, ascii_domain in _domain_like_values(normalized):
        if ascii_domain not in permitted:
            raise ValueError(f"{description} contains an unapproved domain-like string: {domain}")
    permitted_ips = frozenset(allowed_ips)
    if ENCODED_IPV4_RE.search(normalized):
        raise ValueError(f"{description} contains a noncanonical IP address encoding")
    encoded_url_host = _encoded_ipv4_url_host(normalized)
    if encoded_url_host is not None:
        raise ValueError(
            f"{description} contains a noncanonical IP address URL host: {encoded_url_host}",
        )
    for match in DECIMAL_IPV4_RE.finditer(normalized):
        if (
            16_777_216 <= int(match.group(0)) <= 4_294_967_295
            and not (allow_decimal_integer and match.group(0) == normalized)
        ):
            raise ValueError(f"{description} contains a decimal IP address encoding")
    for candidate in IP_CANDIDATE_RE.findall(normalized):
        try:
            parsed = str(ipaddress.ip_address(candidate))
        except ValueError:
            if "." in candidate:
                raise ValueError(f"{description} contains a noncanonical IP address: {candidate}")
            continue
        if parsed not in permitted_ips:
            raise ValueError(f"{description} contains an unapproved IP address: {candidate}")


PUBLIC_HASH_FIELDS: Mapping[str, frozenset[tuple[str, ...]]] = {
    "release.json": frozenset({
        ("source_universe", "normalized_sha256"),
        ("measurement_core", "root_sha256"), ("measurement_core", "final_sha256"),
        ("measurement_core", "transition", "attestation_id"),
        ("measurement_core", "transition", "from_measurement_core_sha256"),
        ("measurement_core", "transition", "to_measurement_core_sha256"),
        ("measurement_core", "transition", "old_file_sha256"),
        ("measurement_core", "transition", "new_file_sha256"),
        ("run_chain", "*", "run_identifier"), ("run_chain", "*", "manifest_sha256"),
        ("run_chain", "*", "measurement_core_sha256"),
        ("aggregate_files", "*", "sha256"), ("doi_reservation_file", "sha256"),
        ("inventory", "*", "sha256"),
    }),
    "aggregate-attestation.json": frozenset({
        ("source_input_normalized_sha256",), ("root_measurement_core_sha256",),
        ("final_measurement_core_sha256",), ("measurement_core_transition_attestation_id",),
        ("final_run_identifier",), ("final_manifest_sha256",), ("final_database_sha256",),
        ("metric_files", "*", "sha256"),
    }),
    "doi-reservation.json": frozenset({
        ("external_verification", "public_key_fingerprint_sha256"),
    }),
    "figures/manifest.json": frozenset({
        ("figures", "*", "source_snapshot_sha256"), ("figures", "*", "sha256"),
    }),
    "EDITORIAL-SIGNOFF.json": frozenset({
        ("reviewed_artifact_root_sha256",),
        ("external_verification", "public_key_fingerprint_sha256"),
    }),
}
PUBLIC_GIT_REVISION_FIELDS: Mapping[str, frozenset[tuple[str, ...]]] = {
    "release.json": frozenset({("run_chain", "*", "scanner_git_revision")}),
}
PUBLIC_OPAQUE_FIELDS: Mapping[str, frozenset[tuple[str, ...]]] = {
    "doi-reservation.json": frozenset({("external_verification", "signature_base64")}),
    "EDITORIAL-SIGNOFF.json": frozenset({("external_verification", "signature_base64")}),
}
PUBLIC_NUMERIC_FIELDS: Mapping[str, frozenset[tuple[str, ...]]] = {
    "release.json": frozenset({
        ("source_universe", "normalized_line_count"),
        ("aggregate_row_accounting", "*"), ("metric_count",),
        ("run_chain", "*", "sequence"), ("run_chain", "*", "manifest_schema_version"),
        ("run_chain", "*", "attempted_input_count"),
        ("run_chain", "*", "database_pre", "*"),
        ("run_chain", "*", "database_post", "*"),
        ("aggregate_files", "*", "bytes"), ("doi_reservation_file", "bytes"),
        ("inventory", "*", "bytes"),
    }),
    "metrics.json": frozenset({
        ("metrics", "*", "numerator"), ("metrics", "*", "denominator"),
        ("metrics", "*", "precision"),
    }),
    "aggregate-attestation.json": frozenset({
        ("source_input_normalized_line_count",), ("final_database_size_bytes",),
        ("metric_count",), ("metric_files", "*", "bytes"),
    }),
    "doi-reservation.json": frozenset({
        ("record_id",), ("external_verification", "verification_version"),
    }),
    "figures/manifest.json": frozenset({
        ("manifest_version",), ("figures", "*", "width"),
        ("figures", "*", "height"), ("figures", "*", "bytes"),
    }),
    "EDITORIAL-SIGNOFF.json": frozenset({
        ("signoff_version",), ("reviewed_artifact_count",),
        ("external_verification", "verification_version"),
    }),
}
PUBLIC_IP_FIELDS: Mapping[str, frozenset[tuple[str, ...]]] = {
    "release.json": frozenset({("resolver_configuration", "nameservers", "*")}),
}
PUBLIC_DOMAIN_FIELDS: Mapping[str, frozenset[tuple[str, ...]]] = {
    "release.json": frozenset({
        ("measurement_core", "files", "*"),
        ("measurement_core", "transition", "changed_file"),
        ("aggregate_files", "*", "name"), ("doi_reservation_file", "name"),
        ("inventory", "*", "name"), ("canonical_repository_url",),
        ("correction_policy_url",),
    }),
    "metrics.json": frozenset({
        ("metrics", "*", "metric_id"), ("metrics", "*", "denominator_metric_id"),
    }),
    "aggregate-attestation.json": frozenset({("metric_files", "*", "name")}),
    "doi-reservation.json": frozenset({
        ("doi_url",), ("external_verification", "approver_identity"),
    }),
    "figures/manifest.json": frozenset({
        ("figures", "*", "path"), ("figures", "*", "metric_ids", "*"),
        ("figures", "*", "denominator_metric_ids", "*"),
        ("figures", "*", "repository"),
    }),
    "EDITORIAL-SIGNOFF.json": frozenset({
        ("signoffs", "*", "reviewer_identity"),
        ("external_verification", "approver_identity"),
    }),
    "CITATION.cff": frozenset({("repository-code",), ("url",)}),
}
PUBLIC_DYNAMIC_DOMAIN_FIELDS: Mapping[str, frozenset[tuple[str, ...]]] = {
    "release.json": frozenset({
        ("measurement_core", "files", "*"),
        ("measurement_core", "transition", "changed_file"),
        ("aggregate_files", "*", "name"), ("doi_reservation_file", "name"),
        ("inventory", "*", "name"),
    }),
    "metrics.json": frozenset({
        ("metrics", "*", "metric_id"), ("metrics", "*", "denominator_metric_id"),
    }),
    "aggregate-attestation.json": frozenset({("metric_files", "*", "name")}),
    "doi-reservation.json": frozenset({
        ("external_verification", "approver_identity"),
    }),
    "figures/manifest.json": frozenset({
        ("figures", "*", "path"), ("figures", "*", "metric_ids", "*"),
        ("figures", "*", "denominator_metric_ids", "*"),
    }),
    "EDITORIAL-SIGNOFF.json": frozenset({
        ("signoffs", "*", "reviewer_identity"),
        ("external_verification", "approver_identity"),
    }),
}


def _field_allowed(path: tuple[str, ...], patterns: Iterable[tuple[str, ...]]) -> bool:
    return any(
        len(path) == len(pattern) and all(
            expected == "*" or expected == actual
            for actual, expected in zip(path, pattern, strict=True)
        )
        for pattern in patterns
    )


def _json_strings(
    value: Any, path: tuple[str, ...] = (),
) -> Iterable[tuple[tuple[str, ...], str | int]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _json_strings(child, (*path, str(key)))
    elif isinstance(value, list):
        for child in value:
            yield from _json_strings(child, (*path, "*"))
    elif isinstance(value, (str, int)) and not isinstance(value, bool):
        yield path, value

DOCUMENT_CONTRACTS: dict[str, tuple[str, tuple[str, ...]]] = {
    "README.md": (
        "Swiss Email Security Report aggregate release v2026.08.2",
        ("Scope", "Contents", "Citation", "Privacy", "Licenses", "Reproduction"),
    ),
    "DATA-DICTIONARY.md": (
        "Data dictionary",
        ("File catalogue", "Metric fields", "Denominators", "Error handling", "Figure fields"),
    ),
    "METHODOLOGY.md": (
        "Methodology",
        ("Source universe", "Measurement interval", "Resolver configuration", "Aggregation", "Scientific limitations"),
    ),
    "CORRECTIONS.md": (
        "Corrections policy",
        ("Contact", "Required evidence", "Review process", "Versioning"),
    ),
    "RELEASE-NOTES.md": (
        "Release notes v2026.08.2",
        ("Release identity", "Included artifacts", "Known limitations", "Corrections"),
    ),
}


@dataclass(frozen=True)
class ManifestRun:
    manifest_sha256: str
    manifest_schema_version: int
    run_identifier: str
    mode: str
    scanner_git_revision: str
    measurement_core_sha256: str
    started_at_utc: str
    finished_at_utc: str
    attempted_input_count: int
    database_pre: dict[str, int]
    database_post: dict[str, int]
    output_sqlite_sha256: str
    output_sqlite_size_bytes: int

    def public_dict(self, sequence: int) -> dict[str, Any]:
        return {
            "sequence": sequence,
            "manifest_schema_version": self.manifest_schema_version,
            "run_identifier": self.run_identifier,
            "manifest_sha256": self.manifest_sha256,
            "mode": self.mode,
            "scanner_git_revision": self.scanner_git_revision,
            "measurement_core_sha256": self.measurement_core_sha256,
            "started_at_utc": self.started_at_utc,
            "finished_at_utc": self.finished_at_utc,
            "attempted_input_count": self.attempted_input_count,
            "database_pre": self.database_pre,
            "database_post": self.database_post,
        }


@dataclass(frozen=True)
class ValidatedChain:
    runs: tuple[ManifestRun, ...]
    source_sha256: str
    source_count: int
    root_measurement_core_sha256: str
    final_measurement_core_sha256: str
    measurement_core_transition: dict[str, Any]
    resolver_configuration: dict[str, Any]

    @property
    def interval(self) -> str:
        return f"{self.runs[0].started_at_utc}/{self.runs[-1].finished_at_utc}"


def _canonical_json(payload: Any) -> bytes:
    return (json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _write_bytes(path: Path, content: bytes) -> None:
    with path.open("wb") as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_public_tree(directory: Path) -> None:
    """Durably persist every validated file and directory before promotion."""
    files = _walk_public_files(directory)
    for path in files.values():
        _require_plain_file(path, "prepared DOI payload")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    directories = [path for path in directory.rglob("*") if path.is_dir()]
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(path)
    _fsync_directory(directory)


def _load_json(path: Path, description: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{description} contains a duplicate JSON key")
            value[key] = item
        return value

    def invalid_constant(value: str) -> None:
        raise ValueError(f"{description} contains non-finite JSON: {value}")

    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=object_pairs,
            parse_constant=invalid_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{description} is not valid UTF-8 JSON") from exc


def _validate_instance(schema_path: Path, instance: Any, description: str) -> None:
    schema = _load_json(schema_path, f"{description} schema")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors:
        raise ValueError(f"{description} schema validation failed: {errors[0].message}")


def _require_plain_file(path: Path, description: str) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"{description} is missing") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise ValueError(f"{description} must be a regular non-symlink file")
    _require_no_symlink_ancestors(path.parent, description)
    if details.st_nlink != 1:
        raise ValueError(f"{description} may not be hard-linked")


def _require_plain_directory(path: Path, description: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise ValueError(f"{description} is missing") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise ValueError(f"{description} must be a regular non-symlink directory")
    _require_no_symlink_ancestors(path.parent, description)


def _reject_parent_traversal(path: Path, description: str) -> None:
    if ".." in path.parts:
        raise ValueError(f"{description} may not contain parent traversal")


def _require_no_symlink_ancestors(path: Path, description: str) -> None:
    """Reject lexical paths which traverse a symlink before their leaf.

    ``Path.resolve`` alone is insufficient here: it quietly follows the very
    indirection the public-release boundary must reject.
    """
    absolute = path.absolute()
    for ancestor in (absolute, *absolute.parents):
        try:
            mode = ancestor.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError(f"{description} may not traverse a symlink ancestor")


def _require_contained(path: Path, root: Path, description: str) -> None:
    _require_no_symlink_ancestors(path, description)
    _require_no_symlink_ancestors(root, "release output root")
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ValueError(f"{description} escapes its approved root") from exc


def _require_no_sqlite_companions(database: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{database}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise ValueError("private database has a live SQLite companion file")


def _load_official_config() -> dict[str, Any]:
    config = _load_json(CONFIG_PATH, "release configuration")
    _validate_instance(CONFIG_SCHEMA_PATH, config, "release configuration")
    root_core = V1_ROOT_CORE_ATTESTATIONS.get(ACTIVE_V1_ROOT_REVISION)
    transition = dict(URI_SAFETY_CORE_TRANSITION)
    if config != {
        "release_version": RELEASE_VERSION,
        "doi_approval_key_fingerprint": "UNCONFIGURED",
        "source_snapshot_date": "2026-04-12",
        "source_input_normalized_sha256": "be742a42b89dbac80b5296316d35a2d245383e31d15d5df0b1242af8ec9e07c8",
        "source_input_normalized_line_count": 2_459_127,
        "root_scanner_git_revision": ACTIVE_V1_ROOT_REVISION,
        "measurement_core_algorithm": MEASUREMENT_CORE_ALGORITHM,
        "measurement_core_files": list(MEASUREMENT_CORE_FILES),
        "root_measurement_core_sha256": root_core,
        "final_measurement_core_sha256": transition["to_measurement_core_sha256"],
        "measurement_core_transition": transition,
        "resolver_configuration": {
            "nameservers": ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"],
            "rotate": True,
            "timeout_seconds": 4.0,
            "lifetime_seconds": 6.0,
            "cache_policy": "disabled",
            "dnspython_version": "2.8.0",
        },
        "root_run": {"mode": FRESH_MODE, "input_order": "seeded_shuffle_then_limit"},
        "retry_run": {"mode": RESUME_MODE},
        "execution": {
            "limit": None, "shuffle": True, "shuffle_seed": 42,
            "concurrency": 120, "batch_pool_size": 300,
        },
    }:
        raise ValueError("official release configuration does not match the reviewed pin")
    return config


def _manifest_paths(
    *, manifest_paths: Sequence[str | Path] | None,
    manifest_directory: str | Path | None,
) -> list[Path]:
    if bool(manifest_paths) == bool(manifest_directory):
        raise ValueError("provide exactly one explicit manifest list or manifest directory")
    if manifest_directory is not None:
        directory = Path(manifest_directory)
        _reject_parent_traversal(directory, "manifest directory")
        _require_plain_directory(directory, "manifest directory")
        entries = list(directory.iterdir())
        if any(entry.is_symlink() or not entry.is_file() or entry.suffix != ".json" for entry in entries):
            raise ValueError("manifest directory may contain only regular JSON files")
        paths = entries
    else:
        paths = [Path(item) for item in manifest_paths or ()]
    if len(paths) < 2:
        raise ValueError("official release requires one v1 root and at least one v2 retry")
    for path in paths:
        _reject_parent_traversal(path, "manifest path")
        _require_plain_file(path, "run manifest")
    return paths


def _accounting_dict(value: Any) -> dict[str, int]:
    return {
        "total": value.total_rows,
        "analyzable": value.analyzable_rows,
        "error": value.error_rows,
    }


def _validate_execution_pin(manifest: Mapping[str, Any], config: Mapping[str, Any]) -> None:
    execution = config["execution"]
    for key in ("limit", "shuffle", "shuffle_seed", "concurrency", "batch_pool_size"):
        if manifest.get(key) != execution[key]:
            raise ValueError(f"run manifest differs from official {key} pin")
    if manifest.get("resolver_configuration") != config["resolver_configuration"]:
        raise ValueError("run manifest differs from official resolver configuration")


def validate_manifest_chain(
    *, database: str | Path, manifest_paths: Sequence[str | Path] | None = None,
    manifest_directory: str | Path | None = None,
) -> ValidatedChain:
    """Validate the exact private v1 -> v2 retry chain for v2026.08.2."""
    config = _load_official_config()
    database_path = Path(database)
    _reject_parent_traversal(database_path, "private database path")
    _require_plain_file(database_path, "final private database")
    _require_no_sqlite_companions(database_path)
    paths = _manifest_paths(
        manifest_paths=manifest_paths, manifest_directory=manifest_directory,
    )
    loaded: list[tuple[Path, bytes, str, Mapping[str, Any]]] = []
    for path in paths:
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        manifest = _load_manifest_bytes(payload, "run manifest")
        if not isinstance(manifest, dict):
            raise ValueError("run manifest must be a JSON object")
        loaded.append((path, payload, digest, manifest))
    loaded.sort(key=lambda item: item[3].get("started_at_utc", ""))

    root_manifest = loaded[0][3]
    if "manifest_schema_version" in root_manifest:
        raise ValueError("official chain must begin with the attested v1 root")
    root_info = _validate_v1_root(
        root_manifest, loaded[0][2], actual_output_identity=None,
        actual_accounting=None,
    )
    _validate_execution_pin(root_manifest, config)
    if root_manifest["retry_resume_mode"] != config["root_run"]["mode"]:
        raise ValueError("official root must be a fresh run")
    if root_manifest["effective_input_order"] != config["root_run"]["input_order"]:
        raise ValueError("official root input order is not pinned")
    if (
        root_manifest["scanner_git_revision"] != config["root_scanner_git_revision"]
        or root_info["measurement_core_sha256"] != config["root_measurement_core_sha256"]
        or root_info["source_sha256"] != config["source_input_normalized_sha256"]
        or root_info["source_count"] != config["source_input_normalized_line_count"]
    ):
        raise ValueError("v1 root does not match the official release identity")

    previous_info = root_info
    previous_hash = loaded[0][2]
    retry_entries: list[tuple[str, Mapping[str, Any], dict[str, Any]]] = []
    for _path, _payload, manifest_hash, manifest in loaded[1:]:
        if manifest.get("manifest_schema_version") != MANIFEST_SCHEMA_VERSION:
            raise ValueError("all runs after the root must use canonical v2 manifests")
        info = _validate_v2(manifest)
        _validate_execution_pin(manifest, config)
        if info["mode"] != config["retry_run"]["mode"]:
            raise ValueError("official post-root runs must be retry resumes")
        if not info["release_eligible"] or manifest["scanner_git_dirty"]:
            raise ValueError("retry run is not release eligible")
        if manifest["planned_input_order"] != config["root_run"]["input_order"]:
            raise ValueError("retry input order is not pinned")
        if (
            info["source_sha256"] != config["source_input_normalized_sha256"]
            or info["source_count"] != config["source_input_normalized_line_count"]
            or info["measurement_core_sha256"] != config["final_measurement_core_sha256"]
        ):
            raise ValueError("retry source or measurement core changed")
        for field in (
            "planned_sha256", "planned_count", "resolver_configuration",
            "concurrency", "batch_pool_size", "limit", "shuffle",
            "shuffle_seed", "planned_input_order",
        ):
            if info[field] != previous_info[field]:
                raise ValueError(f"run chain changed the pinned {field}")
        expected_transition = (
            config["measurement_core_transition"]
            if previous_info["schema"] == 1 else None
        )
        if info["measurement_core_transition"] != expected_transition:
            raise ValueError("measurement-core transition is missing, changed, or repeated")
        if info["previous_manifest_sha256"] != previous_hash:
            raise ValueError("retry does not link to the exact prior manifest bytes")
        if (info["input_sha256"], info["input_size"]) != (
            previous_info["output_sha256"], previous_info["output_size"],
        ):
            raise ValueError("retry input database identity does not link")
        if info["root_attestation"] != root_info["root_attestation"]:
            raise ValueError("retry root measurement-core attestation changed")
        if _parse_utc_timestamp(info["started_at"], "retry start") < _parse_utc_timestamp(
            previous_info["finished_at"], "previous finish"
        ):
            raise ValueError("run times overlap or are out of order")
        if info["pre_database"].total_rows != config["source_input_normalized_line_count"]:
            raise ValueError("retry pre-accounting does not cover the source universe")
        if info["post_database"].total_rows != config["source_input_normalized_line_count"]:
            raise ValueError("retry post-accounting does not cover the source universe")
        if previous_info.get("schema") == 2 and info["pre_database"] != previous_info["post_database"]:
            raise ValueError("retry pre/post accounting does not link")
        if manifest["attempted_input_normalized_line_count"] != info["pre_database"].error_rows:
            raise ValueError("retry attempted count does not equal pre-run error rows")
        if manifest["planned_excluded_count"] != info["pre_database"].analyzable_rows:
            raise ValueError("retry excluded count does not equal pre-run analyzable rows")
        if manifest["rows_written"] != manifest["attempted_input_normalized_line_count"]:
            raise ValueError("retry rows-written count does not equal actual attempts")
        retry_entries.append((manifest_hash, manifest, info))
        previous_info = info
        previous_hash = manifest_hash

    final_identity = _sha256_and_size(database_path)
    if final_identity != (previous_info["output_sha256"], previous_info["output_size"]):
        raise ValueError("final manifest output identity does not match private database")

    first_retry_pre = retry_entries[0][2]["pre_database"]
    root_run = ManifestRun(
        manifest_sha256=loaded[0][2], manifest_schema_version=1,
        run_identifier=loaded[0][2], mode=FRESH_MODE,
        scanner_git_revision=root_manifest["scanner_git_revision"],
        measurement_core_sha256=root_info["measurement_core_sha256"],
        started_at_utc=root_info["started_at"], finished_at_utc=root_info["finished_at"],
        attempted_input_count=config["source_input_normalized_line_count"],
        database_pre={"total": 0, "analyzable": 0, "error": 0},
        database_post=_accounting_dict(first_retry_pre),
        output_sqlite_sha256=root_info["output_sha256"],
        output_sqlite_size_bytes=root_info["output_size"],
    )
    runs = [root_run]
    for manifest_hash, manifest, info in retry_entries:
        runs.append(ManifestRun(
            manifest_sha256=manifest_hash, manifest_schema_version=2,
            run_identifier=manifest["run_id"], mode=info["mode"],
            scanner_git_revision=manifest["scanner_git_revision"],
            measurement_core_sha256=info["measurement_core_sha256"],
            started_at_utc=info["started_at"], finished_at_utc=info["finished_at"],
            attempted_input_count=manifest["attempted_input_normalized_line_count"],
            database_pre=_accounting_dict(info["pre_database"]),
            database_post=_accounting_dict(info["post_database"]),
            output_sqlite_sha256=info["output_sha256"],
            output_sqlite_size_bytes=info["output_size"],
        ))
    for run in runs:
        if _parse_utc_timestamp(run.finished_at_utc, "run finish") <= _parse_utc_timestamp(
            run.started_at_utc, "run start"
        ):
            raise ValueError("every run must have a nonempty measurement interval")
    return ValidatedChain(
        runs=tuple(runs), source_sha256=config["source_input_normalized_sha256"],
        source_count=config["source_input_normalized_line_count"],
        root_measurement_core_sha256=config["root_measurement_core_sha256"],
        final_measurement_core_sha256=config["final_measurement_core_sha256"],
        measurement_core_transition=dict(config["measurement_core_transition"]),
        resolver_configuration=dict(config["resolver_configuration"]),
    )


def _read_only_connection(database: Path) -> sqlite3.Connection:
    return sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)


def _independent_schema(conn: sqlite3.Connection) -> dict[str, str]:
    tables = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = ?", ("table",)
    )}
    if RESULTS_TABLE not in tables:
        raise ValueError("database has no results table")
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({RESULTS_TABLE})")}
    if columns == EXPECTED_COLUMNS:
        return {}
    legacy = {
        "dnssec_signed" if column == "has_ds_record" else
        "has_tlsa" if column == "has_tlsa_record" else column
        for column in EXPECTED_COLUMNS if column != "query_statuses"
    }
    if columns == legacy:
        return {"has_ds_record": "dnssec_signed", "has_tlsa_record": "has_tlsa"}
    raise ValueError("database schema is not a supported scanner schema")


def _independent_count(
    conn: sqlite3.Connection, predicate: str = "1 = 1",
    parameters: tuple[Any, ...] = (), *, all_rows: bool = False,
) -> int:
    prefix = "" if all_rows else "error = '' AND "
    return int(conn.execute(
        f"SELECT COUNT(*) FROM {RESULTS_TABLE} WHERE {prefix}({predicate})", parameters,
    ).fetchone()[0])


def _count_metric_independently(
    conn: sqlite3.Connection, metric_id: str, aliases: dict[str, str],
) -> int:
    ds = aliases.get("has_ds_record", "has_ds_record")
    tlsa = aliases.get("has_tlsa_record", "has_tlsa_record")
    direct: dict[str, tuple[str, tuple[Any, ...], bool]] = {
        "population.total": ("1 = 1", (), True),
        "population.analyzable": ("error = ''", (), True),
        "population.error": ("error <> ''", (), True),
        "domain.exists": ("domain_exists = ?", (1,), False),
        "domain.not_exists": ("domain_exists = ?", (0,), False),
        "mx.present": ("has_mx = ?", (1,), False),
        "mx.absent": ("has_mx = ?", (0,), False),
        "spf.present": ("has_mx = ? AND has_spf = ?", (1, 1), False),
        "spf.absent": ("has_mx = ? AND has_spf = ?", (1, 0), False),
        "spf.hardfail": ("has_mx = ? AND has_spf = ? AND spf_all_mechanism = ?", (1, 1, "hardfail"), False),
        "spf.softfail": ("has_mx = ? AND has_spf = ? AND spf_all_mechanism = ?", (1, 1, "softfail"), False),
        "spf.neutral": ("has_mx = ? AND has_spf = ? AND spf_all_mechanism = ?", (1, 1, "neutral"), False),
        "spf.pass": ("has_mx = ? AND has_spf = ? AND spf_all_mechanism = ?", (1, 1, "pass"), False),
        "spf.no_terminal_mechanism": ("has_mx = ? AND has_spf = ? AND COALESCE(NULLIF(spf_all_mechanism, ?), ?) = ?", (1, 1, "", "none", "none"), False),
        "spf.legacy_rrtype99": ("has_legacy_spf_rrtype = ?", (1,), False),
        "spf.no_mx_present": ("has_mx = ? AND has_spf = ?", (0, 1), False),
        "dkim.selector_observed": ("has_mx = ? AND has_dkim = ?", (1, 1), False),
        "dkim.selector_not_observed": ("has_mx = ? AND has_dkim = ?", (1, 0), False),
        "dkim.weak_key_heuristic": ("has_mx = ? AND has_dkim = ? AND dkim_weak_key = ?", (1, 1, 1), False),
        "dkim.testing_mode": ("has_mx = ? AND has_dkim = ? AND dkim_testing_mode = ?", (1, 1, 1), False),
        "dmarc.detected": ("has_mx = ? AND has_dmarc = ?", (1, 1), False),
        "dmarc.reject": ("has_mx = ? AND has_dmarc = ? AND dmarc_policy = ?", (1, 1, "reject"), False),
        "dmarc.quarantine": ("has_mx = ? AND has_dmarc = ? AND dmarc_policy = ?", (1, 1, "quarantine"), False),
        "dmarc.none": ("has_mx = ? AND has_dmarc = ? AND dmarc_policy = ?", (1, 1, "none"), False),
        "dmarc.genuine_no_record": ("has_mx = ? AND has_dmarc = ?", (1, 0), False),
        "dmarc.missing_policy": ("has_mx = ? AND has_dmarc = ? AND COALESCE(NULLIF(dmarc_policy, ?), ?) = ?", (1, 1, "", "absent", "absent"), False),
        "dmarc.unsupported_policy": ("has_mx = ? AND has_dmarc = ? AND COALESCE(NULLIF(dmarc_policy, ?), ?) NOT IN (?, ?, ?, ?)", (1, 1, "", "absent", "reject", "quarantine", "none", "absent"), False),
        "dmarc.no_supported_effective_policy": ("has_mx = ? AND (has_dmarc = ? OR (has_dmarc = ? AND COALESCE(NULLIF(dmarc_policy, ?), ?) NOT IN (?, ?, ?)))", (1, 0, 1, "", "absent", "reject", "quarantine", "none"), False),
        "dmarc.no_detected_enforcement": ("has_mx = ? AND (has_dmarc = ? OR (has_dmarc = ? AND COALESCE(NULLIF(dmarc_policy, ?), ?) NOT IN (?, ?)))", (1, 0, 1, "", "absent", "reject", "quarantine"), False),
        "dmarc.detected_all": ("has_dmarc = ?", (1,), False),
        "dmarc.partial_pct": ("has_dmarc = ? AND dmarc_pct >= ? AND dmarc_pct < ?", (1, 0, 100), False),
        "dmarc.strict_alignment": ("has_dmarc = ? AND (dmarc_adkim = ? OR dmarc_aspf = ?)", (1, "s", "s"), False),
        "dmarc.no_mx_detected": ("has_mx = ? AND has_dmarc = ?", (0, 1), False),
        "ds.record_present": (f"{ds} = ?", (1,), False),
        "ns.answer_present": ("ns_hosts IS NOT NULL AND ns_hosts <> ? AND ns_hosts <> ?", ("", "[]"), False),
        "tlsa.record_present": (f"has_mx = ? AND {tlsa} = ?", (1, 1), False),
        "bimi.record_present": ("has_mx = ? AND has_bimi = ?", (1, 1), False),
        "mta_sts.txt_present": ("has_mx = ? AND has_mta_sts = ?", (1, 1), False),
        "tls_rpt.record_present": ("has_mx = ? AND has_tlsrpt = ?", (1, 1), False),
        "caa.record_present": ("has_mx = ? AND has_caa = ?", (1, 1), False),
        "mx.unresolvable": ("has_mx = ? AND mx_unresolvable = ?", (1, 1), False),
    }
    if metric_id.startswith("mx.provider."):
        provider = metric_id.removeprefix("mx.provider.")
        if provider not in KNOWN_PROVIDERS:
            raise ValueError(f"independent catalogue does not know {metric_id}")
        if provider == "unknown":
            return _independent_count(conn, "has_mx = ? AND COALESCE(NULLIF(mx_provider, ?), ?) = ?", (1, "", "unknown", "unknown"))
        return _independent_count(conn, "has_mx = ? AND mx_provider = ?", (1, provider))
    try:
        predicate, params, all_rows = direct[metric_id]
    except KeyError as exc:
        raise ValueError(f"independent catalogue does not know {metric_id}") from exc
    return _independent_count(conn, predicate, params, all_rows=all_rows)


def independent_count_reconciliation_connection(
    conn: sqlite3.Connection, metrics: Iterable[Metric],
) -> None:
    """Reconcile every metric on the caller's already-open snapshot."""
    if not conn.in_transaction:
        raise ValueError("independent reconciliation requires an explicit snapshot")
    aliases = _independent_schema(conn)
    for metric in metrics:
        if _count_metric_independently(conn, metric.metric_id, aliases) != metric.numerator:
            raise ValueError(f"independent count reconciliation failed for {metric.metric_id}")


def _validate_count_only_trace(statements: Sequence[str]) -> None:
    for raw in statements:
        statement = " ".join(raw.strip().split())
        lowered = statement.lower()
        if not lowered or lowered in {"begin", "rollback", "commit"}:
            continue
        if lowered.startswith("pragma table_info(dmarc_scan_results)"):
            continue
        if lowered.startswith("select name from sqlite_master where type ="):
            continue
        if not lowered.startswith("select count(*) from dmarc_scan_results where "):
            raise ValueError("aggregate SQL attempted a non-COUNT projection")
        projection = lowered.split(" from ", 1)[0]
        if projection != "select count(*)" or "select *" in lowered:
            raise ValueError("aggregate SQL attempted a raw projection")
        if re.search(r"(?:[.\"\[]|\bselect\s+)domain(?:[.\"\]]|\b)", lowered):
            raise ValueError("aggregate SQL projected a domain identifier")


def _metrics_from_snapshot(
    database: Path, chain: ValidatedChain,
) -> tuple[tuple[Metric, ...], tuple[str, int]]:
    expected_identity = (
        chain.runs[-1].output_sqlite_sha256,
        chain.runs[-1].output_sqlite_size_bytes,
    )
    before = _sha256_and_size(database)
    if before != expected_identity:
        raise ValueError("private database changed after manifest-chain validation")
    _require_no_sqlite_companions(database)
    trace: list[str] = []
    conn = _read_only_connection(database)
    try:
        conn.set_trace_callback(trace.append)
        conn.execute("BEGIN")
        metrics = aggregate_connection(conn, chain.interval)
        validate_metrics(metrics)
        independent_count_reconciliation_connection(conn, metrics)
        conn.execute("ROLLBACK")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    _validate_count_only_trace(trace)
    after = _sha256_and_size(database)
    _require_no_sqlite_companions(database)
    if after != before or after != expected_identity:
        raise ValueError("private database changed during aggregate snapshot")
    return metrics, after


def _metric_payload(metrics: Iterable[Metric]) -> dict[str, list[dict[str, Any]]]:
    ordered = sorted((metric.to_dict() for metric in metrics), key=lambda item: item["metric_id"])
    if any(set(metric) != PUBLIC_METRIC_FIELDS for metric in ordered):
        raise ValueError("metric serializer changed the reviewed public fields")
    payload = {"metrics": ordered}
    _validate_instance(METRICS_SCHEMA_PATH, payload, "metrics")
    return payload


def _aggregate_accounting(metrics: Iterable[Metric]) -> dict[str, int]:
    values = {metric.metric_id: metric.numerator for metric in metrics}
    return {
        "total": values["population.total"],
        "analyzable": values["population.analyzable"],
        "error": values["population.error"],
    }


def _require_final_database_unchanged(
    database: Path, chain: ValidatedChain, expected_identity: tuple[str, int],
) -> None:
    _require_no_sqlite_companions(database)
    manifest_identity = (
        chain.runs[-1].output_sqlite_sha256,
        chain.runs[-1].output_sqlite_size_bytes,
    )
    if _sha256_and_size(database) != expected_identity or expected_identity != manifest_identity:
        raise ValueError("private database changed after aggregate serialization")
    _require_no_sqlite_companions(database)


def _write_metrics_csv(path: Path, metrics: list[dict[str, Any]]) -> None:
    fields = ["metric_id", *sorted(PUBLIC_METRIC_FIELDS - {"metric_id"})]
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n", extrasaction="raise")
        writer.writeheader()
        writer.writerows(metrics)
        output.flush()
        os.fsync(output.fileno())


def _metadata(path: Path, name: str) -> dict[str, Any]:
    digest, size = _sha256_and_size(path)
    return {"name": name, "sha256": digest, "bytes": size}


def _walk_public_files(directory: Path, *, allow_checksums: bool = False) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ValueError("public payload may not contain symlinks")
        if stat.S_ISDIR(mode):
            if path.name.startswith("."):
                raise ValueError("public payload may not contain hidden directories")
            continue
        if not stat.S_ISREG(mode):
            raise ValueError("public payload may contain regular files only")
        if path.name.startswith(".") or path.name.endswith(("~", ".bak", ".tmp", ".swp")):
            raise ValueError("public payload contains a hidden, backup, or temporary file")
        if path.suffix.lower() in PRIVATE_EXTENSIONS:
            raise ValueError("public payload contains a private database file")
        if path.name == "checksums.sha256" and not allow_checksums:
            raise ValueError("staging may not contain final checksums")
        safe = PurePosixPath(relative)
        if safe.is_absolute() or ".." in safe.parts or relative in files:
            raise ValueError("public payload contains an unsafe path")
        files[relative] = path
    return files


def _assert_public_content_safe(files: Mapping[str, Path]) -> None:
    known_domain_like = set(SAFE_PUBLIC_DOMAINS)
    known_domain_like.update(
        ascii_domain
        for relative in files
        for _raw, ascii_domain in _domain_like_values(relative)
    )
    metrics_path = files.get("metrics.json")
    if metrics_path is not None:
        metrics_payload = _load_json(metrics_path, "metrics privacy catalogue")
        if isinstance(metrics_payload, dict) and isinstance(metrics_payload.get("metrics"), list):
            for metric in metrics_payload["metrics"]:
                if isinstance(metric, dict):
                    for field in ("metric_id", "denominator_metric_id"):
                        value = metric.get(field)
                        if isinstance(value, str):
                            known_domain_like.update(
                                ascii_domain for _raw, ascii_domain in _domain_like_values(value)
                            )
    for relative, path in files.items():
        suffix = path.suffix.lower()
        if suffix == ".png" or relative == "doi-approval-public.der":
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"public text file is not UTF-8: {relative}") from exc
        if PRIVATE_FIELD_RE.search(_normalize_public_text(content)):
            raise ValueError(
                f"public payload contains private scanner material: "
                f"private scanner field vocabulary in {relative}",
            )
        if relative == "checksums.sha256":
            for row in content.splitlines():
                if row.count("  ") == 1:
                    _digest, filename = row.split("  ", 1)
                    _assert_safe_public_text(
                        filename, f"public checksum catalogue {relative}",
                        allowed_domain_like=known_domain_like,
                    )
            continue
        if suffix == ".json":
            payload = _load_json(path, f"public privacy catalogue {relative}")
            hash_fields = PUBLIC_HASH_FIELDS.get(relative, frozenset())
            git_revision_fields = PUBLIC_GIT_REVISION_FIELDS.get(relative, frozenset())
            opaque_fields = PUBLIC_OPAQUE_FIELDS.get(relative, frozenset())
            numeric_fields = PUBLIC_NUMERIC_FIELDS.get(relative, frozenset())
            ip_fields = PUBLIC_IP_FIELDS.get(relative, frozenset())
            domain_fields = PUBLIC_DOMAIN_FIELDS.get(relative, frozenset())
            dynamic_domain_fields = PUBLIC_DYNAMIC_DOMAIN_FIELDS.get(relative, frozenset())
            for field_path, value in _json_strings(payload):
                if _field_allowed(field_path, opaque_fields):
                    continue
                allowed_hash_lengths = set()
                if _field_allowed(field_path, hash_fields):
                    allowed_hash_lengths.add(64)
                if _field_allowed(field_path, git_revision_fields):
                    allowed_hash_lengths.add(40)
                allowed_ips = APPROVED_PUBLIC_IPS if _field_allowed(field_path, ip_fields) else ()
                allowed_numeric = (
                    isinstance(value, int) and _field_allowed(field_path, numeric_fields)
                )
                allowed_domains: set[str] = set()
                if _field_allowed(field_path, domain_fields):
                    allowed_domains.update(known_domain_like)
                if isinstance(value, str) and _field_allowed(field_path, dynamic_domain_fields):
                    allowed_domains.update(
                        ascii_domain for _raw, ascii_domain in _domain_like_values(value)
                    )
                _assert_safe_public_text(
                    str(value), f"public JSON field {relative}:{'.'.join(field_path)}",
                    allowed_domain_like=allowed_domains,
                    allowed_hash_lengths=allowed_hash_lengths, allowed_ips=allowed_ips,
                    allow_decimal_integer=allowed_numeric,
                )
        elif suffix == ".svg":
            try:
                svg_root = ET.fromstring(content)
            except ET.ParseError:
                _assert_safe_public_text(
                    content, f"public SVG text {relative}",
                    allowed_domain_like=known_domain_like,
                )
            else:
                style_nodes = [
                    element for element in svg_root.iter()
                    if str(element.tag).rsplit("}", 1)[-1] == "style"
                ]
                for style in style_nodes:
                    _validate_embedded_svg_font(style)
                decoded = " ".join(
                    "".join(element.itertext()) for element in svg_root.iter()
                    if str(element.tag).rsplit("}", 1)[-1] in {"title", "desc", "text"}
                )
                attribute_values = " ".join(
                    value for element in svg_root.iter() for value in element.attrib.values()
                )
                _assert_safe_public_text(
                    f"{decoded} {attribute_values}", f"public SVG decoded surface {relative}",
                    allowed_domain_like=known_domain_like,
                )
        elif relative == "CITATION.cff":
            payload = _parse_citation(path)
            domain_fields = PUBLIC_DOMAIN_FIELDS[relative]
            for field_path, value in _json_strings(payload):
                allowed_domains = (
                    known_domain_like if _field_allowed(field_path, domain_fields) else ()
                )
                _assert_safe_public_text(
                    str(value), f"public CFF field {'.'.join(field_path)}",
                    allowed_domain_like=allowed_domains,
                )
        else:
            _assert_safe_public_text(
                content, f"public text file {relative}",
                allowed_domain_like=known_domain_like,
            )


def _staging_release_payload(
    chain: ValidatedChain, metrics: list[dict[str, Any]],
    aggregate_files: list[dict[str, Any]],
) -> dict[str, Any]:
    values = {metric["metric_id"]: metric["numerator"] for metric in metrics}
    config = _load_official_config()
    payload = {
        "release_version": RELEASE_VERSION,
        "status": "staging",
        "generated_at_utc": chain.runs[-1].finished_at_utc,
        "source_universe": {
            "snapshot_date": config["source_snapshot_date"],
            "normalized_sha256": chain.source_sha256,
            "normalized_line_count": chain.source_count,
        },
        "measurement_interval": {
            "started_at_utc": chain.runs[0].started_at_utc,
            "finished_at_utc": chain.runs[-1].finished_at_utc,
        },
        "measurement_core": {
            "algorithm": MEASUREMENT_CORE_ALGORITHM,
            "files": list(MEASUREMENT_CORE_FILES),
            "root_sha256": chain.root_measurement_core_sha256,
            "final_sha256": chain.final_measurement_core_sha256,
            "transition": chain.measurement_core_transition,
        },
        "resolver_configuration": chain.resolver_configuration,
        "aggregate_row_accounting": {
            "total": values["population.total"],
            "analyzable": values["population.analyzable"],
            "error": values["population.error"],
        },
        "metric_count": len(metrics),
        "run_chain": [run.public_dict(index) for index, run in enumerate(chain.runs, 1)],
        "aggregate_files": sorted(aggregate_files, key=lambda item: item["name"]),
        "licenses": {"code": "MIT", "data_and_figures": "CC BY 4.0"},
        "canonical_repository_url": CANONICAL_REPOSITORY_URL,
        "correction_policy_url": CORRECTION_POLICY_URL,
    }
    _validate_instance(RELEASE_SCHEMA_PATH, payload, "staging release")
    return payload


def stage_release(
    *, database: str | Path, output_directory: str | Path,
    manifest_paths: Sequence[str | Path] | None = None,
    manifest_directory: str | Path | None = None,
) -> Path:
    """Atomically create aggregate-only staging; never create a final release."""
    database_path = Path(database)
    output_root = Path(output_directory)
    _reject_parent_traversal(output_root, "output root")
    _require_no_symlink_ancestors(output_root, "output root")
    if output_root.exists() or output_root.is_symlink():
        _require_plain_directory(output_root, "output root")
        if any(output_root.iterdir()):
            raise FileExistsError("refusing a nonempty output root")
        root_created = False
    else:
        output_root.mkdir(parents=True)
        root_created = True
    staging = output_root / STAGING_DIRECTORY_NAME
    temporary: Path | None = None
    try:
        chain = validate_manifest_chain(
            database=database_path, manifest_paths=manifest_paths,
            manifest_directory=manifest_directory,
        )
        metrics, database_identity = _metrics_from_snapshot(database_path, chain)
        if metrics[0].numerator != chain.source_count:
            raise ValueError("aggregate row count does not match official source universe")
        payload = _metric_payload(metrics)
        if chain.runs[-1].database_post != _aggregate_accounting(metrics):
            raise ValueError("final run accounting differs from the aggregate database")
        temporary = Path(tempfile.mkdtemp(prefix=".aggregate-staging.", dir=output_root))
        os.chmod(temporary, 0o700)
        metrics_json = temporary / "metrics.json"
        metrics_csv = temporary / "metrics.csv"
        _write_bytes(metrics_json, _canonical_json(payload))
        _write_metrics_csv(metrics_csv, payload["metrics"])
        metric_files = [_metadata(metrics_csv, "metrics.csv"), _metadata(metrics_json, "metrics.json")]
        attestation = {
            "attestation_version": 1,
            "release_version": RELEASE_VERSION,
            "measurement_interval": {
                "started_at_utc": chain.runs[0].started_at_utc,
                "finished_at_utc": chain.runs[-1].finished_at_utc,
            },
            "source_input_normalized_sha256": chain.source_sha256,
            "source_input_normalized_line_count": chain.source_count,
            "root_measurement_core_sha256": chain.root_measurement_core_sha256,
            "final_measurement_core_sha256": chain.final_measurement_core_sha256,
            "measurement_core_transition_attestation_id": chain.measurement_core_transition["attestation_id"],
            "final_run_identifier": chain.runs[-1].run_identifier,
            "final_manifest_sha256": chain.runs[-1].manifest_sha256,
            "final_database_sha256": database_identity[0],
            "final_database_size_bytes": database_identity[1],
            "snapshot_method": "single explicit read-only SQLite transaction; canonical and independent COUNT-only catalogues",
            "metric_count": len(payload["metrics"]),
            "metric_files": metric_files,
        }
        _validate_instance(ATTESTATION_SCHEMA_PATH, attestation, "aggregate attestation")
        attestation_path = temporary / "aggregate-attestation.json"
        _write_bytes(attestation_path, _canonical_json(attestation))
        aggregate_files = [*metric_files, _metadata(attestation_path, "aggregate-attestation.json")]
        release = _staging_release_payload(chain, payload["metrics"], aggregate_files)
        _write_bytes(temporary / "release.json", _canonical_json(release))
        public_files = _walk_public_files(temporary)
        if set(public_files) != STAGING_FILES:
            raise ValueError("aggregate staging file contract changed")
        _assert_public_content_safe(public_files)
        _fsync_directory(temporary)
        _require_final_database_unchanged(database_path, chain, database_identity)
        os.replace(temporary, staging)
        temporary = None
        _fsync_directory(output_root)
        return staging
    except Exception:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
        if root_created:
            try:
                output_root.rmdir()
            except OSError:
                pass
        raise


def _reservation_signed_bytes(reservation: Mapping[str, Any]) -> bytes:
    """Canonical complete attestation, excluding only its detached signature."""
    payload = dict(reservation)
    verification = dict(payload["external_verification"])
    verification.pop("signature_base64", None)
    payload["external_verification"] = verification
    return _canonical_json(payload)


def _public_key_fingerprint(public_key: Path) -> str:
    return hashlib.sha256(_public_key_der(public_key)).hexdigest()


def _public_key_format(public_key: Path) -> str:
    _require_plain_file(public_key, "approval public key")
    return "PEM" if public_key.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----") else "DER"


def _public_key_der(public_key: Path) -> bytes:
    _require_ed25519_public_key(public_key)
    try:
        return subprocess.run(
            ["openssl", "pkey", "-pubin", "-inform", _public_key_format(public_key),
             "-in", os.fspath(public_key), "-pubout", "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("DOI approval public key cannot be encoded as DER") from exc


def _require_ed25519_public_key(public_key: Path) -> None:
    """OpenSSL must positively identify the key; generic pkey acceptance is unsafe."""
    try:
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-inform", _public_key_format(public_key),
             "-in", os.fspath(public_key), "-text_pub", "-noout"],
            check=True, capture_output=True, text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("DOI approval public key is not an Ed25519 public key") from exc
    if "ED25519" not in result.stdout.upper():
        raise ValueError("DOI approval public key must be Ed25519")


def _configured_doi_approval_fingerprint() -> str:
    fingerprint = _load_official_config().get("doi_approval_key_fingerprint")
    if not isinstance(fingerprint, str) or not SHA256_PATTERN.fullmatch(fingerprint):
        raise ValueError(
            "DOI approval key fingerprint is intentionally UNCONFIGURED; "
            "record a reviewed user-owned Ed25519 key before binding or sealing",
        )
    return fingerprint


def _verify_ed25519_signature(
    *, payload: bytes, signature_base64: str, public_key: Path, description: str,
) -> None:
    _require_ed25519_public_key(public_key)
    try:
        signature = base64.b64decode(signature_base64, validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"{description} signature is not valid base64") from exc
    if len(signature) != 64:
        raise ValueError(f"{description} signature is not an Ed25519 signature")
    with tempfile.TemporaryDirectory(prefix="release-approval-") as temporary:
        payload_path = Path(temporary) / "payload"
        signature_path = Path(temporary) / "signature"
        _write_bytes(payload_path, payload)
        _write_bytes(signature_path, signature)
        command = [
            "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
            "-keyform", _public_key_format(public_key), "-inkey", os.fspath(public_key),
            "-in", os.fspath(payload_path), "-sigfile", os.fspath(signature_path),
        ]
        try:
            subprocess.run(command, check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ValueError(f"{description} signature is not valid for the approved key") from exc


def _verify_reservation_approval(reservation: Mapping[str, Any], public_key: Path, approved_fingerprint: str) -> None:
    approval = reservation["external_verification"]
    if not SHA256_PATTERN.fullmatch(approved_fingerprint):
        raise ValueError("approved DOI public-key fingerprint is invalid")
    _require_ed25519_public_key(public_key)
    payload = _reservation_signed_bytes(reservation)
    fingerprint = _public_key_fingerprint(public_key)
    if fingerprint != approved_fingerprint or fingerprint != approval["public_key_fingerprint_sha256"]:
        raise ValueError("DOI approval key fingerprint is not the separately approved key")
    _verify_ed25519_signature(
        payload=payload, signature_base64=approval["signature_base64"],
        public_key=public_key, description="DOI approval",
    )


def _reservation_payload(value: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, Mapping):
        payload = dict(value)
    else:
        path = Path(value)
        _reject_parent_traversal(path, "DOI reservation attestation")
        _require_plain_file(path, "DOI reservation attestation")
        payload = _load_json(path, "DOI reservation attestation")
    _validate_instance(DOI_RESERVATION_SCHEMA_PATH, payload, "DOI reservation")
    record_id = payload["record_id"]
    expected_doi = f"10.5281/zenodo.{record_id}"
    if payload["doi"] != expected_doi or payload["doi_url"] != f"https://doi.org/{expected_doi}":
        raise ValueError("DOI reservation record ID, DOI, and URL do not match")
    if not payload["reserved_at_utc"].endswith("Z"):
        raise ValueError("DOI reservation timestamp must use UTC Z notation")
    _parse_utc_timestamp(payload["reserved_at_utc"], "DOI reservation timestamp")
    placeholder_text = " ".join(str(payload[key]) for key in (
        "provider", "doi", "doi_url", "reserved_at_utc", "release_version",
    )) + " " + " ".join(str(payload["external_verification"][key]) for key in (
        "authority_name", "approver_name", "approver_identity", "approver_role", "scope",
    ))
    if re.search(r"(?:pending|placeholder|example|tbd|todo)", placeholder_text, re.I):
        raise ValueError("DOI reservation may not contain placeholder metadata")
    return payload


def _bind_reserved_doi_in_place(
    *, staging_directory: str | Path,
    reservation_attestation: str | Path | Mapping[str, Any],
    approval_public_key: str | Path | None = None,
    approved_key_fingerprint: str | None = None,
) -> Path:
    """Bind a trusted, offline-approved Zenodo reservation; never publication."""
    staging = Path(staging_directory)
    _reject_parent_traversal(staging, "staging path")
    if staging.name not in {STAGING_DIRECTORY_NAME, f"{STAGING_DIRECTORY_NAME}.doi-prepared"}:
        raise ValueError("DOI binding requires the canonical staging directory")
    _require_plain_directory(staging, "staging directory")
    _require_plain_directory(staging.parent, "release output root")
    if staging.name == STAGING_DIRECTORY_NAME and {entry.name for entry in staging.parent.iterdir()} != {STAGING_DIRECTORY_NAME}:
        raise FileExistsError("release output root contains unexpected state")
    files = _walk_public_files(staging)
    if set(files) != STAGING_FILES:
        raise ValueError("DOI binding requires untouched aggregate staging")
    release, _metrics, _attestation = _validate_aggregate_components(
        files, expected_status="staging",
    )
    reservation = _reservation_payload(reservation_attestation)
    if approval_public_key is None or approved_key_fingerprint is None:
        raise ValueError("DOI binding requires separately approved external-verification key material")
    configured_fingerprint = _configured_doi_approval_fingerprint()
    if approved_key_fingerprint != configured_fingerprint:
        raise ValueError("DOI approval key fingerprint differs from the reviewed release configuration")
    key_path = Path(approval_public_key)
    _reject_parent_traversal(key_path, "DOI approval public key")
    _verify_reservation_approval(reservation, key_path, approved_key_fingerprint)
    der = _public_key_der(key_path)
    if _parse_utc_timestamp(
        reservation["reserved_at_utc"], "DOI reservation timestamp",
    ) < _parse_utc_timestamp(
        release["measurement_interval"]["finished_at_utc"], "measurement finish",
    ):
        raise ValueError("DOI reservation predates the completed measurement interval")

    reservation_bytes = _canonical_json(reservation)
    original_release_bytes = files["release.json"].read_bytes()
    reservation_temp = staging / ".doi-reservation.json.tmp"
    release_temp = staging / ".release.json.tmp"
    reservation_path = staging / "doi-reservation.json"
    der_path = staging / "doi-approval-public.der"
    try:
        _write_bytes(reservation_temp, reservation_bytes)
        _write_bytes(staging / ".doi-approval-public.der.tmp", der)
        reservation_identity = _sha256_and_size(reservation_temp)
        reserved_release = dict(release)
        reserved_release["status"] = "doi_reserved"
        reserved_release["doi"] = reservation["doi"]
        reserved_release["doi_reservation_file"] = {
            "name": "doi-reservation.json",
            "sha256": reservation_identity[0],
            "bytes": reservation_identity[1],
        }
        _validate_instance(RELEASE_SCHEMA_PATH, reserved_release, "DOI-reserved release")
        _write_bytes(release_temp, _canonical_json(reserved_release))
        os.replace(reservation_temp, reservation_path)
        os.replace(staging / ".doi-approval-public.der.tmp", der_path)
        os.replace(release_temp, staging / "release.json")
        _fsync_directory(staging)
    except BaseException:
        reservation_temp.unlink(missing_ok=True)
        release_temp.unlink(missing_ok=True)
        reservation_path.unlink(missing_ok=True)
        der_path.unlink(missing_ok=True)
        (staging / ".doi-approval-public.der.tmp").unlink(missing_ok=True)
        if (staging / "release.json").read_bytes() != original_release_bytes:
            _write_bytes(staging / "release.json", original_release_bytes)
        raise
    return staging


def bind_reserved_doi(
    *, staging_directory: str | Path, reservation_attestation: str | Path | Mapping[str, Any],
    approval_public_key: str | Path | None = None, approved_key_fingerprint: str | None = None,
) -> Path:
    """Prepare a complete sibling tree, then promote it as one filesystem step."""
    staging = Path(staging_directory)
    _reject_parent_traversal(staging, "staging path")
    if staging.name != STAGING_DIRECTORY_NAME:
        raise ValueError("DOI binding requires the canonical staging directory")
    root = staging.parent
    _require_plain_directory(root, "release output root")
    temporary = root / f"{STAGING_DIRECTORY_NAME}.doi-prepared"
    backup = root / f"{STAGING_DIRECTORY_NAME}.doi-backup"

    # Deterministically reconcile a process interruption at either atomic
    # directory rename. A canonical staging tree is never assembled in place.
    if backup.exists() or backup.is_symlink():
        _require_plain_directory(backup, "DOI binding backup")
        if staging.exists() or staging.is_symlink():
            _require_plain_directory(staging, "staging directory")
            current = _walk_public_files(staging)
            _validate_reserved_doi_staging(current)
            shutil.rmtree(backup)
        else:
            os.replace(backup, staging)
        if temporary.exists() or temporary.is_symlink():
            _require_plain_directory(temporary, "DOI binding prepared tree")
            shutil.rmtree(temporary)
        _fsync_directory(root)
    elif temporary.exists() or temporary.is_symlink():
        _require_plain_directory(temporary, "DOI binding prepared tree")
        shutil.rmtree(temporary)
        _fsync_directory(root)

    _require_plain_directory(staging, "staging directory")
    if {entry.name for entry in root.iterdir()} != {STAGING_DIRECTORY_NAME}:
        raise FileExistsError("release output root contains unexpected state")
    existing = _walk_public_files(staging)
    if set(existing) == RESERVED_STAGING_FILES:
        existing_release, existing_reservation = _validate_reserved_doi_staging(existing)
        reservation = _reservation_payload(reservation_attestation)
        if approval_public_key is None or approved_key_fingerprint is None:
            raise ValueError("DOI binding requires separately approved external-verification key material")
        configured = _configured_doi_approval_fingerprint()
        if approved_key_fingerprint != configured:
            raise ValueError("DOI approval key fingerprint differs from the reviewed release configuration")
        public_key = Path(approval_public_key)
        _verify_reservation_approval(reservation, public_key, configured)
        if (
            existing["doi-reservation.json"].read_bytes() != _canonical_json(reservation)
            or existing["doi-approval-public.der"].read_bytes() != _public_key_der(public_key)
        ):
            raise ValueError("DOI staging is already bound to a different reservation or key")
        if (
            existing_reservation != reservation
            or existing_release["doi"] != reservation["doi"]
        ):
            raise ValueError("existing DOI-bound staging metadata is inconsistent")
        return staging
    if set(existing) != STAGING_FILES:
        raise ValueError("DOI binding requires untouched aggregate staging")

    try:
        shutil.copytree(staging, temporary, copy_function=shutil.copy2)
        _bind_reserved_doi_in_place(
            staging_directory=temporary, reservation_attestation=reservation_attestation,
            approval_public_key=approval_public_key, approved_key_fingerprint=approved_key_fingerprint,
        )
        _validate_reserved_doi_staging(_walk_public_files(temporary))
        _fsync_public_tree(temporary)
        os.replace(staging, backup)
        _fsync_directory(root)
        os.replace(temporary, staging)
        _fsync_directory(root)
        shutil.rmtree(backup)
        _fsync_directory(root)
        return staging
    except BaseException:
        if backup.exists() or backup.is_symlink():
            if staging.exists() or staging.is_symlink():
                # Promotion completed. Retain the complete prepared tree and
                # discard only the preserved original.
                shutil.rmtree(backup)
            else:
                os.replace(backup, staging)
        if temporary.exists() or temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        _fsync_directory(root)
        raise


def _metric_objects(payload: Any) -> tuple[Metric, ...]:
    _validate_instance(METRICS_SCHEMA_PATH, payload, "metrics")
    metrics = []
    for item in payload["metrics"]:
        if set(item) != PUBLIC_METRIC_FIELDS:
            raise ValueError("metrics contain unreviewed fields")
        metrics.append(Metric(
            metric_id=item["metric_id"], category=item["category"],
            numerator=item["numerator"], denominator=item["denominator"],
            denominator_metric_id=item["denominator_metric_id"],
            percentage=Decimal(item["percentage"]),
            display_percentage=item["display_percentage"], precision=item["precision"],
            population=item["population"], unit=item["unit"],
            measurement_period=item["measurement_period"], method=item["method"],
            caveat=item["caveat"],
        ))
    validate_metrics(metrics)
    return tuple(metrics)


def _validate_csv_parity(path: Path, metrics: Sequence[Metric]) -> None:
    with path.open("r", encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    expected = [metric.to_dict() for metric in metrics]
    if len(rows) != len(expected):
        raise ValueError("metrics CSV row count differs from metrics JSON")
    for csv_row, json_row in zip(rows, expected, strict=True):
        if set(csv_row) != set(json_row) or any(
            csv_row[key] != ("" if value is None else str(value))
            for key, value in json_row.items()
        ):
            raise ValueError("metrics CSV does not match metrics JSON")


def _safe_figure_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or len(path.parts) < 2 or path.parts[0] != "figures":
        raise ValueError("figure manifest contains an unsafe path")
    return path


def _validate_png(content: bytes, item: Mapping[str, Any]) -> tuple[int, int]:
    if len(content) > 20 * 1024 * 1024:
        raise ValueError("figure PNG exceeds the reviewed size limit")
    if not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("figure is not a valid PNG")
    offset = 8
    chunk_types = []
    text_keys = []
    while offset < len(content):
        if offset + 12 > len(content):
            raise ValueError("figure PNG is corrupt or truncated")
        length = int.from_bytes(content[offset:offset + 4], "big")
        end = offset + length + 12
        if end > len(content):
            raise ValueError("figure PNG is corrupt or truncated")
        chunk_type = content[offset + 4:offset + 8]
        chunk_types.append(chunk_type)
        if chunk_type in {b"tEXt", b"iTXt"}:
            keyword, separator, value = content[offset + 8:end - 4].partition(b"\x00")
            if not separator:
                raise ValueError("figure PNG text metadata is invalid")
            try:
                text_keys.append(keyword.decode("latin-1"))
                if chunk_type == b"tEXt":
                    _assert_safe_public_text(value.decode("latin-1"), "figure PNG text metadata", allowed_domain_like=[*item["metric_ids"], *item["denominator_metric_ids"]])
            except UnicodeDecodeError as exc:
                raise ValueError("figure PNG text metadata key is invalid") from exc
        offset = end
    if offset != len(content) or not chunk_types or chunk_types[0] != b"IHDR" or chunk_types[-1] != b"IEND":
        raise ValueError("figure PNG chunk structure is invalid")
    if not set(chunk_types).issubset({b"IHDR", b"IDAT", b"IEND", b"tEXt", b"iTXt"}):
        raise ValueError("figure PNG contains an unreviewed metadata chunk")
    if sorted(text_keys) != ["caption", "doi", "source"]:
        raise ValueError("figure PNG text metadata keys differ from the contract")
    try:
        with Image.open(BytesIO(content)) as image:
            if image.format != "PNG":
                raise ValueError("figure is not a valid PNG")
            metadata = dict(image.info)
            image.verify()
        with Image.open(BytesIO(content)) as image:
            image.load()
            dimensions = image.size
            mode = image.mode
    except (UnidentifiedImageError, OSError, SyntaxError) as exc:
        raise ValueError("figure PNG is corrupt or truncated") from exc
    if dimensions != (item["width"], item["height"]):
        raise ValueError("figure PNG dimensions differ from the exact chart contract")
    if mode not in {"RGB", "RGBA"}:
        raise ValueError("figure PNG mode must be RGB or RGBA")
    expected_metadata = {
        "doi": item["doi"], "source": item["source_label"],
        "caption": item["caption"],
    }
    if metadata != expected_metadata:
        raise ValueError("figure PNG visible-metadata contract is missing or changed")
    for value in metadata.values():
        _assert_safe_public_text(str(value), "figure PNG text metadata", allowed_domain_like=[*item["metric_ids"], *item["denominator_metric_ids"]])
    return dimensions


@cache
def _figure_font_bytes() -> bytes:
    """Load the one licensed font accepted by the release boundary."""
    _require_plain_file(FIGURE_FONT_PATH, "bundled DM Sans figure font")
    payload = FIGURE_FONT_PATH.read_bytes()
    if hashlib.sha256(payload).hexdigest() != FIGURE_FONT_SHA256:
        raise ValueError("bundled DM Sans figure font differs from the pinned licensed asset")
    return payload


@cache
def _svg_font_face_declaration() -> str:
    encoded = base64.b64encode(_figure_font_bytes()).decode("ascii")
    return (
        f"@font-face{{font-family:'{FIGURE_FONT_FAMILY}';"
        f"src:url('data:font/ttf;base64,{encoded}') format('truetype');"
        "font-style:normal;font-weight:100 1000;font-display:block;}"
    )


def _validate_embedded_svg_font(style: ET.Element) -> bytes:
    """Accept only the exact inert data-URI declaration for pinned DM Sans."""
    if style.attrib != {"type": "text/css"} or len(style) or style.tail and style.tail.strip():
        raise ValueError("figure SVG embedded font style structure differs from the contract")
    declaration = style.text or ""
    if declaration != _svg_font_face_declaration():
        raise ValueError("figure SVG embedded font declaration is not the exact allowlisted style")
    expected = _figure_font_bytes()
    return expected


SVG_ALLOWED_ATTRIBUTES = {
    "svg": {"width", "height", "viewBox", "role", "aria-labelledby"},
    "g": {"transform", "fill", "stroke", "stroke-width", "opacity", "font-family", "font-size", "font-weight", "text-anchor"},
    "title": {"id"}, "desc": {"id"},
    "style": {"type"},
    "rect": {"x", "y", "width", "height", "rx", "ry", "fill", "stroke", "stroke-width", "opacity"},
    "line": {"x1", "y1", "x2", "y2", "stroke", "stroke-width", "opacity"},
    "path": {"d", "fill", "stroke", "stroke-width", "opacity"},
    "circle": {"cx", "cy", "r", "fill", "stroke", "stroke-width", "opacity"},
    "text": {"id", "x", "y", "dx", "dy", "fill", "font-family", "font-size", "font-weight", "text-anchor", "dominant-baseline"},
    "tspan": {"x", "y", "dx", "dy", "fill", "font-family", "font-size", "font-weight"},
}
SVG_BACKGROUND_FILL = "#f8f7f3"
SVG_REQUIRED_TEXT_FILL = "#111111"
SVG_MIN_REQUIRED_FONT_SIZE_PX = 10.0
SVG_MAX_REQUIRED_FONT_SIZE_PX = 96.0
SVG_REQUIRED_TEXT_FONT_SIZE_PX = 12.0
SVG_REQUIRED_TEXT_X = 40
SVG_CAPTION_START_Y = 140
SVG_CAPTION_LINE_HEIGHT = 24
SVG_REQUIRED_TEXT_HORIZONTAL_INSET = 40


def _svg_caption_lines(caption: str, width: int) -> tuple[str, ...]:
    """Return the one reviewed, conservatively bounded caption line layout."""
    normalized = " ".join(caption.split())
    available_width = width - (2 * SVG_REQUIRED_TEXT_HORIZONTAL_INSET)
    max_characters = int(available_width // SVG_REQUIRED_TEXT_FONT_SIZE_PX)
    if not normalized or max_characters < 1:
        raise ValueError("figure SVG caption cannot fit the approved canvas")
    lines = tuple(textwrap.wrap(
        normalized, width=max_characters,
        break_long_words=False, break_on_hyphens=False,
    ))
    if (
        not lines
        or " ".join(lines) != normalized
        or any(len(line) * SVG_REQUIRED_TEXT_FONT_SIZE_PX > available_width for line in lines)
    ):
        raise ValueError("figure SVG caption cannot fit the approved visible line layout")
    return lines


def _svg_required_text_layout(item: Mapping[str, Any]) -> tuple[tuple[str, int, int], ...]:
    width, height = int(item["width"]), int(item["height"])
    caption_lines = _svg_caption_lines(str(item["caption"]), width)
    caption_layout = tuple(
        (line, SVG_REQUIRED_TEXT_X, SVG_CAPTION_START_Y + index * SVG_CAPTION_LINE_HEIGHT)
        for index, line in enumerate(caption_lines)
    )
    if caption_layout[-1][2] > height - 100:
        raise ValueError("figure SVG caption overlaps the approved source and DOI area")
    return (
        (" ".join(str(item["title"]).split()), SVG_REQUIRED_TEXT_X, 80),
        *caption_layout,
        (" ".join(str(item["source_label"]).split()), SVG_REQUIRED_TEXT_X, height - 60),
        (" ".join(str(item["doi"]).split()), SVG_REQUIRED_TEXT_X, height - 30),
    )


def _svg_contrast_ratio(foreground: str, background: str) -> float:
    def luminance(value: str) -> float:
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", value):
            raise ValueError("figure SVG palette contains an unapproved color")
        channels = [int(value[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [
            channel / 12.92 if channel <= 0.04045
            else ((channel + 0.055) / 1.055) ** 2.4
            for channel in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    foreground_luminance = luminance(foreground)
    background_luminance = luminance(background)
    lighter, darker = sorted((foreground_luminance, background_luminance), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def _svg_local_name(tag: str) -> tuple[str, str]:
    if not isinstance(tag, str) or not tag.startswith("{http://www.w3.org/2000/svg}"):
        raise ValueError("figure SVG contains an external namespace")
    return tag.rsplit("}", 1)[-1], "http://www.w3.org/2000/svg"


def _validate_svg(content: bytes, item: Mapping[str, Any]) -> tuple[int, int]:
    if len(content) > 5 * 1024 * 1024:
        raise ValueError("figure SVG exceeds the reviewed size limit")
    lowered = content.lower()
    if any(token in lowered for token in (
        b"<!doctype", b"<!entity", b"<?", b"xmlns:", b"javascript:",
    )):
        raise ValueError("figure SVG must be an inactive standalone document")
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError("figure is not valid SVG XML") from exc
    root_name, _namespace = _svg_local_name(root.tag)
    if root_name != "svg":
        raise ValueError("figure SVG root element is invalid")
    for element in root.iter():
        name, _namespace = _svg_local_name(element.tag)
        if name not in SVG_ALLOWED_ATTRIBUTES:
            raise ValueError(f"figure SVG element is not allowlisted: {name}")
        if element.tail and element.tail.strip():
            raise ValueError("figure SVG contains unreviewed mixed-content text")
        if name not in {"title", "desc", "style", "text"} and element.text and element.text.strip():
            raise ValueError("figure SVG contains unreviewed mixed-content text")
        for attribute, value in element.attrib.items():
            if (
                attribute.startswith("{") or ":" in attribute
                or attribute.lower().startswith("on")
                or attribute not in SVG_ALLOWED_ATTRIBUTES[name]
                or re.search(r"(?:url\s*\(|javascript:|data:|https?:|file:|//)", value, re.I)
            ):
                raise ValueError(f"figure SVG attribute is not allowlisted: {attribute}")
        if name == "text" and element.attrib.get("font-family") != FIGURE_FONT_FAMILY:
            raise ValueError("figure SVG text must explicitly use the embedded DM Sans font")
    dimensions = []
    for name in ("width", "height"):
        raw = root.attrib.get(name, "")
        if not re.fullmatch(r"[1-9][0-9]*", raw):
            raise ValueError("figure SVG must declare integer pixel dimensions")
        dimensions.append(int(raw))
    expected_dimensions = (item["width"], item["height"])
    if tuple(dimensions) != expected_dimensions or root.attrib.get("viewBox") != f"0 0 {dimensions[0]} {dimensions[1]}":
        raise ValueError("figure SVG dimensions or viewBox differ from the exact chart contract")
    if root.attrib.get("role") != "img" or root.attrib.get("aria-labelledby") != "figure-title figure-description":
        raise ValueError("figure SVG must expose localized title and description through ARIA")
    children = list(root)
    child_names = [_svg_local_name(child.tag)[0] for child in children]
    all_elements = list(root.iter())
    required_layout = _svg_required_text_layout(item)
    required_count = len(required_layout)
    if (
        len(children) < 4 + required_count
        or child_names[:4] != ["title", "desc", "style", "rect"]
        or child_names[-required_count:] != ["text"] * required_count
        or sum(_svg_local_name(element.tag)[0] == "title" for element in all_elements) != 1
        or sum(_svg_local_name(element.tag)[0] == "desc" for element in all_elements) != 1
        or sum(_svg_local_name(element.tag)[0] == "style" for element in all_elements) != 1
    ):
        raise ValueError("figure SVG requires the exact direct accessibility and text layer order")
    title, description, style, background = children[:4]
    _validate_embedded_svg_font(style)
    identifiers = [element.attrib["id"] for element in all_elements if "id" in element.attrib]
    if (
        title.attrib != {"id": "figure-title"}
        or description.attrib != {"id": "figure-description"}
        or len(title) or len(description)
        or " ".join("".join(title.itertext()).split()) != " ".join(item["title"].split())
        or " ".join("".join(description.itertext()).split()) != " ".join(item["description"].split())
        or identifiers != ["figure-title", "figure-description"]
        or len(identifiers) != len(set(identifiers))
    ):
        raise ValueError("figure SVG localized title, description, or ARIA IDs differ from the exact contract")
    if background.attrib != {
        "x": "0", "y": "0", "width": str(dimensions[0]), "height": str(dimensions[1]),
        "fill": SVG_BACKGROUND_FILL,
    }:
        raise ValueError("figure SVG requires the exact approved full-canvas background")
    if _svg_contrast_ratio(SVG_REQUIRED_TEXT_FILL, SVG_BACKGROUND_FILL) < 7:
        raise ValueError("figure SVG required-text palette lacks approved contrast")

    required_nodes = children[-required_count:]
    available_width = dimensions[0] - (2 * SVG_REQUIRED_TEXT_HORIZONTAL_INSET)
    for element, (expected_text, expected_x, expected_y) in zip(
        required_nodes, required_layout, strict=True,
    ):
        actual_text = " ".join("".join(element.itertext()).split())
        attributes = dict(element.attrib)
        font_size_value = attributes.pop("font-size", str(SVG_REQUIRED_TEXT_FONT_SIZE_PX))
        try:
            font_size = float(font_size_value)
        except ValueError as exc:
            raise ValueError("figure SVG required text font size is invalid") from exc
        if (
            len(element) or actual_text != expected_text
            or attributes != {
                "x": str(expected_x), "y": str(expected_y), "fill": SVG_REQUIRED_TEXT_FILL,
                "font-family": FIGURE_FONT_FAMILY,
            }
            or not SVG_MIN_REQUIRED_FONT_SIZE_PX <= font_size <= SVG_MAX_REQUIRED_FONT_SIZE_PX
            or len(actual_text) * font_size > available_width
        ):
            raise ValueError(
                "figure SVG requires exact direct, visible, high-contrast text at approved positions",
            )
    visible_text = [
        " ".join("".join(element.itertext()).split())
        for element in all_elements if _svg_local_name(element.tag)[0] == "text"
    ]
    title_text = required_layout[0][0]
    caption_lines = [line for line, _x, _y in required_layout[1:-2]]
    source_text, doi_text = required_layout[-2][0], required_layout[-1][0]
    if any(visible_text.count(value) != 1 for value in (title_text, source_text, doi_text)):
        raise ValueError("figure SVG required visible title, source, and DOI must occur exactly once")
    caption_occurrences = sum(
        visible_text[index:index + len(caption_lines)] == caption_lines
        for index in range(len(visible_text) - len(caption_lines) + 1)
    )
    full_caption = " ".join(str(item["caption"]).split())
    normalized_visible_text = " ".join(visible_text)
    if (
        caption_occurrences != 1
        or normalized_visible_text.count(full_caption) != 1
    ):
        raise ValueError("figure SVG required visible caption must occur exactly once")
    all_text = " ".join(
        " ".join("".join(element.itertext()).split())
        for element in all_elements
        if _svg_local_name(element.tag)[0] in {"title", "desc", "text"}
        and "".join(element.itertext()).strip()
    )
    _assert_safe_public_text(
        all_text, "figure SVG decoded text",
        allowed_domain_like=[*item["metric_ids"], *item["denominator_metric_ids"]],
    )
    return expected_dimensions


def _validate_figures(
    staging: Path, metrics: Sequence[Metric], release: Mapping[str, Any], doi: str,
) -> set[str]:
    manifest_path = staging / "figures" / "manifest.json"
    _require_plain_file(manifest_path, "figure manifest")
    manifest = _load_json(manifest_path, "figure manifest")
    _validate_instance(FIGURES_SCHEMA_PATH, manifest, "figure manifest")
    known_metrics = {metric.metric_id: metric for metric in metrics}
    listed: set[str] = set()
    pair_metadata: dict[tuple[str, str], dict[str, Any]] = {}
    localized_copy: dict[str, list[tuple[str, str, str]]] = {
        chart_id: [] for chart_id in FIGURE_SPECS
    }
    expected_paths = {
        f"figures/{chart_id}.{locale}.{fmt}"
        for chart_id in FIGURE_SPECS for locale in FIGURE_LOCALES
        for fmt in ("svg", "png")
    }
    for item in manifest["figures"]:
        relative = _safe_figure_path(item["path"]).as_posix()
        if relative in listed:
            raise ValueError("figure manifest contains duplicate paths")
        listed.add(relative)
        specification = FIGURE_SPECS[item["chart_id"]]
        expected_path = f"figures/{item['chart_id']}.{item['locale']}.{item['format']}"
        expected_dimensions = specification["dimensions"]
        if (
            relative != expected_path
            or item["family"] != specification["family"]
            or item["kind"] != specification["kind"]
            or (item["width"], item["height"]) != expected_dimensions
            or tuple(item["metric_ids"]) != specification["metric_ids"]
            or tuple(item["denominator_metric_ids"]) != specification["denominator_metric_ids"]
        ):
            raise ValueError("figure differs from its exact chart, family, metric, or dimension contract")
        metric_objects = [known_metrics.get(metric_id) for metric_id in item["metric_ids"]]
        if any(metric is None for metric in metric_objects):
            raise ValueError("figure references an unknown metric")
        if tuple(metric.denominator_metric_id for metric in metric_objects if metric is not None) != specification["denominator_metric_ids"]:
            raise ValueError("figure denominator IDs differ from canonical metrics")
        expected_methods = list(dict.fromkeys(metric.method for metric in metric_objects if metric is not None))
        expected_caveats = list(dict.fromkeys(metric.caveat for metric in metric_objects if metric is not None))
        if specification.get("required_caveat"):
            expected_caveats.append(specification["required_caveat"])
        if item["methodology_signals"] != expected_methods or item["caveat_signals"] != expected_caveats:
            raise ValueError("figure method or scientific caveat signals differ from canonical metrics")
        if (
            item["doi"] != doi or doi not in item["caption"]
            or item["source_snapshot_date"] != release["source_universe"]["snapshot_date"]
            or item["source_snapshot_sha256"] != release["source_universe"]["normalized_sha256"]
            or item["source_label"] != FIGURE_SOURCE_LABELS[item["locale"]]
            or item["measurement_interval"] != release["measurement_interval"]
            or item["repository"] != CANONICAL_REPOSITORY_URL
        ):
            raise ValueError("figure DOI, source, interval, caption, or repository contract changed")
        approved_copy = _approved_figure_copy(item["chart_id"], item["locale"], metrics, release, doi)
        if any(item[key] != value for key, value in approved_copy.items()):
            raise ValueError("figure localized copy is not the reviewed deterministic template")
        pair_key = (item["chart_id"], item["locale"])
        comparable = {
            key: value for key, value in item.items()
            if key not in {"path", "format", "mime_type", "sha256", "bytes"}
        }
        if pair_key in pair_metadata and pair_metadata[pair_key] != comparable:
            raise ValueError("SVG and PNG figure pair metadata differs")
        if pair_key not in pair_metadata:
            localized_copy[item["chart_id"]].append(
                (item["title"], item["description"], item["caption"]),
            )
        pair_metadata[pair_key] = comparable
        path = staging / relative
        _require_plain_file(path, "figure payload")
        content = path.read_bytes()
        if item["format"] == "png":
            dimensions = _validate_png(content, item)
            mime = "image/png"
        else:
            dimensions = _validate_svg(content, item)
            mime = "image/svg+xml"
        if item["mime_type"] != mime or (item["width"], item["height"]) != dimensions:
            raise ValueError("figure MIME type or dimensions do not match")
        digest, size = _sha256_and_size(path)
        if (item["sha256"], item["bytes"]) != (digest, size):
            raise ValueError("figure checksum or byte count does not match")
    actual = {
        f"figures/{path.relative_to(staging / 'figures').as_posix()}"
        for path in (staging / "figures").rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    if listed != expected_paths or actual != expected_paths or len(listed) != EXPECTED_FIGURE_COUNT:
        raise ValueError("figure manifest must contain the exact 30 reviewed SVG/PNG payloads")
    if any(
        len({copy[index] for copy in copies}) != len(FIGURE_LOCALES)
        for copies in localized_copy.values() for index in range(3)
    ):
        raise ValueError("figure titles, descriptions, and captions must be localized per locale")
    return listed


def _yaml_scalar(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("CITATION.cff contains an empty YAML scalar")
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("CITATION.cff contains an invalid quoted YAML scalar") from exc
        if not isinstance(parsed, str):
            raise ValueError("CITATION.cff permits string scalars only")
        return parsed
    if value.startswith("'") and value.endswith("'") and len(value) >= 2:
        return value[1:-1].replace("''", "'")
    if any(character in value for character in "{}[]&*!|>#"):
        raise ValueError("CITATION.cff contains unsafe YAML syntax")
    return value


def _parse_citation(path: Path) -> dict[str, Any]:
    """Parse the deliberately small, inactive YAML subset accepted for CFF."""
    text = path.read_text(encoding="utf-8")
    if "\t" in text or re.search(r"(?m)^\s*(?:---|\.\.\.|%|!!|&|\*|<<:)", text):
        raise ValueError("CITATION.cff contains unsafe YAML directives or tags")
    lines = [line for line in text.splitlines() if line.strip()]
    payload: dict[str, Any] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith(" ") or ":" not in line:
            raise ValueError("CITATION.cff uses unsupported YAML indentation")
        key, raw = line.split(":", 1)
        if not re.fullmatch(r"[a-z][a-z-]*", key) or key in payload:
            raise ValueError("CITATION.cff contains an invalid or duplicate key")
        if key != "authors":
            payload[key] = _yaml_scalar(raw)
            index += 1
            continue
        if raw.strip():
            raise ValueError("CITATION.cff authors must be a block sequence")
        authors: list[dict[str, str]] = []
        index += 1
        while index < len(lines) and lines[index].startswith("  - "):
            author: dict[str, str] = {}
            first = lines[index][4:]
            if ":" not in first:
                raise ValueError("CITATION.cff author entry is invalid")
            author_key, author_value = first.split(":", 1)
            author[author_key] = _yaml_scalar(author_value)
            index += 1
            while index < len(lines) and lines[index].startswith("    "):
                nested = lines[index][4:]
                if ":" not in nested:
                    raise ValueError("CITATION.cff author field is invalid")
                author_key, author_value = nested.split(":", 1)
                if author_key in author:
                    raise ValueError("CITATION.cff contains a duplicate author field")
                author[author_key] = _yaml_scalar(author_value)
                index += 1
            authors.append(author)
        if not authors:
            raise ValueError("CITATION.cff requires at least one author")
        payload[key] = authors
    _validate_instance(CITATION_SCHEMA_PATH, payload, "CITATION.cff")
    return payload


def _validate_release_cross_references(
    release: Mapping[str, Any], attestation: Mapping[str, Any],
    metrics: Sequence[Metric],
) -> None:
    config = _load_official_config()
    if release["source_universe"] != {
        "snapshot_date": config["source_snapshot_date"],
        "normalized_sha256": config["source_input_normalized_sha256"],
        "normalized_line_count": config["source_input_normalized_line_count"],
    }:
        raise ValueError("public release differs from the pinned source universe")
    values = {metric.metric_id: metric.numerator for metric in metrics}
    expected_accounting = {
        "total": values["population.total"],
        "analyzable": values["population.analyzable"],
        "error": values["population.error"],
    }
    if release["aggregate_row_accounting"] != expected_accounting:
        raise ValueError("release row accounting differs from aggregate metrics")
    if expected_accounting["total"] != config["source_input_normalized_line_count"]:
        raise ValueError("aggregate total differs from the pinned source universe")
    if expected_accounting["total"] != expected_accounting["analyzable"] + expected_accounting["error"]:
        raise ValueError("release row accounting does not partition its total")

    runs = release["run_chain"]
    if [run["sequence"] for run in runs] != list(range(1, len(runs) + 1)):
        raise ValueError("public run-chain sequence is not contiguous")
    for index, run in enumerate(runs):
        if run["database_pre"]["total"] != run["database_pre"]["analyzable"] + run["database_pre"]["error"]:
            raise ValueError("public run-chain pre-accounting is invalid")
        if run["database_post"]["total"] != run["database_post"]["analyzable"] + run["database_post"]["error"]:
            raise ValueError("public run-chain post-accounting is invalid")
        started = _parse_utc_timestamp(run["started_at_utc"], "public run start")
        finished = _parse_utc_timestamp(run["finished_at_utc"], "public run finish")
        if finished <= started:
            raise ValueError("public run-chain interval is empty")
        if index and started < _parse_utc_timestamp(runs[index - 1]["finished_at_utc"], "previous public run finish"):
            raise ValueError("public run-chain intervals overlap")
    root = runs[0]
    if (
        root["manifest_schema_version"] != 1
        or root["mode"] != config["root_run"]["mode"]
        or root["scanner_git_revision"] != config["root_scanner_git_revision"]
        or root["measurement_core_sha256"] != config["root_measurement_core_sha256"]
        or root["attempted_input_count"] != config["source_input_normalized_line_count"]
        or root["database_pre"] != {"total": 0, "analyzable": 0, "error": 0}
        or root["database_post"]["total"] != config["source_input_normalized_line_count"]
    ):
        raise ValueError("public v1 root summary differs from the pinned chain")
    for index, run in enumerate(runs[1:], 1):
        previous = runs[index - 1]
        if (
            run["manifest_schema_version"] != 2
            or run["mode"] != config["retry_run"]["mode"]
            or run["measurement_core_sha256"] != config["final_measurement_core_sha256"]
            or run["database_pre"] != previous["database_post"]
            or run["database_pre"]["total"] != config["source_input_normalized_line_count"]
            or run["database_post"]["total"] != config["source_input_normalized_line_count"]
            or run["attempted_input_count"] != run["database_pre"]["error"]
            or run["database_post"]["error"] > run["database_pre"]["error"]
        ):
            raise ValueError("public retry summary does not preserve chain invariants")
    if runs[-1]["database_post"] != expected_accounting:
        raise ValueError("public final run accounting differs from aggregate row accounting")
    expected_interval = {
        "started_at_utc": runs[0]["started_at_utc"],
        "finished_at_utc": runs[-1]["finished_at_utc"],
    }
    if release["measurement_interval"] != expected_interval or release["generated_at_utc"] != runs[-1]["finished_at_utc"]:
        raise ValueError("public measurement interval differs from its run chain")
    if attestation["measurement_interval"] != expected_interval:
        raise ValueError("aggregate attestation interval differs from the run chain")
    if (
        attestation["source_input_normalized_sha256"] != release["source_universe"]["normalized_sha256"]
        or attestation["source_input_normalized_line_count"] != release["source_universe"]["normalized_line_count"]
        or attestation["root_measurement_core_sha256"] != release["measurement_core"]["root_sha256"]
        or attestation["final_measurement_core_sha256"] != release["measurement_core"]["final_sha256"]
        or attestation["measurement_core_transition_attestation_id"] != release["measurement_core"]["transition"]["attestation_id"]
        or attestation["final_run_identifier"] != runs[-1]["run_identifier"]
        or attestation["final_manifest_sha256"] != runs[-1]["manifest_sha256"]
    ):
        raise ValueError("aggregate attestation differs from public release metadata")


def _validate_aggregate_components(
    files: Mapping[str, Path], *, expected_status: str,
) -> tuple[dict[str, Any], tuple[Metric, ...], dict[str, Any]]:
    release = _load_json(files["release.json"], "staging release")
    _validate_instance(RELEASE_SCHEMA_PATH, release, "staging release")
    if release["status"] != expected_status:
        raise ValueError(f"release status must be {expected_status}")
    if expected_status == "staging" and any(
        field in release for field in ("doi", "doi_reservation_file", "inventory")
    ):
        raise ValueError("aggregate staging may not bind a DOI or inventory")
    if expected_status == "doi_reserved" and "inventory" in release:
        raise ValueError("DOI-reserved staging may not contain a sealed inventory")
    metrics_payload = _load_json(files["metrics.json"], "metrics")
    metrics = _metric_objects(metrics_payload)
    _validate_csv_parity(files["metrics.csv"], metrics)
    if release["metric_count"] != len(metrics):
        raise ValueError("release metric count does not match metrics")
    attestation = _load_json(files["aggregate-attestation.json"], "aggregate attestation")
    _validate_instance(ATTESTATION_SCHEMA_PATH, attestation, "aggregate attestation")
    if attestation["metric_count"] != len(metrics):
        raise ValueError("aggregate attestation metric count does not match")
    _validate_release_cross_references(release, attestation, metrics)
    expected_aggregate = {
        item["name"]: (item["sha256"], item["bytes"])
        for item in release["aggregate_files"]
    }
    for name in ("metrics.json", "metrics.csv", "aggregate-attestation.json"):
        if expected_aggregate.get(name) != _sha256_and_size(files[name]):
            raise ValueError("aggregate file changed after staging")
    if {item["name"] for item in attestation["metric_files"]} != {"metrics.json", "metrics.csv"}:
        raise ValueError("aggregate attestation metric-file contract changed")
    for item in attestation["metric_files"]:
        if (item["sha256"], item["bytes"]) != _sha256_and_size(files[item["name"]]):
            raise ValueError("metric file differs from aggregate attestation")
    interval = f"{release['measurement_interval']['started_at_utc']}/{release['measurement_interval']['finished_at_utc']}"
    if any(metric.measurement_period != interval for metric in metrics):
        raise ValueError("metric measurement interval differs from release")
    return release, metrics, attestation


def _validate_document(path: Path, name: str, release: Mapping[str, Any], doi: str) -> None:
    text = path.read_text(encoding="utf-8")
    title, headings = DOCUMENT_CONTRACTS[name]
    if re.search(r"\b(?:tbd|todo|pending|placeholder|lorem ipsum)\b", text, re.I):
        raise ValueError(f"{name} contains placeholder text")
    lines = text.splitlines()
    if not lines or lines[0] != f"# {title}":
        raise ValueError(f"{name} title heading differs from the document contract")
    actual_headings = tuple(
        line.removeprefix("## ") for line in lines if line.startswith("## ")
    )
    if actual_headings != headings:
        raise ValueError(f"{name} section headings differ from the document contract")
    expected_fields = {
        "Release-Version": RELEASE_VERSION,
        "DOI": doi,
        "Source-Snapshot-Date": release["source_universe"]["snapshot_date"],
        "Measurement-Started-At": release["measurement_interval"]["started_at_utc"],
        "Measurement-Finished-At": release["measurement_interval"]["finished_at_utc"],
        "Repository": CANONICAL_REPOSITORY_URL,
        "License": "CC BY 4.0",
    }
    first_section = next(
        (index for index, line in enumerate(lines) if line.startswith("## ")),
        len(lines),
    )
    actual_fields: dict[str, str] = {}
    for line in lines[1:first_section]:
        if not line.strip():
            continue
        if ": " not in line:
            raise ValueError(f"{name} metadata field syntax is invalid")
        field, value = line.split(": ", 1)
        if field in actual_fields:
            raise ValueError(f"{name} contains a duplicate metadata field: {field}")
        actual_fields[field] = value
    if actual_fields != expected_fields:
        raise ValueError(f"{name} required metadata fields differ")
    sections = re.split(r"(?m)^## [^\n]+\n", text)[1:]
    if len(sections) != len(headings) or any(len(section.split()) < 10 for section in sections):
        raise ValueError(f"{name} contains an empty or incomplete structured section")


def _reviewed_artifact_entries(files: Mapping[str, Path]) -> list[dict[str, Any]]:
    """Return a prospective catalogue that is stable across deterministic sealing.

    The signoff itself and the derived checksum envelope are necessarily
    excluded. ``release.json`` contributes every stable semantic field; only
    lifecycle ``status`` and derived ``inventory`` are removed. All other
    reviewed artifacts contribute their exact bytes.
    """
    entries: list[dict[str, Any]] = []
    for name in sorted(files):
        if name in {"EDITORIAL-SIGNOFF.json", "checksums.sha256"}:
            continue
        if name == "release.json":
            release = _load_json(files[name], "reviewed release semantics")
            stable = dict(release)
            stable.pop("status", None)
            stable.pop("inventory", None)
            content = _canonical_json(stable)
            entries.append({
                "path": "release.json#stable-semantics", "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            })
        else:
            digest, size = _sha256_and_size(files[name])
            entries.append({"path": name, "sha256": digest, "bytes": size})
    return entries


def _reviewed_artifact_root(files: Mapping[str, Path]) -> str:
    payload = {
        "catalogue_version": 1,
        "scope": EDITORIAL_REVIEW_SCOPE,
        "artifacts": _reviewed_artifact_entries(files),
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _editorial_signoff_signed_bytes(payload: Mapping[str, Any]) -> bytes:
    signed = dict(payload)
    verification = dict(signed["external_verification"])
    verification.pop("signature_base64", None)
    signed["external_verification"] = verification
    return _canonical_json(signed)


def _validate_editorial_signoff(
    path: Path, *, doi: str, reservation: Mapping[str, Any], files: Mapping[str, Path],
    public_key: Path,
) -> None:
    payload = _load_json(path, "editorial signoff")
    _validate_instance(EDITORIAL_SIGNOFF_SCHEMA_PATH, payload, "editorial signoff")
    if payload["doi"] != doi:
        raise ValueError("editorial signoff DOI differs from the reservation")
    if payload["reviewed_scope"] != EDITORIAL_REVIEW_SCOPE:
        raise ValueError("editorial signoff review scope differs from the prospective contract")
    entries = _reviewed_artifact_entries(files)
    if payload["reviewed_artifact_count"] != len(entries):
        raise ValueError("editorial signoff reviewed artifact count differs from its scope")
    if payload["reviewed_artifact_root_sha256"] != _reviewed_artifact_root(files):
        raise ValueError("editorial signoff does not bind the reviewed artifact root")
    reservation_time = _parse_utc_timestamp(reservation["reserved_at_utc"], "reservation time")
    top_time = _parse_utc_timestamp(payload["signed_at_utc"], "editorial signoff time")
    signed_times = []
    expected_roles = {
        "scientific": "scientific-methods-reviewer", "privacy": "privacy-reviewer",
        "de": "german-language-editor", "fr": "french-language-editor", "it": "italian-language-editor",
    }
    identities = set()
    for role, signoff in payload["signoffs"].items():
        if signoff["approved"] is not True:
            raise ValueError(f"editorial {role} signoff is not approved")
        if signoff["reviewer_role"] != expected_roles[role]:
            raise ValueError(f"editorial {role} signoff role is not the required review role")
        if re.search(r"(?:pending|placeholder|example|tbd|todo)", " ".join((signoff["reviewer_name"], signoff["reviewer_identity"])), re.I):
            raise ValueError(f"editorial {role} signoff reviewer is a placeholder")
        if signoff["reviewer_identity"] in identities:
            raise ValueError("editorial signoff reviewer identities must be distinct")
        identities.add(signoff["reviewer_identity"])
        signed_times.append(_parse_utc_timestamp(signoff["signed_at_utc"], f"{role} signoff time"))
    if any(value < reservation_time for value in signed_times) or top_time != max(signed_times):
        raise ValueError("editorial signoff timestamps do not follow the DOI reservation")
    verification = payload["external_verification"]
    reservation_verification = reservation["external_verification"]
    configured = _configured_doi_approval_fingerprint()
    if (
        verification["authority_name"] != reservation_verification["authority_name"]
        or verification["approver_name"] != reservation_verification["approver_name"]
        or verification["approver_identity"] != reservation_verification["approver_identity"]
        or verification["approver_role"] != reservation_verification["approver_role"]
        or verification["public_key_fingerprint_sha256"] != configured
        or _public_key_fingerprint(public_key) != configured
    ):
        raise ValueError("editorial signoff authority or key differs from the DOI approval")
    _verify_ed25519_signature(
        payload=_editorial_signoff_signed_bytes(payload),
        signature_base64=verification["signature_base64"], public_key=public_key,
        description="editorial signoff",
    )


def _mime_type(relative: str) -> str:
    overrides = {
        ".json": "application/json", ".csv": "text/csv", ".md": "text/markdown",
        ".cff": "text/yaml", ".svg": "image/svg+xml", ".png": "image/png",
        ".sha256": "text/plain",
    }
    path = Path(relative)
    if path.name == "LICENSE":
        return "text/plain"
    return overrides.get(path.suffix.lower()) or mimetypes.guess_type(relative)[0] or "application/octet-stream"


def _verify_bundled_reservation(files: Mapping[str, Path]) -> dict[str, Any]:
    reservation = _reservation_payload(
        _load_json(files["doi-reservation.json"], "DOI reservation"),
    )
    public_key = files["doi-approval-public.der"]
    _require_ed25519_public_key(public_key)
    configured = _configured_doi_approval_fingerprint()
    if (
        _public_key_fingerprint(public_key) != configured
        or reservation["external_verification"]["public_key_fingerprint_sha256"] != configured
    ):
        raise ValueError("bundled DOI approval DER key differs from the reviewed configuration")
    _verify_reservation_approval(reservation, public_key, configured)
    return reservation


def _validate_reserved_doi_staging(
    files: Mapping[str, Path],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Authenticate a complete promoted DOI tree before trusting its presence."""
    if set(files) != RESERVED_STAGING_FILES:
        raise FileExistsError("interrupted DOI promotion contains an incomplete canonical tree")
    _assert_public_content_safe(files)
    release, _metrics, _attestation = _validate_aggregate_components(
        files, expected_status="doi_reserved",
    )
    reservation = _verify_bundled_reservation(files)
    identity = _sha256_and_size(files["doi-reservation.json"])
    if (
        release["doi"] != reservation["doi"]
        or release["doi_reservation_file"] != {
            "name": "doi-reservation.json", "sha256": identity[0], "bytes": identity[1],
        }
    ):
        raise ValueError("DOI-reserved staging differs from its authenticated reservation")
    return release, reservation


def _validate_staging(staging: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    _require_plain_directory(staging, "staging directory")
    files = _walk_public_files(staging)
    if not REQUIRED_FINAL_FILES.issubset(files):
        missing = sorted(REQUIRED_FINAL_FILES - files.keys())
        raise ValueError(f"staging is missing required public files: {', '.join(missing)}")
    _assert_public_content_safe(files)
    release, metrics, _attestation = _validate_aggregate_components(
        files, expected_status="doi_reserved",
    )
    reservation = _verify_bundled_reservation(files)
    der_key = files["doi-approval-public.der"]
    doi = release["doi"]
    if reservation["doi"] != doi:
        raise ValueError("release DOI differs from the Zenodo reservation")
    reservation_file = release["doi_reservation_file"]
    if (
        reservation_file["name"] != "doi-reservation.json"
        or (reservation_file["sha256"], reservation_file["bytes"])
        != _sha256_and_size(files["doi-reservation.json"])
    ):
        raise ValueError("DOI reservation file differs from release metadata")
    citation = _parse_citation(files["CITATION.cff"])
    if re.search(
        r"\b(?:tbd|todo|pending|placeholder|lorem ipsum)\b",
        json.dumps(citation), re.I,
    ):
        raise ValueError("CITATION.cff contains placeholder metadata")
    if (
        citation["doi"] != doi or citation["version"] != RELEASE_VERSION
        or citation["url"] != reservation["doi_url"]
        or citation["repository-code"] != CANONICAL_REPOSITORY_URL
        or "date-released" in citation
    ):
        raise ValueError("CITATION.cff differs from the DOI reservation or sealed-release contract")
    if files["LICENSE"].read_bytes() != CODE_LICENSE_PATH.read_bytes():
        raise ValueError("staging LICENSE differs from the canonical MIT license")
    if files["LICENSE-DATA.md"].read_bytes() != DATA_LICENSE_PATH.read_bytes():
        raise ValueError("staging LICENSE-DATA.md differs from the canonical data license")
    for name in DOCUMENT_CONTRACTS:
        _validate_document(files[name], name, release, doi)
    figure_files = _validate_figures(staging, metrics, release, doi)
    allowed_files = REQUIRED_FINAL_FILES | figure_files
    if set(files) != allowed_files:
        unexpected = sorted(set(files) - allowed_files)
        raise ValueError(f"staging contains an unreviewed public file: {', '.join(unexpected)}")
    _validate_editorial_signoff(
        files["EDITORIAL-SIGNOFF.json"], doi=doi, reservation=reservation, files=files,
        public_key=der_key,
    )
    return release, files


def _immutable_tree(directory: Path, *, include_root: bool = True) -> None:
    for path in sorted(directory.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        os.chmod(path, 0o555 if path.is_dir() else 0o444)
    if include_root:
        os.chmod(directory, 0o555)


def _walk_public_files_for_verification(directory: Path) -> dict[str, Path]:
    return _walk_public_files(directory, allow_checksums=True)


def _verify_checksums(directory: Path) -> None:
    checksum_path = directory / "checksums.sha256"
    _require_plain_file(checksum_path, "checksum manifest")
    rows = checksum_path.read_text(encoding="utf-8").splitlines()
    parsed: dict[str, str] = {}
    for row in rows:
        if row.count("  ") != 1:
            raise ValueError("checksum manifest syntax is invalid")
        digest, name = row.split("  ", 1)
        if not SHA256_PATTERN.fullmatch(digest) or name in parsed:
            raise ValueError("checksum manifest entry is invalid")
        parsed[name] = digest
    actual = _walk_public_files_for_verification(directory)
    _assert_public_content_safe(actual)
    expected_names = set(actual) - {"checksums.sha256"}
    if set(parsed) != expected_names:
        raise ValueError("checksum manifest does not cover every public file")
    for name, digest in parsed.items():
        if _sha256_and_size(actual[name])[0] != digest:
            raise ValueError(f"checksum verification failed for {name}")
    # A sealed bundle must still authenticate its DOI and prospective editorial
    # review, not merely reproduce its checksums.
    if (directory / "doi-reservation.json").exists():
        reservation = _verify_bundled_reservation(actual)
        release = _load_json(actual["release.json"], "sealed release")
        _validate_instance(RELEASE_SCHEMA_PATH, release, "sealed release")
        if release["status"] != "sealed" or release["doi"] != reservation["doi"]:
            raise ValueError("sealed release DOI or lifecycle status differs from reservation")
        expected_inventory = []
        for name, path in sorted(actual.items()):
            if name in {"release.json", "checksums.sha256"}:
                continue
            digest, size = _sha256_and_size(path)
            expected_inventory.append({
                "name": name, "sha256": digest, "bytes": size,
                "media_type": _mime_type(name),
            })
        if release["inventory"] != expected_inventory:
            raise ValueError("sealed release inventory differs from the exact public tree")
        reservation_identity = _sha256_and_size(actual["doi-reservation.json"])
        if release["doi_reservation_file"] != {
            "name": "doi-reservation.json", "sha256": reservation_identity[0],
            "bytes": reservation_identity[1],
        }:
            raise ValueError("sealed release DOI reservation inventory differs from its bytes")
        _validate_aggregate_components(actual, expected_status="sealed")
        _validate_editorial_signoff(
            actual["EDITORIAL-SIGNOFF.json"], doi=release["doi"],
            reservation=reservation, files=actual,
            public_key=actual["doi-approval-public.der"],
        )


def _copy_to_fresh_inode(source: Path, destination: Path) -> None:
    _require_plain_file(source, "staging payload")
    before = source.lstat()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ValueError("staging payload changed or is hard-linked")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    after = source.lstat()
    if (
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink)
        != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, 1)
    ):
        raise ValueError("staging payload changed during finalization")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _write_bytes(destination, b"".join(chunks))
    if destination.stat().st_ino == source.stat().st_ino:
        raise ValueError("sealed payload did not receive a fresh inode")


def finalize_release(*, staging_directory: str | Path) -> Path:
    """Validate all reviewed payloads, then atomically seal immutable output."""
    staging = Path(staging_directory)
    _reject_parent_traversal(staging, "staging path")
    if staging.name != STAGING_DIRECTORY_NAME:
        raise ValueError("finalizer requires the canonical staging directory")
    root = staging.parent
    _require_plain_directory(root, "release output root")
    final = root / FINAL_DIRECTORY_NAME
    if final.exists() or final.is_symlink():
        raise FileExistsError("refusing to overwrite an existing final release")
    if {entry.name for entry in root.iterdir()} != {STAGING_DIRECTORY_NAME}:
        raise FileExistsError("release output root contains unexpected state")
    release, source_files = _validate_staging(staging)
    doi = release["doi"]
    finalizing = root / f".{RELEASE_VERSION}.finalizing"
    if finalizing.exists() or finalizing.is_symlink():
        raise FileExistsError("unsafe partial finalization directory exists")
    finalizing.mkdir(mode=0o700)
    try:
        for name, source in sorted(source_files.items()):
            _copy_to_fresh_inode(source, finalizing / name)
        copied_release, files = _validate_staging(finalizing)
        if copied_release != release:
            raise ValueError("fresh-inode staging copy differs from the validated release")
    except Exception:
        shutil.rmtree(finalizing, ignore_errors=True)
        raise
    inventory = []
    for name, path in sorted(files.items()):
        if name == "release.json":
            continue
        digest, size = _sha256_and_size(path)
        inventory.append({
            "name": name, "sha256": digest, "bytes": size,
            "media_type": _mime_type(name),
        })
    sealed = dict(release)
    sealed["status"] = "sealed"
    sealed["inventory"] = inventory
    _validate_instance(RELEASE_SCHEMA_PATH, sealed, "sealed release")
    release_bytes = _canonical_json(sealed)
    try:
        _write_bytes(finalizing / "release.json", release_bytes)
        names = sorted(
            name for name in _walk_public_files_for_verification(finalizing)
            if name != "checksums.sha256"
        )
        checksum_bytes = ("\n".join(
            f"{_sha256_and_size(finalizing / name)[0]}  {name}" for name in names
        ) + "\n").encode("utf-8")
        _write_bytes(finalizing / "checksums.sha256", checksum_bytes)
        _verify_checksums(finalizing)
        _fsync_directory(finalizing)
        _immutable_tree(finalizing, include_root=False)
        os.replace(finalizing, final)
        os.chmod(final, 0o555)
        _fsync_directory(root)
        shutil.rmtree(staging)
        _fsync_directory(root)
    except Exception:
        try:
            if not finalizing.exists() and final.exists():
                os.chmod(final, 0o755)
                for path in final.rglob("*"):
                    os.chmod(path, 0o755 if path.is_dir() else 0o644)
                shutil.rmtree(final)
            elif finalizing.exists():
                os.chmod(finalizing, 0o755)
                for path in finalizing.rglob("*"):
                    os.chmod(path, 0o755 if path.is_dir() else 0o644)
                shutil.rmtree(finalizing)
        except OSError:
            pass
        raise
    return final


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage or finalize the v2026.08.2 aggregate release")
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage_parser = subparsers.add_parser("stage", help="create aggregate-only staging")
    stage_parser.add_argument("--database", required=True)
    stage_parser.add_argument("--output-directory", required=True)
    group = stage_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--manifest", action="append", dest="manifests")
    group.add_argument("--manifest-directory")
    bind_parser = subparsers.add_parser("bind-doi", help="bind a trusted externally verified Zenodo DOI reservation")
    bind_parser.add_argument("--staging-directory", required=True)
    bind_parser.add_argument("--reservation-attestation", required=True)
    bind_parser.add_argument("--approval-public-key", required=True)
    bind_parser.add_argument("--approved-key-fingerprint", required=True)
    final_parser = subparsers.add_parser("finalize", help="seal reviewed staging")
    final_parser.add_argument("--staging-directory", required=True)
    args = parser.parse_args(argv)
    if args.command == "stage":
        stage_release(
            database=args.database, output_directory=args.output_directory,
            manifest_paths=args.manifests, manifest_directory=args.manifest_directory,
        )
    elif args.command == "bind-doi":
        bind_reserved_doi(
            staging_directory=args.staging_directory,
            reservation_attestation=args.reservation_attestation,
            approval_public_key=args.approval_public_key,
            approved_key_fingerprint=args.approved_key_fingerprint,
        )
    else:
        finalize_release(staging_directory=args.staging_directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
