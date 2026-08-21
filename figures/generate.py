"""Generate deterministic, aggregate-only SVG/PNG editorial figures.

The generator intentionally knows metric *identifiers*, never report values or
domains.  It is a release consumer: a mismatched or incomplete aggregate
bundle is rejected before any output directory is touched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from PIL import Image, ImageDraw, ImageFont

from release.metric import high_precision_percentage


ROOT = Path(__file__).resolve().parent
WIDTH, HEIGHT = 1600, 900
SOCIAL_WIDTH, SOCIAL_HEIGHT = 1200, 630
REQUIRED_VERSION = "v2026.08.2"
PRIVATE_KEYS = frozenset({
    "domain", "domains", "query_statuses", "ns_hosts", "mx_hosts", "spf_record",
    "dkim_selectors", "dmarc_record", "rua_domains", "ruf_domains", "bimi_record",
    "mta_sts_record", "tlsrpt_record", "caa_records", "tlsa_hosts",
})
DOI_RE = re.compile(r"^10\.\d{4,9}/[-._;()/:a-z0-9]+$", re.IGNORECASE)


COPY: dict[str, dict[str, Any]] = {
    "de": {
        "name": "Schweizer E-Mail-Sicherheitsreport", "source": "Quelle", "method": "Methode",
        "license": "Lizenz", "repository": "Repository", "denominator": "Nenner",
        "metric": "Beobachtung", "share": "Anteil", "count": "Anzahl", "version": "Release",
        "period": "Messzeitraum", "footnote": "DNS-Beobachtung; keine Aussage über tatsächliche Zustellung oder Durchsetzung.",
        "titles": {
            "dmarc-policy-observations": "Beobachtete DMARC-Richtlinien bei Domains mit MX",
            "spf-dkim-observations": "SPF-Präsenz und beobachtete DKIM-Selectoren",
            "dns-transport-signals": "Beobachtete DNS- und Transport-Signale",
            "mx-hostname-fingerprint-distribution": "MX-Hostname-Fingerprint-Verteilung",
        },
        "labels": {
            "dmarc.reject": "DMARC p=reject", "dmarc.quarantine": "DMARC p=quarantine", "dmarc.none": "DMARC p=none",
            "dmarc.no_supported_effective_policy": "Keine unterstützte DMARC-Richtlinie erkannt",
            "spf.present": "SPF-TXT-Eintrag vorhanden", "dkim.selector_observed": "DKIM-Selector beobachtet (Untergrenze)",
            "ds.record_present": "DS-Eintrag vorhanden", "tlsa.record_present": "TLSA-Eintrag vorhanden",
            "bimi.record_present": "BIMI-TXT-Eintrag vorhanden", "mta_sts.txt_present": "_mta-sts TXT-Eintrag vorhanden",
            "tls_rpt.record_present": "TLS-RPT-TXT-Eintrag vorhanden", "caa.record_present": "CAA-Eintrag vorhanden",
            "hostpoint": "Hostpoint", "infomaniak": "Infomaniak", "microsoft365": "Microsoft 365",
            "google_workspace": "Google Workspace", "remainder": "Weitere Fingerabdruck-Kategorien",
        },
        "caveats": {
            "dmarc": "Ein publiziertes DMARC p=-Tag belegt keine operative Durchsetzung oder Ausrichtungsergebnisse.",
            "spf_dkim": "Die Balken sind nicht gegenseitig ausschliessend. DKIM ist eine anbieterabhängige Selector-Untergrenze.",
            "signals": "DS bedeutet keine validierte DNSSEC-Kette; TLSA, BIMI, MTA-STS, TLS-RPT und CAA zeigen nur Record-Präsenz.",
            "providers": "Hostname-Fingerprints sind keine Marktanteile und belegen keine Geschäftsbeziehung oder vollständige Mail-Infrastruktur.",
        },
        "social": "Aggregate DNS-Beobachtungen für .ch-Domains",
    },
    "fr": {
        "name": "Rapport suisse sur la sécurité des e-mails", "source": "Source", "method": "Méthode",
        "license": "Licence", "repository": "Dépôt", "denominator": "Dénominateur",
        "metric": "Observation", "share": "Part", "count": "Nombre", "version": "Version",
        "period": "Période de mesure", "footnote": "Observation DNS; aucune conclusion sur la livraison ou l’application effective.",
        "titles": {
            "dmarc-policy-observations": "Politiques DMARC observées pour les domaines avec MX",
            "spf-dkim-observations": "Présence SPF et sélecteurs DKIM observés",
            "dns-transport-signals": "Signaux DNS et de transport observés",
            "mx-hostname-fingerprint-distribution": "Répartition des empreintes de noms d’hôtes MX",
        },
        "labels": {
            "dmarc.reject": "DMARC p=reject", "dmarc.quarantine": "DMARC p=quarantine", "dmarc.none": "DMARC p=none",
            "dmarc.no_supported_effective_policy": "Aucune politique DMARC prise en charge détectée",
            "spf.present": "Enregistrement SPF TXT présent", "dkim.selector_observed": "Sélecteur DKIM observé (borne inférieure)",
            "ds.record_present": "Enregistrement DS présent", "tlsa.record_present": "Enregistrement TLSA présent",
            "bimi.record_present": "Enregistrement BIMI TXT présent", "mta_sts.txt_present": "Enregistrement TXT _mta-sts présent",
            "tls_rpt.record_present": "Enregistrement TLS-RPT TXT présent", "caa.record_present": "Enregistrement CAA présent",
            "hostpoint": "Hostpoint", "infomaniak": "Infomaniak", "microsoft365": "Microsoft 365",
            "google_workspace": "Google Workspace", "remainder": "Autres catégories d’empreintes",
        },
        "caveats": {
            "dmarc": "Un tag DMARC p= publié ne démontre ni application opérationnelle ni résultats d’alignement.",
            "spf_dkim": "Les barres ne s’excluent pas mutuellement. DKIM est une borne inférieure fondée sur des sélecteurs dépendants du fournisseur.",
            "signals": "DS ne prouve pas une chaîne DNSSEC validée; TLSA, BIMI, MTA-STS, TLS-RPT et CAA indiquent uniquement la présence d’un enregistrement.",
            "providers": "Les empreintes de noms d’hôtes ne sont pas des parts de marché et ne prouvent ni relation commerciale ni infrastructure complète.",
        },
        "social": "Observations DNS agrégées pour les domaines .ch",
    },
    "it": {
        "name": "Rapporto svizzero sulla sicurezza e-mail", "source": "Fonte", "method": "Metodo",
        "license": "Licenza", "repository": "Repository", "denominator": "Denominatore",
        "metric": "Osservazione", "share": "Quota", "count": "Numero", "version": "Versione",
        "period": "Periodo di misurazione", "footnote": "Osservazione DNS; nessuna conclusione su consegna o applicazione effettiva.",
        "titles": {
            "dmarc-policy-observations": "Politiche DMARC osservate per domini con MX",
            "spf-dkim-observations": "Presenza SPF e selettori DKIM osservati",
            "dns-transport-signals": "Segnali DNS e di trasporto osservati",
            "mx-hostname-fingerprint-distribution": "Distribuzione delle impronte dei nomi host MX",
        },
        "labels": {
            "dmarc.reject": "DMARC p=reject", "dmarc.quarantine": "DMARC p=quarantine", "dmarc.none": "DMARC p=none",
            "dmarc.no_supported_effective_policy": "Nessuna politica DMARC supportata rilevata",
            "spf.present": "Record SPF TXT presente", "dkim.selector_observed": "Selettore DKIM osservato (limite inferiore)",
            "ds.record_present": "Record DS presente", "tlsa.record_present": "Record TLSA presente",
            "bimi.record_present": "Record BIMI TXT presente", "mta_sts.txt_present": "Record TXT _mta-sts presente",
            "tls_rpt.record_present": "Record TLS-RPT TXT presente", "caa.record_present": "Record CAA presente",
            "hostpoint": "Hostpoint", "infomaniak": "Infomaniak", "microsoft365": "Microsoft 365",
            "google_workspace": "Google Workspace", "remainder": "Altre categorie di impronte",
        },
        "caveats": {
            "dmarc": "Un tag DMARC p= pubblicato non dimostra applicazione operativa né risultati di allineamento.",
            "spf_dkim": "Le barre non si escludono a vicenda. DKIM è un limite inferiore basato su selettori dipendenti dal fornitore.",
            "signals": "DS non prova una catena DNSSEC validata; TLSA, BIMI, MTA-STS, TLS-RPT e CAA indicano soltanto la presenza di un record.",
            "providers": "Le impronte dei nomi host non sono quote di mercato e non provano relazioni commerciali né un’infrastruttura completa.",
        },
        "social": "Osservazioni DNS aggregate per domini .ch",
    },
}


@dataclass(frozen=True)
class Item:
    identifier: str
    label: str
    numerator: int
    denominator: int
    percentage: Decimal
    metric_ids: tuple[str, ...]


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON {path}") from exc


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_aggregate_only(value: Any) -> None:
    if isinstance(value, dict):
        blocked = PRIVATE_KEYS.intersection(value)
        if blocked:
            raise ValueError(f"private field(s) forbidden in figure input: {', '.join(sorted(blocked))}")
        for nested in value.values():
            _assert_aggregate_only(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_aggregate_only(nested)


def _validate_inputs(metrics_path: Path, release_path: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    raw_metrics, release = _load(metrics_path), _load(release_path)
    _assert_aggregate_only(raw_metrics)
    if not isinstance(raw_metrics, dict) or not isinstance(raw_metrics.get("metrics"), list) or not isinstance(release, dict):
        raise ValueError("metrics.json and release.json must be objects with a metrics array")
    if release.get("version") != REQUIRED_VERSION:
        raise ValueError(f"unsupported release version; expected {REQUIRED_VERSION}")
    needed = {"measurement_period", "repository_url", "license", "metrics_sha256", "metric_count"}
    if missing := needed - release.keys():
        raise ValueError(f"release metadata missing: {', '.join(sorted(missing))}")
    if release["metrics_sha256"] != _sha256(metrics_path):
        raise ValueError("release metrics_sha256 does not match metrics.json")
    if release["metric_count"] != len(raw_metrics["metrics"]):
        raise ValueError("release metric_count does not match metrics.json")
    doi = release.get("doi")
    if doi is not None and (not isinstance(doi, str) or not DOI_RE.fullmatch(doi.strip())):
        raise ValueError("release DOI must be a validated DOI, never a placeholder")
    values: dict[str, dict[str, Any]] = {}
    for metric in raw_metrics["metrics"]:
        required = {"metric_id", "numerator", "denominator", "denominator_metric_id", "percentage", "measurement_period", "caveat"}
        if not isinstance(metric, dict) or required - metric.keys():
            raise ValueError("metric object is incomplete")
        metric_id = metric["metric_id"]
        if not isinstance(metric_id, str) or metric_id in values:
            raise ValueError("metric IDs must be unique strings")
        numerator, denominator = metric["numerator"], metric["denominator"]
        if not isinstance(numerator, int) or not isinstance(denominator, int) or not 0 <= numerator <= denominator:
            raise ValueError(f"invalid metric counts for {metric_id}")
        if metric["measurement_period"] != release["measurement_period"]:
            raise ValueError(f"metric/release measurement period mismatch for {metric_id}")
        if Decimal(str(metric["percentage"])) != high_precision_percentage(numerator, denominator):
            raise ValueError(f"metric percentage mismatch for {metric_id}")
        values[metric_id] = metric
    for metric_id, metric in values.items():
        denominator_id = metric["denominator_metric_id"]
        if denominator_id is not None:
            if denominator_id not in values or values[denominator_id]["numerator"] != metric["denominator"]:
                raise ValueError(f"metric denominator identity failed for {metric_id}")
    return values, release


def _format_count(value: int, locale: str) -> str:
    groups: list[str] = []
    raw = str(value)
    while raw:
        groups.append(raw[-3:])
        raw = raw[:-3]
    separator = "\u202f" if locale == "fr" else "'"
    return separator.join(reversed(groups))


def _format_percent(value: Decimal, locale: str) -> str:
    shown = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    rendered = f"{shown:.2f}".replace(".", ",")
    return f"{rendered}\u202f%" if locale == "fr" else f"{rendered}%"


def _wrap(text: str, limit: int = 68) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if current and len(candidate) > limit:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [""]


def _metric_item(metric_id: str, values: dict[str, dict[str, Any]], label: str) -> Item:
    metric = values.get(metric_id)
    if metric is None:
        raise ValueError(f"chart references missing metric ID {metric_id}")
    return Item(metric_id, label, metric["numerator"], metric["denominator"], Decimal(str(metric["percentage"])), (metric_id,))


def _chart_items(chart: dict[str, Any], values: dict[str, dict[str, Any]], locale: str) -> list[Item]:
    labels = COPY[locale]["labels"]
    kind = chart["kind"]
    if kind == "provider_distribution":
        result = []
        for group in chart["groups"]:
            ids = tuple(group["metric_ids"])
            entries = [_metric_item(metric_id, values, metric_id) for metric_id in ids]
            denominator = entries[0].denominator
            if any(entry.denominator != denominator for entry in entries):
                raise ValueError(f"provider group denominator mismatch for {group['id']}")
            numerator = sum(entry.numerator for entry in entries)
            result.append(Item(group["id"], labels[group["id"]], numerator, denominator,
                               high_precision_percentage(numerator, denominator), ids))
        return result
    return [_metric_item(metric_id, values, labels[metric_id]) for metric_id in chart["metric_ids"]]


def _validate_chart(chart: dict[str, Any], items: list[Item]) -> None:
    if not items:
        raise ValueError(f"chart {chart['id']} has no items")
    declared = chart.get("denominator_metric_id")
    if declared:
        if any(item.denominator != items[0].denominator for item in items):
            raise ValueError(f"chart denominator mismatch for {chart['id']}")
        # The declared metric ID must be present and define the common count.
        # We validate it in the caller where metric values are available.
    if chart["kind"] == "partition" and sum(item.numerator for item in items) != items[0].denominator:
        raise ValueError("DMARC policy partition does not reconcile to its MX denominator")


def _svg_text(x: int, y: int, lines: list[str], size: int, color: str, weight: str = "400", anchor: str = "start") -> str:
    return "".join(
        f'<text x="{x}" y="{y + index * (size + 7)}" fill="{color}" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}">{escape(line)}</text>'
        for index, line in enumerate(lines)
    )


def _svg_chart(chart: dict[str, Any], items: list[Item], release: dict[str, Any], locale: str, style: dict[str, str]) -> tuple[str, str]:
    copy = COPY[locale]
    title = copy["titles"][chart["id"]]
    caveat = copy["caveats"][chart["caveat_key"]]
    desc = f"{title}. {caveat} {copy['period']}: {release['measurement_period']}."
    y0, gap, bar_x, bar_w = 240, max(68, min(94, 420 // len(items))), 600, 670
    content = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{escape(title)}</title><desc id="desc">{escape(desc)}</desc>',
        f'<rect width="100%" height="100%" fill="{style["canvas"]}"/>',
        _svg_text(80, 92, [copy["name"].upper()], 20, style["red"], "700"),
        _svg_text(80, 152, _wrap(title, 52), 42, style["ink"], "700"),
    ]
    for index, item in enumerate(items):
        y = y0 + index * gap
        bar_length = round(bar_w * float(item.percentage / Decimal("100"))) if item.denominator else 0
        content.append(_svg_text(80, y + 21, _wrap(item.label, 42), 22, style["ink"], "600"))
        content.append(f'<rect x="{bar_x}" y="{y}" width="{bar_w}" height="31" fill="{style["gray_light"]}"/>')
        if bar_length:
            content.append(f'<rect x="{bar_x}" y="{y}" width="{bar_length}" height="31" fill="{style["red"]}"/>')
        value = f"{_format_percent(item.percentage, locale)}  ·  {_format_count(item.numerator, locale)} / {_format_count(item.denominator, locale)}"
        content.append(_svg_text(1320, y + 23, [value], 20, style["ink"], "700", "end"))
    caveat_lines = _wrap(caveat, 130)
    footer_y = 725
    content += [
        f'<line x1="80" x2="1520" y1="{footer_y - 24}" y2="{footer_y - 24}" stroke="{style["gray_light"]}"/>',
        _svg_text(80, footer_y, caveat_lines, 17, style["ink"]),
        _svg_text(80, 805, [f"{copy['version']}: {release['version']}  ·  {copy['period']}: {release['measurement_period']}"], 16, style["gray"]),
        _svg_text(80, 837, [f"{copy['source']}: {release['repository_url']}  ·  {copy['license']}: {release['license']}"], 16, style["gray"]),
    ]
    if release.get("doi"):
        content.append(_svg_text(1520, 837, [f"DOI: {release['doi']}"], 16, style["gray"], "400", "end"))
    content.append("</svg>")
    caption = f"{title}. {caveat} {copy['period']}: {release['measurement_period']}."
    return "".join(content), caption


def _font(size: int) -> ImageFont.ImageFont:
    try:
        return ImageFont.truetype("DejaVuSans.ttf", size=size)
    except OSError:
        return ImageFont.load_default()


def _draw_wrapped(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, font: ImageFont.ImageFont, fill: str, width: int, spacing: int = 6) -> int:
    words, lines, current = text.split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if current and draw.textlength(candidate, font=font) > width:
            lines.append(current); current = word
        else:
            current = candidate
    if current: lines.append(current)
    x, y = xy
    for line in lines:
        draw.text((x, y), line, font=font, fill=fill)
        y += font.getbbox(line)[3] - font.getbbox(line)[1] + spacing
    return y


def _png_chart(chart: dict[str, Any], items: list[Item], release: dict[str, Any], locale: str, style: dict[str, str], target: Path) -> None:
    copy = COPY[locale]
    image = Image.new("RGB", (WIDTH, HEIGHT), style["canvas"])
    draw = ImageDraw.Draw(image)
    draw.text((80, 70), copy["name"].upper(), font=_font(20), fill=style["red"])
    title_y = _draw_wrapped(draw, (80, 112), copy["titles"][chart["id"]], _font(42), style["ink"], 1100, 8)
    y0, gap, bar_x, bar_w = max(235, title_y + 36), max(68, min(94, 420 // len(items))), 600, 670
    for index, item in enumerate(items):
        y = y0 + index * gap
        _draw_wrapped(draw, (80, y), item.label, _font(22), style["ink"], 450, 2)
        draw.rectangle((bar_x, y, bar_x + bar_w, y + 31), fill=style["gray_light"])
        length = round(bar_w * float(item.percentage / Decimal("100"))) if item.denominator else 0
        if length: draw.rectangle((bar_x, y, bar_x + length, y + 31), fill=style["red"])
        value = f"{_format_percent(item.percentage, locale)} · {_format_count(item.numerator, locale)} / {_format_count(item.denominator, locale)}"
        box = draw.textbbox((0, 0), value, font=_font(20))
        draw.text((1320 - (box[2] - box[0]), y + 4), value, font=_font(20), fill=style["ink"])
    draw.line((80, 700, 1520, 700), fill=style["gray_light"], width=1)
    caveat_y = _draw_wrapped(draw, (80, 724), copy["caveats"][chart["caveat_key"]], _font(17), style["ink"], 1400, 4)
    draw.text((80, max(802, caveat_y + 10)), f"{copy['version']}: {release['version']} · {copy['period']}: {release['measurement_period']}", font=_font(16), fill=style["gray"])
    source = f"{copy['source']}: {release['repository_url']} · {copy['license']}: {release['license']}"
    draw.text((80, 840), source, font=_font(16), fill=style["gray"])
    image.save(target, format="PNG", optimize=False)


def _social_card(release: dict[str, Any], locale: str, style: dict[str, str], target_svg: Path, target_png: Path, item: Item) -> str:
    copy = COPY[locale]
    title = copy["name"]
    value = f"{_format_percent(item.percentage, locale)} · {_format_count(item.numerator, locale)} / {_format_count(item.denominator, locale)}"
    caveat = copy["caveats"]["dmarc"]
    description = f"{copy['social']}. {item.label}: {value}. {caveat} {copy['period']}: {release['measurement_period']}."
    svg = "".join([
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{SOCIAL_WIDTH}" height="{SOCIAL_HEIGHT}" viewBox="0 0 {SOCIAL_WIDTH} {SOCIAL_HEIGHT}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{escape(title)}</title><desc id="desc">{escape(description)}</desc>',
        f'<rect width="100%" height="100%" fill="{style["canvas"]}"/>',
        f'<rect x="70" y="70" width="11" height="390" fill="{style["red"]}"/>',
        _svg_text(112, 125, [copy["social"].upper()], 20, style["red"], "700"),
        _svg_text(112, 220, _wrap(title, 27), 56, style["ink"], "700"),
        _svg_text(112, 405, _wrap(f"{item.label}: {value}", 68), 23, style["ink"], "700"),
        _svg_text(112, 470, _wrap(caveat, 100), 15, style["ink"]),
        _svg_text(112, 550, [f"{copy['source']}: {release['repository_url']}  ·  {release['version']}  ·  {release['license']}"], 15, style["gray"]),
        "</svg>",
    ])
    target_svg.write_text(svg, encoding="utf-8")
    image = Image.new("RGB", (SOCIAL_WIDTH, SOCIAL_HEIGHT), style["canvas"])
    draw = ImageDraw.Draw(image)
    draw.rectangle((70, 70, 81, 460), fill=style["red"])
    draw.text((112, 105), copy["social"].upper(), font=_font(20), fill=style["red"])
    y = _draw_wrapped(draw, (112, 180), title, _font(56), style["ink"], 860, 10)
    draw.text((112, max(400, y + 25)), f"{item.label}: {value}", font=_font(21), fill=style["ink"])
    _draw_wrapped(draw, (112, 450), caveat, _font(15), style["ink"], 940, 3)
    draw.text((112, 550), f"{copy['source']}: {release['repository_url']} · {release['version']} · {release['license']}", font=_font(15), fill=style["gray"])
    image.save(target_png, format="PNG", optimize=False)
    return description


def _verify_image(path: Path, dimensions: tuple[int, int]) -> None:
    with Image.open(path) as image:
        if image.size != dimensions or image.mode not in {"RGB", "RGBA"}:
            raise ValueError(f"invalid PNG output {path.name}")


def generate(metrics_path: str | Path, release_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Generate all localized figures atomically and return their manifest."""
    metrics_path, release_path, out = Path(metrics_path), Path(release_path), Path(output_dir)
    values, release = _validate_inputs(metrics_path, release_path)
    charts = _load(ROOT / "charts.json")["charts"]
    style = _load(ROOT / "style.json")
    if not out.name or out.resolve() in {Path("/").resolve(), Path.cwd().resolve()}:
        raise ValueError("refusing unsafe figure output directory")
    marker = out / ".figures-output"
    if out.exists() and not marker.is_file():
        raise ValueError("refusing to replace an unmarked output directory")
    stage = Path(tempfile.mkdtemp(prefix=f".{out.name}.tmp-", dir=out.parent.resolve()))
    files: list[dict[str, Any]] = []
    try:
        (stage / ".figures-output").write_text("aggregate-only figures\n", encoding="utf-8")
        for locale in COPY:
            for chart in charts:
                items = _chart_items(chart, values, locale)
                _validate_chart(chart, items)
                declared = chart.get("denominator_metric_id")
                if declared and (declared not in values or values[declared]["numerator"] != items[0].denominator):
                    raise ValueError(f"declared denominator identity failed for {chart['id']}")
                if declared and any(values[metric_id]["denominator_metric_id"] != declared for item in items for metric_id in item.metric_ids):
                    raise ValueError(f"chart denominator metric ID mismatch for {chart['id']}")
                if chart["kind"] == "signals":
                    for item in items:
                        expected = chart["denominator_metric_ids"][item.identifier]
                        if values[expected]["numerator"] != item.denominator or values[item.identifier]["denominator_metric_id"] != expected:
                            raise ValueError(f"signal denominator identity failed for {item.identifier}")
                svg, caption = _svg_chart(chart, items, release, locale, style)
                stem = f"{locale}/{chart['id']}"
                svg_path, png_path = stage / f"{stem}.svg", stage / f"{stem}.png"
                svg_path.parent.mkdir(parents=True, exist_ok=True)
                svg_path.write_text(svg, encoding="utf-8")
                _png_chart(chart, items, release, locale, style, png_path)
                ET.parse(svg_path)
                _verify_image(png_path, (WIDTH, HEIGHT))
                metric_ids = [metric_id for item in items for metric_id in item.metric_ids]
                for path, dimensions in ((svg_path, [WIDTH, HEIGHT]), (png_path, [WIDTH, HEIGHT])):
                    files.append({"path": str(path.relative_to(stage)), "sha256": _sha256(path), "dimensions": dimensions,
                                  "locale": locale, "chart_id": chart["id"], "metric_ids": metric_ids, "caption": caption})
            social_svg, social_png = stage / f"{locale}/social-card.svg", stage / f"{locale}/social-card.png"
            social_item = _metric_item("dmarc.no_supported_effective_policy", values, COPY[locale]["labels"]["dmarc.no_supported_effective_policy"])
            caption = _social_card(release, locale, style, social_svg, social_png, social_item)
            ET.parse(social_svg); _verify_image(social_png, (SOCIAL_WIDTH, SOCIAL_HEIGHT))
            for path in (social_svg, social_png):
                files.append({"path": str(path.relative_to(stage)), "sha256": _sha256(path), "dimensions": [SOCIAL_WIDTH, SOCIAL_HEIGHT],
                              "locale": locale, "chart_id": "social-card", "metric_ids": list(social_item.metric_ids), "caption": caption})
        manifest = {"release_version": release["version"], "measurement_period": release["measurement_period"],
                    "repository_url": release["repository_url"], "license": release["license"], "files": sorted(files, key=lambda entry: entry["path"])}
        if release.get("doi"): manifest["doi"] = release["doi"]
        _assert_aggregate_only(manifest)
        (stage / "figure-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if out.exists():
            backup = out.with_name(f".{out.name}.previous-{os.getpid()}")
            os.replace(out, backup)
            try:
                os.replace(stage, out)
            except Exception:
                os.replace(backup, out)
                raise
            shutil.rmtree(backup)
        else:
            os.replace(stage, out)
        return manifest
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", required=True, type=Path)
    parser.add_argument("--release", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    manifest = generate(args.metrics, args.release, args.output)
    print(json.dumps({"output": str(args.output), "files": len(manifest["files"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
