"""Build reviewed aggregate-only figures for one DOI-bound release.

The renderer reads only the four aggregate release inputs needed for figures.
It never opens a scanner database, a domain list, or raw DNS material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable, Mapping
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from PIL import Image, ImageDraw, ImageFont, PngImagePlugin

from release import build_release as contract


HERE = Path(__file__).resolve().parent
FONT_PATH = HERE / "fonts" / "DMSans-Variable.ttf"
CANVAS, INK, RED, LIGHT = "#f8f7f3", "#111111", "#e30613", "#dedbd4"
KICKERS = {
    "mail-authentication-overview": {
        "de": "E-MAIL-AUTHENTIFIZIERUNG", "fr": "AUTHENTIFICATION E-MAIL", "it": "AUTENTICAZIONE E-MAIL",
    },
    "dmarc-policy-observations": {
        "de": "DMARC-BEOBACHTUNGEN", "fr": "OBSERVATIONS DMARC", "it": "OSSERVAZIONI DMARC",
    },
    "dns-transport-signals": {
        "de": "DNS- UND TRANSPORT-SIGNALE", "fr": "SIGNAUX DNS ET TRANSPORT", "it": "SEGNALI DNS E TRASPORTO",
    },
    "mx-provider-fingerprints": {
        "de": "MX-HOSTNAME-FINGERPRINTS", "fr": "EMPREINTES D’HÔTES MX", "it": "IMPRONTE HOST MX",
    },
    "social-report-card": {
        "de": "SCHWEIZER E-MAIL-SICHERHEITSREPORT", "fr": "RAPPORT SUISSE SUR LA SÉCURITÉ E-MAIL", "it": "RAPPORTO SVIZZERO SULLA SICUREZZA E-MAIL",
    },
}


def _validate_chart_catalogue() -> None:
    """Keep the editorial catalogue reviewable and locked to Task 6 specs."""
    payload = contract._load_json(HERE / "charts.json", "figure chart catalogue")
    expected = [
        {
            "id": chart_id,
            "family": specification["family"],
            "metric_ids": list(specification["metric_ids"]),
            "denominator_metric_ids": list(specification["denominator_metric_ids"]),
        }
        for chart_id, specification in contract.FIGURE_SPECS.items()
        if specification["kind"] == "chart"
    ]
    if payload != {"charts": expected}:
        raise ValueError("figure chart catalogue differs from the reviewed contract")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_release_inputs(staging: Path) -> tuple[dict[str, Any], tuple[contract.Metric, ...], dict[str, Any]]:
    """Delegate all authenticity and parsing decisions to the Task 6 boundary."""
    contract._reject_parent_traversal(staging, "figure staging path")
    contract._require_no_symlink_ancestors(staging, "figure staging path")
    contract._require_plain_directory(staging, "figure staging directory")
    files = contract._walk_public_files(staging)
    release, _reservation = contract._validate_reserved_doi_staging(files)
    metrics = contract._metric_objects(contract._load_json(files["metrics.json"], "figure metrics"))
    attestation = contract._load_json(files["aggregate-attestation.json"], "figure aggregate attestation")
    return release, metrics, attestation


def _metric_map(metrics: Iterable[contract.Metric]) -> dict[str, contract.Metric]:
    values = {metric.metric_id: metric for metric in metrics}
    if len(values) != len(tuple(metrics)):
        raise ValueError("metric IDs must be unique")
    return values


def _metric_lines(chart_id: str, locale: str, metrics: Mapping[str, contract.Metric]) -> list[str]:
    labels = contract._locale_payload(locale)["labels"]
    return [
        f"{labels[identifier]}  "
        f"{contract._localized_number(metrics[identifier].display_percentage, locale)} %  "
        f"({metrics[identifier].numerator}/{metrics[identifier].denominator})"
        for identifier in contract.FIGURE_SPECS[chart_id]["metric_ids"]
    ]


def _visual_labels(chart_id: str, locale: str) -> list[str]:
    labels = contract._locale_payload(locale)["labels"]
    return [labels[identifier] for identifier in contract.FIGURE_SPECS[chart_id]["metric_ids"]]


def _svg_text(x: int, y: int, value: str, *, size: int, fill: str = INK, weight: int = 400, anchor: str = "start") -> str:
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-family="{contract.FIGURE_FONT_FAMILY}" '
        f'font-size="{size}" font-weight="{weight}" text-anchor="{anchor}">{escape(value)}</text>'
    )


def _svg_required_layer(item: Mapping[str, Any]) -> str:
    layout = contract._svg_required_text_layout(item)
    title_size = min(
        32 if item["kind"] == "chart" else 22,
        max(10, (int(item["width"]) - 80) // max(1, len(layout[0][0]))),
    )
    nodes = [
        f'<text x="{layout[0][1]}" y="{layout[0][2]}" fill="#111111" '
        f'font-family="{contract.FIGURE_FONT_FAMILY}" '
        f'font-size="{title_size}">{escape(layout[0][0])}</text>',
    ]
    nodes.extend(
        f'<text x="{x}" y="{y}" fill="#111111" '
        f'font-family="{contract.FIGURE_FONT_FAMILY}" '
        f'font-size="12">{escape(value)}</text>'
        for value, x, y in layout[1:]
    )
    return "".join(nodes)


def _svg_social_visual(item: Mapping[str, Any], metrics: Mapping[str, contract.Metric]) -> str:
    labels = _visual_labels(item["chart_id"], item["locale"])
    nodes = [
        _svg_text(60, 260, KICKERS[item["chart_id"]][item["locale"]], size=16, fill=RED, weight=700),
        '<rect x="60" y="284" width="10" height="210" fill="#e30613"/>',
    ]
    for index, (identifier, label) in enumerate(zip(item["metric_ids"], labels, strict=True)):
        metric = metrics[identifier]
        column, row = index % 2, index // 2
        x, y = 90 + column * 535, 318 + row * 100
        value = f"{contract._localized_number(metric.display_percentage, item['locale'])} %"
        nodes.extend((
            _svg_text(x, y, value, size=36, weight=700),
            _svg_text(x, y + 27, label, size=14, weight=600),
            _svg_text(x, y + 49, f"({metric.numerator}/{metric.denominator})", size=13),
        ))
    return f'<g>{"".join(nodes)}</g>'


def _svg_chart_visual(item: Mapping[str, Any], metrics: Mapping[str, contract.Metric]) -> str:
    lines = _visual_labels(item["chart_id"], item["locale"])
    gap = 55 if len(lines) <= 4 else 46
    bars = []
    for index, (identifier, label) in enumerate(zip(item["metric_ids"], lines, strict=True)):
        metric = metrics[identifier]
        y = 400 + index * gap
        length = round(500 * float(metric.percentage) / 100) if metric.denominator else 0
        value = (
            f"{contract._localized_number(metric.display_percentage, item['locale'])} % "
            f"({metric.numerator}/{metric.denominator})"
        )
        bars.extend((
            _svg_text(110, y + 19, label, size=16, weight=600),
            f'<rect x="850" y="{y}" width="500" height="24" rx="12" fill="{LIGHT}"/>',
            f'<rect x="850" y="{y}" width="{length}" height="24" rx="12" fill="{RED}"/>' if length else "",
            _svg_text(1520, y + 19, value, size=16, weight=700, anchor="end"),
        ))
    return "".join((
        '<g><rect x="80" y="330" width="12" height="360" fill="#e30613"/>',
        _svg_text(110, 350, KICKERS[item["chart_id"]][item["locale"]], size=16, fill=RED, weight=700),
        "".join(bars), '</g>',
    ))


def _svg_chart(item: Mapping[str, Any], metrics: Mapping[str, contract.Metric]) -> bytes:
    width, height = int(item["width"]), int(item["height"])
    visual = (
        _svg_social_visual(item, metrics)
        if item["kind"] == "social" else _svg_chart_visual(item, metrics)
    )
    font_style = contract._svg_font_face_declaration()
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="figure-title figure-description">'
        f'<title id="figure-title">{escape(item["title"])}</title>'
        f'<desc id="figure-description">{escape(item["description"])}</desc>'
        f'<style type="text/css">{font_style}</style>'
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#f8f7f3"/>'
        f'{visual}{_svg_required_layer(item)}</svg>'
    ).encode("utf-8")


def _rasterized_image(svg: bytes) -> Image.Image:
    """Rasterize the generated inactive SVG using only bundled DM Sans and Pillow."""
    try:
        root = ET.fromstring(svg)
    except ET.ParseError as exc:
        raise ValueError("figure SVG cannot be rasterized because its XML is invalid") from exc
    style = root.find("{http://www.w3.org/2000/svg}style")
    if style is None:
        raise ValueError("figure SVG cannot be rasterized without its embedded font")
    font_bytes = contract._validate_embedded_svg_font(style)
    try:
        width, height = int(root.attrib["width"]), int(root.attrib["height"])
    except (KeyError, ValueError) as exc:
        raise ValueError("figure SVG raster dimensions are invalid") from exc
    image = Image.new("RGB", (width, height), CANVAS)
    draw = ImageDraw.Draw(image)
    fonts: dict[tuple[int, int], ImageFont.FreeTypeFont] = {}

    def font(size: int, weight: int) -> ImageFont.FreeTypeFont:
        key = (size, weight)
        if key not in fonts:
            loaded = ImageFont.truetype(
                BytesIO(font_bytes), size=size, layout_engine=ImageFont.Layout.BASIC,
            )
            loaded.set_variation_by_axes([min(40, max(9, size)), weight])
            fonts[key] = loaded
        return fonts[key]

    def paint(element: ET.Element) -> None:
        name = str(element.tag).rsplit("}", 1)[-1]
        if name == "rect":
            x, y = int(element.attrib["x"]), int(element.attrib["y"])
            rect_width, rect_height = int(element.attrib["width"]), int(element.attrib["height"])
            radius = int(element.attrib.get("rx", "0"))
            box = (x, y, x + rect_width, y + rect_height)
            if radius:
                draw.rounded_rectangle(box, radius=radius, fill=element.attrib["fill"])
            else:
                draw.rectangle(box, fill=element.attrib["fill"])
        elif name == "text":
            if element.attrib.get("font-family") != contract.FIGURE_FONT_FAMILY:
                raise ValueError("figure SVG raster text does not use embedded DM Sans")
            size = int(float(element.attrib.get("font-size", "12")))
            weight = int(element.attrib.get("font-weight", "400"))
            anchor = element.attrib.get("text-anchor", "start")
            pillow_anchor = {"start": "ls", "end": "rs"}.get(anchor)
            if pillow_anchor is None:
                raise ValueError("figure SVG raster text has an unsupported anchor")
            draw.text(
                (int(element.attrib["x"]), int(element.attrib["y"])),
                "".join(element.itertext()), fill=element.attrib["fill"],
                font=font(size, weight), anchor=pillow_anchor,
            )
        elif name not in {"svg", "g", "title", "desc", "style"}:
            raise ValueError(f"figure SVG rasterizer does not allow {name}")
        for child in element:
            paint(child)

    paint(root)
    return image


def _rasterize_svg(svg: bytes) -> bytes:
    """Return a metadata-free PNG proof of the exact SVG rendering path."""
    output = BytesIO()
    _rasterized_image(svg).save(output, format="PNG", optimize=False)
    return output.getvalue()


def _png_from_svg(svg: bytes, item: Mapping[str, Any]) -> bytes:
    """Rasterize the already-validated SVG; PNG is its visual partner."""
    try:
        image = _rasterized_image(svg)
        if image.size != (int(item["width"]), int(item["height"])):
            raise ValueError("SVG raster dimensions differ from the figure manifest")
    except Exception as exc:
        raise ValueError("Pillow could not rasterize the validated figure SVG") from exc
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("caption", item["caption"])
    metadata.add_text("doi", item["doi"])
    metadata.add_text("source", item["source_label"])
    output = BytesIO()
    image.save(output, format="PNG", pnginfo=metadata, optimize=False)
    return output.getvalue()


def _entry(chart_id: str, locale: str, fmt: str, release: Mapping[str, Any], metrics: tuple[contract.Metric, ...]) -> dict[str, Any]:
    specification = contract.FIGURE_SPECS[chart_id]
    copy = contract._approved_figure_copy(chart_id, locale, metrics, release, str(release["doi"]))
    values = _metric_map(metrics)
    selected = [values[identifier] for identifier in specification["metric_ids"]]
    caveats = list(dict.fromkeys(metric.caveat for metric in selected))
    if specification.get("required_caveat"):
        caveats.append(specification["required_caveat"])
    width, height = specification["dimensions"]
    return {
        "chart_id": chart_id, "family": specification["family"],
        "path": f"figures/{chart_id}.{locale}.{fmt}", "kind": specification["kind"],
        "format": fmt, "mime_type": "image/svg+xml" if fmt == "svg" else "image/png",
        "width": width, "height": height, "locale": locale,
        "metric_ids": list(specification["metric_ids"]),
        "denominator_metric_ids": list(specification["denominator_metric_ids"]),
        **copy,
        "source_snapshot_date": release["source_universe"]["snapshot_date"],
        "source_snapshot_sha256": release["source_universe"]["normalized_sha256"],
        "source_label": contract.FIGURE_SOURCE_LABELS[locale],
        "measurement_interval": release["measurement_interval"],
        "release_version": release["release_version"], "license": "CC BY 4.0",
        "doi": release["doi"], "repository": contract.CANONICAL_REPOSITORY_URL,
        "methodology_signals": list(dict.fromkeys(metric.method for metric in selected)),
        "caveat_signals": caveats,
    }


def generate(staging_directory: str | Path) -> dict[str, Any]:
    """Generate the exact 30-file matrix into an otherwise untouched staging tree."""
    staging = Path(staging_directory)
    _validate_chart_catalogue()
    release, metrics, _attestation = _load_release_inputs(staging)
    figures = staging / "figures"
    if figures.exists() or figures.is_symlink():
        raise FileExistsError("figure generation requires a staging tree without figures")
    temporary = Path(tempfile.mkdtemp(prefix=".figures-", dir=staging))
    try:
        entries: list[dict[str, Any]] = []
        values = _metric_map(metrics)
        for chart_id in contract.FIGURE_SPECS:
            for locale in contract.FIGURE_LOCALES:
                for fmt in ("svg", "png"):
                    entry = _entry(chart_id, locale, fmt, release, metrics)
                    target = temporary / Path(entry["path"]).name
                    if fmt == "svg":
                        payload = _svg_chart(entry, values)
                        contract._validate_svg(payload, entry)
                    else:
                        svg_path = temporary / f"{chart_id}.{locale}.svg"
                        svg_payload = svg_path.read_bytes()
                        contract._validate_svg(svg_payload, entry)
                        payload = _png_from_svg(svg_payload, entry)
                    contract._write_bytes(target, payload)
                    entry["sha256"], entry["bytes"] = _sha256(target), target.stat().st_size
                    entries.append(entry)
        manifest = {"manifest_version": 1, "release_version": contract.RELEASE_VERSION, "figures": sorted(entries, key=lambda item: item["path"])}
        contract._write_bytes(
            temporary / "manifest.json",
            (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
        contract._validate_instance(contract.FIGURES_SCHEMA_PATH, manifest, "figure manifest")
        for entry in manifest["figures"]:
            content = (temporary / Path(entry["path"]).name).read_bytes()
            if entry["format"] == "svg":
                contract._validate_svg(content, entry)
            else:
                contract._validate_png(content, entry)
        contract._fsync_directory(temporary)
        os.replace(temporary, figures)
        contract._fsync_directory(staging)
        return manifest
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging", required=True, type=Path, help="DOI-bound staging release directory")
    args = parser.parse_args(argv)
    result = generate(args.staging)
    print(json.dumps({"files": len(result["figures"]), "staging": str(args.staging)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
