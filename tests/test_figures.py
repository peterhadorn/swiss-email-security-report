"""Adversarial tests for the DOI-bound editorial figure renderer."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from io import BytesIO
from pathlib import Path
import tomllib
import xml.etree.ElementTree as ET

import pytest
from PIL import Image, ImageChops

import figures.generate as renderer


DOI = "10.5281/zenodo.1234567"


def _write_boolean_metric_with_reconciled_file_hashes(stage: Path) -> None:
    """Reach Task 6 metric type validation rather than failing only on a hash."""
    metrics_path = stage / "metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    metrics["metrics"][0]["numerator"] = True
    metrics_path.write_text(json.dumps(metrics, sort_keys=True) + "\n", encoding="utf-8")
    digest = hashlib.sha256(metrics_path.read_bytes()).hexdigest()
    size = metrics_path.stat().st_size
    release_path = stage / "release.json"
    release = json.loads(release_path.read_text(encoding="utf-8"))
    for entry in release["aggregate_files"]:
        if entry["name"] == "metrics.json":
            entry.update({"sha256": digest, "bytes": size})
    release_path.write_text(json.dumps(release, sort_keys=True) + "\n", encoding="utf-8")
    attestation_path = stage / "aggregate-attestation.json"
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    for entry in attestation["metric_files"]:
        if entry["name"] == "metrics.json":
            entry.update({"sha256": digest, "bytes": size})
    attestation_path.write_text(json.dumps(attestation, sort_keys=True) + "\n", encoding="utf-8")
    attestation_digest = hashlib.sha256(attestation_path.read_bytes()).hexdigest()
    for entry in release["aggregate_files"]:
        if entry["name"] == "aggregate-attestation.json":
            entry.update({"sha256": attestation_digest, "bytes": attestation_path.stat().st_size})
    release_path.write_text(json.dumps(release, sort_keys=True) + "\n", encoding="utf-8")


def _bundle_tests_module():
    spec = importlib.util.spec_from_file_location(
        "figure_bundle_tests", Path("tests/test_release_bundle.py"),
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def doi_staging(tmp_path, monkeypatch):
    """Create a genuinely signed Task 6 DOI-bound synthetic release tree."""
    bundle_tests = _bundle_tests_module()
    bundle = bundle_tests.release_module.__wrapped__(monkeypatch)
    stage, _database, _manifests = bundle_tests._stage(tmp_path, bundle)
    bundle_tests._reserve_staging(stage, bundle, DOI)
    return stage, bundle


def _hashes(stage: Path) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((stage / "figures").glob("*.*"))
    }


def test_generates_exact_validated_30_file_matrix_with_real_doi_bound_stage(doi_staging):
    stage, bundle = doi_staging
    manifest = renderer.generate(stage)

    assert renderer.FONT_PATH.is_file()
    assert len(manifest["figures"]) == 30
    bundle._validate_instance(bundle.FIGURES_SCHEMA_PATH, manifest, "figure manifest")
    release = bundle._load_json(stage / "release.json", "release")
    metrics = bundle._metric_objects(bundle._load_json(stage / "metrics.json", "metrics"))
    bundle._validate_figures(stage, metrics, release, DOI)
    assert {entry["path"] for entry in manifest["figures"]} == {
        f"figures/{chart}.{locale}.{fmt}"
        for chart in bundle.FIGURE_SPECS for locale in bundle.FIGURE_LOCALES
        for fmt in ("svg", "png")
    }
    for entry in manifest["figures"]:
        payload = stage / entry["path"]
        assert entry["sha256"] == hashlib.sha256(payload.read_bytes()).hexdigest()
        assert entry["bytes"] == payload.stat().st_size
    for chart_id in bundle.FIGURE_SPECS:
        for locale in bundle.FIGURE_LOCALES:
            svg = (stage / f"figures/{chart_id}.{locale}.svg").read_bytes()
            with Image.open(BytesIO(renderer._rasterize_svg(svg))) as expected, Image.open(
                stage / f"figures/{chart_id}.{locale}.png",
            ) as actual:
                expected.load(); actual.load()
                assert ImageChops.difference(expected.convert("RGBA"), actual.convert("RGBA")).getbbox() is None
    for locale in bundle.FIGURE_LOCALES:
        svg = (stage / f"figures/mail-authentication-overview.{locale}.svg").read_text(encoding="utf-8")
        assert renderer.KICKERS["mail-authentication-overview"][locale] in svg
        assert "AUTHENTICATION-ADOPTION" not in svg
        assert "50,00 %" in svg  # all report locales use decimal commas
        assert "(1/2)" in svg  # the exact numerator and denominator remain visible
        with Image.open(stage / f"figures/social-report-card.{locale}.png") as image:
            assert image.size == (1200, 630) and image.mode == "RGB"
            assert image.info["doi"] == DOI
            assert any(pixel != (248, 247, 243) for pixel in image.crop((0, 540, 800, 630)).get_flattened_data())


def test_every_svg_embeds_and_uses_the_pinned_dm_sans_font(doi_staging):
    stage, bundle = doi_staging
    renderer.generate(stage)
    assert hashlib.sha256(renderer.FONT_PATH.read_bytes()).hexdigest() == bundle.FIGURE_FONT_SHA256
    for path in sorted((stage / "figures").glob("*.svg")):
        root = ET.fromstring(path.read_bytes())
        style = root.find("{http://www.w3.org/2000/svg}style")
        assert style is not None
        assert bundle._validate_embedded_svg_font(style) == renderer.FONT_PATH.read_bytes()
        text_nodes = root.findall(".//{http://www.w3.org/2000/svg}text")
        assert text_nodes
        assert all(node.attrib.get("font-family") == bundle.FIGURE_FONT_FAMILY for node in text_nodes)


def test_social_card_values_are_prominent_and_accent_avoids_copy(doi_staging):
    stage, bundle = doi_staging
    renderer.generate(stage)
    namespace = {"svg": "http://www.w3.org/2000/svg"}
    for locale in bundle.FIGURE_LOCALES:
        root = ET.fromstring(
            (stage / f"figures/social-report-card.{locale}.svg").read_bytes(),
        )
        texts = root.findall(".//svg:text", namespace)
        prominent = [
            node for node in texts
            if "," in (node.text or "") and "%" in (node.text or "")
            and float(node.attrib["font-size"]) >= 32
        ]
        assert len(prominent) == 4
        assert any("1/2" in (node.text or "") for node in texts)
        stripe = next(
            node for node in root.findall(".//svg:rect", namespace)
            if node.attrib.get("fill") == renderer.RED
            and node.attrib.get("width") == "10"
        )
        stripe_top = int(stripe.attrib["y"])
        stripe_bottom = stripe_top + int(stripe.attrib["height"])
        protected = [
            node for node in texts
            if (node.text or "") in {
                renderer.KICKERS["social-report-card"][locale], DOI,
                bundle.FIGURE_SOURCE_LABELS[locale],
            }
        ]
        assert len(protected) == 3
        assert all(
            not (stripe_top <= int(node.attrib["y"]) <= stripe_bottom)
            for node in protected
        )


def test_generation_is_deterministic_for_two_authenticated_stages(tmp_path, monkeypatch):
    first = _bundle_tests_module()
    bundle = first.release_module.__wrapped__(monkeypatch)
    stage_one, _, _ = first._stage(tmp_path / "one", bundle)
    first._reserve_staging(stage_one, bundle, DOI)
    renderer.generate(stage_one)
    stage_two, _, _ = first._stage(tmp_path / "two", bundle)
    first._reserve_staging(stage_two, bundle, DOI)
    renderer.generate(stage_two)
    assert _hashes(stage_one) == _hashes(stage_two)
    with pytest.raises(FileExistsError, match="incomplete"):
        renderer.generate(stage_one)


@pytest.mark.parametrize("mutation", [
    lambda stage: (stage / "doi-reservation.json").write_text("{}\n", encoding="utf-8"),
    lambda stage: (stage / "metrics.json").write_text('{"metrics": [], "metrics": []}\n', encoding="utf-8"),
    _write_boolean_metric_with_reconciled_file_hashes,
])
def test_refuses_tampered_unsigned_duplicate_or_boolean_public_inputs(doi_staging, mutation):
    stage, _bundle = doi_staging
    mutation(stage)
    with pytest.raises(ValueError):
        renderer.generate(stage)
    assert not (stage / "figures").exists()


def test_refuses_hardlinks_symlink_ancestors_and_parent_traversal(doi_staging, tmp_path):
    stage, _bundle = doi_staging
    os.link(stage / "metrics.json", stage / "metrics-copy.json")
    with pytest.raises((ValueError, FileExistsError), match="hard-linked|incomplete"):
        renderer.generate(stage)
    (stage / "metrics-copy.json").unlink()

    link = tmp_path / "linked-root"
    os.symlink(stage.parent, link)
    with pytest.raises(ValueError, match="symlink"):
        renderer.generate(link / stage.name)
    with pytest.raises(ValueError, match="parent traversal"):
        renderer.generate(stage.parent / "fictional" / ".." / stage.name)


def test_keyboard_interrupt_leaves_no_partial_figure_tree(doi_staging, monkeypatch):
    stage, _bundle = doi_staging

    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(renderer, "_entry", interrupt)
    with pytest.raises(KeyboardInterrupt):
        renderer.generate(stage)
    assert not (stage / "figures").exists()
    assert not list(stage.glob(".figures-*"))


def test_catalogue_is_exact_and_excludes_ds_caa_and_obsolete_provider_groups():
    catalogue = json.loads((renderer.HERE / "charts.json").read_text(encoding="utf-8"))
    assert [chart["id"] for chart in catalogue["charts"]] == [
        "mail-authentication-overview", "dmarc-policy-observations",
        "dns-transport-signals", "mx-provider-fingerprints",
    ]
    transport = catalogue["charts"][2]["metric_ids"]
    assert transport == ["tlsa.record_present", "bimi.record_present", "mta_sts.txt_present", "tls_rpt.record_present"]
    assert "ds.record_present" not in transport and "caa.record_present" not in transport
    assert not (renderer.HERE / "style.json").exists()


def test_runtime_catalogue_and_font_are_declared_as_wheel_package_data():
    configuration = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    packaged = configuration["tool"]["setuptools"]["package-data"]["figures"]
    assert "charts.json" in packaged
    assert "fonts/*.ttf" in packaged
    assert "fonts/*.txt" in packaged
