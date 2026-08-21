"""Regression tests for aggregate-only localized editorial figures."""

import hashlib
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from PIL import Image

from figures.generate import HEIGHT, SOCIAL_HEIGHT, SOCIAL_WIDTH, WIDTH, generate


FIXTURES = Path("tests/fixtures/figures")


def _copy_bundle(tmp_path: Path) -> tuple[Path, Path]:
    metrics, release = tmp_path / "metrics.json", tmp_path / "release.json"
    shutil.copy(FIXTURES / "metrics.json", metrics)
    shutil.copy(FIXTURES / "release.json", release)
    return metrics, release


def _set_release_hash(metrics: Path, release: Path) -> None:
    data = json.loads(release.read_text(encoding="utf-8"))
    data["metrics_sha256"] = hashlib.sha256(metrics.read_bytes()).hexdigest()
    data["metric_count"] = len(json.loads(metrics.read_text(encoding="utf-8"))["metrics"])
    release.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def test_generates_accessible_localized_svg_png_and_deterministic_manifest(tmp_path):
    metrics, release = _copy_bundle(tmp_path)
    output = tmp_path / "figures"
    manifest = generate(metrics, release, output)

    assert len(manifest["files"]) == 30
    assert manifest["release_version"] == "v2026.08.2"
    first_hashes = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
    assert generate(metrics, release, output)["files"] == manifest["files"]
    assert {entry["path"]: entry["sha256"] for entry in manifest["files"]} == first_hashes

    for locale in ("de", "fr", "it"):
        svg = output / locale / "dmarc-policy-observations.svg"
        root = ET.parse(svg).getroot()
        assert root.attrib["role"] == "img"
        assert root.find("{http://www.w3.org/2000/svg}title") is not None
        assert root.find("{http://www.w3.org/2000/svg}desc") is not None
        text = svg.read_text(encoding="utf-8")
        assert "<text " in text and "p=reject" in text
        assert "2026-08-21/2026-08-22" in text
        assert "10." not in text  # fixture intentionally has no DOI/placeholder
        with Image.open(output / locale / "dmarc-policy-observations.png") as image:
            assert image.size == (WIDTH, HEIGHT)
            assert image.mode == "RGB"
        with Image.open(output / locale / "social-card.png") as image:
            assert image.size == (SOCIAL_WIDTH, SOCIAL_HEIGHT)
            assert image.mode == "RGB"
    assert "40,00%" in (output / "de/dmarc-policy-observations.svg").read_text(encoding="utf-8")
    assert "40,00\u202f%" in (output / "fr/dmarc-policy-observations.svg").read_text(encoding="utf-8")
    assert "40,00%" in (output / "it/dmarc-policy-observations.svg").read_text(encoding="utf-8")


@pytest.mark.parametrize("mutation, message", [
    (lambda metrics, release: release.write_text(release.read_text().replace("v2026.08.2", "v2026.08.1")), "unsupported release version"),
    (lambda metrics, release: release.write_text(release.read_text().replace("30dafd", "000000")), "metrics_sha256"),
    (lambda metrics, release: release.write_text(release.read_text().replace('"metric_count": 40', '"metric_count": 39')), "metric_count"),
])
def test_rejects_stale_or_mismatched_release_metadata(tmp_path, mutation, message):
    metrics, release = _copy_bundle(tmp_path)
    mutation(metrics, release)
    with pytest.raises(ValueError, match=message):
        generate(metrics, release, tmp_path / "out")


def test_fails_closed_for_partition_and_private_input_and_preserves_existing_output(tmp_path):
    metrics, release = _copy_bundle(tmp_path)
    data = json.loads(metrics.read_text(encoding="utf-8"))
    next(metric for metric in data["metrics"] if metric["metric_id"] == "dmarc.none")["numerator"] = 19
    next(metric for metric in data["metrics"] if metric["metric_id"] == "dmarc.none")["percentage"] = "19"
    metrics.write_text(json.dumps(data), encoding="utf-8")
    _set_release_hash(metrics, release)
    output = tmp_path / "out"
    output.mkdir(); (output / "keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="unmarked"):
        generate(metrics, release, output)
    assert (output / "keep.txt").read_text(encoding="utf-8") == "keep"

    shutil.rmtree(output)
    with pytest.raises(ValueError, match="partition"):
        generate(metrics, release, output)

    data["metrics"][0]["domain"] = "forbidden"
    metrics.write_text(json.dumps(data), encoding="utf-8")
    _set_release_hash(metrics, release)
    with pytest.raises(ValueError, match="private field"):
        generate(metrics, release, output)


def test_accepts_validated_doi_but_rejects_placeholder(tmp_path):
    metrics, release = _copy_bundle(tmp_path)
    data = json.loads(release.read_text(encoding="utf-8"))
    data["doi"] = "10.5281/zenodo.1234567"
    release.write_text(json.dumps(data), encoding="utf-8")
    generate(metrics, release, tmp_path / "with-doi")
    assert "DOI: 10.5281/zenodo.1234567" in (tmp_path / "with-doi/de/dmarc-policy-observations.svg").read_text(encoding="utf-8")
    data["doi"] = "pending DOI"
    release.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="DOI"):
        generate(metrics, release, tmp_path / "bad-doi")


def test_zero_denominator_and_zero_values_are_rendered_without_invalid_images(tmp_path):
    metrics, release = _copy_bundle(tmp_path)
    data = json.loads(metrics.read_text(encoding="utf-8"))
    for metric in data["metrics"]:
        metric["numerator"] = 0
        metric["denominator"] = 0
        metric["percentage"] = "0"
    metrics.write_text(json.dumps(data), encoding="utf-8")
    _set_release_hash(metrics, release)
    manifest = generate(metrics, release, tmp_path / "zero")
    assert len(manifest["files"]) == 30
    assert "0,00%" in (tmp_path / "zero/it/dmarc-policy-observations.svg").read_text(encoding="utf-8")


def test_rejects_metric_with_matching_count_but_wrong_denominator_identity(tmp_path):
    metrics, release = _copy_bundle(tmp_path)
    data = json.loads(metrics.read_text(encoding="utf-8"))
    next(metric for metric in data["metrics"] if metric["metric_id"] == "spf.present")["denominator_metric_id"] = "population.analyzable"
    metrics.write_text(json.dumps(data), encoding="utf-8")
    _set_release_hash(metrics, release)
    with pytest.raises(ValueError, match="metric denominator identity"):
        generate(metrics, release, tmp_path / "wrong-denominator")
