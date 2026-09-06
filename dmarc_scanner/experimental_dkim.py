"""Candidate for a future measurement core; NOT used by v2026.08.2.

The historical scanner is byte-pinned by signed provenance. Integrating this
candidate requires a new measurement-core version and run, not a silent patch
to the core used to validate the existing release.
"""
from .parsers import _parse_tags, _WEAK_DKIM_KEY_B64_THRESHOLD


def parse_dkim_candidate(record: str) -> dict:
    tags = _parse_tags(record)
    return {
        "testing_mode": "y" in {flag.strip().lower() for flag in tags.get("t", "").split(":")},
        "weak_key": tags.get("k", "rsa").lower() == "rsa"
        and 0 < len(tags.get("p", "")) < _WEAK_DKIM_KEY_B64_THRESHOLD,
    }
