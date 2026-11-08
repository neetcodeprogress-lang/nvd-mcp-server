"""Tests for models.from_nvd. Pure functions: no HTTP, no async, no respx needed."""

import pytest

from nvd_mcp.models import CveSummary, from_nvd


def make_item(**cve_fields) -> dict:
    """A raw NVD item ({"cve": {...}}) with an ID plus whatever fields the test passes."""
    return {"cve": {"id": "CVE-2021-44228", **cve_fields}}


def score(base_score: float, severity: str, scorer: str = "Primary") -> dict:
    """One v3.x / v4.0 CVSS entry. scorer is "Primary" (NVD) or "Secondary" (e.g. the vendor)."""
    return {"type": scorer, "cvssData": {"baseScore": base_score, "baseSeverity": severity}}


def v2_score(base_score: float, severity: str, scorer: str = "Primary") -> dict:
    """One v2 CVSS entry. Unlike v3/v4, v2 keeps baseSeverity outside cvssData."""
    return {"type": scorer, "baseSeverity": severity, "cvssData": {"baseScore": base_score}}


# --- Happy path ---


def test_full_item_maps_every_field():
    item = make_item(
        published="2021-12-10T10:15:09.143",
        cisaExploitAdd="2021-12-10",
        descriptions=[{"lang": "en", "value": "Log4j lets attackers run code."}],
        metrics={"cvssMetricV31": [score(10.0, "CRITICAL")]},
    )

    assert from_nvd(item) == CveSummary(
        cve_id="CVE-2021-44228",
        published="2021-12-10T10:15:09.143",
        cvss_score=10.0,
        severity="CRITICAL",
        cvss_version="3.1",
        description="Log4j lets attackers run code.",
        in_kev=True,
        url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    )


# --- Picking the CVSS score: version first, then NVD's Primary within that version ---


@pytest.mark.parametrize(
    ("metrics", "expected"),
    [
        pytest.param(
            {"cvssMetricV31": [score(9.0, "CRITICAL", "Secondary"), score(10.0, "CRITICAL")]},
            (10.0, "CRITICAL", "3.1"),
            id="same version: NVD Primary beats vendor (quiz 2c)",
        ),
        pytest.param(
            {"cvssMetricV31": [score(7.5, "HIGH", "Secondary"), score(8.1, "HIGH", "Secondary")]},
            (7.5, "HIGH", "3.1"),
            id="no Primary: first listed wins",
        ),
        pytest.param(
            {"cvssMetricV31": [score(7.5, "HIGH", "Secondary")], "cvssMetricV30": [score(9.8, "CRITICAL")]},
            (7.5, "HIGH", "3.1"),
            id="vendor v3.1 beats NVD v3.0 (quiz 2e)",
        ),
        pytest.param(
            {"cvssMetricV40": [score(8.7, "HIGH", "Secondary")], "cvssMetricV2": [v2_score(10.0, "HIGH")]},
            (8.7, "HIGH", "4.0"),
            id="vendor v4.0 beats NVD v2 (quiz 2d)",
        ),
        pytest.param(
            {"cvssMetricV2": [v2_score(9.3, "HIGH")]},
            (9.3, "HIGH", "2.0"),
            id="v2 only: severity read from one level up",
        ),
        pytest.param(
            {"cvssMetricV31": [], "cvssMetricV30": [score(5.3, "MEDIUM")]},
            (5.3, "MEDIUM", "3.0"),
            id="empty version list is skipped",
        ),
    ],
)
def test_picks_cvss_score(metrics, expected):
    summary = from_nvd(make_item(metrics=metrics))

    assert (summary.cvss_score, summary.severity, summary.cvss_version) == expected


# --- Description ---


def test_long_description_cut_to_300_by_default():
    item = make_item(descriptions=[{"lang": "en", "value": "x" * 500}])

    description = from_nvd(item).description

    assert len(description) == 300
    assert description.endswith("…")


def test_max_description_none_keeps_full_text():
    item = make_item(descriptions=[{"lang": "en", "value": "x" * 500}])

    assert from_nvd(item, max_description=None).description == "x" * 500


def test_short_description_unchanged():
    item = make_item(descriptions=[{"lang": "en", "value": "Short."}])

    assert from_nvd(item).description == "Short."


def test_picks_english_description():
    item = make_item(
        descriptions=[{"lang": "es", "value": "Hola."}, {"lang": "en", "value": "Hello."}]
    )

    assert from_nvd(item).description == "Hello."


# --- Missing data never crashes ---


def test_empty_item_gives_all_none():
    assert from_nvd({}) == CveSummary(
        cve_id=None,
        published=None,
        cvss_score=None,
        severity=None,
        cvss_version=None,
        description=None,
        in_kev=False,
        url=None,
    )


def test_null_fields_dont_crash():
    # NVD JSON can carry a key whose value is null; .get() alone would hand back None, not {}.
    item = make_item(metrics=None, descriptions=None, cisaExploitAdd=None)

    summary = from_nvd(item)

    assert summary.cve_id == "CVE-2021-44228"
    assert summary.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert summary.cvss_score is None
    assert summary.description is None
    assert summary.in_kev is False
