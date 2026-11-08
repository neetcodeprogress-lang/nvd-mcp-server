"""Turns NVD's large raw CVE JSON into small, flat summaries for the AI assistant."""

from dataclasses import dataclass

NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"

# Search results cut descriptions to this many characters so 100 CVEs don't flood the
# assistant's context. A single-CVE lookup passes max_description=None to get the full text.
SEARCH_DESCRIPTION_LIMIT = 300

# CVSS versions to try, best first: (key inside NVD's "metrics" object, version label we show).
CVSS_PREFERENCE = [
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
]


# frozen=True: fields can't be changed after the object is built (like a Java record).
@dataclass(frozen=True)
class CveSummary:
    """The few fields of a CVE that matter. None means NVD didn't provide it."""

    cve_id: str | None
    published: str | None  # NVD's timestamp as-is, e.g. "2021-12-10T10:15:09.143"
    cvss_score: float | None  # 0.0-10.0
    severity: str | None  # e.g. "CRITICAL"; v2 scores only go up to "HIGH"
    cvss_version: str | None  # which CVSS version the score came from, e.g. "3.1"
    description: str | None  # English description, maybe shortened (ends with "…" if so)
    in_kev: bool  # True if CISA lists it as actively exploited (Known Exploited Vulnerabilities)
    url: str | None  # the CVE's page on the NVD website


def _pick_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Return (score, severity, version) from the best CVSS entry, or (None, None, None)."""
    for key, version in CVSS_PREFERENCE:
        entries = metrics.get(key) or []
        if not entries:
            continue  # this CVE has no score for this version; try the next one
        # Several organizations can score the same CVE. Prefer NVD's own ("Primary");
        # otherwise take the first one listed (usually the vendor's "Secondary" score).
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        # v3.x and v4.0 keep baseSeverity inside cvssData; v2 keeps it one level up.
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return data.get("baseScore"), severity, version
    return None, None, None


def _english_description(descriptions: list) -> str | None:
    """Return the English description, or None if there isn't one."""
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    return None


def _shorten(text: str | None, limit: int | None) -> str | None:
    """Cut text to at most `limit` characters, ending with "…". limit=None means don't cut."""
    if text is None or limit is None or len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def from_nvd(item: dict, *, max_description: int | None = SEARCH_DESCRIPTION_LIMIT) -> CveSummary:
    """Build a CveSummary from one raw NVD item (shaped like {"cve": {...}}).

    Never raises on missing fields; anything absent becomes None (or False for in_kev).
    """
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    score, severity, version = _pick_cvss(cve.get("metrics") or {})
    description = _english_description(cve.get("descriptions") or [])

    return CveSummary(
        cve_id=cve_id,
        published=cve.get("published"),
        cvss_score=score,
        severity=severity,
        cvss_version=version,
        description=_shorten(description, max_description),
        # NVD adds cisaExploitAdd (the date CISA listed it) only for CVEs in the KEV catalog.
        in_kev=cve.get("cisaExploitAdd") is not None,
        url=f"{NVD_DETAIL_URL}{cve_id}" if cve_id else None,
    )
