"""EPSS scores from the FIRST API, 100 CVEs per request, cached per CVE."""

from __future__ import annotations

import urllib.parse

from portgoblin.intelligence.cache import Fetcher, JsonCache, fetch_json

EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH = 100


def parse_epss(payload: dict) -> dict[str, float]:
    scores = {}
    for item in payload.get("data", []):
        try:
            scores[item["cve"]] = float(item["epss"])
        except (KeyError, TypeError, ValueError):
            continue
    return scores


def epss_scores(
    cve_ids: list[str], cache: JsonCache, timeout: float = 30, fetch: Fetcher = fetch_json
) -> dict[str, float]:
    """Scores for the CVEs FIRST knows. CVEs without a score are left out.
    Raises FetchError if the API cannot be reached for uncached CVEs."""
    scores: dict[str, float] = {}
    missing = []
    for cve in sorted(set(cve_ids)):
        cached = cache.get("epss", cve)
        if cached is None:
            missing.append(cve)
        elif cached.get("epss") is not None:
            scores[cve] = cached["epss"]
    for start in range(0, len(missing), BATCH):
        batch = missing[start : start + BATCH]
        query = urllib.parse.urlencode({"cve": ",".join(batch), "limit": BATCH})
        found = parse_epss(fetch(f"{EPSS_URL}?{query}", timeout, None))
        for cve in batch:
            cache.set("epss", cve, {"epss": found.get(cve)})
            if cve in found:
                scores[cve] = found[cve]
    return scores
