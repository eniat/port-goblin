"""CISA Known Exploited Vulnerabilities catalogue (JSON feed)."""

from __future__ import annotations

from dataclasses import dataclass

from portgoblin.intelligence.cache import Fetcher, FetchError, JsonCache, fetch_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KevEntry:
    cve_id: str
    date_added: str | None
    ransomware: str | None


@dataclass
class KevCatalogue:
    version: str | None
    entries: dict[str, KevEntry]
    stale: bool = False

    def get(self, cve_id: str) -> KevEntry | None:
        return self.entries.get(cve_id)


def parse_kev(payload: dict) -> KevCatalogue:
    entries = {}
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cveID")
        if cve:
            entries[cve] = KevEntry(
                cve, item.get("dateAdded"), item.get("knownRansomwareCampaignUse")
            )
    return KevCatalogue(payload.get("catalogVersion"), entries)


def load_kev(
    cache: JsonCache, timeout: float = 30, fetch: Fetcher = fetch_json, refresh: bool = False
) -> KevCatalogue:
    """The cached catalogue if fresh, else the feed. Falls back to a stale copy if offline."""
    if not refresh:
        cached = cache.get("kev", KEV_URL)
        if cached is not None:
            return parse_kev(cached)
    try:
        payload = fetch(KEV_URL, timeout, None)
    except FetchError:
        stale = cache.get("kev", KEV_URL, allow_stale=True)
        if stale is None:
            raise
        catalogue = parse_kev(stale)
        catalogue.stale = True
        return catalogue
    cache.set("kev", KEV_URL, payload)
    return parse_kev(payload)
