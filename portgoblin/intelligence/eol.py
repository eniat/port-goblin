"""End of life from endoflife.date (API v1, /products/full).

Products are matched by the CPE identifiers endoflife.date publishes (293 of 490 products
had one when this was written), plus aliases in the config for products whose CPE there
differs from nmap's (for example nmap's igor_sysoev:nginx). Versions are matched to a
release cycle by prefix: 1.0.2k is in cycle 1.0.2, 2.4.41 in 2.4.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime

from portgoblin.intelligence.cache import Fetcher, JsonCache, fetch_json
from portgoblin.intelligence.nvd import vendor_product

EOL_URL = "https://endoflife.date/api/v1/products/full"


@dataclass
class EolResult:
    product: str
    label: str
    cycle: str
    eol_from: str | None
    is_eol: bool
    latest: str | None
    link: str


class EolIndex:
    def __init__(self, products: list[dict], aliases: dict[str, str] | None = None) -> None:
        self.products = {p["name"]: p for p in products if p.get("name")}
        self.by_cpe: dict[str, str] = {}
        for product in products:
            for identifier in product.get("identifiers", []):
                if identifier.get("type") == "cpe":
                    key = vendor_product(identifier.get("id", ""))
                    if key:
                        self.by_cpe.setdefault(key.lower(), product["name"])
        for key, name in (aliases or {}).items():
            if name in self.products:
                self.by_cpe.setdefault(key.lower(), name)

    def product_for(self, cpe: str) -> str | None:
        key = vendor_product(cpe)
        return self.by_cpe.get(key.lower()) if key else None

    @staticmethod
    def cycle_for(releases: list[dict], version: str) -> dict | None:
        best = None
        for release in releases:
            name = str(release.get("name", ""))
            if not name:
                continue
            matches = version == name or (
                version.startswith(name) and not version[len(name)].isdigit()
            )
            if matches and (best is None or len(name) > len(best["name"])):
                best = release
        return best

    def check(self, cpe: str, version: str, today: date | None = None) -> EolResult | None:
        name = self.product_for(cpe)
        if not name:
            return None
        product = self.products[name]
        release = self.cycle_for(product.get("releases", []), version)
        if not release:
            return None
        today = today or datetime.now(UTC).date()
        eol_from = release.get("eolFrom")
        is_eol = bool(release.get("isEol"))
        if not is_eol and eol_from and re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(eol_from)):
            is_eol = date.fromisoformat(eol_from) <= today
        latest = (release.get("latest") or {}).get("name")
        link = (product.get("links") or {}).get("html") or f"https://endoflife.date/{name}"
        return EolResult(
            name, product.get("label", name), str(release["name"]), eol_from, is_eol, latest, link
        )


def load_eol(
    cache: JsonCache,
    aliases: dict[str, str],
    timeout: float = 30,
    fetch: Fetcher = fetch_json,
    refresh: bool = False,
) -> EolIndex:
    payload = None if refresh else cache.get("eol", EOL_URL)
    if payload is None:
        payload = fetch(EOL_URL, timeout, None)
        cache.set("eol", EOL_URL, payload)
    return EolIndex(payload.get("result", []), aliases)
