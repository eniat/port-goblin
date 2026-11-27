"""CPE to CVE lookups with the NVD CVE API 2.0 (virtualMatchString).

Checked against the live API (November 2026):
- virtualMatchString with a versioned CPE also matches version ranges in NVD's
  configurations, so no local range matching is needed.
- nmap writes OpenSSH versions as 8.9p1, and NVD matches that form.
- nmap and NVD sometimes disagree on the vendor (nmap cpe:/a:vsftpd:vsftpd, NVD
  vsftpd_project), which returns nothing. Then the CPE dictionary is searched with a
  wildcard vendor, and the lookup is retried only if exactly one vendor has that product
  and version.
"""

from __future__ import annotations

import os
import re
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

from portgoblin.intelligence.cache import Fetcher, FetchError, JsonCache, fetch_json

CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
PAGE = 2000
RETRY_STATUSES = (403, 429, 500, 502, 503, 504)

_UNRESERVED = re.compile(r"[A-Za-z0-9_\-.]")
# A usable version: starts with a digit and is not a range or wildcard such as "2.2.X - 2.3.X".
VERSION_RE = re.compile(r"^\d[\w.+~-]*$")


def _decode_22(value: str) -> str:
    return urllib.parse.unquote(value)


def _encode_23(value: str) -> str:
    if value in ("", "*"):
        return "*"
    if value == "-":
        return "-"
    return "".join(c if _UNRESERVED.match(c) else "\\" + c for c in value)


def cpe22_to_23(cpe: str) -> str | None:
    """Convert a CPE 2.2 URI (cpe:/a:vendor:product:version...) to a 2.3 formatted string."""
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        return None
    parts = cpe[len("cpe:/") :].split(":")
    if not parts or parts[0] not in ("a", "o", "h"):
        return None
    parts += [""] * (7 - len(parts))
    part, vendor, product, version, update, edition, language = parts[:7]
    sw_edition = target_sw = target_hw = other = ""
    if edition.startswith("~"):
        packed = edition[1:].split("~") + [""] * 5
        edition, sw_edition, target_sw, target_hw, other = packed[:5]
    fields = [
        vendor,
        product,
        version,
        update,
        edition,
        language,
        sw_edition,
        target_sw,
        target_hw,
        other,
    ]
    return "cpe:2.3:" + part + ":" + ":".join(_encode_23(_decode_22(f)) for f in fields)


def split23(cpe23: str) -> list[str]:
    """Split a CPE 2.3 string on colons that are not escaped."""
    return re.split(r"(?<!\\):", cpe23)


def cpe_version(cpe23: str) -> str | None:
    fields = split23(cpe23)
    version = fields[5].replace("\\", "") if len(fields) > 5 else ""
    return version if VERSION_RE.match(version) else None


def vendor_product(cpe: str) -> str | None:
    """'vendor:product' from a 2.2 or 2.3 CPE."""
    cpe23 = cpe22_to_23(cpe)
    if not cpe23:
        return None
    fields = split23(cpe23)
    if len(fields) < 5:
        return None
    return f"{fields[3]}:{fields[4]}".replace("\\", "")


def with_vendor(cpe23: str, vendor: str) -> str:
    fields = split23(cpe23)
    fields[3] = vendor
    return ":".join(fields)


@dataclass
class Cve:
    cve_id: str
    cvss: float | None
    cvss_version: str | None
    published: str | None = None

    @property
    def cvss_label(self) -> str:
        if self.cvss is None:
            return "-"
        return f"{self.cvss:.1f} (v{self.cvss_version})"


@dataclass
class CpeResult:
    cpe: str  # the CPE nmap reported (2.3 form)
    queried: str  # the CPE sent to NVD, which differs if the vendor was mapped
    cves: list[Cve] = field(default_factory=list)
    note: str | None = None


def _cvss(metrics: dict) -> tuple[float | None, str | None]:
    """The newest CVSS version NVD has, preferring NVD's own (Primary) score."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entries = sorted(entries, key=lambda e: 0 if e.get("type") == "Primary" else 1)
        data = entries[0].get("cvssData", {})
        if "baseScore" in data:
            return float(data["baseScore"]), str(data.get("version", key[-2:]))
    return None, None


def parse_cves(payload: dict) -> list[Cve]:
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if not cve.get("id") or cve.get("vulnStatus") == "Rejected":
            continue
        score, version = _cvss(cve.get("metrics", {}))
        out.append(Cve(cve["id"], score, version, cve.get("published")))
    return out


class NvdClient:
    def __init__(
        self,
        cache: JsonCache,
        timeout: float = 30,
        delay_no_key: float = 6.0,
        delay_with_key: float = 0.6,
        fetch: Fetcher = fetch_json,
        sleep: Callable[[float], None] = time.sleep,
        api_key: str | None = None,
    ) -> None:
        self.cache = cache
        self.timeout = timeout
        # The key is read once and only ever sent in the apiKey header. Never printed.
        self._api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY") or None
        self.delay = delay_with_key if self._api_key else delay_no_key
        self.fetch = fetch
        self.sleep = sleep
        self._last = 0.0
        self.requests = 0

    @property
    def has_key(self) -> bool:
        return bool(self._api_key)

    def _get(self, url: str) -> dict:
        headers = {"apiKey": self._api_key} if self._api_key else None
        for attempt in range(4):
            wait = self.delay - (time.monotonic() - self._last)
            if self._last and wait > 0:
                self.sleep(wait)
            self._last = time.monotonic()
            self.requests += 1
            try:
                return self.fetch(url, self.timeout, headers)
            except FetchError as exc:
                if exc.status not in RETRY_STATUSES or attempt == 3:
                    raise
                # NVD answers 403 when the rate limit is hit; back off and try again.
                self.sleep(30 * (attempt + 1))
        raise FetchError("unreachable")

    def _cves(self, cpe23: str) -> list[Cve]:
        cached = self.cache.get("nvd-cves", cpe23)
        if cached is not None:
            return [Cve(**c) for c in cached]
        cves: list[Cve] = []
        start = 0
        while True:
            query = urllib.parse.urlencode(
                {"virtualMatchString": cpe23, "resultsPerPage": PAGE, "startIndex": start}
            )
            payload = self._get(f"{CVE_API}?{query}")
            cves += parse_cves(payload)
            total = int(payload.get("totalResults", 0))
            start += int(payload.get("resultsPerPage", PAGE)) or PAGE
            if start >= total:
                break
        self.cache.set("nvd-cves", cpe23, [c.__dict__ for c in cves])
        return cves

    def _vendors_for(self, cpe23: str) -> list[str]:
        fields = split23(cpe23)
        pattern = ":".join(fields[:3] + ["*"] + fields[4:6])
        cached = self.cache.get("nvd-cpes", pattern)
        if cached is None:
            query = urllib.parse.urlencode({"cpeMatchString": pattern, "resultsPerPage": 100})
            payload = self._get(f"{CPE_API}?{query}")
            cached = sorted(
                {
                    split23(p["cpe"]["cpeName"])[3]
                    for p in payload.get("products", [])
                    if p.get("cpe", {}).get("cpeName")
                }
            )
            self.cache.set("nvd-cpes", pattern, cached)
        return cached

    def lookup(self, cpe: str) -> CpeResult:
        """CVEs for one versioned CPE. Raises FetchError if NVD cannot be reached."""
        cpe23 = cpe22_to_23(cpe) or cpe
        result = CpeResult(cpe=cpe23, queried=cpe23, cves=self._cves(cpe23))
        if result.cves:
            return result
        vendors = self._vendors_for(cpe23)
        original = split23(cpe23)[3]
        if len(vendors) == 1 and vendors[0] != original:
            mapped = with_vendor(cpe23, vendors[0])
            result.queried = mapped
            result.cves = self._cves(mapped)
            result.note = f"NVD lists this product under vendor {vendors[0]}, not {original}"
        return result
