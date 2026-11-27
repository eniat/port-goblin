"""Version intelligence against real API responses saved in tests/fixtures/intel.

NVD, KEV, EPSS, endoflife.date and Metasploit fixtures are trimmed copies of live
responses (November 2026). The searchsploit fixtures are real Exploit-DB rows printed in
the JSON layout of searchsploit 4.2.1's source (searchsploit itself was not run).
"""

import asyncio
import json
from datetime import date
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from portgoblin.analysis.versions import LABEL, Sources, VersionIntel
from portgoblin.core.models import Host, Port, ScanResult, Service, Status
from portgoblin.intelligence.cache import FetchError, JsonCache
from portgoblin.intelligence.eol import EolIndex, load_eol
from portgoblin.intelligence.epss import epss_scores, parse_epss
from portgoblin.intelligence.exploitdb import ExploitDb, parse_searchsploit, search_terms
from portgoblin.intelligence.kev import load_kev, parse_kev
from portgoblin.intelligence.metasploit import MetasploitIndex
from portgoblin.intelligence.nvd import (
    NvdClient,
    cpe22_to_23,
    cpe_version,
    parse_cves,
    vendor_product,
)

INTEL = Path(__file__).parent / "fixtures" / "intel"


def load(name):
    return json.loads((INTEL / name).read_text())


# CPE conversion


@pytest.mark.parametrize(
    ("cpe22", "cpe23"),
    [
        ("cpe:/a:vsftpd:vsftpd:2.3.4", "cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*"),
        ("cpe:/a:openbsd:openssh:8.9p1", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"),
        ("cpe:/o:linux:linux_kernel", "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"),
        ("cpe:/a:x:x.org_x11", "cpe:2.3:a:x:x.org_x11:*:*:*:*:*:*:*:*"),
        ("cpe:/a:foo:bar%21:1.0", "cpe:2.3:a:foo:bar\\!:1.0:*:*:*:*:*:*:*"),
        (
            "cpe:/a:vendor:product:1.0:sp1:~ed~sw~tsw~thw~oth",
            "cpe:2.3:a:vendor:product:1.0:sp1:ed:*:sw:tsw:thw:oth",
        ),
    ],
)
def test_cpe22_to_23(cpe22, cpe23):
    assert cpe22_to_23(cpe22) == cpe23


def test_cpe_version_rejects_ranges_and_missing_versions():
    assert cpe_version(cpe22_to_23("cpe:/a:openbsd:openssh:8.9p1")) == "8.9p1"
    assert cpe_version(cpe22_to_23("cpe:/a:openldap:openldap")) is None
    assert cpe_version(cpe22_to_23("cpe:/a:openldap:openldap:2.2.X - 2.3.X")) is None
    assert vendor_product("cpe:/a:igor_sysoev:nginx:1.18.0") == "igor_sysoev:nginx"


# NVD


def test_parse_cves_picks_newest_cvss_published():
    cves = {c.cve_id: c for c in parse_cves(load("nvd_vsftpd_project_2.3.4.json"))}
    assert set(cves) == {"CVE-2011-2523", "CVE-2015-1419", "CVE-2021-3618"}
    assert cves["CVE-2011-2523"].cvss == 9.8 and cves["CVE-2011-2523"].cvss_version == "3.1"
    assert cves["CVE-2011-2523"].cvss_label == "9.8 (v3.1)"


class FakeFetch:
    """Answers NVD URLs from the saved responses."""

    def __init__(self, fail_first: int | None = None):
        self.urls = []
        self.headers = []
        self.fail_first = fail_first

    def __call__(self, url, timeout, headers):
        self.urls.append(url)
        self.headers.append(headers)
        if self.fail_first and len(self.urls) <= 1:
            raise FetchError("HTTP 403", self.fail_first)
        query = parse_qs(urlparse(url).query)
        if "cpeMatchString" in query:
            return load("nvd_cpes_wildcard_vsftpd_2.3.4.json")
        match = query["virtualMatchString"][0]
        return {
            "cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*": load(
                "nvd_vsftpd_vsftpd_2.3.4_empty.json"
            ),
            "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*": load(
                "nvd_vsftpd_project_2.3.4.json"
            ),
            "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*": load("nvd_openssh_8.9p1.json"),
        }[match]


def nvd(tmp_path, fetch, key=""):
    waits = []
    client = NvdClient(
        JsonCache(tmp_path, 24), fetch=fetch, sleep=waits.append, api_key=key, delay_no_key=6
    )
    return client, waits


def test_nvd_maps_vendor_when_nmap_and_nvd_disagree(tmp_path):
    fetch = FakeFetch()
    client, _ = nvd(tmp_path, fetch)
    result = client.lookup("cpe:/a:vsftpd:vsftpd:2.3.4")
    assert {c.cve_id for c in result.cves} == {"CVE-2011-2523", "CVE-2015-1419", "CVE-2021-3618"}
    assert result.queried.startswith("cpe:2.3:a:vsftpd_project:vsftpd:2.3.4")
    assert "vsftpd_project" in result.note
    assert len(fetch.urls) == 3
    assert "virtualMatchString" in fetch.urls[0] and "cpeMatchString" in fetch.urls[1]


def test_nvd_results_are_cached(tmp_path):
    fetch = FakeFetch()
    client, _ = nvd(tmp_path, fetch)
    client.lookup("cpe:/a:openbsd:openssh:8.9p1")
    client.lookup("cpe:/a:openbsd:openssh:8.9p1")
    assert len(fetch.urls) == 1
    fresh, _ = nvd(tmp_path, FakeFetch())
    assert len(fresh.lookup("cpe:/a:openbsd:openssh:8.9p1").cves) == 33


def test_nvd_cache_expires(tmp_path):
    now = [1000.0]
    cache = JsonCache(tmp_path, 24, clock=lambda: now[0])
    cache.set("nvd-cves", "k", [])
    assert cache.get("nvd-cves", "k") == []
    now[0] += 25 * 3600
    assert cache.get("nvd-cves", "k") is None
    assert cache.get("nvd-cves", "k", allow_stale=True) == []


def test_nvd_rate_limit_without_key_and_header_with_key(tmp_path):
    fetch = FakeFetch()
    client, waits = nvd(tmp_path, fetch)
    client.lookup("cpe:/a:vsftpd:vsftpd:2.3.4")
    assert waits and all(5.9 < w <= 6 for w in waits)
    assert fetch.headers[0] is None

    keyed_fetch = FakeFetch()
    keyed, _ = nvd(tmp_path / "k", keyed_fetch, key="secret-key-value")
    assert keyed.delay == 0.6 and keyed.has_key
    keyed.lookup("cpe:/a:openbsd:openssh:8.9p1")
    assert keyed_fetch.headers[0] == {"apiKey": "secret-key-value"}
    assert "secret-key-value" not in repr(keyed.__dict__.get("delay"))


def test_nvd_retries_after_rate_limit(tmp_path):
    fetch = FakeFetch(fail_first=403)
    client, waits = nvd(tmp_path, fetch)
    assert len(client.lookup("cpe:/a:openbsd:openssh:8.9p1").cves) == 33
    assert 30 in waits


# KEV and EPSS


def test_kev_real_feed_sample():
    catalogue = parse_kev(load("kev_sample.json"))
    assert catalogue.version == "2026.11.25"
    assert catalogue.get("CVE-2026-123158") is not None
    assert catalogue.get("CVE-2011-2523") is None


def test_kev_falls_back_to_stale_copy(tmp_path):
    now = [0.0]
    cache = JsonCache(tmp_path, 24, clock=lambda: now[0])
    load_kev(cache, fetch=lambda url, t, h: load("kev_sample.json"))
    now[0] += 48 * 3600

    def offline(url, t, h):
        raise FetchError("no route")

    catalogue = load_kev(cache, fetch=offline)
    assert catalogue.stale and catalogue.get("CVE-2026-123158")
    with pytest.raises(FetchError):
        load_kev(JsonCache(tmp_path / "empty", 24), fetch=offline)


def test_epss_real_sample_and_cache(tmp_path):
    assert parse_epss(load("epss_sample.json"))["CVE-2011-2523"] == pytest.approx(0.97675)
    calls = []

    def fetch(url, t, h):
        calls.append(url)
        return load("epss_sample.json")

    cache = JsonCache(tmp_path, 24)
    cves = ["CVE-2011-2523", "CVE-2024-6387", "CVE-1999-9999"]
    scores = epss_scores(cves, cache, fetch=fetch)
    assert set(scores) == {"CVE-2011-2523", "CVE-2024-6387"}  # unknown CVEs are left out
    epss_scores(cves, cache, fetch=fetch)
    assert len(calls) == 1


# Exploit-DB


def test_searchsploit_json_layout():
    found = parse_searchsploit((INTEL / "searchsploit_vsftpd_2.3.4.json").read_text())
    assert {e.edb_id for e in found} == {"17491", "49757"}
    assert all("CVE-2011-2523" in e.codes for e in found)
    assert parse_searchsploit((INTEL / "searchsploit_empty.json").read_text()) == []


def test_searchsploit_broken_json_falls_back_to_fields():
    text = (INTEL / "searchsploit_vsftpd_2.3.4.json").read_text()
    broken = text.replace("Backdoor Command Execution (Metasploit)", 'Backdoor "quoted", title')
    with pytest.raises(json.JSONDecodeError):
        json.loads(broken)
    found = parse_searchsploit(broken)
    assert {e.edb_id for e in found} == {"17491", "49757"}


def test_search_terms():
    assert search_terms("vsftpd", "2.3.4") == ["vsftpd", "2.3.4"]
    assert search_terms("OpenSSH", "8.9p1 Ubuntu 3ubuntu0.6") == ["OpenSSH", "8.9p1"]
    assert search_terms("Apache httpd", "2.4.41") == ["Apache", "2.4.41"]
    assert search_terms("Microsoft IIS httpd", "10.0") == ["Microsoft", "IIS", "10.0"][:2] + [
        "10.0"
    ]


def fake_searchsploit():
    calls = []

    async def runner(cmd):
        calls.append(cmd)
        if "--cve" in cmd and cmd[-1] == "CVE-2011-2523":
            return 0, (INTEL / "searchsploit_cve_2011-2523.json").read_text(), ""
        if cmd[-2:] == ["vsftpd", "2.3.4"]:
            return 0, (INTEL / "searchsploit_vsftpd_2.3.4.json").read_text(), ""
        return 0, (INTEL / "searchsploit_empty.json").read_text(), ""

    return ExploitDb("/usr/bin/searchsploit", runner), calls


def test_exploitdb_by_cve_and_product():
    edb, calls = fake_searchsploit()
    assert {e.edb_id for e in asyncio.run(edb.by_cve("CVE-2011-2523"))} == {"17491", "49757"}
    assert calls[0] == ["/usr/bin/searchsploit", "--json", "--cve", "CVE-2011-2523"]
    asyncio.run(edb.by_cve("CVE-2011-2523"))
    assert len(calls) == 1


# Metasploit and end of life


def test_metasploit_index_from_real_metadata_sample():
    index = MetasploitIndex.load(INTEL / "msf_modules_metadata_sample.json")
    assert index.modules("CVE-2011-2523") == ["exploit/unix/ftp/vsftpd_234_backdoor"]
    assert index.modules("CVE-1999-0001") == []


def eol_index():
    return EolIndex(
        load("eol_products_full_sample.json")["result"],
        {"igor_sysoev:nginx": "nginx", "samba:samba": "samba"},
    )


def test_eol_by_cpe_identifier_and_alias():
    index = eol_index()
    openssl = index.check("cpe:/a:openssl:openssl:1.0.2k", "1.0.2k", date(2026, 11, 27))
    assert openssl.cycle == "1.0.2" and openssl.is_eol
    nginx = index.check("cpe:/a:igor_sysoev:nginx:1.18.0", "1.18.0", date(2026, 11, 27))
    assert nginx.product == "nginx" and nginx.cycle == "1.18" and nginx.is_eol
    assert index.check("cpe:/a:vsftpd:vsftpd:2.3.4", "2.3.4") is None


def test_eol_cycle_prefix_rule():
    releases = [{"name": "1.1.1"}, {"name": "1.1"}, {"name": "1.0.2"}]
    assert EolIndex.cycle_for(releases, "1.1.1w")["name"] == "1.1.1"
    assert EolIndex.cycle_for(releases, "1.1.10")["name"] == "1.1"
    assert EolIndex.cycle_for(releases, "1.0.20") is None


def test_eol_loader_caches(tmp_path):
    calls = []

    def fetch(url, t, h):
        calls.append(url)
        return load("eol_products_full_sample.json")

    cache = JsonCache(tmp_path, 24)
    load_eol(cache, {}, fetch=fetch)
    load_eol(cache, {}, fetch=fetch)
    assert calls == ["https://endoflife.date/api/v1/products/full"]


# End to end with saved responses


def scan_result():
    ports = [
        Port(
            protocol="tcp",
            portid=21,
            state="open",
            service=Service(
                name="ftp", product="vsftpd", version="2.3.4", cpes=["cpe:/a:vsftpd:vsftpd:2.3.4"]
            ),
        ),
        Port(
            protocol="tcp",
            portid=22,
            state="open",
            service=Service(
                name="ssh",
                product="OpenSSH",
                version="8.9p1 Ubuntu 3ubuntu0.6",
                cpes=["cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"],
            ),
        ),
        Port(protocol="tcp", portid=443, state="open", service=Service(name="https")),
    ]
    host = Host(address="10.0.0.12", status="up", status_reason="syn-ack", ports=ports)
    return ScanResult(hosts={host.address: host})


def sources(tmp_path, edb=True, msf=True):
    cache = JsonCache(tmp_path, 24)
    client, _ = nvd(tmp_path / "nvd", FakeFetch())
    return Sources(
        nvd=client,
        kev=lambda: parse_kev(load("kev_sample.json")),
        epss=lambda cves: epss_scores(cves, cache, fetch=lambda u, t, h: load("epss_sample.json")),
        eol=eol_index,
        exploitdb=fake_searchsploit()[0] if edb else None,
        metasploit=(
            (lambda: MetasploitIndex.load(INTEL / "msf_modules_metadata_sample.json"))
            if msf
            else None
        ),
        today=date(2026, 11, 27),
    )


def test_version_intelligence_end_to_end(tmp_path):
    result = asyncio.run(VersionIntel(sources(tmp_path)).run(scan_result()))
    rows = {r.target: r for r in result.rows}
    vsftpd = rows["10.0.0.12:21"]
    assert len(vsftpd.cves) == 3 and vsftpd.metasploit_count == 1 and vsftpd.exploit_count == 2
    assert vsftpd.max_epss == pytest.approx(0.97675)
    assert any("vsftpd_project" in n for n in vsftpd.notes)
    ssh = rows["10.0.0.12:22"]
    assert ssh.kev_count == 1 and ssh.cves[0].cve_id == "CVE-2026-123158"  # KEV sorted first
    assert any("Ubuntu" in n for n in ssh.notes)

    by_id = {f.finding_id: f for f in result.findings}
    highlighted = [f for f in result.findings if f.finding_id.startswith("VER-")]
    assert {f.status for f in highlighted} == {Status.MANUAL_CHECK}
    titles = " ".join(f.title for f in highlighted)
    assert "KEV-listed CVE" in titles and "Metasploit module" in titles
    assert all(LABEL in f.observed for f in highlighted)
    assert all(f.reproduce and f.manual_steps for f in highlighted)
    no_version = by_id["NA-intel-cve-check"]
    assert no_version.observed == "Not assessed: CVE check not possible: no version detected"
    assert no_version.hosts == ["10.0.0.12:443"]


def test_missing_tools_are_not_assessed_with_install_commands(tmp_path):
    result = asyncio.run(VersionIntel(sources(tmp_path, edb=False, msf=False)).run(scan_result()))
    text = " ".join(f.observed for f in result.findings if f.status is Status.NOT_ASSESSED)
    assert "sudo apt install exploitdb" in text
    assert "sudo apt install metasploit-framework" in text


def test_nvd_offline_stops_and_reports(tmp_path):
    calls = []

    def offline(url, t, h):
        calls.append(url)
        raise FetchError("Name or service not known")

    src = sources(tmp_path)
    src.nvd = NvdClient(JsonCache(tmp_path / "x", 24), fetch=offline, sleep=lambda s: None)
    result = asyncio.run(VersionIntel(src).run(scan_result()))
    assert len(calls) == 1
    assert any("NVD not reachable" in (f.observed or "") for f in result.findings)
    # Without NVD there are no CVEs; Exploit-DB title matches still show as possible matches.
    assert all(not r.cves for r in result.rows)
    assert result.rows[0].possible_exploits


def test_eol_uses_vendor_nvd_mapped_to(tmp_path):
    """Live nmap -sV reports Redis only as redislabs:redis; endoflife.date lists redis:redis."""
    port = Port(
        protocol="tcp",
        portid=6379,
        state="open",
        service=Service(
            name="redis",
            product="Redis key-value store",
            version="7.0.15",
            cpes=["cpe:/a:redislabs:redis:7.0.15"],
        ),
    )
    host = Host(address="127.0.0.1", status="up", status_reason="syn-ack", ports=[port])

    class MappedNvd:
        def lookup(self, cpe):
            from portgoblin.intelligence.nvd import CpeResult

            return CpeResult(
                cpe=cpe,
                queried="cpe:2.3:a:redis:redis:7.0.15:*:*:*:*:*:*:*",
                note="NVD lists this product under vendor redis, not redislabs",
            )

    src = sources(tmp_path)
    src.nvd = MappedNvd()
    result = asyncio.run(VersionIntel(src).run(ScanResult(hosts={host.address: host})))
    (row,) = result.rows
    assert row.eol.startswith("Redis 7.0 ended 2024-07-29")
    assert any(f.finding_id == "EOL-001" for f in result.findings)
