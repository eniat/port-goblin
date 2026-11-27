"""Parses nmap XML into models with defusedxml (imported files may come from anywhere)."""

from __future__ import annotations

from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

from portgoblin.core.models import Host, Port, ScanResult, Script, Service

MAX_XML_BYTES = 512 * 1024 * 1024


class NmapParseError(Exception):
    pass


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _scripts(parent: Element | None) -> list[Script]:
    if parent is None:
        return []
    return [
        Script(script_id=el.get("id", ""), output=el.get("output", ""))
        for el in parent.findall("script")
        if el.get("id")
    ]


def _service(el: Element | None) -> Service | None:
    if el is None:
        return None
    return Service(
        name=el.get("name"),
        product=el.get("product"),
        version=el.get("version"),
        extrainfo=el.get("extrainfo"),
        tunnel=el.get("tunnel"),
        method=el.get("method"),
        conf=_int(el.get("conf")),
        cpes=[c.text.strip() for c in el.findall("cpe") if c.text and c.text.strip()],
    )


def _port(el: Element) -> Port | None:
    portid = _int(el.get("portid"))
    protocol = el.get("protocol")
    state_el = el.find("state")
    if portid is None or not protocol or state_el is None or not state_el.get("state"):
        return None
    return Port(
        protocol=protocol,
        portid=portid,
        state=state_el.get("state", ""),
        reason=state_el.get("reason"),
        service=_service(el.find("service")),
        scripts=_scripts(el),
    )


def _host(el: Element) -> Host | None:
    address = None
    mac = None
    for addr in el.findall("address"):
        kind = addr.get("addrtype")
        if kind == "ipv4" and address is None:
            address = addr.get("addr")
        elif kind == "mac":
            mac = addr.get("addr")
    if not address:
        return None
    status_el = el.find("status")
    hostnames: list[str] = []
    user_hostnames: list[str] = []
    for name_el in el.findall("hostnames/hostname"):
        name = name_el.get("name")
        if not name:
            continue
        if name_el.get("type") == "user":
            user_hostnames.append(name)
        if name not in hostnames:
            hostnames.append(name)
    ports = [p for p in (_port(port_el) for port_el in el.findall("ports/port")) if p]
    return Host(
        address=address,
        status=status_el.get("state", "unknown") if status_el is not None else "unknown",
        status_reason=status_el.get("reason") if status_el is not None else None,
        mac=mac,
        hostnames=hostnames,
        user_hostnames=user_hostnames,
        ports=ports,
        scripts=_scripts(el.find("hostscript")),
    )


def repair_truncated(text: str) -> str | None:
    """Close the XML of an interrupted nmap run: keep complete hosts, drop the partial tail.

    nmap writes the closing tag only when a run finishes, so an interrupted -oA file is
    unclosed. Returns None if the text does not look like a truncated nmap run.
    """
    if "<nmaprun" not in text or "</nmaprun>" in text:
        return None
    cut = text.rfind("</host>")
    if cut != -1:
        return text[: cut + len("</host>")] + "\n</nmaprun>\n"
    start = text.find(">", text.find("<nmaprun"))
    if start == -1:
        return None
    return text[: start + 1] + "\n</nmaprun>\n"


def parse_xml_text(text: str, source: str = "<string>", tolerant: bool = False) -> ScanResult:
    """Parse nmap XML text. tolerant=True repairs files from interrupted runs."""
    try:
        root = fromstring(text)
    except (ParseError, DefusedXmlException) as exc:
        repaired = repair_truncated(text) if tolerant else None
        if repaired is None:
            raise NmapParseError(f"could not parse nmap output: {source} ({exc})") from exc
        try:
            root = fromstring(repaired)
        except (ParseError, DefusedXmlException) as exc2:
            raise NmapParseError(f"could not parse nmap output: {source} ({exc2})") from exc2
    if root.tag != "nmaprun":
        raise NmapParseError(f"could not parse nmap output: {source} (not an nmap XML file)")

    result = ScanResult(sources=[source])
    version = root.get("version")
    if version:
        result.nmap_versions.append(version)
    for host_el in root.findall("host"):
        host = _host(host_el)
        if host is None:
            continue
        if host.address in result.hosts:
            result.hosts[host.address].merge(host)
        else:
            result.hosts[host.address] = host
    return result


def parse_file(path: Path, tolerant: bool = False) -> ScanResult:
    try:
        if path.stat().st_size > MAX_XML_BYTES:
            raise NmapParseError(f"could not parse nmap output: {path} (file too large)")
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise NmapParseError(f"could not read nmap output: {path} ({exc.strerror})") from exc
    return parse_xml_text(text, source=str(path), tolerant=tolerant)


def is_complete(path: Path) -> bool:
    """True if an nmap XML file was closed, meaning that run finished."""
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - 4096))
            return b"</nmaprun>" in handle.read()
    except OSError:
        return False


def parse_many(paths: list[Path], tolerant: bool = False) -> ScanResult:
    """Parse and merge several files. Failures are recorded, not raised."""
    merged = ScanResult()
    for path in paths:
        try:
            merged.merge(parse_file(path, tolerant=tolerant))
        except NmapParseError as exc:
            merged.parse_errors.append(str(exc))
    return merged
