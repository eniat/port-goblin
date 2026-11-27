"""Check parsers against real tool output captured in a lab (tests/fixtures/checks), and
against hand-written fixtures copied from nmap's own @output examples where a service could
not be run (crafted_from_nsedoc.xml)."""

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from portgoblin.checks import base as cb
from portgoblin.checks.cleartext import RServicesExposed, TelnetExposed, TftpExposed
from portgoblin.checks.databases import (
    ElasticsearchUnauthenticated,
    MongoDbUnauthenticated,
    RedisUnauthenticated,
)
from portgoblin.checks.docker import DockerApiUnauthenticated
from portgoblin.checks.ftp import FtpAnonymous
from portgoblin.checks.ipmi import IpmiCipherZero
from portgoblin.checks.ldap import LdapAnonymous
from portgoblin.checks.nfs import NfsExports
from portgoblin.checks.rdp import RdpNla
from portgoblin.checks.remote_display import VncNoAuth, X11Open
from portgoblin.checks.rsync import RsyncModules
from portgoblin.checks.smb import SmbNullGuest, SmbSigning, SmbV1, parse_netexec, parse_smbclient
from portgoblin.checks.snmp import SnmpPublic
from portgoblin.checks.ssh import SshAlgorithms
from portgoblin.checks.tls import TlsCheck
from portgoblin.core.models import Status, group_findings
from portgoblin.core.nmap_parser import parse_file

CHECKS = Path(__file__).parent / "fixtures" / "checks"


def host_of(name, address="127.0.0.1"):
    return parse_file(CHECKS / name).hosts[address]


def results_for(host, ran=()):
    results = cb.ScriptResults()
    for port in host.ports:
        results.ports[port.key] = {s.script_id: s.output for s in port.scripts}
    results.host = {s.script_id: s.output for s in host.scripts}
    results.ran = {s.script_id for p in host.ports for s in p.scripts} | set(ran)
    results.ran |= set(results.host)
    return results


def run(check, host, ran=()):
    ports = check.ports(host)
    # The runner only calls a check for hosts with matching ports.
    return check.evaluate(host, ports, results_for(host, ran)) if ports else []


def by_status(findings):
    return {(f.finding_id, f.status) for f in findings}


def test_ftp_anonymous_real_vsftpd():
    host = host_of("ftp_anon.xml")
    (finding,) = run(FtpAnonymous(), host)
    assert finding.status is Status.ISSUE
    assert "backup.zip, pub, readme.txt" in finding.observed
    assert finding.reproduce[0] == "nmap -Pn -sV --script ftp-anon -p 21 127.0.0.1"


def test_ftp_anonymous_refused_real_vsftpd():
    host = host_of("ftp_noanon.xml")
    (finding,) = run(FtpAnonymous(), host, ran=["ftp-anon"])
    assert finding.status is Status.OK


def test_ssh_weak_and_strong_real_openssh():
    host = host_of("ssh.xml")
    findings = {hp: f for f in run(SshAlgorithms(), host) for hp in f.hosts}
    weak = findings["127.0.0.1:2223"]
    assert weak.status is Status.ISSUE
    for name in (
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "ssh-rsa",
        "aes128-cbc",
        "3des-cbc",
        "hmac-md5",
    ):
        assert name in weak.observed
    assert "hmac-sha1" not in weak.observed.replace("group14-sha1", "").replace("exchange-sha1", "")
    # OpenSSH defaults (which include hmac-sha1 and umac-64) are not flagged.
    assert findings["127.0.0.1:2222"].status is Status.OK


def test_smb_weak_samba_real():
    host = host_of("smb_weak_nmap.xml")
    (signing,) = run(SmbSigning(), host)
    (v1,) = run(SmbV1(), host)
    assert signing.status is Status.ISSUE and "enabled but not required" in signing.observed
    assert "message_signing disabled" in signing.observed
    assert v1.status is Status.ISSUE and "NT LM 0.12 (SMBv1)" in v1.observed
    assert signing.hosts == ["127.0.0.1:445"]


def test_smb_hardened_samba_real():
    host = host_of("smb_strong_nmap.xml")
    (signing,) = run(SmbSigning(), host)
    (v1,) = run(SmbV1(), host)
    assert signing.status is Status.OK and v1.status is Status.OK


def test_netexec_output_real():
    auth, shares, error = parse_netexec((CHECKS / "smb_weak_nxc_null.txt").read_text())
    assert auth is True and error is None
    assert shares == [("public", "READ"), ("finance", ""), ("IPC$", "")]
    auth, shares, error = parse_netexec((CHECKS / "smb_weak_nxc_guest.txt").read_text())
    assert auth is True and shares == [] and "STATUS_ACCESS_DENIED" in error
    auth, shares, error = parse_netexec((CHECKS / "smb_strong_nxc_guest.txt").read_text())
    assert auth is False and "STATUS_LOGON_FAILURE" in error


def test_netexec_help_real_has_acl_share_check():
    assert "--file-write-check" in (CHECKS / "netexec_1.5.1_smb_help.txt").read_text()


def test_smbclient_output_real():
    listed, shares, _ = parse_smbclient((CHECKS / "smb_weak_smbclient_null.txt").read_text())
    assert listed and shares == ["public", "finance", "IPC$"]
    listed, shares, error = parse_smbclient((CHECKS / "smb_strong_smbclient_null.txt").read_text())
    assert not listed and error == "NT_STATUS_ACCESS_DENIED"


class FakeContext:
    def __init__(self, tools=None, outputs=None, safe=True, http=None):
        self.tools = tools or {}
        self.outputs = outputs or {}
        self.safe = safe
        self.http = http or {}
        self.commands = []
        self.urls = []
        self.is_root = True

    def tool(self, name):
        return self.tools.get(name)

    def netexec_safe(self, path):
        return self.safe

    async def run_tool(self, check, target, cmd):
        self.commands.append(cmd)
        user = cmd[cmd.index("-u") + 1] if "-u" in cmd else None
        key = {"": "null", "guest": "guest", "guest%": "guest"}.get(user, "null")
        return cb.ToolResult(0, self.outputs.get(key, ""), "")

    async def http_get(self, check, target, url):
        self.urls.append(url)
        return self.http.get(url, cb.HttpResult(None, error="refused"))

    def record(self, record):
        pass


def smb_host():
    return host_of("smb_weak_nmap.xml")


def test_smb_null_guest_with_netexec():
    ctx = FakeContext(
        tools={"netexec": "/usr/bin/netexec"},
        outputs={
            "null": (CHECKS / "smb_weak_nxc_null.txt").read_text(),
            "guest": (CHECKS / "smb_weak_nxc_guest.txt").read_text(),
        },
    )
    host = smb_host()
    findings = asyncio.run(SmbNullGuest().run(ctx, host, SmbNullGuest().ports(host)))
    assert by_status(findings) == {("SMB-003", Status.ISSUE), ("SMB-004", Status.OBSERVATION)}
    assert "public (READ)" in findings[0].observed
    # One null and one guest attempt, empty passwords, never anything else.
    assert len(ctx.commands) == 2
    assert all(c[c.index("-p") + 1] == "" for c in ctx.commands)
    assert all("--file-write-check" not in c for c in ctx.commands)


def test_smb_unsafe_netexec_falls_back_to_smbclient():
    ctx = FakeContext(
        tools={"netexec": "/usr/bin/netexec", "smbclient": "/usr/bin/smbclient"},
        outputs={"null": (CHECKS / "smb_weak_smbclient_null.txt").read_text()},
        safe=False,
    )
    host = smb_host()
    findings = asyncio.run(SmbNullGuest().run(ctx, host, SmbNullGuest().ports(host)))
    assert all(c[0] == "/usr/bin/smbclient" for c in ctx.commands)
    assert ctx.commands[0][:3] == ["/usr/bin/smbclient", "-N", "-L"]
    assert findings[0].status is Status.ISSUE


def test_smb_no_tools_not_assessed_with_install_command():
    host = smb_host()
    (finding,) = asyncio.run(SmbNullGuest().run(FakeContext(), host, SmbNullGuest().ports(host)))
    assert finding.status is Status.NOT_ASSESSED
    assert "sudo apt install netexec" in finding.observed


def test_redis_real():
    host = host_of("redis.xml")
    findings = {f.hosts[0]: f for f in run(RedisUnauthenticated(), host, ran=["redis-info"])}
    assert findings["127.0.0.1:6379"].status is Status.ISSUE
    assert "7.0.15" in findings["127.0.0.1:6379"].observed
    assert findings["127.0.0.1:6380"].status is Status.OK


def test_rsync_modern_server_is_manual_check():
    host = host_of("rsync.xml")
    (finding,) = run(RsyncModules(), host, ran=["rsync-list-modules"])
    assert finding.status is Status.MANUAL_CHECK and finding.manual_steps
    assert finding.reproduce == ["rsync rsync://127.0.0.1:873/  (lists module names only)"]


def test_rsync_modules_listed():
    host = host_of("rsync.xml")
    results = results_for(host, ran=["rsync-list-modules"])
    results.ports[("tcp", 873)] = {"rsync-list-modules": "\n  backups\tNightly backups\n  www"}
    (finding,) = RsyncModules().evaluate(host, RsyncModules().ports(host), results)
    assert finding.status is Status.OBSERVATION and "backups, www" in finding.observed


def test_snmp_public_real():
    host = host_of("snmp.xml")
    findings = run(SnmpPublic(), host)
    assert [f.status for f in findings] == [Status.ISSUE]
    assert "Linux fs01 6.8.0 test" in findings[0].observed
    assert "snmpcommunity=public" in findings[0].reproduce[0]


def test_snmp_only_on_confirmed_open():
    host = host_of("snmp.xml")
    assert [p.portid for p in SnmpPublic().ports(host)] == [161]


def test_ldap_anonymous_real():
    host = host_of("ldap_anon.xml")
    findings = run(LdapAnonymous(), host)
    assert by_status(findings) == {("LDAP-001", Status.ISSUE), ("LDAP-002", Status.OBSERVATION)}
    assert "dc=nodomain" in findings[0].observed


def test_ldap_refused_real():
    host = host_of("ldap_noanon.xml")
    findings = run(LdapAnonymous(), host, ran=["ldap-rootdse", "ldap-search"])
    assert by_status(findings) == {("LDAP-001", Status.OK)}


def test_vnc_real():
    host = host_of("vnc_x11.xml")
    findings = {f.hosts[0]: f for f in run(VncNoAuth(), host)}
    assert findings["127.0.0.1:5900"].status is Status.ISSUE
    assert findings["127.0.0.1:5901"].status is Status.OK


def test_x11_from_version_detection_real():
    host = host_of("vnc_x11.xml")
    findings = run(X11Open(), host)
    assert {f.status for f in findings} == {Status.ISSUE}
    assert len(group_findings(findings)[0].hosts) == 2


def test_tls_real_modern_and_tls10():
    host = host_of("tls.xml")
    check = TlsCheck(now=datetime(2026, 12, 1, tzinfo=UTC))
    findings = run(check, host)
    statuses = {(f.finding_id, f.hosts[0], f.status) for f in findings}
    assert ("TLS-001", "127.0.0.1:8443", Status.OK) in statuses
    assert ("TLS-001", "127.0.0.1:9443", Status.ISSUE) in statuses
    assert ("TLS-002", "127.0.0.1:9443", Status.ISSUE) in statuses
    assert ("TLS-004", "127.0.0.1:8443", Status.OBSERVATION) in statuses
    assert not any(f.finding_id == "TLS-003" for f in findings)


def test_tls_expired_and_weak_certificate():
    host = parse_file(CHECKS / "crafted_from_nsedoc.xml").hosts["10.0.0.31"]
    findings = run(TlsCheck(now=datetime(2026, 11, 27, tzinfo=UTC)), host)
    ids = {f.finding_id: f for f in findings}
    assert ids["TLS-003"].status is Status.ISSUE and "2020-01-01" in ids["TLS-003"].observed
    assert "RSA 1024-bit key" in ids["TLS-005"].observed
    assert "sha1WithRSAEncryption" in ids["TLS-005"].observed


def crafted(address):
    return parse_file(CHECKS / "crafted_from_nsedoc.xml").hosts[address]


def test_rdp_nla():
    (open_rdp,) = run(RdpNla(), crafted("10.0.0.30"))
    assert open_rdp.status is Status.ISSUE and "Native RDP, SSL, RDSTLS" in open_rdp.observed
    (nla,) = run(RdpNla(), crafted("10.0.0.31"))
    assert nla.status is Status.OK


def test_nfs_exports():
    (finding,) = run(NfsExports(), crafted("10.0.0.30"))
    assert finding.status is Status.ISSUE
    assert "/home/storage/backup allowed 10.46.200.0/255.255.255.0" in finding.observed


def test_mongodb_names_only():
    (finding,) = run(MongoDbUnauthenticated(), crafted("10.0.0.30"))
    assert finding.status is Status.ISSUE
    assert "test, httpstorage, local, admin" in finding.observed
    assert "sizeOnDisk" not in finding.observed


def test_ipmi():
    findings = run(IpmiCipherZero(), crafted("10.0.0.30"))
    assert by_status(findings) == {("IPMI-001", Status.ISSUE), ("IPMI-002", Status.OBSERVATION)}


def test_cleartext_presence_only():
    host = crafted("10.0.0.31")
    (telnet,) = run(TelnetExposed(), host)
    assert telnet.status is Status.ISSUE and telnet.hosts == ["10.0.0.31:23"]
    (x11,) = run(X11Open(), host)
    assert x11.status is Status.OK
    other = crafted("10.0.0.32")
    (tftp,) = run(TftpExposed(), other)
    assert tftp.status is Status.MANUAL_CHECK and tftp.manual_steps
    (rlogin,) = run(RServicesExposed(), other)
    assert "rlogin" in rlogin.observed


def es_host():
    from portgoblin.core.models import Host, Port, Service

    return Host(
        address="10.0.0.40",
        status="up",
        ports=[
            Port(protocol="tcp", portid=9200, state="open", service=Service(name="http")),
            Port(protocol="tcp", portid=2375, state="open", service=Service(name="docker")),
            Port(
                protocol="tcp",
                portid=2376,
                state="open",
                service=Service(name="docker", tunnel="ssl"),
            ),
        ],
    )


def test_elasticsearch_unauthenticated_lists_index_names_only():
    body = b'{"name":"n1","cluster_name":"c","version":{"number":"8.12.0"}}'
    ctx = FakeContext(
        http={
            "http://10.0.0.40:9200/": cb.HttpResult(200, body),
            "http://10.0.0.40:9200/_cat/indices?h=index": cb.HttpResult(200, b"logs\ncustomers\n"),
        }
    )
    host = es_host()
    (finding,) = asyncio.run(
        ElasticsearchUnauthenticated().run(ctx, host, ElasticsearchUnauthenticated().ports(host))
    )
    assert finding.status is Status.ISSUE
    assert "version 8.12.0" in finding.observed and "customers, logs" in finding.observed
    assert ctx.urls == ["http://10.0.0.40:9200/", "http://10.0.0.40:9200/_cat/indices?h=index"]


def test_elasticsearch_auth_required():
    ctx = FakeContext(http={"http://10.0.0.40:9200/": cb.HttpResult(401, b"")})
    host = es_host()
    (finding,) = asyncio.run(
        ElasticsearchUnauthenticated().run(ctx, host, ElasticsearchUnauthenticated().ports(host))
    )
    assert finding.status is Status.OK and len(ctx.urls) == 1


def test_docker_api():
    ctx = FakeContext(
        http={
            "http://10.0.0.40:2375/version": cb.HttpResult(
                200, b'{"Version":"24.0.7","ApiVersion":"1.43","Os":"linux"}'
            ),
            "https://10.0.0.40:2376/version": cb.HttpResult(
                None, error="tlsv13 alert certificate required"
            ),
        }
    )
    host = es_host()
    findings = asyncio.run(
        DockerApiUnauthenticated().run(ctx, host, DockerApiUnauthenticated().ports(host))
    )
    assert [(f.hosts[0], f.status) for f in findings] == [
        ("10.0.0.40:2375", Status.ISSUE),
        ("10.0.0.40:2376", Status.OK),
    ]


def test_same_finding_grouped_across_hosts():
    findings = []
    for address in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        host = host_of("smb_weak_nmap.xml").model_copy(update={"address": address})
        findings += run(SmbSigning(), host)
    (grouped,) = group_findings(findings)
    assert grouped.hosts == ["10.0.0.1:445", "10.0.0.2:445", "10.0.0.3:445"]
    assert len(grouped.observed.splitlines()) == 3


@pytest.mark.parametrize("check", [FtpAnonymous(), SshAlgorithms(), SmbSigning(), TlsCheck()])
def test_issues_always_have_a_reproduce_command(check):
    for name in ("ftp_anon.xml", "ssh.xml", "smb_weak_nmap.xml", "tls.xml"):
        host = host_of(name)
        for finding in run(check, host):
            if finding.status in (Status.ISSUE, Status.MANUAL_CHECK):
                assert finding.reproduce
