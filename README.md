# PortGoblin

Knocking on every door.

By Taine ([github.com/eniat](https://github.com/eniat)). MIT licence.

## Install on Kali

- External tools (nmap is required, the rest are used when present):

```bash
sudo apt install nmap exploitdb metasploit-framework netexec smbclient
```

- PortGoblin itself (Python 3.11 or later):

```bash
pipx install ./PortGoblin
```

- Scanning needs root for `-sS` and `-sU`. pipx installs to `~/.local/bin`, which is not on sudo's path, so call it by full path:

```bash
sudo "$(command -v portgoblin)" scan 10.0.0.0/24 --internal
```

- sudo drops most environment variables. To pass an NVD API key through:

```bash
sudo --preserve-env=NVD_API_KEY "$(command -v portgoblin)" scan 10.0.0.0/24 --internal
```

- Run state lives in `~/.local/share/portgoblin/runs/` and the cache in `~/.cache/portgoblin/` (or `$XDG_DATA_HOME` and `$XDG_CACHE_HOME`). Under sudo these follow `$HOME` as sudo sets it; `sudo sh -c 'echo $HOME'` shows where.
- Check the set-up:

```bash
portgoblin doctor
```

- Tested with nmap 7.94SVN, netexec 1.5.1, smbclient 4.19.5, Python 3.11 and 3.13. Built and tested on Ubuntu 24.04, not on Kali itself.

## Usage

```bash
portgoblin scan 10.0.0.0/24 --internal
portgoblin scan -f targets.txt --external --exclude-file exclude.txt
portgoblin scan 203.0.113.0/28 --external --tcp-only
portgoblin scan 10.0.0.0/24 --internal --udp-only --top-udp 100
portgoblin scan 10.0.0.0/24 --internal --rate 500
portgoblin scan 10.0.0.0/24 --internal --no-checks --no-intel
portgoblin scan 10.0.0.0/24 --internal --save results.txt --keep-raw ./evidence --yes
portgoblin import tcp.xml udp.xml
portgoblin runs
portgoblin resume <run-id>
portgoblin doctor
portgoblin update
portgoblin --version
```

### Options

| Option | Effect |
|---|---|
| `--internal` / `--external` | Required on every scan, exactly one. No auto-detection. |
| `-f FILE` | Targets from a file: one or more per line, comma or space separated, `#` comments. |
| `--exclude TARGETS`, `--exclude-file FILE` | Never scanned. Removed from the target list and also passed to nmap as `--excludefile` as a second guard. |
| `--tcp-only`, `--udp-only` | Skip the other protocol. |
| `--top-udp N` | Top UDP ports (default 200). |
| `--rate PPS` | `--min-rate` for the full TCP scan (default 300 internal, 100 external). |
| `--no-checks` | Skip follow-up checks. |
| `--no-intel` | Skip version intelligence, for offline use. |
| `--save FILE` | Also write the report as plain text (no ANSI). Asks before overwriting; with `--yes` an existing file stops the run before any traffic. |
| `--keep-raw DIR` | Copy the raw nmap files there before the working directory is deleted. |
| `-y`, `--yes` | Skip `Proceed? [y/N]`. |
| `-v`, `--verbose` | Every port per host, every CVE, all observed lines and the log of what each check sent. |
| `--no-color` | Plain output. |
| `--config FILE` | Config file (see Configuration). |

### Targets

- IPs, CIDRs, ranges (`10.0.0.1-50` or `10.0.0.1-10.0.0.50`) and hostnames.
- CIDRs skip the network and broadcast addresses (a /24 is 254 hosts), except /31 and /32.
- Hostnames are resolved once, at pre-flight, to every IPv4 address they have. nmap gets the IPs, never the names, so it cannot resolve them differently.
- Externally, every hostname gets a scope warning: shared hosting or CDN addresses may belong to someone else.
- IPv6 is not supported in this version.
- Target sets over 65,536 addresses are refused (`scan.max_hosts`).

### Exit codes

- `0` done.
- `1` stopped: not root, nmap missing, `Proceed?` declined, nmap failed, or every imported file failed to parse.
- `2` bad arguments or targets.
- `130` interrupted with Ctrl+C. Results so far are printed and the run can be resumed.

## Pre-flight

Before any traffic, the scan shows the targets, the host count after exclusions, the mode, the timing profile, the phases, whether follow-up checks and version intelligence will run, missing tools with install commands, and a time estimate. Then `Proceed? [y/N]`.

- The TCP estimate is a worst case: hosts × 65,535 ÷ `--min-rate`. `--min-rate` is a floor, so nmap is usually faster. Internally it assumes every host is live.
- The UDP figure is a rough guide (about one second per port per group of 64 hosts, because most hosts rate-limit ICMP port unreachable replies).
- Service detection is not in the estimate: it depends on how many ports are open.
- One external /24 at the default 100 packets per second is up to about 47 hours.

## Scan phases

Large target sets are split into chunks of one /24 (`scan.chunk_prefix`). Each chunk finishes its phases before the next starts, so results arrive early. Every phase writes `-oA` output into the run's working directory.

1. **Host discovery (internal only):**
   - `nmap -sn -PE -PP -PS21,22,25,80,135,139,443,445,3389 -PA80,443 -T3`
   - ARP is used automatically on local subnets.
   - Later phases scan only hosts found live, with `-Pn` so nmap does not repeat discovery.
   - External scans skip this phase and use `-Pn`, because ICMP is usually blocked.
2. **All TCP ports:** `nmap -sS -Pn -p- -T3 --min-rate <rate> --max-retries 2`
3. **TCP service detection:**
   - Run per host, only on the ports found open in phase 2.
   - `nmap -sS -Pn -sV --script "default and not (brute or dos or exploit or intrusive)" -p <ports> -T3`
   - This replaces `-sC`, so the rule holds even if a future nmap adds an intrusive script to the default category.
4. **UDP top ports:**
   - `nmap -sU -Pn --top-ports 200 -sV --version-intensity 0 -T3 --max-retries 1`
   - Runs alongside phases 2 and 3 by default (`scan.udp_parallel`).
   - No `--min-rate`, which makes UDP miss ports.
   - `open|filtered` is reported separately from `open`. Only confirmed `open` ports go into the service lists.

### Progress, Ctrl+C and resume

- **Progress:** comes from nmap's `--stats-every 30s` lines. nmap 7.94 only prints them when it has a controlling terminal, so each nmap runs in its own session with a pseudo-terminal.
- **Ctrl+C:** sends SIGINT to nmap and waits for it to stop (up to `scan.interrupt_grace_seconds`, then it is killed). It then prints the results so far and keeps the working directory.
- **Resume:** `portgoblin runs` lists interrupted runs, and `portgoblin resume <run-id>` continues one:
    - A phase that was running is continued with `nmap --resume`. nmap accepts no other option alongside it.
    - A phase whose XML is already complete is never resumed: nmap would append a second document and break the file. If nmap cannot resume, the phase starts again.
    - Service detection is per host, so hosts without finished output are scanned again.
    - Follow-up checks and version intelligence run again in full.
- **Clean-up:** on success the working directory is deleted. Raw nmap files are not kept unless `--keep-raw` is given.

## Import

```bash
portgoblin import tcp.xml udp.xml
```

- Takes one or more nmap XML files (TCP, UDP or both), from any nmap version, and goes straight to analysis.
- XML is parsed with defusedxml (entity expansion is refused) and files over 512 MB are refused.
- Root is not needed, except for UDP checks (SNMP and IPMI), which are reported as `Not assessed: UDP checks need root` without it.
- Follow-up checks send traffic to hosts in someone else's file, so import first lists the hosts and checks and asks `Proceed? [y/N]` (`--yes` skips this).
- Then it tries a TCP connect to up to 5 hosts on a known open port. If none answer, no checks run and the result is `Not assessed: hosts not reachable from this machine`.
- Imports with only UDP ports have nothing to test, so the checks run without the reachability test.
- Output nmap already produced is reused. For example, `ftp-anon` from `-sC` or `-A` means no second anonymous FTP login.

## Output

In order:

1. **Summary:** mode, targets, live hosts, TCP open, UDP open, UDP open|filtered, duration.
2. **Quick wins:** issues, then manual checks. Each shows hosts, what was observed, why it matters, the fix and commands to reproduce it.
3. **Observations.**
4. **Vulnerable versions.**
5. **Hosts table:** `--verbose` adds every port with service, version and CPE.
6. **Services:** grouped by type as copy-ready lists.
    - Web services print as full URLs (`http://` or `https://` from nmap's TLS detection), ready for a ProbeGoblin targets file. They use the hostname if the target was given as one.
    - Everything else prints as `IP:port`.
7. **Passed checks.**
8. **Not assessed:** each line with the reason.
9. **Check log:** `--verbose` only. Every command and request a check sent, and what came back.

### Statuses

- **Issue:** the configuration is clearly wrong for the check.
- **Observation:** worth knowing, not a problem by itself.
- **Manual check:** a possible issue PortGoblin deliberately did not confirm. Always has manual steps.
- **OK:** the check passed.
- **Not assessed:** could not run, with the reason.

No severity ratings. The same finding on several hosts is one result listing every host, with one observed line per host. Every issue and manual check has at least one reproduce command.

## Follow-up checks

They run after the scan, one host at a time, at `-T3`. They are read-only:

- Only anonymous, null, guest or `public` access attempts, one per service.
- No password guessing, no writes, no file downloads.
- Names and metadata only, never data contents.

All NSE scripts a host needs are batched into one nmap call per protocol, with only allowlisted scripts. HTTP requests from checks ignore proxy settings and never follow redirects, so they cannot leave the target list. A check whose tool is missing reports `Not assessed` with the install command.

| Service | How | Findings | Limitations |
|---|---|---|---|
| FTP (21, 990, ftp, ftps) | `ftp-anon` (usually reused from service detection) | FTP-001 anonymous login, with top-level names only. Names nmap marks writeable (from the listing's permissions, nothing is written) are listed. | No output is read as "anonymous refused". |
| SSH | `ssh2-enum-algos` | SSH-001 weak algorithms: SHA-1 key exchange and group1 (RFC 9142), `ssh-dss`, `ssh-rsa`, CBC, 3DES, RC4, 64-bit block ciphers, MD5 and 96-bit MACs. | `hmac-sha1` and `umac-64` are in OpenSSH's defaults and are not flagged. Terrapin (CVE-2023-48795) is left to version intelligence. |
| SMB (445, 139) | `smb2-security-mode`, `smb-security-mode` | SMB-001 signing not required (SMBv2+ or SMBv1) | `smb-security-mode` logs in as guest, which is part of the script. |
| SMB | `smb-protocols` | SMB-002 SMBv1 enabled | |
| SMB (445) | `netexec smb <host> -u '' -p '' --shares`, then `-u guest -p ''` | SMB-003 null session, SMB-004 guest session: share names and access. Observation if a session is accepted but listing is refused. | netexec is only used if its `--help` lists `--file-write-check`. Those builds check write access from ACLs and create nothing. Older builds created a directory on each share, so PortGoblin uses `smbclient -N -L //host -g` (and `-U 'guest%'`) instead, which gives names only. |
| RDP (3389) | `rdp-enum-encryption` | RDP-001 without NLA: Native RDP, SSL or RDSTLS accepted | Tested against nmap's own example output only, not a live RDP server. |
| RDP | `rdp-ntlm-info` | RDP-002 host, domain and Windows build disclosed (observation) | |
| SNMP (161/udp, open only) | `snmp-sysdescr`, `snmp-info` with `snmpcommunity=public` | SNMP-001 community `public` readable, with the sysDescr | Only confirmed open 161 is tried, because nmap's `-sV` already sent a `public` probe. Needs root. |
| NFS (111) | `nfs-showmount` | NFS-001 exports and allowed clients | Mounting is never attempted. Tested against nmap's example output only. |
| LDAP (389, 636, 3268, 3269) | `ldap-rootdse`, `ldap-search` with `ldap.maxobjects=1,ldap.attrib=distinguishedName` | LDAP-001 anonymous search (one object, DN only), LDAP-002 naming contexts (observation) | A readable root DSE is normal and is only an observation. |
| Redis (6379) | `redis-info` | REDIS-001 unauthenticated | nmap prints nothing when authentication is required, so no output on a detected Redis is read as OK. |
| MongoDB (27017) | `mongodb-databases` | MONGO-001 unauthenticated: database names only, sizes are dropped | Tested against nmap's example output only. |
| Elasticsearch (9200, 9201, or product Elasticsearch) | One `GET /` and one `GET /_cat/indices?h=index` | ES-001 unauthenticated, with index names only | Tested against documented responses, not a live server. |
| Docker API (2375, 2376) | One `GET /version` | DOCKER-001 unauthenticated | A refused TLS handshake on 2376 is read as "client certificate required". Tested against documented responses. |
| rsync (873) | `rsync-list-modules` | RSYNC-001 module names (observation), RSYNC-002 manual check | nmap 7.94's rsync library rejects the greeting from rsync 3.2 and later (it adds checksum names), so the script prints nothing. PortGoblin then gives the manual `rsync rsync://host/` command. |
| VNC (5900-5910) | `vnc-info` | VNC-001 security type None | |
| X11 (6000-6009) | nmap's `-sV` result, or `x11-access` | X11-001 open X server | `x11-access` skips itself once `-sV` has identified the X server, because `-sV` already ran the same test (extra info "open" or "access denied"). |
| IPMI (623/udp, open or open\|filtered) | `ipmi-version`, `ipmi-cipher-zero` | IPMI-001 cipher zero, IPMI-002 BMC exposed (observation) | Needs root. Tested against nmap's example output only. |
| Telnet, rlogin, rsh, rexec | Presence only | CLEAR-001 Telnet, CLEAR-003 rlogin, rsh or rexec | No login attempts. |
| TFTP (69/udp) | Presence only | CLEAR-002 issue if open, manual check if open\|filtered | No files are requested. |
| TLS (tunnel ssl, or nmap's likely-TLS services) | `ssl-cert`, `ssl-enum-ciphers` | TLS-001 SSLv3, TLS 1.0 or 1.1. TLS-002 nmap strength C or worse, or nmap warnings. TLS-003 expired. TLS-004 self-signed (observation). TLS-005 RSA or DSA key under 2048 bits, or MD5 or SHA-1 signature. | nmap 7.94 grades TLS 1.0 CBC suites "A", so protocols are checked separately from grades. Self-signed needs the issuer, which `ssl-cert` only prints with `-v`, so normal scans miss it. |

## Version intelligence

For every open service with a versioned CPE from `-sV`:

- **CVEs:**
    - nmap's CPE 2.2 is converted to 2.3 and NVD's CVE API 2.0 is queried with `virtualMatchString`, which also matches version ranges.
    - Lookups are deduplicated by CPE and cached for 24 hours in `~/.cache/portgoblin`.
    - Without `NVD_API_KEY`, requests are 6 seconds apart (NVD allows 5 per 30 seconds); with it, 0.6 seconds. When NVD rate-limits (HTTP 403 or 429), PortGoblin backs off and retries.
    - The key is only ever sent in the `apiKey` header and is never printed.
- **Vendor mismatches:** when nmap and NVD disagree on the vendor (nmap `vsftpd:vsftpd`, NVD `vsftpd_project:vsftpd`), the first lookup returns nothing. The CPE dictionary is then searched with a wildcard vendor, and the lookup is retried only if exactly one vendor has that product and version.
- **Per CVE:**
    - the CVSS score as NVD publishes it (newest CVSS version, NVD's own score first)
    - the CISA KEV flag (KEV JSON feed)
    - the EPSS score (FIRST API)
    - Exploit-DB entries (`searchsploit --json --cve`, keeping only results whose codes contain the CVE)
    - Metasploit modules (CVE references in `modules_metadata_base.json`, found at runtime)
- **Exploit-DB by product and version:** `searchsploit --json <product> <version>` matches on titles. Results not tied to a listed CVE are shown as possible matches.
- **End of life:**
    - Uses endoflife.date's API v1. Products are matched by the CPE identifiers endoflife.date publishes, plus aliases in `intelligence.eol_aliases` (`igor_sysoev:nginx`, `samba:samba`).
    - Versions are matched to a release cycle by prefix (1.0.2k is in 1.0.2; 1.1.10 is not in 1.1.1).
    - EOL-nnn findings are manual checks.
- **Where results appear:**
    - Every result is labelled "version-based, unconfirmed, distro backports possible", and distro builds get a note.
    - Services with a KEV-listed CVE or a Metasploit module go into quick wins as VER-nnn manual checks.
    - All other matches are in the Vulnerable versions table, with every CVE under `--verbose`.
    - Ports with no versioned CPE report `CVE check not possible: no version detected`.

### What leaves this machine

- Product and version strings (CPEs and CVE IDs) are sent to NVD, FIRST and endoflife.date, and the KEV feed is fetched from CISA. Target addresses are never sent. Pre-flight says so.
- `--no-intel` turns this off.
- These lookups follow your proxy settings. Checks against targets do not.

### Limitations

- **Not covered by endoflife.date:** OpenSSH, IIS and vsftpd, so their end of life is not assessed.
- **Windows Server:** not mapped, because nmap's service detection does not say reliably whether a host is Windows Server or a client.
- **searchsploit's JSON:** it builds its JSON with awk and no escaping. The Exploit-DB index had no titles with commas or quotes when this was written; if one breaks the JSON, PortGoblin falls back to reading the fields with a pattern.
- **searchsploit not run:** it was never executed while building PortGoblin; its output format comes from its source code. Check `searchsploit --json vsftpd 2.3.4` once on Kali.
- **Title-only matches:** a product search finds only titles containing that exact version, so "OpenSSH < 7.4" style titles are found through the CVE searches instead.
- **Ctrl+C during an NVD request:** this can take up to the request timeout (30 seconds) to stop.
- **Offline:** if NVD cannot be reached, lookups stop after the first failure and are reported as Not assessed. KEV falls back to a stale cached copy if there is one.

## NSE scripts

Every follow-up script is checked against nmap's `script.db` before it runs (service detection uses the fixed expression shown under Scan phases instead): it must be on the allowlist, installed, and either outside `brute`, `dos`, `exploit` and `intrusive` or confirmed by the tester (`nse.confirmed_non_safe`). `portgoblin doctor` shows this table for the installed nmap. Categories below are from nmap 7.94SVN.

| Script | Categories | Used by |
|---|---|---|
| ftp-anon | auth, default, safe | FTP |
| ssh2-enum-algos | discovery, safe | SSH |
| smb2-security-mode | default, discovery, safe | SMB signing |
| smb-security-mode | default, discovery, safe | SMB signing (SMBv1) |
| smb-protocols | discovery, safe | SMBv1 |
| rdp-enum-encryption | discovery, safe | RDP NLA |
| rdp-ntlm-info | default, discovery, safe | RDP NTLM info |
| snmp-info | default, safe, version | SNMP |
| snmp-sysdescr | default, discovery, safe | SNMP |
| nfs-showmount | discovery, safe | NFS |
| ldap-rootdse | discovery, safe | LDAP |
| ldap-search | discovery, safe | LDAP anonymous search |
| redis-info | discovery, safe | Redis |
| mongodb-info | default, discovery, safe | Allowlisted, not run by a check |
| mongodb-databases | default, discovery, safe | MongoDB |
| rsync-list-modules | discovery, safe | rsync |
| vnc-info | default, discovery, safe | VNC |
| x11-access | auth, default, safe | X11 |
| ipmi-version | discovery, safe | IPMI |
| ipmi-cipher-zero | safe, vuln | IPMI |
| ssl-cert | default, discovery, safe | TLS |
| ssl-enum-ciphers | discovery, **intrusive** | TLS. Confirmed by the tester: it makes many TLS handshakes. |

`docker-version` (category `version` only) was dropped: the direct `GET /version` does the same job.

## Configuration

PortGoblin reads the first of `--config`, `$PORTGOBLIN_CONFIG`, `~/.config/portgoblin/portgoblin.toml` and the repository's `config/portgoblin.toml`, or uses built-in defaults that match that file. Unknown keys are refused.

- `[rates]` `internal`, `external`: `--min-rate` per mode.
- `[scan]`:
    - `chunk_prefix`, `top_udp`, `udp_parallel`, `stats_every`
    - `max_hosts`
    - `interrupt_grace_seconds`
- `[nse]` `allowlist`, `confirmed_non_safe`.
- `[timeouts]` `default` (per check), `reachability`, `http`.
- `[intelligence]`:
    - `cache_ttl_hours`, `request_timeout`
    - `nvd_delay_no_key`, `nvd_delay_with_key`
    - `max_cves_shown`
    - `[intelligence.eol_aliases]`
- API keys come only from environment variables (`NVD_API_KEY`).

## doctor and update

- `doctor` shows:
    - each tool with its version and install command
    - whether netexec's share check writes
    - whether PortGoblin is running as root
    - the cache date, `NVD_API_KEY`, and the KEV and endoflife.date fetch dates
    - the allowlisted scripts with their categories
- `update`:
    - refreshes the KEV feed and endoflife.date data
    - runs `searchsploit -u`, which uses `sudo apt` on Kali and may ask for a password
    - reports where the Metasploit metadata is

## Adding a check

Drop a file into `portgoblin/checks/`. The engine does not need editing.

- `ScriptCheck`: set `scripts` (allowlisted NSE scripts), optionally `script_args`, `protocol` and `states`, and implement `matches(port)` and `evaluate(host, ports, results)`. The runner batches and reuses script output.
- `DirectCheck`: implement `matches(port)` and `async run(ctx, host, ports)`, using `ctx.run_tool(...)` or `ctx.http_get(...)` so every request lands in the check log.
- Return `Finding` objects. Use the same `finding_id` for the same problem on every host, so results group. Every issue and manual check needs a reproduce command.
- New scripts must be added to `nse.allowlist`. A test fails if a check uses a script that is not on it.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check . && black --check . && pytest
```

- Tests use saved fixtures and never touch the network or run nmap against anything but the test's own fake runner.
- `tests/fixtures/checks/` holds real output from FTP, SSH, Samba, SNMP, Redis, LDAP, rsync, VNC, X11 and TLS servers, each in an insecure and a hardened configuration, plus real netexec 1.5.1 and smbclient output.
- `crafted_from_nsedoc.xml` copies nmap's own `@output` examples for RDP, NFS, MongoDB and IPMI, which could not be run.
- `tests/fixtures/intel/` holds trimmed live responses from NVD, CISA KEV, FIRST EPSS, endoflife.date and Metasploit's module metadata (November 2026), and searchsploit JSON built from real Exploit-DB rows in the layout of searchsploit's source.
