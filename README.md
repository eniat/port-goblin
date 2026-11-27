# PortGoblin

Knocking on every door.

nmap scanning and triage for internal and external infrastructure tests. By Taine (github.com/eniat).

**Status: build phase 3 of 4.** Scanning, import, resume, follow-up checks, quick wins, version intelligence (NVD, CISA KEV, EPSS, Exploit-DB, Metasploit, endoflife.date), `--save`, `doctor` and `update` work. The full README (installation, every check and its limitations, the NSE script category table) comes in phase 4.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check . && black --check . && pytest
```

Scanning needs root:

```bash
sudo .venv/bin/portgoblin scan 10.0.0.0/24 --internal
```
