# portdiff

**Compare network scans and detect attack surface changes.**

`portdiff` is a single-binary, cross-platform CLI tool that compares two [nmap](https://nmap.org) or [masscan](https://github.com/robertdavidgraham/masscan) scan results and produces a clear, actionable diff showing new hosts, removed hosts, new/removed ports, and changed services.

Built for defenders, security teams, pentesters, and compliance teams tracking infrastructure drift.

---

## Why portdiff?

- **nmap's `ndiff`** is Python 2-era, unmaintained, and produces poor output
- **No single binary** cross-platform tool does scan diffing well
- **No existing tool** outputs structured JSON diffs or integrates cleanly into automation pipelines
- `portdiff` is **zero-dependency**, runs anywhere Go runs, and exits with meaningful codes for scripting

---

## Installation

### Pre-built binaries

Download from the [Releases](https://github.com/redhoundinfosec/portdiff/releases) page.

### Build from source

```bash
git clone https://github.com/redhoundinfosec/portdiff
cd portdiff
make build
# Binary: ./portdiff
```

### Go install

```bash
go install github.com/redhoundinfosec/portdiff/cmd/portdiff@latest
```

---

## Quick Start

```bash
# Compare two nmap scans
portdiff diff scan-before.xml scan-after.xml

# JSON output for automation
portdiff diff scan-before.xml scan-after.xml -f json

# Show only new hosts and ports (reduce noise)
portdiff diff scan-before.xml scan-after.xml --only-new

# Ignore ephemeral/noise ports
portdiff diff scan-before.xml scan-after.xml --ignore-ports 8080,8443

# Summarize a single scan
portdiff summary scan-before.xml

# Write report to file
portdiff diff baseline.xml current.xml -f json -o report.json
```

---

## Commands

### `portdiff diff <baseline> <current>`

Compare two scan files and show changes.

```
Flags:
  -f, --format string        Output format: text, json, csv  (default: text)
  -o, --output string        Write output to file (default: stdout)
      --only-new             Show only new hosts and ports
      --ignore-ports string  Comma-separated ports to ignore (e.g. 80,443)
      --no-color             Disable colored output
  -q, --quiet                Suppress output; use exit code only
  -v, --verbose              Show all details including unchanged hosts/ports
```

### `portdiff summary <scan>`

Summarize a single scan file — hosts, ports, services.

```
Flags:
  -f, --format string   Output format: text, json, csv  (default: text)
  -o, --output string   Write output to file
      --no-color        Disable colors
  -q, --quiet           Suppress output
```

### `portdiff version`

Print version and license information.

---

## Supported Input Formats

`portdiff` auto-detects the format of each input file.

| Format | Scanner Flag | Notes |
|--------|-------------|-------|
| nmap XML | `nmap -oX <file>` | Recommended — richest data |
| nmap grepable | `nmap -oG <file>` | Supported |
| masscan JSON | `masscan -oJ <file>` | Supported |

---

## Sample Output

```
portdiff v0.1.0 — Scan Comparison

  Baseline: scan-before.xml (3 hosts, 6 ports)
  Current:  scan-after.xml  (3 hosts, 7 ports)

  NEW HOSTS
  ● 192.168.1.30 (newserver.internal)
    ├─ 139/tcp     open     netbios-ssn      [CRITICAL]
    └─ 445/tcp     open     microsoft-ds     [CRITICAL]

  REMOVED HOSTS
  ○ 192.168.1.20 (dbserver.internal)
    ├─ 22/tcp      was open  ssh
    └─ 3306/tcp    was open  mysql

  CHANGED HOSTS
  △ 192.168.1.1 (gateway.internal)
    + 3389/tcp     open     ms-wbt-server    [CRITICAL]  new port
    ~ 80/tcp       open     http             [WARNING]   Apache httpd 2.4.41 → Apache httpd 2.4.52

  UNCHANGED HOSTS
    192.168.1.10 (2 port(s), no changes)

  Summary: 1 new host(s), 1 removed host(s), 1 changed host(s), 1 unchanged
  Critical: 3 | Warning: 1 | Info: 0
```

---

## JSON Output

```bash
portdiff diff scan-before.xml scan-after.xml -f json
```

```json
{
  "portdiff_version": "0.1.0",
  "baseline": { "source": "scan-before.xml", "format": "nmap-xml", "hosts": 3, "open_ports": 6 },
  "current":  { "source": "scan-after.xml",  "format": "nmap-xml", "hosts": 3, "open_ports": 7 },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "gateway.internal",
      "change": "changed_host",
      "severity": "CRITICAL",
      "port_changes": [
        { "port": "3389", "protocol": "tcp", "state": "open", "service": "ms-wbt-server",
          "change": "new_port", "severity": "CRITICAL" },
        { "port": "80", "protocol": "tcp", "state": "open", "service": "http",
          "change": "changed_port", "severity": "WARNING",
          "old_version": "Apache httpd 2.4.41", "product": "Apache httpd", "version": "2.4.52" }
      ]
    }
  ],
  "summary": {
    "new_hosts": 1, "removed_hosts": 1, "changed_hosts": 1, "unchanged_hosts": 1,
    "new_ports": 3, "removed_ports": 2, "changed_ports": 1,
    "critical": 3, "warning": 1, "info": 0, "has_changes": true
  }
}
```

---

## Severity Classification

| Level | Triggers |
|-------|----------|
| **CRITICAL** | New port in high-risk set: 21, 22, 23, 25, 53, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 11211, 27017 |
| **WARNING** | Service version changed; new port (not high-risk); host removed |
| **INFO** | Port removed; no change |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No changes detected |
| `1` | Changes detected |
| `2` | Error (parse failure, bad flags, etc.) |

This makes `portdiff` easy to use in CI pipelines:

```bash
portdiff diff baseline.xml current.xml -q
if [ $? -eq 1 ]; then
  echo "Attack surface changed!"
  portdiff diff baseline.xml current.xml -f json -o report.json
fi
```

---

## Workflow Examples

### Continuous Monitoring

```bash
# Daily scan
nmap -sV -oX /scans/$(date +%F).xml 10.0.0.0/24

# Diff against yesterday
portdiff diff /scans/$(date -d yesterday +%F).xml /scans/$(date +%F).xml
```

### Pentesting Pre/Post Comparison

```bash
# Before exploitation
nmap -sV -oX before-exploit.xml 192.168.1.0/24

# After lateral movement
nmap -sV -oX after-exploit.xml 192.168.1.0/24

# What changed?
portdiff diff before-exploit.xml after-exploit.xml --only-new
```

### CI/CD Pipeline Gate

```yaml
- name: Scan production
  run: nmap -sV -oX current.xml $PROD_RANGE

- name: Check for attack surface drift
  run: |
    portdiff diff baseline.xml current.xml -q
    if [ $? -ne 0 ]; then
      portdiff diff baseline.xml current.xml -f json -o drift-report.json
      exit 1
    fi
```

### masscan Integration

```bash
# Fast scan with masscan
masscan -p1-65535 10.0.0.0/24 --rate 1000 -oJ masscan-current.json

# Diff against previous masscan result
portdiff diff masscan-previous.json masscan-current.json
```

---

## Architecture

```
portdiff/
├── cmd/portdiff/main.go       Entry point
├── internal/
│   ├── parser/                Scan file parsers + data model
│   │   ├── parser.go          Common types (Host, Port, ScanResult)
│   │   ├── nmap_xml.go        nmap -oX parser
│   │   ├── nmap_grep.go       nmap -oG parser
│   │   ├── masscan.go         masscan -oJ parser
│   │   └── detect.go          Auto-format detection
│   ├── diff/                  Diff engine
│   │   ├── diff.go            Core comparison logic
│   │   └── severity.go        Severity classification rules
│   └── output/                Output formatters
│       └── output.go          Text, JSON, CSV renderers
└── examples/                  Sample scan files
```

---

## Building

```bash
make build       # Build for current platform
make test        # Run all tests
make release     # Cross-compile for Linux, macOS, Windows
make clean       # Remove build artifacts
make lint        # Run go vet
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).

Copyright 2026 Red Hound Information Security LLC.
