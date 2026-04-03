---
name: portdiff
description: >
  Build, extend, and operate portdiff — a Go CLI tool that compares network scan
  results (nmap XML, nmap grepable, masscan JSON) and produces severity-classified
  diffs showing new, removed, and changed hosts and ports. Use when working on the
  redhoundinfosec/portdiff repository, when the user asks about attack surface
  monitoring, scan comparison, or network change detection. Covers architecture,
  CLI usage, parser extension, severity classification, and testing.
license: MIT
metadata:
  author: Red Hound Information Security LLC
  version: '0.1.0'
  repo: https://github.com/redhoundinfosec/portdiff
  language: Go
---

# portdiff Agent Skill

## When to Use This Skill

Use this skill when:
- Working on the `redhoundinfosec/portdiff` repository
- The user asks about comparing network scans or tracking attack surface changes
- The user wants to detect new hosts, ports, or service version changes between scans
- The user needs to build or extend a scan diffing tool
- The user asks about nmap, masscan, or network scan analysis

## What portdiff Does

portdiff compares two network scan files and produces a clear, severity-classified diff. It auto-detects input formats (nmap XML, nmap grepable, masscan JSON), identifies new/removed/changed hosts and ports, and classifies changes as CRITICAL, WARNING, or INFO based on risk. Zero external dependencies — Go stdlib only.

## Core Concepts

### Supported Scan Formats

| Format | Source Command | Auto-detected By |
|--------|---------------|-----------------|
| nmap XML | `nmap -oX scan.xml` | `<?xml` + `nmaprun` |
| nmap grepable | `nmap -oG scan.gnmap` | `Host:` lines |
| masscan JSON | `masscan -oJ scan.json` | JSON array |

### Severity Classification

| Level | Trigger |
|-------|---------|
| CRITICAL | New port in high-risk set (21,22,23,25,53,139,445,1433,1521,3306,3389,5432,5900,6379,9200,11211,27017) |
| WARNING | Service version changed, new port not in high-risk set, host removed |
| INFO | Port removed/closed, no changes |

### Exit Codes

- `0` — No changes between scans
- `1` — Changes detected
- `2` — Error

## CLI Reference

```bash
# Compare two scans
portdiff diff baseline.xml current.xml
portdiff diff scan1.gnmap scan2.gnmap
portdiff diff before.json after.json

# Output formats
portdiff diff baseline.xml current.xml -f json
portdiff diff baseline.xml current.xml -f csv
portdiff diff baseline.xml current.xml -f json -o report.json

# Filters
portdiff diff baseline.xml current.xml --only-new              # Only new hosts/ports
portdiff diff baseline.xml current.xml --ignore-ports 80,443   # Ignore specific ports

# Options
portdiff diff baseline.xml current.xml -v             # Verbose (show unchanged)
portdiff diff baseline.xml current.xml -q             # Quiet (exit code only)
portdiff diff baseline.xml current.xml --no-color     # No ANSI colors

# Summarize a single scan
portdiff summary scan.xml
portdiff summary scan.xml -f json
```

## Architecture (for development)

```
internal/parser/parser.go      — Core models: Host, Port, ScanResult, Format
                                 Parse() entry point with auto-detect
internal/parser/nmap_xml.go    — nmap -oX parser (encoding/xml)
internal/parser/nmap_grep.go   — nmap -oG parser (string splitting)
internal/parser/masscan.go     — masscan -oJ parser (encoding/json)
internal/parser/detect.go      — Content-based format detection
internal/diff/diff.go          — Diff engine: Compare() → DiffResult
internal/diff/severity.go      — Severity classification and high-risk port set
internal/output/output.go      — Text/JSON/CSV renderers
internal/cli/*.go              — CLI commands (diff, summary, version)
```

Zero external dependencies.

## Data Flow

```
scan-before ──→ Parse() ──→ ScanResult ──┐
                                          ├──→ Compare() ──→ DiffResult ──→ Render()
scan-after  ──→ Parse() ──→ ScanResult ──┘
```

## Extending portdiff

### Adding a new scan format

1. Create `internal/parser/newformat.go` — implement `ParseNewFormat(data []byte) (*ScanResult, error)`
2. Map to existing `Host`/`Port` model
3. Add format constant to `parser.go`
4. Add detection in `detect.go` → `DetectFormat()`
5. Wire into `Parse()` switch
6. Add tests with embedded fixtures
7. Add sample file to `examples/`, update docs

### Adding high-risk ports

1. Edit `severity.go` → `highRiskPorts` map
2. Only add ports that are universally high-risk (not environment-specific)
3. Add tests

### Adding a new output format

1. Add render function in `output/output.go`
2. Wire into format switch
3. Update CLI help

## Safety Constraints

- NEVER add active scanning — portdiff reads files only
- Maintain JSON output backward compatibility
- Keep high-risk port set conservative (avoid false positives)
- Always test parser changes against example files

## Build and Test

```bash
go build -o portdiff ./cmd/portdiff/
go test ./... -v -count=1
go vet ./...
make release
```

## Common Workflows

### Weekly attack surface monitoring

```bash
# Baseline scan (once)
nmap -sV -p- -oX baseline-$(date +%Y%m%d).xml 192.168.1.0/24

# Weekly comparison
nmap -sV -p- -oX current-$(date +%Y%m%d).xml 192.168.1.0/24
portdiff diff baseline.xml current.xml -f json -o weekly-diff.json
```

### CI/CD security gate

```bash
portdiff diff approved-baseline.xml latest-scan.xml -q
[ $? -eq 0 ] || { echo "Attack surface changed — review required"; exit 1; }
```

### Filter noise in large environments

```bash
portdiff diff before.xml after.xml --ignore-ports 80,443,8080 --only-new -f json
```
