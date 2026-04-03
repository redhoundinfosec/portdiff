# Agent Instructions for portdiff

This document tells AI coding agents how to work with the `portdiff` codebase — build, test, extend, and contribute.

## Project Overview

`portdiff` compares two network scan results (nmap XML, nmap grepable, masscan JSON) and produces a clear, severity-classified diff showing new/removed/changed hosts and ports. Written in Go with **zero external dependencies** — stdlib only.

## Quick Commands

```bash
# Build
go build -o portdiff ./cmd/portdiff/

# Test
go test ./... -v -count=1

# Lint
go vet ./...

# Cross-compile all platforms
make release

# Run
./portdiff diff baseline.xml current.xml              # Text diff
./portdiff diff baseline.xml current.xml -f json       # JSON output
./portdiff diff scan1.xml scan2.xml --only-new         # Only new hosts/ports
./portdiff diff scan1.xml scan2.xml --ignore-ports 80,443  # Filter noise
./portdiff summary scan.xml                            # Single scan summary
```

## Architecture

```
cmd/portdiff/main.go              Entry point — calls cli.NewRoot().Run(os.Args[1:])
internal/
  parser/
    parser.go                      Core models: Host, Port, ScanResult, Format enum
                                   Parse() entry point with auto-detection
    nmap_xml.go                    Parses nmap -oX output via encoding/xml
    nmap_grep.go                   Parses nmap -oG output via string splitting
    masscan.go                     Parses masscan -oJ output via encoding/json
    detect.go                      DetectFormat() — content-based format detection
  diff/
    diff.go                        Core diff engine: Compare() → DiffResult
                                   Produces: NewHosts, RemovedHosts, ChangedHosts, UnchangedHosts
                                   Each changed host has: NewPorts, RemovedPorts, ChangedPorts
    severity.go                    Severity classification (CRITICAL/WARNING/INFO)
                                   High-risk port set: 21,22,23,25,53,139,445,1433,1521,
                                   3306,3389,5432,5900,6379,9200,11211,27017
  output/
    output.go                      Renderers: text (ANSI colored), JSON, CSV
  cli/
    root.go                        CLI dispatcher, flag helpers, splitArgs for flexible flag placement
    diff.go                        `diff` subcommand
    summary.go                     `summary` and `version` subcommands
```

## Key Design Decisions

1. **Auto-detect input format.** `DetectFormat()` inspects file content — XML declaration for nmap XML, `Host:` lines for grepable, JSON arrays for masscan. Agents should maintain this.
2. **High-risk port set drives severity.** New ports in the `highRiskPorts` map are CRITICAL. Service version changes are WARNING. Removed ports are INFO.
3. **Flags can appear after positional args.** `splitArgs()` in `root.go` handles `portdiff diff file1 file2 --no-color`. This is intentional CLI ergonomics.
4. **Exit codes are part of the API.** 0 = no changes, 1 = changes detected, 2 = error.
5. **No third-party dependencies.** XML, JSON, and string parsing all use Go stdlib.

## Data Flow

```
scan-before.xml ──→ Parse() ──→ ScanResult ──┐
                                              ├──→ Compare() ──→ DiffResult ──→ Render()
scan-after.xml  ──→ Parse() ──→ ScanResult ──┘
```

Each `ScanResult` contains `Hosts[]`, each Host contains `Ports[]`. `BuildHostMap()` and `BuildPortMap()` create lookup maps after parsing.

## How to Add a New Feature

### Adding a new scan format (e.g., Nessus XML)

1. Create `internal/parser/nessus.go`:
   - Implement a `ParseNessus(data []byte) (*ScanResult, error)` function
   - Map Nessus output to the existing `Host`/`Port` model
2. Add detection logic to `internal/parser/detect.go` → `DetectFormat()`
3. Wire it into `internal/parser/parser.go` → `Parse()` switch
4. Add `FormatNessus` constant
5. Write tests in `internal/parser/nessus_test.go` with embedded XML fixtures
6. Add a sample file to `examples/`
7. Update `docs/supported-formats.md` and README.md

### Adding a new severity rule

1. Edit `internal/diff/severity.go`:
   - For port-level rules: modify `highRiskPorts` or add conditional logic in `ClassifyNewPort()`
   - For host-level rules: modify `ClassifyNewHost()` or `ClassifyRemovedHost()`
2. Add tests in `internal/diff/severity_test.go`

### Adding a new output format

1. Edit `internal/output/output.go`:
   - Add rendering function
   - Wire into the format switch
2. Update CLI help text in `internal/cli/root.go`

## Testing Conventions

- Test files are colocated: `foo.go` → `foo_test.go`
- Parser tests embed small scan samples as string constants
- Diff tests build `ScanResult` structs programmatically
- Severity tests use table-driven patterns
- Always test: empty scans, single-host scans, no-change diffs, all-new diffs

## Key Types

```go
// Core models
type Port struct {
    Number int; Protocol Protocol; State PortState
    Service, Product, Version string
}
type Host struct { IP, Hostname, Status string; Ports []Port; PortMap map[string]Port }
type ScanResult struct { Source string; Format Format; Hosts []Host; HostMap map[string]*Host }

// Diff results
type DiffResult struct {
    Baseline, Current *ScanResult
    NewHosts, RemovedHosts []*HostChange
    ChangedHosts []*HostChange
    UnchangedIPs []string
}
type HostChange struct {
    Host *Host; Severity Severity
    NewPorts, RemovedPorts []PortChange
    ChangedPorts []PortChange
}
type PortChange struct { Port, OldPort Port; Severity Severity; Reason string }
```

## Safety Rules for Agents

1. **Never add active scanning.** portdiff reads files only — it never touches the network.
2. **Maintain backward compatibility** of JSON output structure. Downstream tools may parse it.
3. **Keep the high-risk port set conservative.** Adding a port to the set increases noise for every user. Only add ports that are universally high-risk.
4. **Always test parser changes** against the example files to prevent regressions.

## Dependencies

- Go 1.22+
- Zero external dependencies (stdlib only)
- No CGO required
