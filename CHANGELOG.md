# Changelog

All notable changes to portdiff will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

_Nothing yet._

---

## [0.1.0] — 2026-04-03

Initial release.

### Added

- **`portdiff diff <baseline> <current>`** — compare two scan files, show new/removed/changed hosts and ports
- **`portdiff summary <scan>`** — summarize a single scan file
- **`portdiff version`** — print version information
- **nmap XML parser** — parse `nmap -oX` output with full service/version detection
- **nmap grepable parser** — parse `nmap -oG` output
- **masscan JSON parser** — parse `masscan -oJ` output, merging multi-record entries by IP
- **Auto-format detection** — automatically identify scan file format from file contents
- **Text output** (default) — colored terminal output with tree-style port listings
- **JSON output** (`-f json`) — structured output for automation and SIEM ingestion
- **CSV output** (`-f csv`) — tabular output for spreadsheet analysis
- **Severity classification**:
  - CRITICAL — new port in high-risk set (RDP, SMB, telnet, databases, Redis, Elasticsearch, etc.)
  - WARNING — service version changed, new non-critical port, host removed
  - INFO — port removed, no change
- **`--ignore-ports`** flag — filter out noisy ports by number
- **`--only-new`** flag — show only new hosts and ports (suppress removed/unchanged)
- **`--no-color`** flag — disable ANSI colors for log files and non-TTY output
- **`-v/--verbose`** flag — show all details including unchanged hosts/ports
- **`-q/--quiet`** flag — suppress all output, use exit code only
- **`-o/--output`** flag — write output to a file instead of stdout
- **Exit codes**: 0 = no changes, 1 = changes detected, 2 = error
- **Unit tests** for all parsers, diff engine, and severity classification
- **Example scan files** — realistic nmap XML before/after scenario and masscan JSON sample
- **GitHub Actions CI** — build and test on Linux, macOS, Windows (Go 1.21+)
- **MIT license** — Copyright 2026 Red Hound Information Security LLC

[Unreleased]: https://github.com/redhoundinfosec/portdiff/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/redhoundinfosec/portdiff/releases/tag/v0.1.0
