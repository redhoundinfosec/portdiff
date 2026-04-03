# portdiff Roadmap

## v0.1.0 (Current)

- [x] Parse nmap XML (`-oX`)
- [x] Parse nmap grepable (`-oG`)
- [x] Parse masscan JSON (`-oJ`)
- [x] `portdiff diff` command — compare two scans
- [x] `portdiff summary` command — summarize a single scan
- [x] Text, JSON, CSV output formats
- [x] Severity classification (CRITICAL / WARNING / INFO)
- [x] `--ignore-ports` flag
- [x] `--only-new` flag
- [x] Colored terminal output
- [x] Structured exit codes (0/1/2)
- [x] Auto-detect scan format
- [x] GitHub Actions CI

## v0.2.0 — Richer Diffing

- [ ] **OS detection diff** — track OS fingerprint changes (nmap `-O` output)
- [ ] **Script output diff** — compare NSE script results (e.g. SSL cert changes, HTTP title changes)
- [ ] **UDP port support** — better handling of UDP services
- [ ] **Port range filtering** — `--port-range 1-1024` to scope the diff
- [ ] **Hostname tracking** — detect hostname changes for the same IP
- [ ] **Confidence thresholds** — filter by nmap service detection confidence level

## v0.3.0 — Storage and Trending

- [ ] **Scan history database** — SQLite-backed scan history (`portdiff store add <scan>`)
- [ ] **Trend queries** — `portdiff trend 192.168.1.1` to see all changes for a host over time
- [ ] **Baseline management** — `portdiff baseline set <scan>` to lock a reference state
- [ ] **First-seen tracking** — know when a port first appeared across all historical scans

## v0.4.0 — Integrations and Notifications

- [ ] **Slack webhook integration** — post diffs to a channel
- [ ] **Email notifications** — SMTP support for critical changes
- [ ] **Webhook output** — POST JSON diffs to arbitrary HTTP endpoints
- [ ] **SARIF output** — integrate with GitHub Advanced Security and VSCode

## v0.5.0 — Network Discovery Helpers

- [ ] **Asset inventory** — build and maintain an asset inventory from scans
- [ ] **CIDR grouping** — group hosts by subnet for cleaner output
- [ ] **Service tagging** — apply custom tags to services (e.g. "approved", "unknown")
- [ ] **Allow-list mode** — alert on any port NOT in an approved list

## Future / Wishlist

- **nmap XML v2 support** — when nmap updates its XML schema
- **Censys/Shodan import** — diff against internet scan data
- **Docker image** — `docker pull ghcr.io/redhoundinfosec/portdiff`
- **Homebrew formula** — `brew install portdiff`
- **man page** — system manual page
- **Shell completions** — bash, zsh, fish

## Contributing

Want to work on any of these? Open an issue to discuss first, then submit a PR. See [CONTRIBUTING.md](CONTRIBUTING.md).
