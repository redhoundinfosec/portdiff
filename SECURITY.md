# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report security vulnerabilities privately to:

**Email:** security@redhoundinfosec.com

Include in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

We will acknowledge receipt within 48 hours and provide a timeline for a fix within 5 business days.

## Threat Model

portdiff is a **read-only** analysis tool. It:

- Reads scan output files from disk (does not perform network scans itself)
- Writes reports to stdout or specified output files
- Has no network connectivity
- Has no persistent state or daemon components

The primary attack surface is **malicious scan files**. If an attacker can control the content of a scan file passed to portdiff, they could potentially:

- Cause a panic via malformed XML or JSON (we defend against this via safe parsing)
- Consume excessive memory via pathologically large scan files (mitigated by OS limits)

portdiff does not execute external commands or load plugins, limiting the impact of parser vulnerabilities.

## Safe Parsing Practices

- XML parsing uses Go's `encoding/xml` with strict struct mapping — no `innerHTML` or script execution
- JSON parsing uses Go's `encoding/json` — no `eval()`-style execution
- All file I/O is read-only (scan files) or write-only (output files)
- No shell command execution
- No reflection of user-controlled data back as code
