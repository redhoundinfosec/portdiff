# Supported Scan Formats

portdiff supports three scan output formats, all auto-detected from file contents.

## nmap XML (`-oX`)

The richest format — includes full service/version detection, OS detection, and script output.

```bash
nmap -sV -oX scan.xml 192.168.1.0/24
nmap -sV -sC -oX scan.xml 192.168.1.0/24    # with scripts
nmap -sV -O -oX scan.xml 192.168.1.0/24     # with OS detection
```

portdiff uses the following XML elements:

| Element | Usage |
|---------|-------|
| `<nmaprun>` | Scanner name, version, scan time |
| `<host>` | One per host |
| `<status state="up">` | Host liveness |
| `<address addrtype="ipv4">` | Host IP |
| `<hostname type="PTR">` | Reverse DNS hostname |
| `<port protocol portid>` | Port number and protocol |
| `<state state="open">` | Port state |
| `<service name product version>` | Service identification |

## nmap Grepable (`-oG`)

Single-line-per-host format, easy to process with grep/awk but less detailed than XML.

```bash
nmap -sV -oG scan.gnmap 192.168.1.0/24
```

Each host line format:
```
Host: <ip> (<hostname>)  Ports: <port>/<state>/<proto>//<service>//<version>/,...
```

**Limitations vs. XML:**
- Version parsing is less reliable (heuristic-based)
- No OS detection fields
- No script output

## masscan JSON (`-oJ`)

masscan scans much faster than nmap but provides less service information.

```bash
masscan -p1-65535 10.0.0.0/24 --rate 1000 -oJ masscan.json
```

Each record format:
```json
{ "ip": "10.0.0.1", "timestamp": "1735689600", "ports": [
    { "port": 80, "proto": "tcp", "status": "open",
      "reason": "syn-ack", "ttl": 64,
      "service": { "name": "http", "banner": "" } }
]}
```

**Notes:**
- masscan emits one record per port (not per host) — portdiff merges them by IP
- masscan JSON sometimes has a trailing comma before `]` — portdiff handles this
- Banner information is stored in the `ExtraInfo` field
- No hostname resolution — combine with nmap for hostnames

## Format Auto-Detection

portdiff uses the following heuristics to detect format:

1. **nmap XML** — file starts with `<?xml` or contains `<nmaprun` in the first 512 bytes
2. **masscan JSON** — file starts with `[` and contains `"ip"` or `masscan` in the first 256 bytes
3. **nmap Grepable** — file contains `# Nmap` or `Host:` in the first 1024 bytes

If detection fails, portdiff returns an error with exit code 2.
