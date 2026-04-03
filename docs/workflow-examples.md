# Workflow Examples

## Continuous Attack Surface Monitoring

Automate weekly scans and diff against the previous week:

```bash
#!/bin/bash
SCAN_DIR="/var/lib/portdiff/scans"
TODAY=$(date +%F)
YESTERDAY=$(date -d "7 days ago" +%F)

# Run scan
nmap -sV -oX "$SCAN_DIR/$TODAY.xml" 10.0.0.0/8

# Diff against baseline
portdiff diff "$SCAN_DIR/$YESTERDAY.xml" "$SCAN_DIR/$TODAY.xml" \
  -f json -o "/var/lib/portdiff/reports/$TODAY-diff.json"

# Alert on critical changes
CRITICAL=$(jq '.summary.critical' "/var/lib/portdiff/reports/$TODAY-diff.json")
if [ "$CRITICAL" -gt 0 ]; then
  echo "ALERT: $CRITICAL critical attack surface changes detected!" | mail -s "portdiff Alert" soc@example.com
fi
```

## Penetration Testing — Pre/Post Comparison

Track what changed after an exploitation phase:

```bash
# Before: document the initial attack surface
nmap -sV -oX before.xml 192.168.1.0/24
echo "Baseline recorded: $(date)"

# ... exploitation ...

# After: see what your access revealed
nmap -sV -oX after.xml 192.168.1.0/24
portdiff diff before.xml after.xml --only-new
```

## CI/CD Pipeline Gate

Block deployments if the attack surface unexpectedly changes:

```yaml
# .github/workflows/scan-gate.yml
name: Attack Surface Gate

on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6am

jobs:
  scan-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Download portdiff
        run: |
          curl -L https://github.com/redhoundinfosec/portdiff/releases/latest/download/portdiff-linux-amd64 \
            -o portdiff && chmod +x portdiff

      - name: Download baseline
        run: aws s3 cp s3://my-scans/baseline.xml baseline.xml

      - name: Scan current state
        run: nmap -sV -oX current.xml ${{ secrets.SCAN_TARGET }}

      - name: Diff
        run: |
          ./portdiff diff baseline.xml current.xml -q
          EXIT=$?
          if [ $EXIT -eq 1 ]; then
            ./portdiff diff baseline.xml current.xml -f json -o drift-report.json
            echo "## Attack Surface Drift Detected" >> $GITHUB_STEP_SUMMARY
            cat drift-report.json >> $GITHUB_STEP_SUMMARY
            exit 1
          fi
```

## SIEM Integration

Pipe JSON output into your SIEM:

```bash
portdiff diff baseline.xml current.xml -f json | \
  curl -X POST https://siem.example.com/api/events \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SIEM_TOKEN" \
    -d @-
```

## masscan + portdiff (Fast Internet-Scale Monitoring)

Use masscan for speed, portdiff for analysis:

```bash
# Fast scan (all ports, high rate)
masscan -p1-65535 10.0.0.0/24 --rate 5000 -oJ masscan-$(date +%F).json

# Diff (both files are masscan JSON — auto-detected)
portdiff diff masscan-2026-01-01.json masscan-2026-01-08.json
```

## Compliance Reporting

Generate weekly CSV reports for your compliance team:

```bash
portdiff diff baseline.xml current.xml -f csv -o weekly-drift-$(date +%F).csv

# Optionally filter to just critical/warning changes
# (filter in Excel/pandas on the port_severity column)
```

## Ignore Ephemeral Ports

High-rate scanners can detect ephemeral ports (32768–60999). Ignore them:

```bash
# Build the ignore list for common ephemeral ranges
EPHEMERAL=$(seq 32768 60999 | tr '\n' ',' | sed 's/,$//')
portdiff diff before.xml after.xml --ignore-ports "$EPHEMERAL"
```

Or just ignore specific noisy ports:

```bash
portdiff diff before.xml after.xml --ignore-ports 8080,8443,9090
```
