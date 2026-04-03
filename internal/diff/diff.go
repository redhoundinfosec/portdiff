package diff

import (
	"sort"

	"github.com/redhoundinfosec/portdiff/internal/parser"
)

// PortChange represents a change to a single port on a host.
type PortChange struct {
	Key      string        // e.g. "80/tcp"
	Port     parser.Port   // current port state (or last-known for removed)
	OldPort  parser.Port   // previous port state (for changes)
	Kind     ChangeKind    // what kind of change
	Severity Severity      // computed severity
}

// ChangeKind represents the type of change.
type ChangeKind string

const (
	KindNewPort      ChangeKind = "new_port"
	KindRemovedPort  ChangeKind = "removed_port"
	KindChangedPort  ChangeKind = "changed_port"  // service/version changed
	KindUnchangedPort ChangeKind = "unchanged_port"
)

// HostDiff represents all changes for a single host.
type HostDiff struct {
	IP          string
	Hostname    string
	Kind        HostChangeKind
	Severity    Severity
	PortChanges []PortChange
	BaseHost    *parser.Host // from baseline scan
	CurrHost    *parser.Host // from current scan
}

// HostChangeKind represents how a host changed.
type HostChangeKind string

const (
	KindNewHost       HostChangeKind = "new_host"
	KindRemovedHost   HostChangeKind = "removed_host"
	KindChangedHost   HostChangeKind = "changed_host"
	KindUnchangedHost HostChangeKind = "unchanged_host"
)

// Result is the complete diff between two scans.
type Result struct {
	Baseline    *parser.ScanResult
	Current     *parser.ScanResult
	HostDiffs   []HostDiff

	// Aggregate counts
	NewHosts       int
	RemovedHosts   int
	ChangedHosts   int
	UnchangedHosts int

	TotalNewPorts     int
	TotalRemovedPorts int
	TotalChangedPorts int

	CriticalCount int
	WarningCount  int
	InfoCount     int

	HasChanges bool
}

// Options configures the diff behavior.
type Options struct {
	IgnorePorts map[int]bool // ports to ignore entirely
	OnlyNew     bool         // only report new hosts/ports
}

// Diff computes the difference between baseline and current scan results.
func Diff(baseline, current *parser.ScanResult, opts Options) *Result {
	res := &Result{
		Baseline: baseline,
		Current:  current,
	}

	// Collect all IPs from both scans
	allIPs := make(map[string]bool)
	for ip := range baseline.HostMap {
		allIPs[ip] = true
	}
	for ip := range current.HostMap {
		allIPs[ip] = true
	}

	// Sort IPs for deterministic output
	sortedIPs := make([]string, 0, len(allIPs))
	for ip := range allIPs {
		sortedIPs = append(sortedIPs, ip)
	}
	sort.Slice(sortedIPs, func(i, j int) bool {
		return compareIPs(sortedIPs[i], sortedIPs[j])
	})

	for _, ip := range sortedIPs {
		baseHost, inBase := baseline.HostMap[ip]
		currHost, inCurr := current.HostMap[ip]

		var hd HostDiff
		hd.IP = ip

		switch {
		case inBase && !inCurr:
			// Host removed
			hd.Kind = KindRemovedHost
			hd.BaseHost = baseHost
			hd.Hostname = baseHost.Hostname
			hd.Severity = ClassifyRemovedHost(baseHost)

			for _, p := range baseHost.OpenPorts() {
				if opts.IgnorePorts[p.Number] {
					continue
				}
				pc := PortChange{
					Key:      p.PortKey(),
					Port:     p,
					Kind:     KindRemovedPort,
					Severity: ClassifyRemovedPort(p),
				}
				hd.PortChanges = append(hd.PortChanges, pc)
			}

			if !opts.OnlyNew {
				res.RemovedHosts++
				res.HasChanges = true
			}

		case !inBase && inCurr:
			// New host
			hd.Kind = KindNewHost
			hd.CurrHost = currHost
			hd.Hostname = currHost.Hostname
			hd.Severity = ClassifyNewHost(currHost)

			for _, p := range currHost.OpenPorts() {
				if opts.IgnorePorts[p.Number] {
					continue
				}
				pc := PortChange{
					Key:      p.PortKey(),
					Port:     p,
					Kind:     KindNewPort,
					Severity: ClassifyNewPort(p),
				}
				hd.PortChanges = append(hd.PortChanges, pc)
			}

			res.NewHosts++
			res.HasChanges = true

		case inBase && inCurr:
			// Host exists in both — check for port changes
			hd.BaseHost = baseHost
			hd.CurrHost = currHost
			hd.Hostname = currHost.Hostname
			if hd.Hostname == "" {
				hd.Hostname = baseHost.Hostname
			}

			portChanges := diffHostPorts(baseHost, currHost, opts)
			hd.PortChanges = portChanges

			hasChange := false
			for _, pc := range portChanges {
				if pc.Kind != KindUnchangedPort {
					hasChange = true
					break
				}
			}

			if hasChange {
				hd.Kind = KindChangedHost
				hd.Severity = computeHostSeverity(portChanges)
				res.ChangedHosts++
				res.HasChanges = true
			} else {
				hd.Kind = KindUnchangedHost
				hd.Severity = SeverityInfo
				res.UnchangedHosts++
			}
		}

		// Filter unchanged hosts if --only-new
		if opts.OnlyNew && (hd.Kind == KindUnchangedHost || hd.Kind == KindRemovedHost) {
			continue
		}

		// Accumulate severity counts
		for _, pc := range hd.PortChanges {
			if pc.Kind == KindUnchangedPort {
				res.InfoCount++
				continue
			}
			switch pc.Severity {
			case SeverityCritical:
				res.CriticalCount++
			case SeverityWarning:
				res.WarningCount++
			case SeverityInfo:
				res.InfoCount++
			}
			switch pc.Kind {
			case KindNewPort:
				res.TotalNewPorts++
			case KindRemovedPort:
				res.TotalRemovedPorts++
			case KindChangedPort:
				res.TotalChangedPorts++
			}
		}

		res.HostDiffs = append(res.HostDiffs, hd)
	}

	return res
}

// diffHostPorts returns the list of port changes between two host states.
func diffHostPorts(base, curr *parser.Host, opts Options) []PortChange {
	var changes []PortChange

	// Collect all port keys
	allKeys := make(map[string]bool)
	for k := range base.PortMap {
		allKeys[k] = true
	}
	for k := range curr.PortMap {
		allKeys[k] = true
	}

	// Sort for deterministic output
	sortedKeys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		var ni, nj int
		_, _ = parsePortKey(sortedKeys[i], &ni)
		_, _ = parsePortKey(sortedKeys[j], &nj)
		return ni < nj
	})

	for _, key := range sortedKeys {
		basePort, inBase := base.PortMap[key]
		currPort, inCurr := curr.PortMap[key]

		// Apply ignore filter (by port number)
		portNum := 0
		if inBase {
			portNum = basePort.Number
		} else if inCurr {
			portNum = currPort.Number
		}
		if opts.IgnorePorts[portNum] {
			continue
		}

		switch {
		case inBase && !inCurr:
			// Only consider removal of open ports as a change
			if basePort.State == parser.StateOpen {
				changes = append(changes, PortChange{
					Key:      key,
					Port:     basePort,
					Kind:     KindRemovedPort,
					Severity: ClassifyRemovedPort(basePort),
				})
			}

		case !inBase && inCurr:
			if currPort.State == parser.StateOpen {
				changes = append(changes, PortChange{
					Key:      key,
					Port:     currPort,
					Kind:     KindNewPort,
					Severity: ClassifyNewPort(currPort),
				})
			}

		case inBase && inCurr:
			if portsChanged(basePort, currPort) {
				if currPort.State == parser.StateOpen {
					changes = append(changes, PortChange{
						Key:      key,
						Port:     currPort,
						OldPort:  basePort,
						Kind:     KindChangedPort,
						Severity: ClassifyVersionChange(basePort, currPort),
					})
				} else if basePort.State == parser.StateOpen {
					// Port went from open to closed/filtered
					changes = append(changes, PortChange{
						Key:      key,
						Port:     currPort,
						OldPort:  basePort,
						Kind:     KindRemovedPort,
						Severity: ClassifyRemovedPort(basePort),
					})
				}
			} else if currPort.State == parser.StateOpen {
				changes = append(changes, PortChange{
					Key:      key,
					Port:     currPort,
					Kind:     KindUnchangedPort,
					Severity: SeverityInfo,
				})
			}
		}
	}

	return changes
}

// portsChanged returns true if two ports differ in a meaningful way.
func portsChanged(a, b parser.Port) bool {
	if a.State != b.State {
		return true
	}
	if a.Service != b.Service {
		return true
	}
	if a.Product != b.Product {
		return true
	}
	if a.Version != b.Version {
		return true
	}
	return false
}

// computeHostSeverity returns the highest severity across all port changes.
func computeHostSeverity(changes []PortChange) Severity {
	sev := SeverityInfo
	for _, pc := range changes {
		if pc.Kind != KindUnchangedPort {
			sev = MaxSeverity(sev, pc.Severity)
		}
	}
	return sev
}

// parsePortKey extracts the port number from a key like "80/tcp".
func parsePortKey(key string, num *int) (string, error) {
	var proto string
	_, err := scanPortKey(key, num, &proto)
	return proto, err
}

func scanPortKey(key string, num *int, proto *string) (int, error) {
	n, err := sscanf2(key, num, proto)
	return n, err
}

func sscanf2(key string, num *int, proto *string) (int, error) {
	// Parse "80/tcp" manually
	for i, c := range key {
		if c == '/' {
			n := 0
			for _, d := range key[:i] {
				if d >= '0' && d <= '9' {
					n = n*10 + int(d-'0')
				} else {
					return 0, nil
				}
			}
			*num = n
			if proto != nil {
				*proto = key[i+1:]
			}
			return 2, nil
		}
	}
	return 0, nil
}

// compareIPs compares two IP address strings numerically.
func compareIPs(a, b string) bool {
	var a1, a2, a3, a4, b1, b2, b3, b4 int
	sscanfIP(a, &a1, &a2, &a3, &a4)
	sscanfIP(b, &b1, &b2, &b3, &b4)
	if a1 != b1 { return a1 < b1 }
	if a2 != b2 { return a2 < b2 }
	if a3 != b3 { return a3 < b3 }
	return a4 < b4
}

func sscanfIP(ip string, a, b, c, d *int) {
	octet := 0
	idx := 0
	nums := []*int{a, b, c, d}
	for _, ch := range ip {
		if ch == '.' {
			if idx < 4 {
				*nums[idx] = octet
			}
			idx++
			octet = 0
		} else if ch >= '0' && ch <= '9' {
			octet = octet*10 + int(ch-'0')
		}
	}
	if idx < 4 {
		*nums[idx] = octet
	}
}
