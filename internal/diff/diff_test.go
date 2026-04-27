package diff

import (
	"testing"

	"github.com/redhoundinfosec/portdiff/internal/parser"
)

// buildScan creates a simple ScanResult for testing.
func buildScan(hosts map[string][]parser.Port) *parser.ScanResult {
	s := &parser.ScanResult{}
	for ip, ports := range hosts {
		h := parser.Host{
			IP:     ip,
			Status: "up",
			Ports:  ports,
		}
		s.Hosts = append(s.Hosts, h)
	}
	s.BuildHostMap()
	return s
}

func openPort(num int, proto parser.Protocol, service, product, version string) parser.Port {
	return parser.Port{
		Number:   num,
		Protocol: proto,
		State:    parser.StateOpen,
		Service:  service,
		Product:  product,
		Version:  version,
	}
}

func TestDiff_NewHost(t *testing.T) {
	baseline := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "", "")},
	})
	current := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "", "")},
		"192.168.1.2": {openPort(22, parser.TCP, "ssh", "", "")},
	})

	result := Diff(baseline, current, Options{})

	if result.NewHosts != 1 {
		t.Errorf("expected 1 new host, got %d", result.NewHosts)
	}
	if !result.HasChanges {
		t.Error("expected HasChanges=true")
	}

	var newHost *HostDiff
	for i := range result.HostDiffs {
		if result.HostDiffs[i].Kind == KindNewHost {
			newHost = &result.HostDiffs[i]
			break
		}
	}
	if newHost == nil {
		t.Fatal("expected new host diff entry")
	}
	if newHost.IP != "192.168.1.2" {
		t.Errorf("expected new host IP 192.168.1.2, got %q", newHost.IP)
	}
}

func TestDiff_RemovedHost(t *testing.T) {
	baseline := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "", "")},
		"192.168.1.2": {openPort(22, parser.TCP, "ssh", "", "")},
	})
	current := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "", "")},
	})

	result := Diff(baseline, current, Options{})

	if result.RemovedHosts != 1 {
		t.Errorf("expected 1 removed host, got %d", result.RemovedHosts)
	}
	if !result.HasChanges {
		t.Error("expected HasChanges=true")
	}
}

func TestDiff_NewPort(t *testing.T) {
	baseline := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "", "")},
	})
	current := buildScan(map[string][]parser.Port{
		"192.168.1.1": {
			openPort(80, parser.TCP, "http", "", ""),
			openPort(3389, parser.TCP, "ms-wbt-server", "", ""),
		},
	})

	result := Diff(baseline, current, Options{})

	if result.ChangedHosts != 1 {
		t.Errorf("expected 1 changed host, got %d", result.ChangedHosts)
	}
	if result.TotalNewPorts != 1 {
		t.Errorf("expected 1 new port, got %d", result.TotalNewPorts)
	}
	if result.CriticalCount != 1 {
		t.Errorf("expected 1 critical change (RDP is high-risk), got %d", result.CriticalCount)
	}
}

func TestDiff_RemovedPort(t *testing.T) {
	baseline := buildScan(map[string][]parser.Port{
		"192.168.1.1": {
			openPort(80, parser.TCP, "http", "", ""),
			openPort(22, parser.TCP, "ssh", "", ""),
		},
	})
	current := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "", "")},
	})

	result := Diff(baseline, current, Options{})

	if result.ChangedHosts != 1 {
		t.Errorf("expected 1 changed host, got %d", result.ChangedHosts)
	}
	if result.TotalRemovedPorts != 1 {
		t.Errorf("expected 1 removed port, got %d", result.TotalRemovedPorts)
	}
}

func TestDiff_VersionChange(t *testing.T) {
	baseline := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "Apache httpd", "2.4.41")},
	})
	current := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "Apache httpd", "2.4.52")},
	})

	result := Diff(baseline, current, Options{})

	if result.ChangedHosts != 1 {
		t.Errorf("expected 1 changed host, got %d", result.ChangedHosts)
	}
	if result.TotalChangedPorts != 1 {
		t.Errorf("expected 1 changed port, got %d", result.TotalChangedPorts)
	}
	if result.WarningCount != 1 {
		t.Errorf("expected 1 warning (version change), got %d", result.WarningCount)
	}
}

func TestDiff_NoChanges(t *testing.T) {
	scan := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "Apache httpd", "2.4.41")},
		"192.168.1.2": {openPort(22, parser.TCP, "ssh", "OpenSSH", "8.9p1")},
	})

	result := Diff(scan, scan, Options{})

	if result.HasChanges {
		t.Error("expected no changes between identical scans")
	}
	if result.UnchangedHosts != 2 {
		t.Errorf("expected 2 unchanged hosts, got %d", result.UnchangedHosts)
	}
}

func TestDiff_PortOrdering_IsStableAcrossProtocols(t *testing.T) {
	baseline := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "", "")},
	})
	current := buildScan(map[string][]parser.Port{
		"192.168.1.1": {
			openPort(80, parser.TCP, "http", "", ""),
			openPort(80, parser.UDP, "domain", "", ""),
		},
	})

	result := Diff(baseline, current, Options{})
	if len(result.HostDiffs) != 1 {
		t.Fatalf("expected exactly 1 host diff, got %d", len(result.HostDiffs))
	}
	if result.HostDiffs[0].Kind != KindChangedHost {
		t.Fatalf("expected KindChangedHost, got %s", result.HostDiffs[0].Kind)
	}

	changes := result.HostDiffs[0].PortChanges
	if len(changes) == 0 {
		t.Fatalf("expected at least one port change")
	}

	// Ordering should be stable: the two 80/* entries should always be ordered by protocol.
	// We rely on lexicographic ordering of protocol strings ("tcp" before "udp").
	found80 := []string{}
	for _, pc := range changes {
		if pc.Port.Number == 80 {
			found80 = append(found80, string(pc.Port.Protocol))
		}
	}
	if len(found80) != 2 {
		t.Fatalf("expected 2 changes for port 80, got %d", len(found80))
	}
	if found80[0] != string(parser.TCP) || found80[1] != string(parser.UDP) {
		t.Fatalf("expected 80/tcp then 80/udp ordering, got %v", found80)
	}
}

func TestDiff_IgnorePorts(t *testing.T) {
	baseline := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "", "")},
	})
	current := buildScan(map[string][]parser.Port{
		"192.168.1.1": {
			openPort(80, parser.TCP, "http", "", ""),
			openPort(8080, parser.TCP, "http", "", ""),  // should be ignored
		},
	})

	result := Diff(baseline, current, Options{
		IgnorePorts: map[int]bool{8080: true},
	})

	if result.HasChanges {
		t.Error("expected no changes after ignoring port 8080")
	}
}

func TestDiff_OnlyNew(t *testing.T) {
	baseline := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "", "")},
		"192.168.1.2": {openPort(22, parser.TCP, "ssh", "", "")},
	})
	current := buildScan(map[string][]parser.Port{
		"192.168.1.1": {openPort(80, parser.TCP, "http", "", "")},
		"192.168.1.3": {openPort(445, parser.TCP, "microsoft-ds", "", "")},
	})

	result := Diff(baseline, current, Options{OnlyNew: true})

	// With --only-new: show new hosts/ports, skip removed and unchanged
	// New: 192.168.1.3
	// Removed: 192.168.1.2 (skipped by OnlyNew)
	// Unchanged: 192.168.1.1 (skipped by OnlyNew)
	for _, hd := range result.HostDiffs {
		if hd.Kind == KindRemovedHost || hd.Kind == KindUnchangedHost {
			t.Errorf("OnlyNew mode should not include %s hosts, got %s for %s", hd.Kind, hd.Kind, hd.IP)
		}
	}

	if result.NewHosts != 1 {
		t.Errorf("expected 1 new host, got %d", result.NewHosts)
	}
}

func TestDiff_FullScenario(t *testing.T) {
	// Mimics the spec's before/after scenario
	baseline := buildScan(map[string][]parser.Port{
		"192.168.1.1": {
			openPort(22, parser.TCP, "ssh", "OpenSSH", "8.9p1"),
			openPort(80, parser.TCP, "http", "Apache httpd", "2.4.41"),
		},
		"192.168.1.10": {
			openPort(80, parser.TCP, "http", "", ""),
			openPort(443, parser.TCP, "https", "", ""),
		},
		"192.168.1.20": {
			openPort(22, parser.TCP, "ssh", "", ""),
			openPort(3306, parser.TCP, "mysql", "", ""),
		},
	})
	current := buildScan(map[string][]parser.Port{
		"192.168.1.1": {
			openPort(22, parser.TCP, "ssh", "OpenSSH", "8.9p1"),
			openPort(80, parser.TCP, "http", "Apache httpd", "2.4.52"),   // version changed
			openPort(3389, parser.TCP, "ms-wbt-server", "", ""),          // new critical
		},
		"192.168.1.10": {
			openPort(80, parser.TCP, "http", "", ""),
			openPort(443, parser.TCP, "https", "", ""),
		},
		// 192.168.1.20 removed
		"192.168.1.30": { // new host
			openPort(445, parser.TCP, "microsoft-ds", "", ""),
			openPort(139, parser.TCP, "netbios-ssn", "", ""),
		},
	})

	result := Diff(baseline, current, Options{})

	if result.NewHosts != 1 {
		t.Errorf("expected 1 new host, got %d", result.NewHosts)
	}
	if result.RemovedHosts != 1 {
		t.Errorf("expected 1 removed host, got %d", result.RemovedHosts)
	}
	if result.ChangedHosts != 1 {
		t.Errorf("expected 1 changed host, got %d", result.ChangedHosts)
	}
	if result.UnchangedHosts != 1 {
		t.Errorf("expected 1 unchanged host, got %d", result.UnchangedHosts)
	}
	if !result.HasChanges {
		t.Error("expected HasChanges=true")
	}
	// 3389 new + 445 + 139 new on new host = at minimum 3 critical
	if result.CriticalCount < 3 {
		t.Errorf("expected at least 3 critical changes, got %d", result.CriticalCount)
	}
}
