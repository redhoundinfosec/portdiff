package diff

import (
	"testing"

	"github.com/redhoundinfosec/portdiff/internal/parser"
)

func TestClassifyNewPort_HighRisk(t *testing.T) {
	highRiskPortNums := []int{445, 3389, 23, 1433, 3306, 5432, 6379, 27017, 11211, 9200}
	for _, num := range highRiskPortNums {
		p := parser.Port{Number: num, Protocol: parser.TCP, State: parser.StateOpen}
		sev := ClassifyNewPort(p)
		if sev != SeverityCritical {
			t.Errorf("port %d: expected CRITICAL, got %s", num, sev)
		}
	}
}

func TestClassifyNewPort_LowRisk(t *testing.T) {
	lowRiskPorts := []int{8443, 8888, 9999, 7777}
	for _, num := range lowRiskPorts {
		p := parser.Port{Number: num, Protocol: parser.TCP, State: parser.StateOpen}
		sev := ClassifyNewPort(p)
		if sev != SeverityWarning {
			t.Errorf("port %d: expected WARNING, got %s", num, sev)
		}
	}
}

func TestClassifyRemovedPort(t *testing.T) {
	p := parser.Port{Number: 80, Protocol: parser.TCP}
	sev := ClassifyRemovedPort(p)
	if sev != SeverityInfo {
		t.Errorf("expected INFO for removed port, got %s", sev)
	}
}

func TestClassifyVersionChange(t *testing.T) {
	old := parser.Port{Number: 80, Service: "http", Version: "2.4.41"}
	new := parser.Port{Number: 80, Service: "http", Version: "2.4.52"}
	sev := ClassifyVersionChange(old, new)
	if sev != SeverityWarning {
		t.Errorf("expected WARNING for version change, got %s", sev)
	}
}

func TestClassifyNewHost_WithCriticalPort(t *testing.T) {
	host := &parser.Host{
		IP:     "192.168.1.30",
		Status: "up",
		Ports: []parser.Port{
			{Number: 445, Protocol: parser.TCP, State: parser.StateOpen, Service: "microsoft-ds"},
			{Number: 139, Protocol: parser.TCP, State: parser.StateOpen, Service: "netbios-ssn"},
		},
	}
	sev := ClassifyNewHost(host)
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL for host with SMB ports, got %s", sev)
	}
}

func TestClassifyNewHost_WithOnlyLowRiskPorts(t *testing.T) {
	host := &parser.Host{
		IP:     "192.168.1.30",
		Status: "up",
		Ports: []parser.Port{
			{Number: 8080, Protocol: parser.TCP, State: parser.StateOpen, Service: "http"},
		},
	}
	sev := ClassifyNewHost(host)
	if sev != SeverityWarning {
		t.Errorf("expected WARNING for host with low-risk port, got %s", sev)
	}
}

func TestClassifyRemovedHost(t *testing.T) {
	host := &parser.Host{IP: "192.168.1.20"}
	sev := ClassifyRemovedHost(host)
	if sev != SeverityWarning {
		t.Errorf("expected WARNING for removed host, got %s", sev)
	}
}

func TestMaxSeverity(t *testing.T) {
	tests := []struct {
		a, b     Severity
		expected Severity
	}{
		{SeverityCritical, SeverityWarning, SeverityCritical},
		{SeverityWarning, SeverityInfo, SeverityWarning},
		{SeverityInfo, SeverityInfo, SeverityInfo},
		{SeverityWarning, SeverityCritical, SeverityCritical},
		{SeverityInfo, SeverityCritical, SeverityCritical},
	}
	for _, tc := range tests {
		got := MaxSeverity(tc.a, tc.b)
		if got != tc.expected {
			t.Errorf("MaxSeverity(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.expected)
		}
	}
}

func TestSeverityOrder(t *testing.T) {
	if SeverityOrder(SeverityCritical) <= SeverityOrder(SeverityWarning) {
		t.Error("CRITICAL should have higher order than WARNING")
	}
	if SeverityOrder(SeverityWarning) <= SeverityOrder(SeverityInfo) {
		t.Error("WARNING should have higher order than INFO")
	}
}
