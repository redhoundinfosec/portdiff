package parser

import (
	"testing"
)

const sampleMasscanJSON = `[
{ "ip": "192.168.1.1", "timestamp": "1704067200", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64, "service": {"name": "http", "banner": ""}} ] },
{ "ip": "192.168.1.1", "timestamp": "1704067200", "ports": [ {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64, "service": {"name": "ssh", "banner": "SSH-2.0-OpenSSH_8.9p1"}} ] },
{ "ip": "192.168.1.10", "timestamp": "1704067201", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64, "service": {"name": "https", "banner": ""}} ] },
{ "ip": "192.168.1.20", "timestamp": "1704067202", "ports": [ {"port": 3389, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128, "service": {"name": "ms-wbt-server", "banner": ""}} ] }
]`

// Masscan sometimes outputs with trailing comma
const sampleMasscanJSONTrailingComma = `[
{ "ip": "192.168.1.1", "timestamp": "1704067200", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64, "service": {"name": "http", "banner": ""}} ] },
{ "ip": "192.168.1.10", "timestamp": "1704067201", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64, "service": {"name": "https", "banner": ""}} ] },
]`

func TestParseMasscanJSON_Basic(t *testing.T) {
	result, err := ParseMasscanJSON([]byte(sampleMasscanJSON))
	if err != nil {
		t.Fatalf("ParseMasscanJSON: unexpected error: %v", err)
	}

	result.BuildHostMap()

	// Should have 3 hosts (192.168.1.1, 192.168.1.10, 192.168.1.20)
	if len(result.Hosts) != 3 {
		t.Errorf("expected 3 hosts, got %d", len(result.Hosts))
	}

	h1, ok := result.HostMap["192.168.1.1"]
	if !ok {
		t.Fatal("expected host 192.168.1.1")
	}

	// 192.168.1.1 has two records (port 80 and port 22) — they should be merged
	if len(h1.Ports) != 2 {
		t.Errorf("expected 2 ports for 192.168.1.1 (merged), got %d", len(h1.Ports))
	}
}

func TestParseMasscanJSON_PortDetails(t *testing.T) {
	result, err := ParseMasscanJSON([]byte(sampleMasscanJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result.BuildHostMap()

	h20, ok := result.HostMap["192.168.1.20"]
	if !ok {
		t.Fatal("expected host 192.168.1.20")
	}
	h20.BuildPortMap()

	rdpPort, ok := h20.PortMap["3389/tcp"]
	if !ok {
		t.Fatal("expected 3389/tcp")
	}
	if rdpPort.State != StateOpen {
		t.Errorf("expected open, got %q", rdpPort.State)
	}
	if rdpPort.Service != "ms-wbt-server" {
		t.Errorf("expected service 'ms-wbt-server', got %q", rdpPort.Service)
	}
}

func TestParseMasscanJSON_TrailingComma(t *testing.T) {
	result, err := ParseMasscanJSON([]byte(sampleMasscanJSONTrailingComma))
	if err != nil {
		t.Fatalf("ParseMasscanJSON with trailing comma: unexpected error: %v", err)
	}
	result.BuildHostMap()

	if len(result.Hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(result.Hosts))
	}
}

func TestParseMasscanJSON_Scanner(t *testing.T) {
	result, err := ParseMasscanJSON([]byte(sampleMasscanJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scanner != "masscan" {
		t.Errorf("expected scanner 'masscan', got %q", result.Scanner)
	}
}

func TestParseMasscanJSON_Banner(t *testing.T) {
	result, err := ParseMasscanJSON([]byte(sampleMasscanJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result.BuildHostMap()

	h1 := result.HostMap["192.168.1.1"]
	h1.BuildPortMap()

	sshPort, ok := h1.PortMap["22/tcp"]
	if !ok {
		t.Fatal("expected 22/tcp")
	}
	if sshPort.ExtraInfo != "SSH-2.0-OpenSSH_8.9p1" {
		t.Errorf("expected banner as extra info, got %q", sshPort.ExtraInfo)
	}
}

func TestCleanMasscanJSON(t *testing.T) {
	tests := []struct {
		input    string
		wantEnd  string
	}{
		{`[{"ip":"1.1.1.1"},]`, `]`},
		{`[{"ip":"1.1.1.1"},` + "\n]", `]`},
		{`[{"ip":"1.1.1.1"}]`, `]`},
	}

	for _, tc := range tests {
		cleaned := cleanMasscanJSON([]byte(tc.input))
		s := string(cleaned)
		if len(s) == 0 || s[len(s)-1] != ']' {
			t.Errorf("cleanMasscanJSON(%q): expected to end with ], got %q", tc.input, s)
		}
	}
}
