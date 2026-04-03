package parser

import (
	"testing"
)

const sampleGrepable = `# Nmap 7.94 scan initiated Thu Jan 01 00:00:00 2026 as: nmap -sV -oG test.gnmap 192.168.1.0/24
Host: 192.168.1.1 (router.local)	Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/, 80/open/tcp//http//Apache httpd 2.4.41/	Ignored State: closed (998)
Host: 192.168.1.10 ()	Ports: 80/open/tcp//http//nginx 1.18.0/, 443/open/tcp//https//nginx 1.18.0/	Ignored State: filtered (998)
Host: 192.168.1.20 ()	Ports: 22/open/tcp//ssh//, 3306/open/tcp//mysql//MySQL 5.7.34/	Ignored State: closed (998)
# Nmap done at Thu Jan 01 00:05:00 2026 -- 256 IP addresses (3 hosts up) scanned in 300.00 seconds
`

func TestParseNmapGrepable_Basic(t *testing.T) {
	result, err := ParseNmapGrepable([]byte(sampleGrepable))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Hosts) != 3 {
		t.Errorf("expected 3 hosts, got %d", len(result.Hosts))
	}
}

func TestParseNmapGrepable_HostDetails(t *testing.T) {
	result, err := ParseNmapGrepable([]byte(sampleGrepable))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result.BuildHostMap()

	h1, ok := result.HostMap["192.168.1.1"]
	if !ok {
		t.Fatal("expected host 192.168.1.1")
	}
	if h1.Hostname != "router.local" {
		t.Errorf("expected hostname 'router.local', got %q", h1.Hostname)
	}
	if h1.Status != "up" {
		t.Errorf("expected status 'up', got %q", h1.Status)
	}
}

func TestParseNmapGrepable_Ports(t *testing.T) {
	result, err := ParseNmapGrepable([]byte(sampleGrepable))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result.BuildHostMap()

	h1 := result.HostMap["192.168.1.1"]
	h1.BuildPortMap()

	if len(h1.OpenPorts()) != 2 {
		t.Errorf("expected 2 open ports for 192.168.1.1, got %d", len(h1.OpenPorts()))
	}

	sshPort, ok := h1.PortMap["22/tcp"]
	if !ok {
		t.Fatal("expected 22/tcp")
	}
	if sshPort.Service != "ssh" {
		t.Errorf("expected service 'ssh', got %q", sshPort.Service)
	}
	if sshPort.State != StateOpen {
		t.Errorf("expected state open, got %q", sshPort.State)
	}

	httpPort, ok := h1.PortMap["80/tcp"]
	if !ok {
		t.Fatal("expected 80/tcp")
	}
	if httpPort.Service != "http" {
		t.Errorf("expected service 'http', got %q", httpPort.Service)
	}
}

func TestParseNmapGrepable_VersionParsing(t *testing.T) {
	result, err := ParseNmapGrepable([]byte(sampleGrepable))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result.BuildHostMap()

	h := result.HostMap["192.168.1.20"]
	if h == nil {
		t.Fatal("expected host 192.168.1.20")
	}
	h.BuildPortMap()

	mysqlPort, ok := h.PortMap["3306/tcp"]
	if !ok {
		t.Fatal("expected 3306/tcp")
	}
	if mysqlPort.Service != "mysql" {
		t.Errorf("expected service 'mysql', got %q", mysqlPort.Service)
	}
}

func TestParseNmapGrepable_EmptyFile(t *testing.T) {
	result, err := ParseNmapGrepable([]byte("# Nmap 7.94 scan\n# Nmap done\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(result.Hosts))
	}
}

func TestLooksLikeVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"2.4.41", true},
		{"1.18.0", true},
		{"8.9p1", true},  // has digit and dot (version-like)
		{"Ubuntu", false},
		{"", false},
		{"v1.0", true},
	}

	for _, tc := range tests {
		got := looksLikeVersion(tc.input)
		if got != tc.expected {
			t.Errorf("looksLikeVersion(%q) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}

func TestParseVersionInfo(t *testing.T) {
	tests := []struct {
		input          string
		expectedProduct string
		expectedVersion string
	}{
		{"Apache httpd 2.4.41", "Apache httpd", "2.4.41"},
		{"nginx 1.18.0", "nginx", "1.18.0"},
		{"OpenSSH", "OpenSSH", ""},
		{"", "", ""},
	}

	for _, tc := range tests {
		p := &Port{}
		parseVersionInfo(p, tc.input)
		if p.Product != tc.expectedProduct {
			t.Errorf("parseVersionInfo(%q): product = %q, want %q", tc.input, p.Product, tc.expectedProduct)
		}
		if p.Version != tc.expectedVersion {
			t.Errorf("parseVersionInfo(%q): version = %q, want %q", tc.input, p.Version, tc.expectedVersion)
		}
	}
}
