package parser

import (
	"testing"
)

const sampleNmapXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX test.xml 192.168.1.0/24" start="1704067200" startstr="Thu Jan 01 00:00:00 2026" version="7.94">
<host starttime="1704067201" endtime="1704067210">
  <status state="up" reason="echo-reply"/>
  <address addr="192.168.1.1" addrtype="ipv4"/>
  <hostnames>
    <hostname name="router.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux; protocol 2.0"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.4.41"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="closed" reason="reset"/>
      <service name="https"/>
    </port>
  </ports>
</host>
<host starttime="1704067211" endtime="1704067220">
  <status state="up" reason="echo-reply"/>
  <address addr="192.168.1.10" addrtype="ipv4"/>
  <hostnames/>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="nginx" version="1.18.0"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="https" product="nginx" version="1.18.0"/>
    </port>
    <port protocol="tcp" portid="3306">
      <state state="filtered" reason="no-response"/>
      <service name="mysql"/>
    </port>
  </ports>
</host>
</nmaprun>`

func TestParseNmapXML_Basic(t *testing.T) {
	result, err := ParseNmapXML([]byte(sampleNmapXML))
	if err != nil {
		t.Fatalf("ParseNmapXML: unexpected error: %v", err)
	}

	if len(result.Hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(result.Hosts))
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
	if len(h1.Ports) != 3 {
		t.Errorf("expected 3 ports on 192.168.1.1, got %d", len(h1.Ports))
	}

	// Check open port count
	open := h1.OpenPorts()
	if len(open) != 2 {
		t.Errorf("expected 2 open ports, got %d", len(open))
	}
}

func TestParseNmapXML_PortDetails(t *testing.T) {
	result, err := ParseNmapXML([]byte(sampleNmapXML))
	if err != nil {
		t.Fatalf("ParseNmapXML: unexpected error: %v", err)
	}
	result.BuildHostMap()

	h1 := result.HostMap["192.168.1.1"]
	h1.BuildPortMap()

	// Check ssh port
	sshPort, ok := h1.PortMap["22/tcp"]
	if !ok {
		t.Fatal("expected 22/tcp port")
	}
	if sshPort.Service != "ssh" {
		t.Errorf("expected service 'ssh', got %q", sshPort.Service)
	}
	if sshPort.Product != "OpenSSH" {
		t.Errorf("expected product 'OpenSSH', got %q", sshPort.Product)
	}
	if sshPort.Version != "8.9p1" {
		t.Errorf("expected version '8.9p1', got %q", sshPort.Version)
	}
	if sshPort.State != StateOpen {
		t.Errorf("expected state open, got %q", sshPort.State)
	}

	// Check http port
	httpPort, ok := h1.PortMap["80/tcp"]
	if !ok {
		t.Fatal("expected 80/tcp port")
	}
	if httpPort.Product != "Apache httpd" {
		t.Errorf("expected product 'Apache httpd', got %q", httpPort.Product)
	}
	if httpPort.Version != "2.4.41" {
		t.Errorf("expected version '2.4.41', got %q", httpPort.Version)
	}

	// Check closed port is included but not open
	httpsPort, ok := h1.PortMap["443/tcp"]
	if !ok {
		t.Fatal("expected 443/tcp port")
	}
	if httpsPort.State != StateClosed {
		t.Errorf("expected state closed for 443/tcp, got %q", httpsPort.State)
	}
}

func TestParseNmapXML_Scanner(t *testing.T) {
	result, err := ParseNmapXML([]byte(sampleNmapXML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scanner != "nmap" {
		t.Errorf("expected scanner 'nmap', got %q", result.Scanner)
	}
}

func TestParseNmapXML_InvalidXML(t *testing.T) {
	_, err := ParseNmapXML([]byte("not valid xml <><>"))
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestParseNmapXML_EmptyNmaprun(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"></nmaprun>`
	result, err := ParseNmapXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(result.Hosts))
	}
}

func TestPort_PortKey(t *testing.T) {
	p := Port{Number: 443, Protocol: TCP}
	if p.PortKey() != "443/tcp" {
		t.Errorf("expected '443/tcp', got %q", p.PortKey())
	}
}

func TestPort_ServiceDescription(t *testing.T) {
	p := Port{Service: "http", Product: "Apache httpd", Version: "2.4.41"}
	desc := p.ServiceDescription()
	if desc != "http Apache httpd 2.4.41" {
		t.Errorf("unexpected service description: %q", desc)
	}

	empty := Port{}
	if empty.ServiceDescription() != "unknown" {
		t.Errorf("expected 'unknown' for empty port, got %q", empty.ServiceDescription())
	}
}

func TestScanResult_TotalOpenPorts(t *testing.T) {
	result, err := ParseNmapXML([]byte(sampleNmapXML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result.BuildHostMap()

	// 192.168.1.1: 2 open (22, 80); 443 is closed
	// 192.168.1.10: 2 open (80, 443); 3306 is filtered
	total := result.TotalOpenPorts()
	if total != 4 {
		t.Errorf("expected 4 total open ports, got %d", total)
	}
}
