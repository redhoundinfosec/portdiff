// Package parser provides types and interfaces for parsing network scan results
// from various tools (nmap XML, nmap grepable, masscan JSON).
package parser

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Protocol represents the transport protocol for a port.
type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

// PortState represents whether a port is open, closed, or filtered.
type PortState string

const (
	StateOpen     PortState = "open"
	StateClosed   PortState = "closed"
	StateFiltered PortState = "filtered"
)

// Port represents a single scanned port with its associated service information.
type Port struct {
	Number   int       `json:"number"`
	Protocol Protocol  `json:"protocol"`
	State    PortState `json:"state"`
	Service  string    `json:"service"`  // Service name (e.g. "http", "ssh")
	Product  string    `json:"product"`  // Product name (e.g. "Apache httpd")
	Version  string    `json:"version"`  // Version string (e.g. "2.4.41")
	ExtraInfo string   `json:"extra_info,omitempty"`
}

// PortKey returns a unique string key for a port (e.g. "80/tcp").
func (p Port) PortKey() string {
	return fmt.Sprintf("%d/%s", p.Number, p.Protocol)
}

// ServiceDescription returns a human-readable description of the service.
func (p Port) ServiceDescription() string {
	parts := []string{}
	if p.Service != "" {
		parts = append(parts, p.Service)
	}
	if p.Product != "" {
		parts = append(parts, p.Product)
	}
	if p.Version != "" {
		parts = append(parts, p.Version)
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, " ")
}

// FullVersion returns the product + version string (without service name).
func (p Port) FullVersion() string {
	parts := []string{}
	if p.Product != "" {
		parts = append(parts, p.Product)
	}
	if p.Version != "" {
		parts = append(parts, p.Version)
	}
	return strings.Join(parts, " ")
}

// Host represents a single scanned host with all its ports.
type Host struct {
	IP       string          `json:"ip"`
	Hostname string          `json:"hostname,omitempty"`
	Status   string          `json:"status"` // "up" or "down"
	Ports    []Port          `json:"ports"`
	PortMap  map[string]Port `json:"-"` // keyed by PortKey()
}

// BuildPortMap builds the PortMap from the Ports slice. Called after parsing.
func (h *Host) BuildPortMap() {
	h.PortMap = make(map[string]Port, len(h.Ports))
	for _, p := range h.Ports {
		h.PortMap[p.PortKey()] = p
	}
}

// OpenPorts returns only the open ports.
func (h *Host) OpenPorts() []Port {
	var open []Port
	for _, p := range h.Ports {
		if p.State == StateOpen {
			open = append(open, p)
		}
	}
	return open
}

// SortedPortKeys returns port keys sorted numerically.
func (h *Host) SortedPortKeys() []string {
	keys := make([]string, 0, len(h.PortMap))
	for k := range h.PortMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		// Parse port number for comparison
		var ni, nj int
		fmt.Sscanf(keys[i], "%d", &ni)
		fmt.Sscanf(keys[j], "%d", &nj)
		return ni < nj
	})
	return keys
}

// ScanResult represents the complete result of a network scan.
type ScanResult struct {
	Source    string          `json:"source"`   // filename
	Format    Format          `json:"format"`   // detected format
	ScanTime  string          `json:"scan_time,omitempty"`
	Scanner   string          `json:"scanner,omitempty"` // "nmap" or "masscan"
	Hosts     []Host          `json:"hosts"`
	HostMap   map[string]*Host `json:"-"` // keyed by IP
}

// Format represents the file format of a scan result.
type Format string

const (
	FormatNmapXML     Format = "nmap-xml"
	FormatNmapGrepable Format = "nmap-grepable"
	FormatMasscanJSON Format = "masscan-json"
	FormatUnknown     Format = "unknown"
)

// BuildHostMap builds the HostMap from the Hosts slice. Called after parsing.
func (s *ScanResult) BuildHostMap() {
	s.HostMap = make(map[string]*Host, len(s.Hosts))
	for i := range s.Hosts {
		s.Hosts[i].BuildPortMap()
		s.HostMap[s.Hosts[i].IP] = &s.Hosts[i]
	}
}

// TotalOpenPorts returns the total number of open ports across all hosts.
func (s *ScanResult) TotalOpenPorts() int {
	total := 0
	for _, h := range s.Hosts {
		total += len(h.OpenPorts())
	}
	return total
}

// SortedIPs returns host IPs in sorted order.
func (s *ScanResult) SortedIPs() []string {
	ips := make([]string, 0, len(s.HostMap))
	for ip := range s.HostMap {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPs(ips[i], ips[j])
	})
	return ips
}

// compareIPs compares two IP address strings numerically.
func compareIPs(a, b string) bool {
	var a1, a2, a3, a4, b1, b2, b3, b4 int
	fmt.Sscanf(a, "%d.%d.%d.%d", &a1, &a2, &a3, &a4)
	fmt.Sscanf(b, "%d.%d.%d.%d", &b1, &b2, &b3, &b4)
	if a1 != b1 { return a1 < b1 }
	if a2 != b2 { return a2 < b2 }
	if a3 != b3 { return a3 < b3 }
	return a4 < b4
}

// Parse reads and parses a scan file, auto-detecting the format.
func Parse(filename string) (*ScanResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading file %q: %w", filename, err)
	}

	format := DetectFormat(data)

	var result *ScanResult
	switch format {
	case FormatNmapXML:
		result, err = ParseNmapXML(data)
	case FormatNmapGrepable:
		result, err = ParseNmapGrepable(data)
	case FormatMasscanJSON:
		result, err = ParseMasscanJSON(data)
	default:
		return nil, fmt.Errorf("unknown or unsupported file format for %q", filename)
	}

	if err != nil {
		return nil, fmt.Errorf("parsing %q as %s: %w", filename, format, err)
	}

	result.Source = filename
	result.Format = format
	result.BuildHostMap()
	return result, nil
}
