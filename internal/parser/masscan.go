package parser

import (
	"encoding/json"
	"fmt"
	"strings"
)

// masscanRecord represents a single record in masscan -oJ output.
// Masscan JSON format is a JSON array of records, each with ip, timestamp, and ports.
type masscanRecord struct {
	IP        string          `json:"ip"`
	Timestamp string          `json:"timestamp"`
	Ports     []masscanPort   `json:"ports"`
}

type masscanPort struct {
	Port    int            `json:"port"`
	Proto   string         `json:"proto"`
	Status  string         `json:"status"`
	Reason  string         `json:"reason"`
	TTL     int            `json:"ttl"`
	Service masscanService `json:"service"`
}

type masscanService struct {
	Name   string `json:"name"`
	Banner string `json:"banner"`
}

// ParseMasscanJSON parses masscan -oJ output into a ScanResult.
//
// Masscan JSON format:
//
//	[
//	{ "ip": "192.168.1.1", "timestamp": "1609459200", "ports": [ {"port":80,"proto":"tcp","status":"open",...} ] },
//	...
//	]
//
// Note: masscan may also prefix the array with a comment line or wrap it differently.
func ParseMasscanJSON(data []byte) (*ScanResult, error) {
	// Masscan JSON sometimes has a trailing comma before the closing bracket,
	// making it invalid JSON. We need to handle that.
	cleaned := cleanMasscanJSON(data)

	var records []masscanRecord
	if err := json.Unmarshal(cleaned, &records); err != nil {
		// Try alternate: masscan sometimes outputs one JSON object per line (NDJSON)
		records2, err2 := parseMasscanNDJSON(data)
		if err2 != nil {
			return nil, fmt.Errorf("masscan JSON parse: %w (also tried NDJSON: %v)", err, err2)
		}
		records = records2
	}

	// Group records by IP (masscan can emit multiple records per IP, one per port)
	hostMap := make(map[string]*Host)
	for _, rec := range records {
		if rec.IP == "" {
			continue
		}
		host, ok := hostMap[rec.IP]
		if !ok {
			host = &Host{
				IP:     rec.IP,
				Status: "up",
			}
			hostMap[rec.IP] = host
		}

		for _, p := range rec.Ports {
			port := Port{
				Number:   p.Port,
				Protocol: Protocol(strings.ToLower(p.Proto)),
				State:    PortState(strings.ToLower(p.Status)),
				Service:  p.Service.Name,
			}
			// Use banner as extra info if available
			if p.Service.Banner != "" {
				port.ExtraInfo = p.Service.Banner
			}
			host.Ports = append(host.Ports, port)
		}
	}

	result := &ScanResult{
		Scanner: "masscan",
	}
	for _, host := range hostMap {
		result.Hosts = append(result.Hosts, *host)
	}

	return result, nil
}

// cleanMasscanJSON fixes common issues with masscan JSON output:
//   - Trailing commas before closing bracket
//   - masscan sometimes emits: [,\n{...},\n{...},\n]
func cleanMasscanJSON(data []byte) []byte {
	s := strings.TrimSpace(string(data))

	// Handle masscan's weird format: starts with "[," — remove leading comma
	if strings.HasPrefix(s, "[,") {
		s = "[" + s[2:]
	}

	// Remove trailing comma before closing bracket: },\n]
	// Replace ",\n]" or ", ]" or ",]" at end
	for _, pattern := range []string{",\n]", ", \n]", ",\r\n]", ", ]", ",]"} {
		if strings.HasSuffix(s, pattern) {
			s = s[:len(s)-len(pattern)] + "\n]"
			break
		}
	}

	return []byte(s)
}

// parseMasscanNDJSON handles newline-delimited JSON (one object per line).
func parseMasscanNDJSON(data []byte) ([]masscanRecord, error) {
	var records []masscanRecord
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "[" || line == "]" {
			continue
		}
		// Remove trailing comma
		line = strings.TrimRight(line, ",")
		if line == "" {
			continue
		}
		var rec masscanRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue // Skip malformed lines
		}
		if rec.IP != "" {
			records = append(records, rec)
		}
	}
	return records, nil
}
