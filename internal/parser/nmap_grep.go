package parser

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// ParseNmapGrepable parses nmap -oG (grepable) output into a ScanResult.
//
// The grepable format looks like:
//
//	# Nmap 7.94 scan initiated ...
//	Host: 192.168.1.1 (hostname) Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/,
//	# Nmap done at ...
func ParseNmapGrepable(data []byte) (*ScanResult, error) {
	result := &ScanResult{}
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and pure comment lines (but capture scan time from them)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			// Try to capture start time from "# Nmap X.Y scan initiated DATE as: ..."
			if strings.Contains(line, "scan initiated") {
				parts := strings.SplitN(line, "scan initiated", 2)
				if len(parts) == 2 {
					timePart := strings.TrimSpace(parts[1])
					// Remove trailing "as: ..."
					if idx := strings.Index(timePart, " as:"); idx != -1 {
						timePart = strings.TrimSpace(timePart[:idx])
					}
					result.ScanTime = timePart
				}
			}
			continue
		}

		// Parse "Host:" lines
		if !strings.HasPrefix(line, "Host:") {
			continue
		}

		host, err := parseGrepableLine(line)
		if err != nil || host == nil {
			continue
		}
		result.Hosts = append(result.Hosts, *host)
	}

	result.Scanner = "nmap"
	return result, scanner.Err()
}

// parseGrepableLine parses a single "Host:" line from grepable output.
func parseGrepableLine(line string) (*Host, error) {
	// Format: Host: <ip> (<hostname>)\tPorts: <port-list>\tIgnored State: ...
	// Split by tab or multiple spaces
	// Normalize: replace tabs with spaces
	line = strings.ReplaceAll(line, "\t", " ")

	host := &Host{Status: "up"}

	// Extract IP and hostname: "Host: 192.168.1.1 (hostname)"
	remaining := strings.TrimPrefix(line, "Host:")
	remaining = strings.TrimSpace(remaining)

	// Split on first \t or multiple spaces to find sections
	// Actually grepable uses \t between fields
	// Re-split original
	sections := strings.Split(line, "\t")
	if len(sections) == 0 {
		// Try spaces
		sections = splitGrepableSections(line)
	}

	for _, section := range sections {
		section = strings.TrimSpace(section)
		if strings.HasPrefix(section, "Host:") {
			// Parse "Host: IP (hostname)"
			s := strings.TrimPrefix(section, "Host:")
			s = strings.TrimSpace(s)
			// Find IP (first token)
			fields := strings.Fields(s)
			if len(fields) == 0 {
				return nil, nil
			}
			host.IP = fields[0]
			// Hostname in parentheses
			if len(fields) > 1 {
				hn := strings.Trim(fields[1], "()")
				if hn != "" {
					host.Hostname = hn
				}
			}
		} else if strings.HasPrefix(section, "Ports:") {
			// Parse ports section
			portsStr := strings.TrimPrefix(section, "Ports:")
			portsStr = strings.TrimSpace(portsStr)
			ports := parseGrepablePorts(portsStr)
			host.Ports = append(host.Ports, ports...)
		} else if strings.HasPrefix(section, "Status:") {
			s := strings.TrimPrefix(section, "Status:")
			s = strings.TrimSpace(s)
			host.Status = strings.ToLower(strings.Fields(s)[0])
		}
	}

	if host.IP == "" {
		return nil, nil
	}

	// Handle the case where sections weren't tab-separated
	// Try parsing from the remaining string if no ports found
	if len(host.Ports) == 0 && strings.Contains(remaining, "Ports:") {
		idx := strings.Index(remaining, "Ports:")
		portsStr := strings.TrimPrefix(remaining[idx:], "Ports:")
		// Cut off at next field
		if tabIdx := strings.Index(portsStr, "\t"); tabIdx != -1 {
			portsStr = portsStr[:tabIdx]
		}
		portsStr = strings.TrimSpace(portsStr)
		host.Ports = parseGrepablePorts(portsStr)
	}

	return host, nil
}

// splitGrepableSections splits a line into sections based on known field prefixes.
func splitGrepableSections(line string) []string {
	prefixes := []string{"Host:", "Ports:", "Status:", "Ignored State:", "OS:", "Seq Index:", "IP ID Seq:"}
	var sections []string

	remaining := line
	for len(remaining) > 0 {
		found := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(remaining, prefix) {
				// Find the next prefix
				nextIdx := -1
				for _, nextPrefix := range prefixes {
					idx := strings.Index(remaining[len(prefix):], nextPrefix)
					if idx != -1 {
						idx += len(prefix)
						if nextIdx == -1 || idx < nextIdx {
							nextIdx = idx
						}
					}
				}
				if nextIdx == -1 {
					sections = append(sections, remaining)
					remaining = ""
				} else {
					sections = append(sections, remaining[:nextIdx])
					remaining = remaining[nextIdx:]
				}
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return sections
}

// parseGrepablePorts parses the ports string from a grepable "Ports:" field.
// Format: "22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu/, 80/open/tcp//http//Apache httpd 2.4.41/,"
func parseGrepablePorts(portsStr string) []Port {
	var ports []Port

	// Split by comma
	entries := strings.Split(portsStr, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Format: portnum/state/protocol/owner/service/rpc_info/version_info
		// The version info may contain spaces but fields are slash-separated
		parts := strings.Split(entry, "/")
		if len(parts) < 3 {
			continue
		}

		portNum, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			continue
		}

		state := strings.TrimSpace(parts[1])
		proto := strings.TrimSpace(parts[2])

		port := Port{
			Number:   portNum,
			Protocol: Protocol(proto),
			State:    PortState(state),
		}

		// parts[3] = owner (usually empty)
		// parts[4] = service name
		// parts[5] = rpc info (usually empty)
		// parts[6+] = version info (joined back)
		if len(parts) > 4 {
			port.Service = strings.TrimSpace(parts[4])
		}
		if len(parts) > 6 {
			versionInfo := strings.Join(parts[6:], "/")
			versionInfo = strings.TrimSpace(versionInfo)
			parseVersionInfo(&port, versionInfo)
		}

		ports = append(ports, port)
	}

	return ports
}

// parseVersionInfo splits a version info string into Product and Version.
// e.g. "Apache httpd 2.4.41" -> Product="Apache httpd", Version="2.4.41"
func parseVersionInfo(port *Port, versionInfo string) {
	if versionInfo == "" {
		return
	}
	// Try to find the last space-separated token that looks like a version number
	fields := strings.Fields(versionInfo)
	if len(fields) == 0 {
		return
	}

	// Check if last field looks like a version (contains a digit and a dot)
	last := fields[len(fields)-1]
	if len(fields) > 1 && looksLikeVersion(last) {
		port.Product = strings.Join(fields[:len(fields)-1], " ")
		port.Version = last
	} else {
		port.Product = versionInfo
	}
}

// looksLikeVersion returns true if a string looks like a version number.
func looksLikeVersion(s string) bool {
	hasDigit := false
	hasDot := false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
		if c == '.' {
			hasDot = true
		}
	}
	return hasDigit && hasDot
}
