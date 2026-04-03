// Package diff provides the core diffing engine and severity classification
// for comparing network scan results.
package diff

import "github.com/redhoundinfosec/portdiff/internal/parser"

// Severity represents the severity level of a change.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityWarning  Severity = "WARNING"
	SeverityInfo     Severity = "INFO"
)

// highRiskPorts is the set of ports that are considered critical when newly opened.
// These ports expose high-risk services (RDP, SMB, telnet, databases, caches, etc.)
var highRiskPorts = map[int]bool{
	21:    true, // FTP
	22:    true, // SSH
	23:    true, // Telnet
	25:    true, // SMTP
	53:    true, // DNS
	139:   true, // NetBIOS
	445:   true, // SMB/Windows shares
	1433:  true, // MSSQL
	1521:  true, // Oracle DB
	3306:  true, // MySQL
	3389:  true, // RDP
	5432:  true, // PostgreSQL
	5900:  true, // VNC
	6379:  true, // Redis
	// 8080 is intentionally not in high-risk: too common in dev environments
	9200:  true, // Elasticsearch
	11211: true, // Memcached
	27017: true, // MongoDB
}

// ClassifyNewPort returns the severity for a newly-appeared open port.
func ClassifyNewPort(port parser.Port) Severity {
	if highRiskPorts[port.Number] {
		return SeverityCritical
	}
	return SeverityWarning
}

// ClassifyRemovedPort returns the severity for a port that was removed.
func ClassifyRemovedPort(_ parser.Port) Severity {
	return SeverityInfo
}

// ClassifyVersionChange returns the severity for a service version change.
func ClassifyVersionChange(_, _ parser.Port) Severity {
	return SeverityWarning
}

// ClassifyNewHost returns the severity for a newly-appeared host.
// It considers the ports on the new host.
func ClassifyNewHost(host *parser.Host) Severity {
	sev := SeverityInfo
	for _, p := range host.OpenPorts() {
		ps := ClassifyNewPort(p)
		if ps == SeverityCritical {
			return SeverityCritical
		}
		if ps == SeverityWarning {
			sev = SeverityWarning
		}
	}
	return sev
}

// ClassifyRemovedHost returns the severity for a host that disappeared.
func ClassifyRemovedHost(_ *parser.Host) Severity {
	return SeverityWarning
}

// SeverityOrder returns a numeric value for ordering severities (higher = more severe).
func SeverityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// MaxSeverity returns the more severe of two severities.
func MaxSeverity(a, b Severity) Severity {
	if SeverityOrder(a) >= SeverityOrder(b) {
		return a
	}
	return b
}
