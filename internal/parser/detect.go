package parser

import (
	"bytes"
	"strings"
)

// DetectFormat inspects raw file bytes and returns the detected Format.
// It checks for XML header/nmaprun tag, masscan JSON structure, or falls back
// to nmap grepable format detection.
func DetectFormat(data []byte) Format {
	// Trim leading whitespace for detection
	trimmed := bytes.TrimSpace(data)

	// Check for XML (nmap -oX)
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.Contains(trimmed[:min(512, len(trimmed))], []byte("<nmaprun")) {
		return FormatNmapXML
	}

	// Check for masscan JSON — starts with array containing objects with "ip" and "ports"
	if bytes.HasPrefix(trimmed, []byte("[")) {
		// Look for masscan-specific structure
		header := trimmed[:min(256, len(trimmed))]
		if bytes.Contains(header, []byte("\"ip\"")) || bytes.Contains(header, []byte("masscan")) {
			return FormatMasscanJSON
		}
		// Also check the masscan comment prefix
		if bytes.HasPrefix(trimmed, []byte("[\n{")) || bytes.HasPrefix(trimmed, []byte("[\r\n{")) {
			return FormatMasscanJSON
		}
	}

	// masscan JSON can also start with a comment like: { "masscan" : ...
	if bytes.HasPrefix(trimmed, []byte("{")) {
		content := string(trimmed[:min(256, len(trimmed))])
		if strings.Contains(content, "masscan") {
			return FormatMasscanJSON
		}
	}

	// Check for nmap grepable format (-oG)
	// Grepable files start with "# Nmap" comments and have "Host:" lines
	content := string(trimmed[:min(1024, len(trimmed))])
	if strings.Contains(content, "# Nmap") || strings.Contains(content, "Host:") {
		return FormatNmapGrepable
	}

	// Check if it's a JSON array (masscan without obvious markers)
	if bytes.HasPrefix(trimmed, []byte("[")) {
		return FormatMasscanJSON
	}

	return FormatUnknown
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
