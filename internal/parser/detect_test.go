package parser

import (
	"testing"
)

func TestDetectFormat_NmapXML(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"xml header", `<?xml version="1.0"?><nmaprun scanner="nmap">`},
		{"nmaprun tag", `<nmaprun scanner="nmap" version="7.94">`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectFormat([]byte(tc.input))
			if got != FormatNmapXML {
				t.Errorf("DetectFormat(%q) = %q, want %q", tc.input, got, FormatNmapXML)
			}
		})
	}
}

func TestDetectFormat_NmapGrepable(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"nmap comment", "# Nmap 7.94 scan initiated\nHost: 192.168.1.1 ()"},
		{"host line", "Host: 192.168.1.1 ()\tPorts: 80/open/tcp//http//"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectFormat([]byte(tc.input))
			if got != FormatNmapGrepable {
				t.Errorf("DetectFormat(%q) = %q, want %q", tc.input, got, FormatNmapGrepable)
			}
		})
	}
}

func TestDetectFormat_MasscanJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"masscan json array with ip", `[{"ip":"192.168.1.1","ports":[]}]`},
		{"masscan json with keyword", `[{"masscan":true}]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectFormat([]byte(tc.input))
			if got != FormatMasscanJSON {
				t.Errorf("DetectFormat(%q) = %q, want %q", tc.input, got, FormatMasscanJSON)
			}
		})
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	inputs := []string{
		"random text",
		"PORT   STATE SERVICE",
		"",
	}
	for _, input := range inputs {
		got := DetectFormat([]byte(input))
		if got == FormatNmapXML || got == FormatNmapGrepable || got == FormatMasscanJSON {
			t.Errorf("DetectFormat(%q) = %q, expected unknown or fallback", input, got)
		}
	}
}
