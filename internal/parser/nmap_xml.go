package parser

import (
	"encoding/xml"
	"fmt"
	"strconv"
)

// nmapRun is the top-level XML element of nmap -oX output.
type nmapRun struct {
	XMLName   xml.Name   `xml:"nmaprun"`
	Scanner   string     `xml:"scanner,attr"`
	StartStr  string     `xml:"startstr,attr"`
	Version   string     `xml:"version,attr"`
	Hosts     []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus   `xml:"status"`
	Addresses []nmapAddr   `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     nmapPorts    `xml:"ports"`
}

type nmapStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

// ParseNmapXML parses nmap -oX (XML) output into a ScanResult.
func ParseNmapXML(data []byte) (*ScanResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("XML unmarshal: %w", err)
	}

	result := &ScanResult{
		Scanner:  run.Scanner,
		ScanTime: run.StartStr,
	}

	for _, h := range run.Hosts {
		host := Host{
			Status: h.Status.State,
		}

		// Find IPv4 address
		for _, addr := range h.Addresses {
			if addr.AddrType == "ipv4" {
				host.IP = addr.Addr
				break
			}
		}
		if host.IP == "" {
			// Fallback: use first address
			for _, addr := range h.Addresses {
				host.IP = addr.Addr
				break
			}
		}

		// Find primary hostname
		for _, hn := range h.Hostnames.Hostnames {
			if hn.Type == "PTR" || host.Hostname == "" {
				host.Hostname = hn.Name
			}
		}

		// Parse ports
		for _, p := range h.Ports.Ports {
			portNum, err := strconv.Atoi(p.PortID)
			if err != nil {
				continue
			}
			port := Port{
				Number:    portNum,
				Protocol:  Protocol(p.Protocol),
				State:     PortState(p.State.State),
				Service:   p.Service.Name,
				Product:   p.Service.Product,
				Version:   p.Service.Version,
				ExtraInfo: p.Service.ExtraInfo,
			}
			host.Ports = append(host.Ports, port)
		}

		if host.IP != "" {
			result.Hosts = append(result.Hosts, host)
		}
	}

	return result, nil
}
