// Package output provides renderers for diff results in text, JSON, and CSV formats.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/redhoundinfosec/portdiff/internal/diff"
	"github.com/redhoundinfosec/portdiff/internal/parser"
)

// Format represents an output format.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

// ParseFormat converts a string to a Format, returning an error for unknown values.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "text", "":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	case "csv":
		return FormatCSV, nil
	default:
		return "", fmt.Errorf("unknown format %q: must be text, json, or csv", s)
	}
}

// Options configures output rendering.
type Options struct {
	Format   Format
	NoColor  bool
	Quiet    bool
	Verbose  bool
	Output   string // file path; empty = stdout
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// Renderer writes diff results to an output destination.
type Renderer struct {
	opts Options
	w    io.Writer
}

// NewRenderer creates a new Renderer with the given options.
// It opens the output file if opts.Output is set.
func NewRenderer(opts Options) (*Renderer, io.Closer, error) {
	var w io.Writer = os.Stdout
	var closer io.Closer = io.NopCloser(nil)

	if opts.Output != "" {
		f, err := os.Create(opts.Output)
		if err != nil {
			return nil, nil, fmt.Errorf("creating output file: %w", err)
		}
		w = f
		closer = f
	}

	return &Renderer{opts: opts, w: w}, closer, nil
}

// RenderDiff writes the diff result in the configured format.
func (r *Renderer) RenderDiff(result *diff.Result) error {
	if r.opts.Quiet {
		return nil
	}
	switch r.opts.Format {
	case FormatJSON:
		return r.renderDiffJSON(result)
	case FormatCSV:
		return r.renderDiffCSV(result)
	default:
		return r.renderDiffText(result)
	}
}

// RenderSummary writes the scan summary in the configured format.
func (r *Renderer) RenderSummary(scan *parser.ScanResult) error {
	if r.opts.Quiet {
		return nil
	}
	switch r.opts.Format {
	case FormatJSON:
		return r.renderSummaryJSON(scan)
	case FormatCSV:
		return r.renderSummaryCSV(scan)
	default:
		return r.renderSummaryText(scan)
	}
}

// ============================================================
// Text rendering
// ============================================================

func (r *Renderer) color(code, s string) string {
	if r.opts.NoColor {
		return s
	}
	return code + s + colorReset
}

func (r *Renderer) bold(s string) string    { return r.color(colorBold, s) }
func (r *Renderer) red(s string) string     { return r.color(colorRed, s) }
func (r *Renderer) green(s string) string   { return r.color(colorGreen, s) }
func (r *Renderer) yellow(s string) string  { return r.color(colorYellow, s) }
func (r *Renderer) cyan(s string) string    { return r.color(colorCyan, s) }
func (r *Renderer) dim(s string) string     { return r.color(colorDim, s) }

func (r *Renderer) severityTag(s diff.Severity) string {
	switch s {
	case diff.SeverityCritical:
		return r.color(colorRed+colorBold, "[CRITICAL]")
	case diff.SeverityWarning:
		return r.color(colorYellow, "[WARNING]")
	default:
		return r.color(colorDim, "[INFO]")
	}
}

func (r *Renderer) renderDiffText(result *diff.Result) error {
	w := r.w
	baseName := filepath.Base(result.Baseline.Source)
	currName := filepath.Base(result.Current.Source)

	fmt.Fprintln(w, r.bold("portdiff v0.1.0 — Scan Comparison"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Baseline: %s (%d hosts, %d ports)\n",
		r.cyan(baseName), len(result.Baseline.Hosts), result.Baseline.TotalOpenPorts())
	fmt.Fprintf(w, "  Current:  %s (%d hosts, %d ports)\n",
		r.cyan(currName), len(result.Current.Hosts), result.Current.TotalOpenPorts())
	fmt.Fprintln(w)

	// Gather host groups
	var newHosts, removedHosts, changedHosts, unchangedHosts []diff.HostDiff
	for _, hd := range result.HostDiffs {
		switch hd.Kind {
		case diff.KindNewHost:
			newHosts = append(newHosts, hd)
		case diff.KindRemovedHost:
			removedHosts = append(removedHosts, hd)
		case diff.KindChangedHost:
			changedHosts = append(changedHosts, hd)
		case diff.KindUnchangedHost:
			unchangedHosts = append(unchangedHosts, hd)
		}
	}

	if len(newHosts) > 0 {
		fmt.Fprintln(w, r.bold(r.green("  NEW HOSTS")))
		for _, hd := range newHosts {
			r.printNewHost(w, hd)
		}
		fmt.Fprintln(w)
	}

	if len(removedHosts) > 0 {
		fmt.Fprintln(w, r.bold(r.red("  REMOVED HOSTS")))
		for _, hd := range removedHosts {
			r.printRemovedHost(w, hd)
		}
		fmt.Fprintln(w)
	}

	if len(changedHosts) > 0 {
		fmt.Fprintln(w, r.bold(r.yellow("  CHANGED HOSTS")))
		for _, hd := range changedHosts {
			r.printChangedHost(w, hd)
		}
		fmt.Fprintln(w)
	}

	if r.opts.Verbose && len(unchangedHosts) > 0 {
		fmt.Fprintln(w, r.bold(r.dim("  UNCHANGED HOSTS")))
		for _, hd := range unchangedHosts {
			openCount := 0
			if hd.CurrHost != nil {
				openCount = len(hd.CurrHost.OpenPorts())
			}
			fmt.Fprintf(w, "    %s (%d port(s), no changes)\n", hd.IP, openCount)
		}
		fmt.Fprintln(w)
	} else if len(unchangedHosts) > 0 {
		fmt.Fprintln(w, r.dim("  UNCHANGED HOSTS"))
		for _, hd := range unchangedHosts {
			openCount := 0
			if hd.CurrHost != nil {
				openCount = len(hd.CurrHost.OpenPorts())
			}
			fmt.Fprintf(w, "    %s (%d port(s), no changes)\n", hd.IP, openCount)
		}
		fmt.Fprintln(w)
	}

	// Summary line
	fmt.Fprintf(w, "  Summary: %d new host(s), %d removed host(s), %d changed host(s), %d unchanged\n",
		result.NewHosts, result.RemovedHosts, result.ChangedHosts, result.UnchangedHosts)
	fmt.Fprintf(w, "  %s %d | %s %d | %s %d\n",
		r.color(colorRed+colorBold, "Critical:"), result.CriticalCount,
		r.color(colorYellow, "Warning:"), result.WarningCount,
		r.color(colorDim, "Info:"), result.InfoCount,
	)

	if !result.HasChanges {
		fmt.Fprintln(w)
		fmt.Fprintln(w, r.green("  No changes detected."))
	}

	return nil
}

func (r *Renderer) printNewHost(w io.Writer, hd diff.HostDiff) {
	label := hd.IP
	if hd.Hostname != "" {
		label = fmt.Sprintf("%s (%s)", hd.IP, hd.Hostname)
	}
	fmt.Fprintf(w, "  %s %s\n", r.green("●"), r.bold(label))

	for i, pc := range hd.PortChanges {
		tree := "├─"
		if i == len(hd.PortChanges)-1 {
			tree = "└─"
		}
		fmt.Fprintf(w, "    %s %-10s %-8s %-16s %s\n",
			tree,
			fmt.Sprintf("%d/%s", pc.Port.Number, pc.Port.Protocol),
			string(pc.Port.State),
			pc.Port.Service,
			r.severityTag(pc.Severity),
		)
	}
}

func (r *Renderer) printRemovedHost(w io.Writer, hd diff.HostDiff) {
	label := hd.IP
	if hd.Hostname != "" {
		label = fmt.Sprintf("%s (%s)", hd.IP, hd.Hostname)
	}
	fmt.Fprintf(w, "  %s %s\n", r.red("○"), r.bold(label))

	for i, pc := range hd.PortChanges {
		tree := "├─"
		if i == len(hd.PortChanges)-1 {
			tree = "└─"
		}
		fmt.Fprintf(w, "    %s %-10s was %-6s %s\n",
			tree,
			fmt.Sprintf("%d/%s", pc.Port.Number, pc.Port.Protocol),
			string(pc.Port.State),
			pc.Port.Service,
		)
	}
}

func (r *Renderer) printChangedHost(w io.Writer, hd diff.HostDiff) {
	label := hd.IP
	if hd.Hostname != "" {
		label = fmt.Sprintf("%s (%s)", hd.IP, hd.Hostname)
	}
	fmt.Fprintf(w, "  %s %s\n", r.yellow("△"), r.bold(label))

	for _, pc := range hd.PortChanges {
		portKey := fmt.Sprintf("%d/%s", pc.Port.Number, pc.Port.Protocol)
		switch pc.Kind {
		case diff.KindNewPort:
			fmt.Fprintf(w, "    %s %-10s %-8s %-16s %s %s\n",
				r.green("+"),
				portKey,
				string(pc.Port.State),
				pc.Port.Service,
				r.severityTag(pc.Severity),
				r.dim("new port"),
			)
		case diff.KindRemovedPort:
			fmt.Fprintf(w, "    %s %-10s %-8s %-16s %s\n",
				r.red("-"),
				portKey,
				string(pc.Port.State),
				pc.Port.Service,
				r.dim("port removed"),
			)
		case diff.KindChangedPort:
			oldDesc := pc.OldPort.FullVersion()
			newDesc := pc.Port.FullVersion()
			changeDesc := ""
			if oldDesc != newDesc && (oldDesc != "" || newDesc != "") {
				changeDesc = fmt.Sprintf("%s → %s", oldDesc, newDesc)
			} else {
				changeDesc = "service changed"
			}
			fmt.Fprintf(w, "    %s %-10s %-8s %-16s %s  %s\n",
				r.yellow("~"),
				portKey,
				string(pc.Port.State),
				pc.Port.Service,
				r.severityTag(pc.Severity),
				r.dim(changeDesc),
			)
		case diff.KindUnchangedPort:
			if r.opts.Verbose {
				fmt.Fprintf(w, "    %s %-10s %-8s %s\n",
					r.dim("="),
					portKey,
					string(pc.Port.State),
					pc.Port.Service,
				)
			}
		}
	}
}

func (r *Renderer) renderSummaryText(scan *parser.ScanResult) error {
	w := r.w
	name := filepath.Base(scan.Source)
	fmt.Fprintln(w, r.bold("portdiff v0.1.0 — Scan Summary"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  File:    %s\n", r.cyan(name))
	fmt.Fprintf(w, "  Format:  %s\n", string(scan.Format))
	if scan.Scanner != "" {
		fmt.Fprintf(w, "  Scanner: %s\n", scan.Scanner)
	}
	if scan.ScanTime != "" {
		fmt.Fprintf(w, "  Time:    %s\n", scan.ScanTime)
	}
	fmt.Fprintf(w, "  Hosts:   %d\n", len(scan.Hosts))
	fmt.Fprintf(w, "  Ports:   %d open\n", scan.TotalOpenPorts())
	fmt.Fprintln(w)

	for _, ip := range scan.SortedIPs() {
		host := scan.HostMap[ip]
		label := ip
		if host.Hostname != "" {
			label = fmt.Sprintf("%s (%s)", ip, host.Hostname)
		}
		openPorts := host.OpenPorts()
		fmt.Fprintf(w, "  %s — %d open port(s)\n", r.bold(label), len(openPorts))
		for i, p := range openPorts {
			tree := "├─"
			if i == len(openPorts)-1 {
				tree = "└─"
			}
			desc := p.ServiceDescription()
			fmt.Fprintf(w, "    %s %-10s %s\n",
				tree,
				fmt.Sprintf("%d/%s", p.Number, p.Protocol),
				desc,
			)
		}
	}

	return nil
}

// ============================================================
// JSON rendering
// ============================================================

// jsonDiffResult is the JSON-serializable representation of a diff result.
type jsonDiffResult struct {
	Version  string           `json:"portdiff_version"`
	Baseline jsonScanMeta     `json:"baseline"`
	Current  jsonScanMeta     `json:"current"`
	Hosts    []jsonHostDiff   `json:"hosts"`
	Summary  jsonSummary      `json:"summary"`
}

type jsonScanMeta struct {
	Source  string `json:"source"`
	Format  string `json:"format"`
	Hosts   int    `json:"hosts"`
	Ports   int    `json:"open_ports"`
}

type jsonHostDiff struct {
	IP          string           `json:"ip"`
	Hostname    string           `json:"hostname,omitempty"`
	Change      string           `json:"change"`
	Severity    string           `json:"severity"`
	PortChanges []jsonPortChange `json:"port_changes,omitempty"`
}

type jsonPortChange struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Change   string `json:"change"`
	Severity string `json:"severity"`
	OldVersion string `json:"old_version,omitempty"`
}

type jsonSummary struct {
	NewHosts      int `json:"new_hosts"`
	RemovedHosts  int `json:"removed_hosts"`
	ChangedHosts  int `json:"changed_hosts"`
	UnchangedHosts int `json:"unchanged_hosts"`
	NewPorts      int `json:"new_ports"`
	RemovedPorts  int `json:"removed_ports"`
	ChangedPorts  int `json:"changed_ports"`
	Critical      int `json:"critical"`
	Warning       int `json:"warning"`
	Info          int `json:"info"`
	HasChanges    bool `json:"has_changes"`
}

func (r *Renderer) renderDiffJSON(result *diff.Result) error {
	out := jsonDiffResult{
		Version: "0.1.0",
		Baseline: jsonScanMeta{
			Source: result.Baseline.Source,
			Format: string(result.Baseline.Format),
			Hosts:  len(result.Baseline.Hosts),
			Ports:  result.Baseline.TotalOpenPorts(),
		},
		Current: jsonScanMeta{
			Source: result.Current.Source,
			Format: string(result.Current.Format),
			Hosts:  len(result.Current.Hosts),
			Ports:  result.Current.TotalOpenPorts(),
		},
		Summary: jsonSummary{
			NewHosts:       result.NewHosts,
			RemovedHosts:   result.RemovedHosts,
			ChangedHosts:   result.ChangedHosts,
			UnchangedHosts: result.UnchangedHosts,
			NewPorts:       result.TotalNewPorts,
			RemovedPorts:   result.TotalRemovedPorts,
			ChangedPorts:   result.TotalChangedPorts,
			Critical:       result.CriticalCount,
			Warning:        result.WarningCount,
			Info:           result.InfoCount,
			HasChanges:     result.HasChanges,
		},
	}

	for _, hd := range result.HostDiffs {
		jh := jsonHostDiff{
			IP:       hd.IP,
			Hostname: hd.Hostname,
			Change:   string(hd.Kind),
			Severity: string(hd.Severity),
		}
		for _, pc := range hd.PortChanges {
			if pc.Kind == diff.KindUnchangedPort && !r.opts.Verbose {
				continue
			}
			jp := jsonPortChange{
				Port:     fmt.Sprintf("%d", pc.Port.Number),
				Protocol: string(pc.Port.Protocol),
				State:    string(pc.Port.State),
				Service:  pc.Port.Service,
				Product:  pc.Port.Product,
				Version:  pc.Port.Version,
				Change:   string(pc.Kind),
				Severity: string(pc.Severity),
			}
			if pc.Kind == diff.KindChangedPort {
				jp.OldVersion = pc.OldPort.FullVersion()
			}
			jh.PortChanges = append(jh.PortChanges, jp)
		}
		out.Hosts = append(out.Hosts, jh)
	}

	enc := json.NewEncoder(r.w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func (r *Renderer) renderSummaryJSON(scan *parser.ScanResult) error {
	type jsonPort struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		State    string `json:"state"`
		Service  string `json:"service,omitempty"`
		Product  string `json:"product,omitempty"`
		Version  string `json:"version,omitempty"`
	}
	type jsonHost struct {
		IP       string     `json:"ip"`
		Hostname string     `json:"hostname,omitempty"`
		Status   string     `json:"status"`
		Ports    []jsonPort `json:"ports"`
	}
	type jsonSummaryResult struct {
		Version string     `json:"portdiff_version"`
		Source  string     `json:"source"`
		Format  string     `json:"format"`
		Scanner string     `json:"scanner,omitempty"`
		Hosts   []jsonHost `json:"hosts"`
		TotalHosts int     `json:"total_hosts"`
		TotalPorts int     `json:"total_open_ports"`
	}

	out := jsonSummaryResult{
		Version:    "0.1.0",
		Source:     scan.Source,
		Format:     string(scan.Format),
		Scanner:    scan.Scanner,
		TotalHosts: len(scan.Hosts),
		TotalPorts: scan.TotalOpenPorts(),
	}

	for _, ip := range scan.SortedIPs() {
		h := scan.HostMap[ip]
		jh := jsonHost{
			IP:       h.IP,
			Hostname: h.Hostname,
			Status:   h.Status,
		}
		for _, p := range h.OpenPorts() {
			jh.Ports = append(jh.Ports, jsonPort{
				Port:     p.Number,
				Protocol: string(p.Protocol),
				State:    string(p.State),
				Service:  p.Service,
				Product:  p.Product,
				Version:  p.Version,
			})
		}
		out.Hosts = append(out.Hosts, jh)
	}

	enc := json.NewEncoder(r.w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ============================================================
// CSV rendering
// ============================================================

func (r *Renderer) renderDiffCSV(result *diff.Result) error {
	cw := csv.NewWriter(r.w)
	defer cw.Flush()

	// Header
	if err := cw.Write([]string{
		"ip", "hostname", "host_change", "host_severity",
		"port", "protocol", "state", "service", "product", "version",
		"port_change", "port_severity", "old_version",
	}); err != nil {
		return err
	}

	for _, hd := range result.HostDiffs {
		if len(hd.PortChanges) == 0 {
			// Emit a row for the host itself
			if err := cw.Write([]string{
				hd.IP, hd.Hostname, string(hd.Kind), string(hd.Severity),
				"", "", "", "", "", "", "", "", "",
			}); err != nil {
				return err
			}
			continue
		}

		for _, pc := range hd.PortChanges {
			if pc.Kind == diff.KindUnchangedPort && !r.opts.Verbose {
				continue
			}
			oldVer := ""
			if pc.Kind == diff.KindChangedPort {
				oldVer = pc.OldPort.FullVersion()
			}
			if err := cw.Write([]string{
				hd.IP,
				hd.Hostname,
				string(hd.Kind),
				string(hd.Severity),
				fmt.Sprintf("%d", pc.Port.Number),
				string(pc.Port.Protocol),
				string(pc.Port.State),
				pc.Port.Service,
				pc.Port.Product,
				pc.Port.Version,
				string(pc.Kind),
				string(pc.Severity),
				oldVer,
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *Renderer) renderSummaryCSV(scan *parser.ScanResult) error {
	cw := csv.NewWriter(r.w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"ip", "hostname", "status", "port", "protocol", "state", "service", "product", "version",
	}); err != nil {
		return err
	}

	for _, ip := range scan.SortedIPs() {
		h := scan.HostMap[ip]
		for _, p := range h.OpenPorts() {
			if err := cw.Write([]string{
				h.IP, h.Hostname, h.Status,
				fmt.Sprintf("%d", p.Number),
				string(p.Protocol),
				string(p.State),
				p.Service,
				p.Product,
				p.Version,
			}); err != nil {
				return err
			}
		}
		if len(h.OpenPorts()) == 0 {
			if err := cw.Write([]string{
				h.IP, h.Hostname, h.Status,
				"", "", "", "", "", "",
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

// FormatIgnorePorts parses a comma-separated list of port numbers into a set.
func FormatIgnorePorts(s string) (map[int]bool, error) {
	if s == "" {
		return nil, nil
	}
	result := make(map[int]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}
		result[n] = true
	}
	return result, nil
}
