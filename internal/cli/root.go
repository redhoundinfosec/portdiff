// Package cli implements the portdiff command-line interface.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
)

const version = "0.1.0"

// ExitCode constants define the process exit codes.
const (
	ExitOK      = 0 // No changes detected
	ExitChanges = 1 // Changes detected
	ExitError   = 2 // Error occurred
)

// Command is a CLI subcommand.
type Command interface {
	Name() string
	Synopsis() string
	Run(args []string) int
}

// Root is the top-level CLI handler.
type Root struct {
	commands map[string]Command
	output   io.Writer
}

// NewRoot creates a new Root with all registered commands.
func NewRoot() *Root {
	r := &Root{
		commands: make(map[string]Command),
		output:   os.Stderr,
	}
	r.register(&DiffCommand{})
	r.register(&SummaryCommand{})
	r.register(&VersionCommand{})
	return r
}

func (r *Root) register(cmd Command) {
	r.commands[cmd.Name()] = cmd
}

// Run dispatches to the appropriate subcommand based on args.
func (r *Root) Run(args []string) int {
	if len(args) == 0 {
		r.printUsage()
		return ExitError
	}

	// Handle global flags before subcommand
	switch args[0] {
	case "-h", "--help", "help":
		r.printUsage()
		return ExitOK
	case "-v", "--version", "version":
		fmt.Fprintf(r.output, "portdiff v%s\n", version)
		return ExitOK
	}

	cmd, ok := r.commands[args[0]]
	if !ok {
		fmt.Fprintf(r.output, "portdiff: unknown command %q\n\n", args[0])
		r.printUsage()
		return ExitError
	}

	return cmd.Run(args[1:])
}

func (r *Root) printUsage() {
	fmt.Fprintf(r.output, `portdiff v%s — Compare network scans and detect attack surface changes

Usage:
  portdiff <command> [flags] [arguments]

Commands:
  diff      Compare two scan files
  summary   Summarize a single scan file
  version   Print version information

Flags for diff:
  -f, --format string        Output format: text, json, csv (default: text)
  -o, --output string        Write output to file (default: stdout)
      --only-new             Show only new hosts and ports
      --ignore-ports string  Comma-separated port numbers to ignore
      --no-color             Disable colored output
  -q, --quiet                Exit code only, no output
  -v, --verbose              Show all details including unchanged hosts/ports

Examples:
  portdiff diff baseline.xml current.xml
  portdiff diff baseline.xml current.xml -f json -o report.json
  portdiff diff scan1.xml scan2.xml --only-new --ignore-ports 80,443
  portdiff summary scan.xml
  portdiff summary scan.xml -f csv

Supported formats (auto-detected):
  nmap XML      nmap -oX output
  nmap grepable nmap -oG output
  masscan JSON  masscan -oJ output

Exit codes:
  0  No changes detected
  1  Changes detected
  2  Error

`, version)
}

// mustStringFlag registers both short and long forms of a string flag.
func mustStringFlag(fs *flag.FlagSet, short, long, defaultVal, usage string) *string {
	v := fs.String(long, defaultVal, usage)
	if short != "" {
		fs.StringVar(v, short, defaultVal, usage+" (short)")
	}
	return v
}

// mustBoolFlag registers both short and long forms of a bool flag.
func mustBoolFlag(fs *flag.FlagSet, short, long string, defaultVal bool, usage string) *bool {
	v := fs.Bool(long, defaultVal, usage)
	if short != "" {
		fs.BoolVar(v, short, defaultVal, usage+" (short)")
	}
	return v
}

// splitArgs separates flag arguments from positional arguments.
// This allows flags to appear after positional arguments (e.g. portdiff diff file1 file2 --no-color).
// It walks through args and identifies anything starting with '-' (and its value if needed) as a flag,
// and everything else as a positional argument.
func splitArgs(args []string) (flags []string, positional []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			// Everything after -- is positional
			positional = append(positional, args[i+1:]...)
			return
		}
		if len(arg) > 0 && arg[0] == '-' {
			flags = append(flags, arg)
			// Check if the next arg is this flag's value (not another flag)
			// For flags like -f json or --format json
			if i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
				// It's a value if the flag doesn't look like a boolean flag
				// We can't easily know without the FlagSet, so we check if it contains '='
				// If the flag has =, it's self-contained; otherwise peek at next arg
				hasValue := false
				for _, c := range arg {
					if c == '=' {
						hasValue = true
						break
					}
				}
				if !hasValue && isValueFlag(arg) {
					i++
					flags = append(flags, args[i])
				}
			}
		} else {
			positional = append(positional, arg)
		}
	}
	return
}

// isValueFlag returns true if the flag takes a string value (not a boolean flag).
func isValueFlag(flag string) bool {
	// Strip leading dashes
	name := flag
	for len(name) > 0 && name[0] == '-' {
		name = name[1:]
	}
	// Known boolean flags (no value)
	boolFlags := map[string]bool{
		"only-new": true,
		"no-color": true,
		"quiet": true, "q": true,
		"verbose": true, "v": true,
	}
	return !boolFlags[name]
}
