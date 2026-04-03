package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/redhoundinfosec/portdiff/internal/output"
	"github.com/redhoundinfosec/portdiff/internal/parser"
)

// SummaryCommand implements the 'summary' subcommand.
type SummaryCommand struct{}

func (c *SummaryCommand) Name() string     { return "summary" }
func (c *SummaryCommand) Synopsis() string { return "Summarize a single scan file" }

func (c *SummaryCommand) Run(args []string) int {
	fs := flag.NewFlagSet("summary", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	formatStr := mustStringFlag(fs, "f", "format", "text", "Output format: text, json, csv")
	outputFile := mustStringFlag(fs, "o", "output", "", "Write output to file")
	noColor := fs.Bool("no-color", false, "Disable colored output")
	quiet := mustBoolFlag(fs, "q", "quiet", false, "Exit code only, suppress all output")

	// Separate flags from positional args to support interleaved usage
	flags, positional := splitArgs(args)

	if err := fs.Parse(flags); err != nil {
		fmt.Fprintf(os.Stderr, "portdiff summary: %v\n", err)
		return ExitError
	}

	remaining := append(positional, fs.Args()...)
	if len(remaining) != 1 {
		fmt.Fprintf(os.Stderr, "portdiff summary: requires exactly 1 scan file\n")
		fmt.Fprintf(os.Stderr, "Usage: portdiff summary [flags] <scan-file>\n")
		return ExitError
	}

	scanFile := remaining[0]

	// Parse output format
	fmt_, err := output.ParseFormat(*formatStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portdiff summary: %v\n", err)
		return ExitError
	}

	// Parse scan file
	scan, err := parser.Parse(scanFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portdiff summary: parsing %q: %v\n", scanFile, err)
		return ExitError
	}

	// Render
	renderOpts := output.Options{
		Format:  fmt_,
		NoColor: *noColor,
		Quiet:   *quiet,
		Output:  *outputFile,
	}

	renderer, closer, err := output.NewRenderer(renderOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portdiff summary: output: %v\n", err)
		return ExitError
	}
	defer closer.Close()

	if err := renderer.RenderSummary(scan); err != nil {
		fmt.Fprintf(os.Stderr, "portdiff summary: rendering output: %v\n", err)
		return ExitError
	}

	return ExitOK
}

// VersionCommand implements the 'version' subcommand.
type VersionCommand struct{}

func (c *VersionCommand) Name() string     { return "version" }
func (c *VersionCommand) Synopsis() string { return "Print version information" }

func (c *VersionCommand) Run(_ []string) int {
	fmt.Printf("portdiff v%s\n", version)
	fmt.Println("Copyright 2026 Red Hound Information Security LLC")
	fmt.Println("License: MIT")
	fmt.Println("https://github.com/redhoundinfosec/portdiff")
	return ExitOK
}
