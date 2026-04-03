package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/redhoundinfosec/portdiff/internal/diff"
	"github.com/redhoundinfosec/portdiff/internal/output"
	"github.com/redhoundinfosec/portdiff/internal/parser"
)

// DiffCommand implements the 'diff' subcommand.
type DiffCommand struct{}

func (c *DiffCommand) Name() string     { return "diff" }
func (c *DiffCommand) Synopsis() string { return "Compare two scan files" }

func (c *DiffCommand) Run(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	formatStr := mustStringFlag(fs, "f", "format", "text", "Output format: text, json, csv")
	outputFile := mustStringFlag(fs, "o", "output", "", "Write output to file")
	ignorePorts := fs.String("ignore-ports", "", "Comma-separated port numbers to ignore")
	onlyNew := fs.Bool("only-new", false, "Show only new hosts and ports")
	noColor := fs.Bool("no-color", false, "Disable colored output")
	quiet := mustBoolFlag(fs, "q", "quiet", false, "Exit code only, suppress all output")
	verbose := mustBoolFlag(fs, "v", "verbose", false, "Show all details including unchanged")

	// Separate flags from positional args to support interleaved usage
	flags, positional := splitArgs(args)

	if err := fs.Parse(flags); err != nil {
		fmt.Fprintf(os.Stderr, "portdiff diff: %v\n", err)
		return ExitError
	}

	// Also collect any remaining positional args from fs.Args() (flags before positional)
	remaining := append(positional, fs.Args()...)
	if len(remaining) != 2 {
		fmt.Fprintf(os.Stderr, "portdiff diff: requires exactly 2 scan files\n")
		fmt.Fprintf(os.Stderr, "Usage: portdiff diff [flags] <baseline> <current>\n")
		return ExitError
	}

	baselineFile := remaining[0]
	currentFile := remaining[1]

	// Parse output format
	fmt_, err := output.ParseFormat(*formatStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portdiff diff: %v\n", err)
		return ExitError
	}

	// Parse ignore-ports
	ignoredPorts, err := output.FormatIgnorePorts(*ignorePorts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portdiff diff: --ignore-ports: %v\n", err)
		return ExitError
	}

	// Parse scan files
	baseline, err := parser.Parse(baselineFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portdiff diff: parsing baseline %q: %v\n", baselineFile, err)
		return ExitError
	}

	current, err := parser.Parse(currentFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portdiff diff: parsing current %q: %v\n", currentFile, err)
		return ExitError
	}

	// Compute diff
	diffOpts := diff.Options{
		IgnorePorts: ignoredPorts,
		OnlyNew:     *onlyNew,
	}
	result := diff.Diff(baseline, current, diffOpts)

	// Render output
	renderOpts := output.Options{
		Format:  fmt_,
		NoColor: *noColor,
		Quiet:   *quiet,
		Verbose: *verbose,
		Output:  *outputFile,
	}

	renderer, closer, err := output.NewRenderer(renderOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portdiff diff: output: %v\n", err)
		return ExitError
	}
	defer closer.Close()

	if err := renderer.RenderDiff(result); err != nil {
		fmt.Fprintf(os.Stderr, "portdiff diff: rendering output: %v\n", err)
		return ExitError
	}

	// Exit codes: 0 = no changes, 1 = changes, 2 = error
	if result.HasChanges {
		return ExitChanges
	}
	return ExitOK
}
