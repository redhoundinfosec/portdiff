// portdiff compares network scan results from nmap or masscan and produces
// a clear, actionable diff showing new hosts, removed hosts, new/removed ports,
// and changed services.
//
// Usage:
//
//	portdiff diff <baseline> <current> [flags]
//	portdiff summary <scan> [flags]
//	portdiff version
//
// See README.md or run portdiff --help for full documentation.
package main

import (
	"os"

	"github.com/redhoundinfosec/portdiff/internal/cli"
)

func main() {
	root := cli.NewRoot()
	code := root.Run(os.Args[1:])
	os.Exit(code)
}
