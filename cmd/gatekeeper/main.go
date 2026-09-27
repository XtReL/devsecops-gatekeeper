// Command gatekeeper scans a directory for leaked secrets using gitleaks'
// built-in rules and writes a deterministic result.json (see internal/engine).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"devsecops-gatekeeper/internal/engine"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// Exit codes: 0 clean, 1 findings present, 2 error.
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gatekeeper <scan|version> [flags]")
		return 2
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "version":
		fmt.Printf("gatekeeper %s\n", engine.Version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "gatekeeper: unknown command %q\n", args[0])
		return 2
	}
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	source := fs.String("source", "", "directory to scan")
	out := fs.String("out", "", "path to write result.json")
	sarif := fs.String("sarif", "", "path to write a SARIF report (optional)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *source == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "gatekeeper scan: --source and --out are required")
		return 2
	}

	ctx := context.Background()

	result, err := engine.Scan(ctx, *source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gatekeeper scan: %v\n", err)
		return 2
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "gatekeeper scan: encode result: %v\n", err)
		return 2
	}
	data = append(data, '\n')

	// #nosec G306 -- result.json is a non-sensitive scan report (no secret values).
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gatekeeper scan: write result: %v\n", err)
		return 2
	}

	if *sarif != "" {
		if err := writeSARIF(ctx, *source, *sarif); err != nil {
			fmt.Fprintf(os.Stderr, "gatekeeper scan: %v\n", err)
			return 2
		}
	}

	if len(result.Findings) > 0 {
		return 1
	}
	return 0
}

func writeSARIF(ctx context.Context, source, path string) error {
	// #nosec G304 -- path comes from the operator's own --sarif flag.
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create sarif file: %w", err)
	}

	if err := engine.WriteSARIF(ctx, source, f); err != nil {
		_ = f.Close()
		return fmt.Errorf("write sarif: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close sarif file: %w", err)
	}
	return nil
}
