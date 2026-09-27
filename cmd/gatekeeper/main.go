// Command gatekeeper scans a directory for leaked secrets using gitleaks'
// built-in rules and writes a deterministic result.json (see internal/engine).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"devsecops-gatekeeper/internal/engine"
	"devsecops-gatekeeper/internal/evidence"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// Exit codes: 0 clean, 1 findings present, 2 error. "record" additionally
// uses 3 to mean "already recorded" (see runRecord).
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gatekeeper <scan|evidence-init|record|version> [flags]")
		return 2
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "evidence-init":
		return runEvidenceInit(args[1:])
	case "record":
		return runRecord(args[1:])
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

// runEvidenceInit is a one-time, local client operation: it does not read
// GATEKEEPER_SIGNING_KEY and is never run in CI (see docs/adr/0001-action-evidence.md).
func runEvidenceInit(args []string) int {
	fs := flag.NewFlagSet("evidence-init", flag.ContinueOnError)
	dir := fs.String("evidence", "", "evidence log directory to create")
	repo := fs.String("repo", "", "OWNER/REPO")
	key := fs.String("key", "", "path to the log/attester Ed25519 private key (PKCS#8 PEM)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" || *repo == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "gatekeeper evidence-init: --evidence, --repo and --key are required")
		return 2
	}

	if err := evidence.Init(*dir, *repo, *key); err != nil {
		fmt.Fprintf(os.Stderr, "gatekeeper evidence-init: %v\n", err)
		return 2
	}
	fmt.Printf("initialised evidence log %s at %s\n", evidence.Origin(*repo), *dir)
	return 0
}

// Exit codes for record: 0 added, 2 error, 3 already recorded (idempotent).
func runRecord(args []string) int {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	result := fs.String("result", "", "path to the scan result.json")
	dir := fs.String("evidence", "", "evidence log directory")
	repo := fs.String("repo", "", "OWNER/REPO")
	commit := fs.String("commit", "", "full commit SHA the scan ran against")
	runURL := fs.String("run-url", "", "link to the CI run")
	runID := fs.String("run-id", "", "CI run id")
	runAttempt := fs.String("run-attempt", "", "CI run attempt")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *result == "" || *dir == "" || *repo == "" || *commit == "" || *runID == "" || *runAttempt == "" {
		fmt.Fprintln(os.Stderr, "gatekeeper record: --result, --evidence, --repo, --commit, --run-id and --run-attempt are required")
		return 2
	}

	err := evidence.Record(evidence.Params{
		ResultPath: *result,
		Evidence:   *dir,
		Repo:       *repo,
		Commit:     *commit,
		RunURL:     *runURL,
		RunID:      *runID,
		RunAttempt: *runAttempt,
	})
	switch {
	case err == nil:
		return 0
	case errors.Is(err, evidence.ErrAlreadyRecorded):
		fmt.Fprintf(os.Stderr, "gatekeeper record: run %s/%s already recorded\n", *runID, *runAttempt)
		return 3
	default:
		fmt.Fprintf(os.Stderr, "gatekeeper record: %v\n", err)
		return 2
	}
}
