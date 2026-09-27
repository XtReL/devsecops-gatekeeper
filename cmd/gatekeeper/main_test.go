package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"devsecops-gatekeeper/internal/engine"
)

// gatekeeperBin is a real `go build` binary, not the `go test` binary this
// file itself compiles into. Its runtime/debug.ReadBuildInfo embeds the full
// module dependency graph (including gitleaks' version), unlike a `go test`
// binary's build info; running it as a subprocess is what lets these tests
// exercise engine.Scan's real, fail-secure gitleaksVersion check end-to-end.
var gatekeeperBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gatekeeper-bin-*")
	if err != nil {
		panic("mkdir temp: " + err.Error())
	}
	defer os.RemoveAll(dir)

	gatekeeperBin = filepath.Join(dir, "gatekeeper")
	build := exec.Command("go", "build", "-o", gatekeeperBin, ".")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic("build gatekeeper binary: " + err.Error())
	}

	os.Exit(m.Run())
}

// fakeToken builds a synthetic, high-entropy secret at runtime out of an
// algorithm and a small alphabet (never a literal secret-looking string),
// so this repository's own test fixtures don't trip gitleaks/GitGuardian.
func fakeToken(prefix string, n int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	x := uint32(0x2545F491)
	b := make([]byte, n)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = alphabet[x%uint32(len(alphabet))]
	}
	return prefix + string(b)
}

// runGatekeeper runs the real built binary and returns its exit code.
func runGatekeeper(t *testing.T, args ...string) (code int, stderr string) {
	t.Helper()
	cmd := exec.Command(gatekeeperBin, args...)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		return 0, errBuf.String()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), errBuf.String()
	}
	t.Fatalf("run gatekeeper %v: %v (stderr: %s)", args, err, errBuf.String())
	return -1, errBuf.String()
}

func TestRunScanCleanDirectoryExitsZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("nothing to see here\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out := filepath.Join(t.TempDir(), "result.json")

	code, stderr := runGatekeeper(t, "scan", "--source", dir, "--out", out)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var result engine.Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", result.Findings)
	}
	// The gatekeeper binary is a real go build artifact, so unlike this test
	// binary, its build info reliably embeds gitleaks' pinned version.
	if result.GitleaksVersion != "v8.30.1" {
		t.Fatalf("expected gitleaksVersion %q, got %q", "v8.30.1", result.GitleaksVersion)
	}
}

func TestRunScanWithFindingsExitsOne(t *testing.T) {
	dir := t.TempDir()
	token := fakeToken("gh"+"p_", 36)
	if err := os.WriteFile(filepath.Join(dir, "leak.txt"), []byte("token=\""+token+"\"\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out := filepath.Join(t.TempDir(), "result.json")

	code, stderr := runGatekeeper(t, "scan", "--source", dir, "--out", out)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d (stderr: %s)", code, stderr)
	}
}

func TestRunScanMissingFlagsExitsTwo(t *testing.T) {
	code, _ := runGatekeeper(t, "scan")
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunVersion(t *testing.T) {
	if code, stderr := runGatekeeper(t, "version"); code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr)
	}
}
