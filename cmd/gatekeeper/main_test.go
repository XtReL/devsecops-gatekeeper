package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"devsecops-gatekeeper/internal/engine"
)

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

func TestRunScanCleanDirectoryExitsZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("nothing to see here\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out := filepath.Join(t.TempDir(), "result.json")

	code := run([]string{"scan", "--source", dir, "--out", out})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
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
}

func TestRunScanWithFindingsExitsOne(t *testing.T) {
	dir := t.TempDir()
	token := fakeToken("gh"+"p_", 36)
	if err := os.WriteFile(filepath.Join(dir, "leak.txt"), []byte("token=\""+token+"\"\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out := filepath.Join(t.TempDir(), "result.json")

	code := run([]string{"scan", "--source", dir, "--out", out})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRunScanMissingFlagsExitsTwo(t *testing.T) {
	code := run([]string{"scan"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunVersion(t *testing.T) {
	if code := run([]string{"version"}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}
