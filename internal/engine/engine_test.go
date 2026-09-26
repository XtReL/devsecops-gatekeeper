package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func marshal(t *testing.T, r Result) []byte {
	t.Helper()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(data, '\n')
}

func TestScanIsDeterministicAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	token1 := githubPAT()
	token2 := githubPAT()
	writeFile(t, filepath.Join(dir, "a.txt"), "token=\""+token1+"\"\n")
	writeFile(t, filepath.Join(dir, "b.txt"), "token=\""+token2+"\"\n")

	r1, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	r2, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}

	if len(r1.Findings) == 0 {
		t.Fatalf("expected findings, got none")
	}

	b1, b2 := marshal(t, r1), marshal(t, r2)
	if string(b1) != string(b2) {
		t.Fatalf("scan result not byte-identical across runs:\n%s\n---\n%s", b1, b2)
	}
}

func TestScanIsIndependentOfFileCreationOrder(t *testing.T) {
	tokenA := githubPAT()
	tokenB := githubPAT()

	forward := t.TempDir()
	writeFile(t, filepath.Join(forward, "a.txt"), tokenA)
	writeFile(t, filepath.Join(forward, "b.txt"), tokenB)

	backward := t.TempDir()
	writeFile(t, filepath.Join(backward, "b.txt"), tokenB)
	writeFile(t, filepath.Join(backward, "a.txt"), tokenA)

	rf, err := Scan(context.Background(), forward)
	if err != nil {
		t.Fatalf("scan forward: %v", err)
	}
	rb, err := Scan(context.Background(), backward)
	if err != nil {
		t.Fatalf("scan backward: %v", err)
	}

	if len(rf.Findings) == 0 {
		t.Fatalf("expected findings, got none")
	}

	bf, bb := marshal(t, rf), marshal(t, rb)
	if string(bf) != string(bb) {
		t.Fatalf("scan result depends on file creation order:\n%s\n---\n%s", bf, bb)
	}
}

func TestScanCleanDirectoryHasNoFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "readme.txt"), "nothing to see here\n")

	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r.Findings == nil {
		t.Fatalf("Findings must be an empty slice, not nil")
	}
	if len(r.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", r.Findings)
	}

	data := marshal(t, r)
	if !strings.Contains(string(data), `"findings": []`) {
		t.Fatalf("expected empty findings array in JSON, got: %s", data)
	}
}

func TestScanIgnoresDotGitDirectory(t *testing.T) {
	dir := t.TempDir()
	token := githubPAT()
	writeFile(t, filepath.Join(dir, ".git", "config"), "token=\""+token+"\"\n")
	writeFile(t, filepath.Join(dir, "readme.txt"), "nothing to see here\n")

	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("expected .git directory to be ignored, got findings: %+v", r.Findings)
	}
}

func TestScanResultNeverContainsTheSecretValue(t *testing.T) {
	dir := t.TempDir()
	token := githubPAT()
	writeFile(t, filepath.Join(dir, "leak.txt"), "token=\""+token+"\"\n")

	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(r.Findings) == 0 {
		t.Fatalf("expected a finding for the injected token")
	}

	data := marshal(t, r)
	if strings.Contains(string(data), token) {
		t.Fatalf("scan result must never contain the secret value")
	}
}

func TestResultFieldsAreStableAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "readme.txt"), "nothing to see here\n")

	r, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r.Format != "gatekeeper-scan/v1" {
		t.Fatalf("unexpected format: %q", r.Format)
	}
	if !strings.HasPrefix(r.RulesDigest, "sha256:") {
		t.Fatalf("unexpected rulesDigest: %q", r.RulesDigest)
	}
}
