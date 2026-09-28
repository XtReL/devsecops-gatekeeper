package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// genPEMKey writes a fresh Ed25519 private key as PKCS#8 PEM, in memory and
// (only for evidence-init's --key flag, never for record's GATEKEEPER_SIGNING_KEY)
// to a file under dir.
func genPEMKey(t *testing.T, dir, name string) ([]byte, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return pemBytes, path
}

// runGatekeeperEnv is runGatekeeper with extra environment variables, used
// to pass GATEKEEPER_SIGNING_KEY the way the record command expects it:
// through the environment, never a file (ADR 0001).
func runGatekeeperEnv(t *testing.T, env []string, args ...string) (code int, stderr string) {
	t.Helper()
	cmd := exec.Command(gatekeeperBin, args...)
	cmd.Env = append(os.Environ(), env...)
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

func TestRunEvidenceInitCreatesLogAndGitkeep(t *testing.T) {
	keyDir := t.TempDir()
	_, keyPath := genPEMKey(t, keyDir, "log.key")
	evidenceDir := filepath.Join(t.TempDir(), "evidence")

	code, stderr := runGatekeeper(t, "evidence-init", "--evidence", evidenceDir, "--repo", "XtReL/devsecops-gatekeeper", "--key", keyPath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(evidenceDir, "checkpoint")); err != nil {
		t.Fatalf("expected checkpoint file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(evidenceDir, "entries", ".gitkeep")); err != nil {
		t.Fatalf("expected entries/.gitkeep: %v", err)
	}
	gitattributes, err := os.ReadFile(filepath.Join(evidenceDir, ".gitattributes"))
	if err != nil {
		t.Fatalf("expected .gitattributes: %v", err)
	}
	if string(gitattributes) != "* -text\n" {
		t.Fatalf("expected .gitattributes to contain \"* -text\\n\", got %q", gitattributes)
	}
}

func TestRunRecordExitCodes(t *testing.T) {
	keyDir := t.TempDir()
	pemBytes, keyPath := genPEMKey(t, keyDir, "log.key")
	evidenceDir := filepath.Join(t.TempDir(), "evidence")
	repo := "XtReL/devsecops-gatekeeper"

	if code, stderr := runGatekeeper(t, "evidence-init", "--evidence", evidenceDir, "--repo", repo, "--key", keyPath); code != 0 {
		t.Fatalf("evidence-init: expected exit code 0, got %d (stderr: %s)", code, stderr)
	}

	scanSource := t.TempDir()
	if err := os.WriteFile(filepath.Join(scanSource, "readme.txt"), []byte("nothing to see here\n"), 0o644); err != nil {
		t.Fatalf("write scan fixture: %v", err)
	}
	out := filepath.Join(t.TempDir(), "result.json")
	if code, stderr := runGatekeeper(t, "scan", "--source", scanSource, "--out", out); code != 0 {
		t.Fatalf("scan: expected exit code 0, got %d (stderr: %s)", code, stderr)
	}

	env := []string{"GATEKEEPER_SIGNING_KEY=" + string(pemBytes)}
	recordArgs := []string{
		"record",
		"--result", out,
		"--evidence", evidenceDir,
		"--repo", repo,
		"--commit", strings.Repeat("f", 40),
		"--run-url", "https://github.com/" + repo + "/actions/runs/1",
		"--run-id", "9001",
		"--run-attempt", "1",
	}

	if code, stderr := runGatekeeperEnv(t, env, recordArgs...); code != 0 {
		t.Fatalf("first record: expected exit code 0, got %d (stderr: %s)", code, stderr)
	}
	if code, stderr := runGatekeeperEnv(t, env, recordArgs...); code != 3 {
		t.Fatalf("duplicate record: expected exit code 3, got %d (stderr: %s)", code, stderr)
	}

	// No GATEKEEPER_SIGNING_KEY at all: the record command must fail, not
	// fall back to reading a key from disk.
	otherArgs := append(append([]string{}, recordArgs[:len(recordArgs)-4]...), "--run-id", "9002", "--run-attempt", "1")
	if code, stderr := runGatekeeper(t, otherArgs...); code != 2 {
		t.Fatalf("record without signing key: expected exit code 2, got %d (stderr: %s)", code, stderr)
	}
}
