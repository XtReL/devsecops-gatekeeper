package evidence

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/XtReL/trust-core/attest"
	"github.com/XtReL/trust-core/keys"
	"github.com/XtReL/trust-core/tlog/filelog"
	"github.com/XtReL/trust-core/verify"

	"devsecops-gatekeeper/internal/engine"
)

// genKeyPEM generates a fresh Ed25519 key and returns it as PKCS#8 PEM
// bytes, the same shape GATEKEEPER_SIGNING_KEY carries — in memory only,
// never written to disk, mirroring the production path (ADR 0001).
func genKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// initLog creates a log the same way "gatekeeper evidence-init" does,
// without going through a key file.
func initLog(t *testing.T, pemBytes []byte, repo string) string {
	t.Helper()
	signer, err := keys.ParseSigner(pemBytes)
	if err != nil {
		t.Fatalf("parse signer: %v", err)
	}
	dir := t.TempDir()
	if _, err := filelog.Init(dir, Origin(repo), signer); err != nil {
		t.Fatalf("init log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "entries", ".gitkeep"), nil, 0o644); err != nil {
		t.Fatalf("write entries/.gitkeep: %v", err)
	}
	return dir
}

// fakeToken builds a synthetic secret-shaped string at runtime (never a
// literal in source), matching cmd/gatekeeper/main_test.go's convention so
// this file doesn't trip gitleaks/GitGuardian on itself.
func fakeToken(prefix string, n int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	x := uint32(0x9e3779b9)
	b := make([]byte, n)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = alphabet[x%uint32(len(alphabet))]
	}
	return prefix + string(b)
}

func writeResult(t *testing.T, dir string, findings []engine.Finding) string {
	t.Helper()
	if findings == nil {
		findings = []engine.Finding{}
	}
	r := engine.Result{
		Format:          "gatekeeper-scan/v1",
		GitleaksVersion: "v8.30.1",
		RulesDigest:     "sha256:" + fakeToken("", 64),
		Findings:        findings,
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(dir, "result.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write result: %v", err)
	}
	return path
}

func withSigningKey(t *testing.T, pemBytes []byte) {
	t.Helper()
	t.Setenv(SigningKeyEnv, string(pemBytes))
}

func TestRecordIsIdempotentByRunIDAndAttempt(t *testing.T) {
	pemBytes := genKeyPEM(t)
	withSigningKey(t, pemBytes)
	repo := "XtReL/devsecops-gatekeeper"
	logDir := initLog(t, pemBytes, repo)
	resultPath := writeResult(t, t.TempDir(), nil)

	params := Params{
		ResultPath: resultPath,
		Evidence:   logDir,
		Repo:       repo,
		Commit:     strings.Repeat("a", 40),
		RunURL:     "https://github.com/" + repo + "/actions/runs/1",
		RunID:      "1001",
		RunAttempt: "1",
	}

	if err := Record(params); err != nil {
		t.Fatalf("first record: %v", err)
	}

	// Re-run with the exact same run_id/run_attempt: nothing new is appended.
	if err := Record(params); !errors.Is(err, ErrAlreadyRecorded) {
		t.Fatalf("second record: expected ErrAlreadyRecorded, got %v", err)
	}

	signer, err := keys.ParseSigner(pemBytes)
	if err != nil {
		t.Fatalf("parse signer: %v", err)
	}
	log, err := filelog.Open(logDir, Origin(repo), signer)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	size, err := log.Size()
	if err != nil {
		t.Fatalf("log size: %v", err)
	}
	if size != 1 {
		t.Fatalf("expected exactly 1 entry after a duplicate record, got %d", size)
	}
}

func TestRecordWithDifferentRunIDAppendsSecondEntry(t *testing.T) {
	pemBytes := genKeyPEM(t)
	withSigningKey(t, pemBytes)
	repo := "XtReL/devsecops-gatekeeper"
	logDir := initLog(t, pemBytes, repo)
	resultPath := writeResult(t, t.TempDir(), nil)

	base := Params{
		ResultPath: resultPath,
		Evidence:   logDir,
		Repo:       repo,
		Commit:     strings.Repeat("b", 40),
		RunURL:     "https://github.com/" + repo + "/actions/runs/2",
		RunID:      "2001",
		RunAttempt: "1",
	}
	if err := Record(base); err != nil {
		t.Fatalf("first record: %v", err)
	}

	other := base
	other.RunID = "2002"
	if err := Record(other); err != nil {
		t.Fatalf("second record (different run_id): %v", err)
	}

	pub, err := keys.ParsePublic(publicPEM(t, pemBytes))
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	rep, err := verify.Log(verify.Options{
		Dir:       logDir,
		Origin:    Origin(repo),
		LogKey:    pub,
		Attesters: []attest.Verifier{keys.NewVerifier(pub)},
	})
	if err != nil {
		t.Fatalf("verify.Log: %v", err)
	}
	if !rep.OK {
		t.Fatalf("verify.Log reported problems: %v", rep.Problems)
	}
	if rep.Size != 2 {
		t.Fatalf("expected 2 entries, got %d", rep.Size)
	}
}

// TestVerifyLogPassesAfterTwoRecords is the scenario stage3 asks for
// explicitly: verify.Log must accept a log built purely through two
// gatekeeper record calls (one PASSED, one FAILED).
func TestVerifyLogPassesAfterTwoRecords(t *testing.T) {
	pemBytes := genKeyPEM(t)
	withSigningKey(t, pemBytes)
	repo := "XtReL/devsecops-gatekeeper"
	logDir := initLog(t, pemBytes, repo)

	cleanResult := writeResult(t, t.TempDir(), nil)
	if err := Record(Params{
		ResultPath: cleanResult,
		Evidence:   logDir,
		Repo:       repo,
		Commit:     strings.Repeat("c", 40),
		RunURL:     "https://github.com/" + repo + "/actions/runs/3",
		RunID:      "3001",
		RunAttempt: "1",
	}); err != nil {
		t.Fatalf("record clean result: %v", err)
	}

	dirtyResult := writeResult(t, t.TempDir(), []engine.Finding{
		{RuleID: "generic-api-key", File: "b.txt", Fingerprint: "sha256:" + fakeToken("", 64)},
		{RuleID: "aws-access-key", File: "a.txt", Fingerprint: "sha256:" + fakeToken("", 64)},
	})
	if err := Record(Params{
		ResultPath: dirtyResult,
		Evidence:   logDir,
		Repo:       repo,
		Commit:     strings.Repeat("d", 40),
		RunURL:     "https://github.com/" + repo + "/actions/runs/4",
		RunID:      "3002",
		RunAttempt: "1",
	}); err != nil {
		t.Fatalf("record failed result: %v", err)
	}

	pub, err := keys.ParsePublic(publicPEM(t, pemBytes))
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	rep, err := verify.Log(verify.Options{
		Dir:       logDir,
		Origin:    Origin(repo),
		LogKey:    pub,
		Attesters: []attest.Verifier{keys.NewVerifier(pub)},
	})
	if err != nil {
		t.Fatalf("verify.Log: %v", err)
	}
	if !rep.OK {
		t.Fatalf("verify.Log reported problems: %v", rep.Problems)
	}
	if rep.Size != 2 {
		t.Fatalf("expected 2 entries, got %d", rep.Size)
	}

	// The second entry's failedTests must be sorted, and neither entry may
	// leak the signing key material.
	entry, err := readEntry(logDir, 1)
	if err != nil {
		t.Fatalf("read entry 1: %v", err)
	}
	var env attest.Envelope
	if err := json.Unmarshal(entry, &env); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	payload, _, err := attest.VerifyEnvelope(env, []attest.Verifier{keys.NewVerifier(pub)})
	if err != nil {
		t.Fatalf("verify entry envelope: %v", err)
	}
	st, err := attest.ParseStatement(payload)
	if err != nil {
		t.Fatalf("parse statement: %v", err)
	}
	var tr struct {
		Result      string   `json:"result"`
		FailedTests []string `json:"failedTests"`
	}
	if err := json.Unmarshal(st.Predicate, &tr); err != nil {
		t.Fatalf("unmarshal predicate: %v", err)
	}
	if tr.Result != "FAILED" {
		t.Fatalf("expected result FAILED, got %q", tr.Result)
	}
	want := []string{"aws-access-key", "generic-api-key"}
	if len(tr.FailedTests) != len(want) || tr.FailedTests[0] != want[0] || tr.FailedTests[1] != want[1] {
		t.Fatalf("expected sorted failedTests %v, got %v", want, tr.FailedTests)
	}

	if bytes.Contains(entry, pemBytes) {
		t.Fatalf("entry must never contain the signing key material")
	}
}

// TestGitkeepIgnoredByFilelogCounting pins the behaviour Record's
// idempotency check and trust-core's own Append rely on: entries/.gitkeep
// (needed so git preserves the otherwise-empty directory, see Init) is not
// mistaken for entry 0.
func TestGitkeepIgnoredByFilelogCounting(t *testing.T) {
	pemBytes := genKeyPEM(t)
	withSigningKey(t, pemBytes)
	repo := "XtReL/devsecops-gatekeeper"
	logDir := initLog(t, pemBytes, repo)

	n, err := filelog.CountEntryFiles(logDir)
	if err != nil {
		t.Fatalf("CountEntryFiles: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 entry files with only entries/.gitkeep present, got %d", n)
	}
	leaves, err := filelog.LeafHashes(logDir, 0)
	if err != nil {
		t.Fatalf("LeafHashes: %v", err)
	}
	if len(leaves) != 0 {
		t.Fatalf("expected 0 leaf hashes, got %d", len(leaves))
	}

	resultPath := writeResult(t, t.TempDir(), nil)
	if err := Record(Params{
		ResultPath: resultPath,
		Evidence:   logDir,
		Repo:       repo,
		Commit:     strings.Repeat("e", 40),
		RunURL:     "https://github.com/" + repo + "/actions/runs/5",
		RunID:      "4001",
		RunAttempt: "1",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	n, err = filelog.CountEntryFiles(logDir)
	if err != nil {
		t.Fatalf("CountEntryFiles after record: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 entry file after one record, got %d (entries/.gitkeep must not count)", n)
	}
}

func readEntry(dir string, index uint64) ([]byte, error) {
	return os.ReadFile(filelog.EntryPath(dir, index))
}

func publicPEM(t *testing.T, privPEM []byte) []byte {
	t.Helper()
	signer, err := keys.ParseSigner(privPEM)
	if err != nil {
		t.Fatalf("parse signer: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
