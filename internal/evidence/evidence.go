// Package evidence turns a gatekeeper scan result into a signed in-toto
// test-result attestation and appends it to the gatekeeper-evidence
// transparency log (see docs/adr/0001-action-evidence.md). It is the only
// package that touches trust-core on gatekeeper's side.
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	trustcore "github.com/XtReL/trust-core"
	"github.com/XtReL/trust-core/attest"
	"github.com/XtReL/trust-core/event"
	"github.com/XtReL/trust-core/keys"
	"github.com/XtReL/trust-core/tlog/filelog"

	"devsecops-gatekeeper/internal/engine"
)

// SigningKeyEnv is the environment variable the record command reads the
// Ed25519 signing key from. ADR 0001, decision B: the key is never written
// to disk in CI.
const SigningKeyEnv = "GATEKEEPER_SIGNING_KEY"

// ErrAlreadyRecorded is returned by Record when the log already has an
// entry for the same run_id and run_attempt (ADR 0001: record is
// idempotent).
var ErrAlreadyRecorded = errors.New("evidence: run already recorded")

// Origin is the trust-core log identity for repo's epoch-1 evidence log
// (ADR 0001, decision A): "github.com/OWNER/REPO/gatekeeper-evidence/v1".
// This is the base origin epoch k>=2 is derived from (event.EpochOrigin);
// see Target.
func Origin(repo string) string {
	return fmt.Sprintf("github.com/%s/gatekeeper-evidence/v1", repo)
}

// DefaultConfigPath is where Record and "gatekeeper evidence-target" look
// for the epoch config when the operator does not point --config elsewhere.
const DefaultConfigPath = ".gatekeeper/evidence.json"

// Config is the evidence log's epoch config (trust-core ADR 0002: epoch is
// the only source of truth in the client repository, branch and origin are
// always derived from it, never stored alongside it).
type Config struct {
	Epoch int `json:"epoch"`
}

// LoadConfig reads the epoch config at path (DefaultConfigPath if path is
// empty). A missing file means epoch 1, for backward compatibility with
// repositories that predate ADR 0002 rotation. The file is strict JSON: an
// unknown field or an epoch below 1 is an error.
func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	// #nosec G304 -- path is DefaultConfigPath or the operator's own --config flag.
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{Epoch: 1}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("evidence: read config %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("evidence: parse config %s: %w", path, err)
	}
	if cfg.Epoch < 1 {
		return Config{}, fmt.Errorf("evidence: config %s: epoch must be >= 1, got %d", path, cfg.Epoch)
	}
	return cfg, nil
}

// Target derives the evidence branch and trust-core log origin for repo at
// the epoch in cfg (trust-core ADR 0002): epoch 1 is branch
// "gatekeeper-evidence" and origin Origin(repo); epoch k>=2 is branch
// "gatekeeper-evidence-e<k>" and origin event.EpochOrigin(Origin(repo), k).
func Target(repo string, cfg Config) (branch, origin string) {
	origin = event.EpochOrigin(Origin(repo), cfg.Epoch)
	if cfg.Epoch <= 1 {
		return "gatekeeper-evidence", origin
	}
	return fmt.Sprintf("gatekeeper-evidence-e%d", cfg.Epoch), origin
}

// gitattributesContents disables git's line-ending translation for every
// file in the evidence log. checkpoint is a signed note and each entry file
// is hashed as a Merkle leaf: both must reach a clone byte-for-byte. Without
// this, a clone with Windows' common core.autocrlf=true turns each file's
// LF into CRLF on checkout, and "trustcore verify" then fails to parse the
// checkpoint ("malformed note") because the bytes it hashes no longer match
// what was signed. "* -text" disables the "text" attribute outright, so git
// treats every file as binary and never rewrites its line endings,
// regardless of the clone's own core.autocrlf.
const gitattributesContents = "* -text\n"

// Init creates a new, empty evidence log at dir for repo at the given epoch,
// signed by the key at keyPath, and adds entries/.gitkeep so git preserves
// the otherwise-empty entries directory (this is what "gatekeeper
// evidence-init" runs, once, on the client's machine, for a client starting
// at an epoch other than 1; a log for epoch k>=2 in an existing rotation
// chain is created by "trustcore rotate", not this command). It also adds
// .gitattributes next to checkpoint (see gitattributesContents) so a clone
// on Windows does not corrupt the log's signed bytes.
func Init(dir, repo, keyPath string, epoch int) error {
	if epoch < 1 {
		return fmt.Errorf("evidence: epoch must be >= 1, got %d", epoch)
	}
	signer, err := keys.LoadSigner(keyPath)
	if err != nil {
		return fmt.Errorf("evidence: load signing key: %w", err)
	}
	origin := event.EpochOrigin(Origin(repo), epoch)
	if _, err := filelog.Init(dir, origin, signer); err != nil {
		return fmt.Errorf("evidence: init log: %w", err)
	}
	gitattributes := filepath.Join(dir, ".gitattributes")
	if err := os.WriteFile(gitattributes, []byte(gitattributesContents), 0o600); err != nil {
		return fmt.Errorf("evidence: write .gitattributes: %w", err)
	}
	gitkeep := filepath.Join(dir, "entries", ".gitkeep")
	if err := os.WriteFile(gitkeep, nil, 0o600); err != nil {
		return fmt.Errorf("evidence: write entries/.gitkeep: %w", err)
	}
	return nil
}

// Params carries everything a CI run knows about one scan to Record.
type Params struct {
	ResultPath string // path to the engine.Result JSON written by "gatekeeper scan"
	Evidence   string // evidence log directory (a checkout of the target epoch's branch)
	Repo       string // "OWNER/REPO"
	Commit     string // full commit SHA the scan ran against
	RunURL     string // link to the CI run
	RunID      string // github.run_id
	RunAttempt string // github.run_attempt
	ConfigPath string // path to the epoch config; DefaultConfigPath if empty
}

const reproduceFormat = "git checkout %s && gatekeeper scan --source . --out result.json"

// Record signs one gatekeeper-scan-result as an in-toto test-result
// attestation and appends it to the evidence log at p.Evidence. The signing
// key comes only from SigningKeyEnv, never from a file.
//
// If the log already carries an entry for the same run_id/run_attempt,
// Record does nothing and returns ErrAlreadyRecorded.
func Record(p Params) error {
	signer, err := signerFromEnv()
	if err != nil {
		return err
	}

	if err := validateCommit(p.Commit); err != nil {
		return fmt.Errorf("evidence: %w", err)
	}

	resultBytes, err := os.ReadFile(p.ResultPath)
	if err != nil {
		return fmt.Errorf("evidence: read result file: %w", err)
	}
	var result engine.Result
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		return fmt.Errorf("evidence: parse result file: %w", err)
	}
	if err := validateResult(result); err != nil {
		return fmt.Errorf("evidence: %w", err)
	}

	cfg, err := LoadConfig(p.ConfigPath)
	if err != nil {
		return fmt.Errorf("evidence: %w", err)
	}
	_, origin := Target(p.Repo, cfg)

	log, err := filelog.Open(p.Evidence, origin, signer)
	if err != nil {
		return fmt.Errorf("evidence: open log: %w", err)
	}

	dup, err := alreadyRecorded(log, signer.Public(), p.RunID, p.RunAttempt)
	if err != nil {
		return fmt.Errorf("evidence: check idempotency: %w", err)
	}
	if dup {
		return ErrAlreadyRecorded
	}

	ev, err := buildEvent(p, result, resultBytes)
	if err != nil {
		return fmt.Errorf("evidence: build event: %w", err)
	}

	rec := trustcore.Recorder{Attester: signer, Log: log}
	if _, err := rec.Record(ev); err != nil {
		return fmt.Errorf("evidence: record event: %w", err)
	}
	return nil
}

// commitSHALen is a full SHA-1 git commit hash length, ADR 0001's "все по
// полным SHA".
const commitSHALen = 40

func validateCommit(commit string) error {
	if len(commit) != commitSHALen {
		return fmt.Errorf("commit %q is not a %d-character SHA", commit, commitSHALen)
	}
	if _, err := hex.DecodeString(commit); err != nil {
		return fmt.Errorf("commit %q is not hex: %w", commit, err)
	}
	if strings.ToLower(commit) != commit {
		return fmt.Errorf("commit %q must be lowercase hex", commit)
	}
	return nil
}

const scanResultFormat = "gatekeeper-scan/v1"

// validateResult rejects a result.json that does not look like it came from
// "gatekeeper scan", before it is ever signed: a malformed or foreign input
// must not become a signed attestation.
func validateResult(result engine.Result) error {
	if result.Format != scanResultFormat {
		return fmt.Errorf("result format %q is not %q", result.Format, scanResultFormat)
	}
	if result.GitleaksVersion == "" {
		return errors.New("result gitleaksVersion is empty")
	}
	if !strings.HasPrefix(result.RulesDigest, "sha256:") {
		return fmt.Errorf("result rulesDigest %q does not start with \"sha256:\"", result.RulesDigest)
	}
	return nil
}

func signerFromEnv() (*keys.Signer, error) {
	pemBytes := os.Getenv(SigningKeyEnv)
	if pemBytes == "" {
		return nil, fmt.Errorf("evidence: %s is not set", SigningKeyEnv)
	}
	signer, err := keys.ParseSigner([]byte(pemBytes))
	if err != nil {
		return nil, fmt.Errorf("evidence: parse signing key: %w", err)
	}
	return signer, nil
}

func buildEvent(p Params, result engine.Result, resultBytes []byte) (event.Event, error) {
	outcome := event.ResultPassed
	var failed []string
	if len(result.Findings) > 0 {
		outcome = event.ResultFailed
		seen := make(map[string]bool, len(result.Findings))
		for _, f := range result.Findings {
			if !seen[f.RuleID] {
				seen[f.RuleID] = true
				failed = append(failed, f.RuleID)
			}
		}
		sort.Strings(failed)
	}

	sum := sha256.Sum256(resultBytes)
	cfg := event.ResourceDescriptor{
		Name:   "gatekeeper-scan-result",
		Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])},
		Annotations: map[string]any{
			"format":            result.Format,
			"gitleaksVersion":   result.GitleaksVersion,
			"rulesDigest":       result.RulesDigest,
			"gatekeeperVersion": engine.Version,
			"findings":          result.Findings,
			"run_id":            p.RunID,
			"run_attempt":       p.RunAttempt,
			"reproduce":         fmt.Sprintf(reproduceFormat, p.Commit),
		},
	}

	subjects := []event.Subject{{
		Name:   "git+https://github.com/" + p.Repo,
		Digest: map[string]string{"gitCommit": strings.ToLower(p.Commit)},
	}}

	tr := event.TestResult{
		Result:        outcome,
		Configuration: []event.ResourceDescriptor{cfg},
		URL:           p.RunURL,
		FailedTests:   failed,
	}

	return event.NewTestResult(subjects, tr)
}

// alreadyRecorded scans the log's existing entries for one already signed by
// this signer's key that carries the same run_id and run_attempt. Entries
// signed by a different (e.g. rotated) key are not this signer's to compare
// and are skipped rather than treated as an error.
func alreadyRecorded(log *filelog.Log, pub ed25519.PublicKey, runID, runAttempt string) (bool, error) {
	size, err := log.Size()
	if err != nil {
		return false, err
	}
	verifier := keys.NewVerifier(pub)
	for i := uint64(0); i < size; i++ {
		data, err := log.Entry(i)
		if err != nil {
			return false, fmt.Errorf("entry %d: %w", i, err)
		}
		var env attest.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return false, fmt.Errorf("entry %d: not a DSSE envelope: %w", i, err)
		}
		payload, _, err := attest.VerifyEnvelope(env, []attest.Verifier{verifier})
		if err != nil {
			continue
		}
		st, err := attest.ParseStatement(payload)
		if err != nil || st.PredicateType != event.PredicateTestResult {
			continue
		}
		var tr event.TestResult
		if err := json.Unmarshal(st.Predicate, &tr); err != nil || len(tr.Configuration) == 0 {
			continue
		}
		ann := tr.Configuration[0].Annotations
		if fmt.Sprint(ann["run_id"]) == runID && fmt.Sprint(ann["run_attempt"]) == runAttempt {
			return true, nil
		}
	}
	return false, nil
}
