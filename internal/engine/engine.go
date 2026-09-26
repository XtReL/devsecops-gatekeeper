// Package engine wraps gitleaks as a library and produces a deterministic,
// sanitized scan result suitable for signed evidence (see docs/adr/0001-action-evidence.md).
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"runtime/debug"
	"sort"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Version is gatekeeper's own version, independent of gitleaks and trust-core.
const Version = "0.1.0"

const gitleaksModulePath = "github.com/zricethezav/gitleaks/v8"

// Finding is a single, sanitized secret detection: no line numbers, no
// secret value or fragment, only what is needed to identify and de-duplicate it.
type Finding struct {
	RuleID      string `json:"rule"`
	File        string `json:"file"`        // path relative to the scan root, "/"-separated
	Fingerprint string `json:"fingerprint"` // "sha256:" + hex(sha256(secret))
}

// Result is the deterministic, reproducible output of Scan.
type Result struct {
	Format          string    `json:"format"`
	GitleaksVersion string    `json:"gitleaksVersion"`
	RulesDigest     string    `json:"rulesDigest"`
	Findings        []Finding `json:"findings"`
}

// Scan runs gitleaks' built-in rules over dir and returns a deterministic,
// sanitized result: no timestamps, absolute paths, line numbers, or secret
// values/fragments. The .git directory is not scanned.
func Scan(ctx context.Context, dir string) (Result, error) {
	rawFindings, err := detectSecrets(ctx, dir)
	if err != nil {
		return Result{}, err
	}

	findings := make([]Finding, 0, len(rawFindings))
	for _, f := range rawFindings {
		rel, err := relFile(dir, f.File)
		if err != nil {
			return Result{}, err
		}
		findings = append(findings, Finding{
			RuleID:      f.RuleID,
			File:        rel,
			Fingerprint: fingerprint(f.Secret),
		})
	}
	findings = sortAndDedupe(findings)

	return Result{
		Format:          "gatekeeper-scan/v1",
		GitleaksVersion: gitleaksVersion(),
		RulesDigest:     rulesDigest(),
		Findings:        findings,
	}, nil
}

// WriteSARIF runs the same gitleaks rules over dir and writes a SARIF report.
// Unlike Scan's Result, the SARIF report may contain line numbers, since it is
// an auxiliary output for code-review tooling, not part of the signed evidence.
func WriteSARIF(ctx context.Context, dir string, w io.Writer) error {
	det, findings, err := scanWithDetector(ctx, dir)
	if err != nil {
		return err
	}
	reporter := &report.SarifReporter{OrderedRules: det.Config.GetOrderedRules()}
	return reporter.Write(nopWriteCloser{w}, findings)
}

func detectSecrets(ctx context.Context, dir string) ([]report.Finding, error) {
	_, findings, err := scanWithDetector(ctx, dir)
	return findings, err
}

func scanWithDetector(ctx context.Context, dir string) (*detect.Detector, []report.Finding, error) {
	det, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("engine: init gitleaks detector: %w", err)
	}

	findings, err := det.DetectSource(ctx, &sources.Files{
		Config: &det.Config,
		Sema:   det.Sema,
		Path:   dir,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("engine: scan %s: %w", dir, err)
	}
	return det, findings, nil
}

func relFile(dir, file string) (string, error) {
	rel, err := filepath.Rel(dir, file)
	if err != nil {
		return "", fmt.Errorf("engine: relative path for %s: %w", file, err)
	}
	return filepath.ToSlash(rel), nil
}

func fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sortAndDedupe(findings []Finding) []Finding {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})

	out := findings[:0]
	for i, f := range findings {
		if i == 0 || f != out[len(out)-1] {
			out = append(out, f)
		}
	}
	return out
}

func gitleaksVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, dep := range info.Deps {
		if dep.Path == gitleaksModulePath {
			return dep.Version
		}
	}
	return ""
}

func rulesDigest() string {
	sum := sha256.Sum256([]byte(config.DefaultConfig))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
