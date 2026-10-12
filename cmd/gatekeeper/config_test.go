package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// runIn runs the built gatekeeper binary with dir as its working directory
// (the default config path is relative to it) and returns stdout, stderr and
// the exit code.
func runIn(t *testing.T, dir string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	return runInEnv(t, dir, nil, args...)
}

// runInEnv is runIn with extra environment variables.
func runInEnv(t *testing.T, dir string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(gatekeeperBin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		return outBuf.String(), errBuf.String(), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return outBuf.String(), errBuf.String(), exitErr.ExitCode()
	}
	t.Fatalf("run gatekeeper %v: %v", args, err)
	return "", "", -1
}

// ACT-0.1 C23: epoch 1 is the answer only when --config is not passed at all
// and .gatekeeper/evidence.json does not exist. Any passed --config must
// name an existing file, the default path and the empty string included.
func TestEvidenceTargetConfigFlagSemantics(t *testing.T) {
	const epochOne = "branch=gatekeeper-evidence\norigin=github.com/o/r/gatekeeper-evidence/v1\n"

	t.Run("flag not passed, no file: epoch 1", func(t *testing.T) {
		stdout, stderr, code := runIn(t, t.TempDir(), "evidence-target", "--repo", "o/r")
		if code != 0 || stdout != epochOne {
			t.Fatalf("want exit 0 and %q, got exit %d, stdout %q (stderr: %s)", epochOne, code, stdout, stderr)
		}
	})
	t.Run("flag not passed, default file present: used", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".gatekeeper"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".gatekeeper", "evidence.json"), []byte(`{"epoch": 2}`), 0o644); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := runIn(t, dir, "evidence-target", "--repo", "o/r")
		if code != 0 || !strings.HasPrefix(stdout, "branch=gatekeeper-evidence-e2\n") {
			t.Fatalf("want exit 0 and epoch 2, got exit %d, stdout %q (stderr: %s)", code, stdout, stderr)
		}
	})
	for name, config := range map[string]string{
		"flag passed, file missing":                        "cfg/missing.json",
		"default path passed explicitly, file missing":     ".gatekeeper/evidence.json",
		"empty value passed explicitly (flag given, \"\")": "",
	} {
		t.Run(name, func(t *testing.T) {
			_, stderr, code := runIn(t, t.TempDir(), "evidence-target", "--repo", "o/r", "--config", config)
			if code != 2 {
				t.Fatalf("want exit 2, got %d (stderr: %s)", code, stderr)
			}
		})
	}
}

// ACT-0.1-RECHECK-1 K8: "record --config ”" must be rejected. The log is a
// valid epoch-1 log and the working directory has no .gatekeeper/evidence.json,
// so without the check the empty value falls through to the default path,
// means epoch 1 and the record succeeds: the first call (flag omitted) proves
// that setup works, the second must fail only because of the empty value.
func TestRunRecordRejectsEmptyConfigFlag(t *testing.T) {
	pemBytes, keyPath := genPEMKey(t, t.TempDir(), "log.key")
	evidenceDir := filepath.Join(t.TempDir(), "evidence")
	repo := "o/r"
	if code, stderr := runGatekeeper(t, "evidence-init", "--evidence", evidenceDir, "--repo", repo, "--key", keyPath); code != 0 {
		t.Fatalf("evidence-init: exit %d (stderr: %s)", code, stderr)
	}
	scanSource := t.TempDir()
	if err := os.WriteFile(filepath.Join(scanSource, "readme.txt"), []byte("nothing to see here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(t.TempDir(), "result.json")
	if code, stderr := runGatekeeper(t, "scan", "--source", scanSource, "--out", result); code != 0 {
		t.Fatalf("scan: exit %d (stderr: %s)", code, stderr)
	}

	cwd := t.TempDir() // no .gatekeeper/evidence.json here
	env := []string{"GATEKEEPER_SIGNING_KEY=" + string(pemBytes)}
	record := func(runID string, extra ...string) (string, int) {
		_, stderr, code := runInEnv(t, cwd, env, append([]string{
			"record",
			"--result", result,
			"--evidence", evidenceDir,
			"--repo", repo,
			"--commit", strings.Repeat("f", 40),
			"--run-url", "https://example.invalid/runs/" + runID,
			"--run-id", runID,
			"--run-attempt", "1",
		}, extra...)...)
		return stderr, code
	}
	entries := func() int {
		files, err := os.ReadDir(filepath.Join(evidenceDir, "entries"))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, f := range files {
			if f.Name() != ".gitkeep" {
				n++
			}
		}
		return n
	}

	if stderr, code := record("1"); code != 0 {
		t.Fatalf("control: record without --config on an epoch-1 log: exit %d (stderr: %s)", code, stderr)
	}
	if got := entries(); got != 1 {
		t.Fatalf("control: expected 1 entry, got %d", got)
	}
	stderr, code := record("2", "--config", "")
	if code != 2 || !strings.Contains(stderr, "--config is empty") {
		t.Fatalf("record --config \"\": expected exit 2 and \"--config is empty\", got exit %d (stderr: %s)", code, stderr)
	}
	if got := entries(); got != 1 {
		t.Fatalf("a rejected record must not append: expected 1 entry, got %d", got)
	}
}

// actionStep returns the run: script of the composite action step with the
// given id, read from the real action.yml.
func actionStep(t *testing.T, id string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
		Runs struct {
			Steps []struct {
				ID  string `yaml:"id"`
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse action.yml: %v", err)
	}
	if def := doc.Inputs["config"].Default; def != "" {
		t.Fatalf("input config must default to the empty string (flag omitted), got %q", def)
	}
	for _, s := range doc.Runs.Steps {
		if s.ID == id {
			return s.Run
		}
	}
	t.Fatalf("action.yml has no step with id %q", id)
	return ""
}

// runActionStep runs a step body from action.yml the way GitHub does
// (bash -eo pipefail) in dir, with CONFIG set to config (the input's value).
func runActionStep(t *testing.T, id, dir, config string, extraEnv ...string) (stdout, stderr string, code int) {
	t.Helper()
	script := filepath.Join(t.TempDir(), id+".sh")
	if err := os.WriteFile(script, []byte(actionStep(t, id)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-eo", "pipefail", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GATEKEEPER_BIN="+gatekeeperBin,
		"REPO=o/r",
		"CONFIG="+config,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		return outBuf.String(), errBuf.String(), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return outBuf.String(), errBuf.String(), exitErr.ExitCode()
	}
	t.Fatalf("run step %s: %v", id, err)
	return "", "", -1
}

func writeEpochConfig(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The target step: --config is passed only when the config input is set.
func TestActionTargetStepConfigInput(t *testing.T) {
	run := func(t *testing.T, dir, config string) (string, int) {
		out := filepath.Join(t.TempDir(), "github_output")
		_, stderr, code := runActionStep(t, "target", dir, config, "GITHUB_OUTPUT="+out)
		data, _ := os.ReadFile(out)
		if code != 0 {
			t.Logf("stderr: %s", stderr)
		}
		return string(data), code
	}

	t.Run("config not set, no file: epoch 1", func(t *testing.T) {
		got, code := run(t, t.TempDir(), "")
		if code != 0 || !strings.HasPrefix(got, "branch=gatekeeper-evidence\n") {
			t.Fatalf("want exit 0 and epoch 1, got exit %d, output %q", code, got)
		}
	})
	t.Run("config set, file missing: error", func(t *testing.T) {
		if got, code := run(t, t.TempDir(), "cfg/missing.json"); code == 0 {
			t.Fatalf("want a non-zero exit, got 0 (output %q)", got)
		}
	})
	t.Run("default path set explicitly, file missing: error", func(t *testing.T) {
		if got, code := run(t, t.TempDir(), ".gatekeeper/evidence.json"); code == 0 {
			t.Fatalf("want a non-zero exit, got 0 (output %q)", got)
		}
	})
	t.Run("config set, file present: used", func(t *testing.T) {
		dir := t.TempDir()
		writeEpochConfig(t, filepath.Join(dir, "cfg", "custom.json"), `{"epoch": 2}`)
		got, code := run(t, dir, "cfg/custom.json")
		if code != 0 || !strings.HasPrefix(got, "branch=gatekeeper-evidence-e2\n") {
			t.Fatalf("want exit 0 and epoch 2, got exit %d, output %q", code, got)
		}
	})
}

// The record step: EVIDENCE_CONFIG (-> --config in evidence-push.sh) is set
// only when the config input is set. A stub evidence-push.sh stands in for
// the real one (covered by scripts/evidence-push_test.sh) and reports what
// the step handed it.
func TestActionRecordStepConfigInput(t *testing.T) {
	run := func(t *testing.T, dir, config string) (report string, code int) {
		actionPath := t.TempDir()
		reportFile := filepath.Join(t.TempDir(), "report")
		stub := "#!/usr/bin/env bash\nprintf 'branch=%s\\nconfig=%s\\n' \"$EVIDENCE_BRANCH\" \"${EVIDENCE_CONFIG-<unset>}\" >\"$STUB_REPORT\"\n"
		if err := os.MkdirAll(filepath.Join(actionPath, "scripts"), 0o755); err != nil {
			t.Fatal(err)
		}
		// #nosec G306 -- the stub must be executable.
		if err := os.WriteFile(filepath.Join(actionPath, "scripts", "evidence-push.sh"), []byte(stub), 0o700); err != nil {
			t.Fatal(err)
		}
		_, stderr, code := runActionStep(t, "record", dir, config,
			"GATEKEEPER_SIGNING_KEY=placeholder-not-a-key",
			"ACTION_PATH="+actionPath,
			"STUB_REPORT="+reportFile,
			// A caller's own environment must not leak into the decision.
			"EVIDENCE_CONFIG=leaked-from-environment",
		)
		data, _ := os.ReadFile(reportFile)
		if code != 0 {
			t.Logf("stderr: %s", stderr)
		}
		return string(data), code
	}

	t.Run("config not set, no file: epoch 1, no --config", func(t *testing.T) {
		got, code := run(t, t.TempDir(), "")
		if code != 0 || got != "branch=gatekeeper-evidence\nconfig=<unset>\n" {
			t.Fatalf("want exit 0, epoch-1 branch and EVIDENCE_CONFIG unset, got exit %d, report %q", code, got)
		}
	})
	t.Run("config set, file missing: error", func(t *testing.T) {
		if got, code := run(t, t.TempDir(), "cfg/missing.json"); code == 0 || got != "" {
			t.Fatalf("want a non-zero exit before evidence-push.sh runs, got exit %d, report %q", code, got)
		}
	})
	t.Run("default path set explicitly, file missing: error", func(t *testing.T) {
		if got, code := run(t, t.TempDir(), ".gatekeeper/evidence.json"); code == 0 || got != "" {
			t.Fatalf("want a non-zero exit before evidence-push.sh runs, got exit %d, report %q", code, got)
		}
	})
	t.Run("config set, file present: passed on", func(t *testing.T) {
		dir := t.TempDir()
		writeEpochConfig(t, filepath.Join(dir, "cfg", "custom.json"), `{"epoch": 2}`)
		got, code := run(t, dir, "cfg/custom.json")
		if code != 0 || got != "branch=gatekeeper-evidence-e2\nconfig=cfg/custom.json\n" {
			t.Fatalf("want exit 0, epoch-2 branch and EVIDENCE_CONFIG=cfg/custom.json, got exit %d, report %q", code, got)
		}
	})
}
