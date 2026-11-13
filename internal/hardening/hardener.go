package hardening

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
)

// Hardener applies a hardening profile on the local host.
type Hardener interface {
	Name() string
	Apply(ctx context.Context, p api.HardeningProfile) api.HardeningReport
}

// New returns the hardener for a driver name: "egida" or "dry-run"/"noop".
func New(driver, workDir, egidaBinary string) (Hardener, error) {
	switch driver {
	case "", "dry-run", "noop":
		return &DryRun{WorkDir: workDir}, nil
	case "egida":
		if egidaBinary == "" {
			egidaBinary = "egida"
		}
		return &Egida{WorkDir: workDir, Binary: egidaBinary}, nil
	}
	return nil, fmt.Errorf("hardening: unknown driver %q (use egida or dry-run)", driver)
}

func writeProgram(dir string, p api.HardeningProfile) (string, error) {
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := sanitize(p.Name)
	if name == "" {
		name = "profile"
	}
	path := filepath.Join(dir, name+".aspida")
	// Egida opens the file read-write, hence 0600 rather than 0400.
	if err := os.WriteFile(path+".tmp", []byte(p.Aspida), 0o600); err != nil {
		return "", err
	}
	return path, os.Rename(path+".tmp", path)
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, s)
}

// DryRun renders the Aspida program to disk without applying it. It is used
// where Egida cannot run (containers without systemd/Ansible).
type DryRun struct {
	WorkDir string
}

// Name implements Hardener.
func (d *DryRun) Name() string { return "dry-run" }

// Apply implements Hardener.
func (d *DryRun) Apply(_ context.Context, p api.HardeningProfile) api.HardeningReport {
	r := api.HardeningReport{Driver: d.Name(), ProfileHash: p.Hash, At: time.Now().UTC()}
	path, err := writeProgram(d.WorkDir, p)
	if err != nil {
		r.Status, r.Message = api.HardeningFailed, err.Error()
		return r
	}
	r.Status, r.File = api.HardeningDryRun, path
	r.Message = "Aspida program rendered, not applied (dry-run driver)"
	return r
}

// Egida applies the profile with `egida compile -f <file>`. Egida runs the
// CIS Ansible roles locally; it must be installed on the host and run as root.
type Egida struct {
	WorkDir string
	Binary  string

	mu      sync.Mutex
	applied string // hash of the last successfully applied profile
}

// Name implements Hardener.
func (e *Egida) Name() string { return "egida" }

// Apply implements Hardener.
func (e *Egida) Apply(ctx context.Context, p api.HardeningProfile) api.HardeningReport {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := api.HardeningReport{Driver: e.Name(), ProfileHash: p.Hash, At: time.Now().UTC()}
	path, err := writeProgram(e.WorkDir, p)
	if err != nil {
		r.Status, r.Message = api.HardeningFailed, err.Error()
		return r
	}
	r.File = path
	if p.Hash != "" && p.Hash == e.applied {
		r.Status, r.Message = api.HardeningUnchanged, "profile already applied"
		return r
	}
	cmd := exec.CommandContext(ctx, e.Binary, "compile", "-f", path)
	out, err := cmd.CombinedOutput()
	r.Output = tail(string(out), 4000)
	switch {
	case err != nil:
		r.Status, r.Message = api.HardeningFailed, fmt.Sprintf("egida: %v", err)
	case bytes.Contains(out, []byte("You're not sudo")):
		r.Status, r.Message = api.HardeningFailed, "egida must run as root"
	case bytes.Contains(out, []byte("FAILED!")) || bytes.Contains(out, []byte("fatal:")):
		r.Status, r.Message = api.HardeningFailed, "egida reported failed tasks (see output)"
	default:
		r.Status, r.Message = api.HardeningApplied, "applied with egida compile"
		e.applied = p.Hash
	}
	return r
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// ---------------------------------------------------------------- Lynis

// Lynis audits the local host with `lynis audit system --quick`.
type Lynis struct {
	Binary string
	// Timeout bounds an audit (default 10 minutes).
	Timeout time.Duration
}

// Audit runs Lynis and parses its report file.
func (l *Lynis) Audit(ctx context.Context) api.AuditReport {
	r := api.AuditReport{Tool: "lynis", At: time.Now().UTC()}
	bin := l.Binary
	if bin == "" {
		bin = "lynis"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		r.Message = "lynis is not installed on this host"
		return r
	}
	r.Available = true
	timeout := l.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dir, err := os.MkdirTemp("", "sdp-lynis-")
	if err != nil {
		r.Message = err.Error()
		return r
	}
	defer os.RemoveAll(dir)
	report := filepath.Join(dir, "report.dat")
	start := time.Now()
	cmd := exec.CommandContext(ctx, path, "audit", "system", "--quick", "--no-colors",
		"--report-file", report, "--logfile", filepath.Join(dir, "lynis.log"))
	out, err := cmd.CombinedOutput()
	r.Duration = time.Since(start).Round(time.Second).String()
	data, rerr := os.ReadFile(report)
	if rerr != nil {
		if err != nil {
			r.Message = fmt.Sprintf("lynis failed: %v: %s", err, tail(string(out), 500))
		} else {
			r.Message = "lynis produced no report: " + rerr.Error()
		}
		return r
	}
	if perr := ParseLynisReport(data, &r); perr != nil {
		r.Message = perr.Error()
	}
	return r
}

// ParseLynisReport fills r from the key=value report file written by Lynis.
func ParseLynisReport(data []byte, r *api.AuditReport) error {
	found := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "hardening_index":
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("lynis: bad hardening_index %q", v)
			}
			r.HardeningIndex, found = n, true
		case "lynis_tests_done":
			r.TestsPerformed, _ = strconv.Atoi(strings.TrimSpace(v))
		case "lynis_version":
			r.Version = strings.TrimSpace(v)
		case "warning[]":
			r.Warnings++
		case "suggestion[]":
			r.Suggestions++
		}
	}
	if !found {
		return errors.New("lynis: report has no hardening_index")
	}
	return sc.Err()
}
