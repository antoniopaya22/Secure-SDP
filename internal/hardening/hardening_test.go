package hardening

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
)

func TestRenderAspida(t *testing.T) {
	got, err := RenderAspida(Program{
		Name:        "securesdp-gw-a",
		Description: `AH "gw-a"`,
		Spec: Spec{
			Sections:   []string{"1.1"},
			Exclusions: []string{"1.1.1.2"},
			Tags:       []string{"ssh"},
			Vars: map[string]any{
				"user_ssh":          "sdp",
				"nameservers":       []any{"1.1.1.1", "9.9.9.9"},
				"sshd_access":       map[string]any{"ssh_port": 336, "allowusers": "sdp"},
				"ufw_deny_outgoing": false,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `MAIN : {
    name: "securesdp-gw-a";
    connection: local;
    description: "AH \"gw-a\"";
}

HOST : "localhost";

TASKS : {
    sections: ["1.1"];
    exclusions: ["1.1.1.2"];
    tags: ["ssh"];
}

VARS : {
    "nameservers": ["1.1.1.1", "9.9.9.9"];
    "sshd_access": {
        "allowusers": "sdp";
        "ssh_port": 336;
    };
    "ufw_deny_outgoing": false;
    "user_ssh": "sdp";
}
`
	if !strings.HasSuffix(got, want) {
		t.Fatalf("unexpected program:\n%s\nwant suffix:\n%s", got, want)
	}
}

func TestRenderRejectsEmpty(t *testing.T) {
	if _, err := RenderAspida(Program{Name: "x"}); err == nil {
		t.Fatal("empty profile rendered")
	}
}

func TestMerge(t *testing.T) {
	m := Merge(
		Spec{Sections: []string{"5.2"}, Points: []string{"1.1.1.1", "3.5.1"}, Vars: map[string]any{"a": map[string]any{"x": 1, "y": 2}}},
		Spec{Sections: []string{"1.1", "5.2"}, Exclusions: []string{"3.5.1"}, Vars: map[string]any{"a": map[string]any{"y": 3}, "b": true}},
	)
	if strings.Join(m.Sections, ",") != "1.1,5.2" {
		t.Errorf("sections = %v", m.Sections)
	}
	if strings.Join(m.Points, ",") != "1.1.1.1" {
		t.Errorf("excluded point kept: %v", m.Points)
	}
	a := m.Vars["a"].(map[string]any)
	if a["x"] != 1 || a["y"] != 3 || m.Vars["b"] != true {
		t.Errorf("vars not deep-merged: %v", m.Vars)
	}
}

func TestParseLynisReport(t *testing.T) {
	data := []byte(`# Lynis Report
report_version_major=1
lynis_version=3.0.8
lynis_tests_done=243
warning[]=FIRE-4512|iptables module(s) loaded, but no rules active|-|-|
suggestion[]=AUTH-9230|Configure password hashing rounds|-|-|
suggestion[]=PKGS-7346|Purge old packages|-|-|
hardening_index=62
`)
	var r api.AuditReport
	if err := ParseLynisReport(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.HardeningIndex != 62 || r.TestsPerformed != 243 || r.Warnings != 1 || r.Suggestions != 2 || r.Version != "3.0.8" {
		t.Fatalf("parsed %+v", r)
	}
	if err := ParseLynisReport([]byte("lynis_version=3\n"), &r); err == nil {
		t.Fatal("report without index accepted")
	}
}

func TestDryRun(t *testing.T) {
	h, err := New("dry-run", t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	r := h.Apply(context.Background(), api.HardeningProfile{Name: "securesdp-gw/a", Aspida: "MAIN : {}", Hash: "abc"})
	if r.Status != api.HardeningDryRun || r.ProfileHash != "abc" {
		t.Fatalf("report %+v", r)
	}
	b, err := os.ReadFile(r.File)
	if err != nil || string(b) != "MAIN : {}" {
		t.Fatalf("program not written: %v", err)
	}
	if strings.Contains(r.File[len(r.File)-len("securesdp-gw_a.aspida"):], "/") {
		t.Fatalf("profile name not sanitized: %s", r.File)
	}
}

func TestEgidaMissingBinary(t *testing.T) {
	h, _ := New("egida", t.TempDir(), "/nonexistent/egida")
	r := h.Apply(context.Background(), api.HardeningProfile{Name: "p", Aspida: "x", Hash: "h"})
	if r.Status != api.HardeningFailed {
		t.Fatalf("status %q, want failed", r.Status)
	}
}

func TestLynisMissing(t *testing.T) {
	r := (&Lynis{Binary: "/nonexistent/lynis"}).Audit(context.Background())
	if r.Available {
		t.Fatal("missing lynis reported as available")
	}
}
