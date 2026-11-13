package policy

import (
	"strings"
	"testing"

	"github.com/antoniopaya22/Secure-SDP/internal/identity"
)

const sample = `
defaults:
  access_timeout: 20s
  grant_ttl: 5m
  hardening: [base]
domains:
  - name: domain-a
  - name: domain-b
gateways:
  - id: gw-a
    domain: domain-a
    address: 10.0.0.20
services:
  - name: web
    gateway: gw-a
    target: 10.0.1.30:80
    hardening: [web]
  - name: web-nat
    gateway: gw-a
    target: 10.0.1.30:80
    mode: forward
    port: 8080
  - name: admin
    gateway: gw-a
    target: 10.0.1.31:22
clients:
  - id: alice
    domain: domain-b
    services: [web, web-nat]
  - id: bob
    domain: domain-b
  - id: carol
    domain: domain-b
    services: [web]
    disabled: true
hardening:
  base:
    sections: ["1.1", "4.2"]
    exclusions: ["1.1.1.2"]
  web:
    points: ["1.1.1.2", "5.2.1"]
    tags: ["nginx"]
    vars:
      sshd_access:
        ssh_port: 336
`

func load(t *testing.T) *Policy {
	t.Helper()
	p, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func id(domain, name string) identity.Identity {
	return identity.Identity{Domain: domain, Role: identity.RoleClient, ID: name}
}

func TestDefaults(t *testing.T) {
	p := load(t)
	g := p.Gateway("gw-a")
	if g.SPAPort != 62201 || g.TunnelPort != 8443 {
		t.Fatalf("gateway defaults not applied: %+v", g)
	}
	if s := p.Service("web"); s.Mode != "tunnel" || s.AccessTimeout.String() != "20s" {
		t.Fatalf("service defaults not applied: %+v", s)
	}
}

func TestDecide(t *testing.T) {
	p := load(t)
	cases := []struct {
		name    string
		client  identity.Identity
		service string
		allowed bool
	}{
		{"entitled", id("domain-b", "alice"), "web", true},
		{"entitled forward", id("domain-b", "alice"), "web-nat", true},
		{"not entitled", id("domain-b", "alice"), "admin", false},
		{"unknown service", id("domain-b", "alice"), "nope", false},
		{"registered without services", id("domain-b", "bob"), "web", false},
		{"disabled", id("domain-b", "carol"), "web", false},
		{"unregistered", id("domain-b", "mallory"), "web", false},
		{"same id other domain", id("domain-a", "alice"), "web", false},
		{"not a client", identity.Identity{Domain: "domain-b", Role: identity.RoleGateway, ID: "alice"}, "web", false},
	}
	for _, c := range cases {
		d := p.Decide(c.client, c.service)
		if d.Allowed != c.allowed {
			t.Errorf("%s: allowed=%v (%s), want %v", c.name, d.Allowed, d.Reason, c.allowed)
		}
		if d.Allowed && (d.Gateway == nil || d.Service == nil) {
			t.Errorf("%s: decision without gateway/service", c.name)
		}
	}
	// Unknown and forbidden services are indistinguishable for the client.
	a := p.Decide(id("domain-b", "alice"), "admin").Reason
	b := p.Decide(id("domain-b", "alice"), "nope").Reason
	if strings.Replace(a, "admin", "X", 1) != strings.Replace(b, "nope", "X", 1) {
		t.Errorf("reasons leak service existence: %q vs %q", a, b)
	}
}

func TestServicesFor(t *testing.T) {
	p := load(t)
	if n := len(p.ServicesFor(id("domain-b", "alice"))); n != 2 {
		t.Fatalf("alice sees %d services, want 2", n)
	}
	if n := len(p.ServicesFor(id("domain-b", "carol"))); n != 0 {
		t.Fatalf("disabled client sees %d services", n)
	}
}

func TestValidate(t *testing.T) {
	bad := map[string]string{
		"unknown gateway":  strings.Replace(sample, "gateway: gw-a\n    target: 10.0.1.31:22", "gateway: gw-x\n    target: 10.0.1.31:22", 1),
		"unknown service":  strings.Replace(sample, "services: [web, web-nat]", "services: [web, ghost]", 1),
		"forward needs ip": strings.Replace(sample, "target: 10.0.1.30:80\n    mode: forward", "target: nginx:80\n    mode: forward", 1),
		"reserved port":    strings.Replace(sample, "port: 8080", "port: 8443", 1),
		"unknown profile":  strings.Replace(sample, "hardening: [web]", "hardening: [nope]", 1),
		"bad mode":         strings.Replace(sample, "mode: forward", "mode: magic", 1),
		"unknown field":    sample + "\nbogus: 1\n",
		"unknown domain":   strings.Replace(sample, "  - id: bob\n    domain: domain-b", "  - id: bob\n    domain: domain-z", 1),
	}
	for name, doc := range bad {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: policy accepted", name)
		}
	}
}

func TestHardeningProfile(t *testing.T) {
	p := load(t)
	prof, err := p.HardeningProfile("gw-a")
	if err != nil {
		t.Fatal(err)
	}
	if prof == nil || prof.Hash == "" || len(prof.Services) != 3 {
		t.Fatalf("unexpected profile %+v", prof)
	}
	for _, want := range []string{
		`sections: ["1.1", "4.2"];`,
		`points: ["5.2.1"];`, // 1.1.1.2 is excluded by the base profile
		`exclusions: ["1.1.1.2"];`,
		`tags: ["nginx"];`,
		`"ssh_port": 336;`,
		`HOST : "localhost";`,
	} {
		if !strings.Contains(prof.Aspida, want) {
			t.Errorf("profile lacks %q:\n%s", want, prof.Aspida)
		}
	}
	again, _ := p.HardeningProfile("gw-a")
	if again.Hash != prof.Hash {
		t.Fatal("profile rendering is not deterministic")
	}
}
