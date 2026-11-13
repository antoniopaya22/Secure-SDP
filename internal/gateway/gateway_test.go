package gateway

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
)

func grant(id, mode, target string) api.GatewayGrant {
	return api.GatewayGrant{
		ID: id, Client: "sdp://domain-b/client/alice", Service: "web", Mode: mode, Protocol: "tcp",
		Port: 8443, Target: target, AccessTimeout: 30, ExpiresAt: time.Now().Add(time.Hour),
		KeyBase64:     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		HMACKeyBase64: base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
}

func TestValidateGrant(t *testing.T) {
	if err := validateGrant(grant("g1", api.ModeTunnel, "web.internal:80")); err != nil {
		t.Fatalf("tunnel grant rejected: %v", err)
	}
	if err := validateGrant(grant("g2", api.ModeForward, "10.0.1.30:80")); err != nil {
		t.Fatalf("forward grant rejected: %v", err)
	}
	bad := []api.GatewayGrant{
		grant("g3", api.ModeForward, "web.internal:80"), // FORCE_NAT needs an IP
		grant("g4", "magic", "10.0.1.30:80"),
		grant("", api.ModeTunnel, "10.0.1.30:80"),
	}
	g := grant("g5", api.ModeTunnel, "10.0.1.30:80")
	g.Client = "sdp://domain-b/gateway/gw-x" // not a client identity
	bad = append(bad, g)
	g = grant("g6", api.ModeTunnel, "10.0.1.30:80")
	g.KeyBase64 = "short"
	bad = append(bad, g)
	for _, b := range bad {
		if validateGrant(b) == nil {
			t.Errorf("invalid grant %+v accepted", b)
		}
	}
}

func TestToStanza(t *testing.T) {
	s, err := toStanza(grant("g1", api.ModeForward, "10.0.1.30:80"))
	if err != nil {
		t.Fatal(err)
	}
	if s.ForceNAT == nil || s.ForceNAT.IP != "10.0.1.30" || s.ForceNAT.Port != 80 || s.OpenPorts[0] != "tcp/8443" {
		t.Fatalf("forward stanza %+v", s)
	}
	s, _ = toStanza(grant("g2", api.ModeTunnel, "10.0.1.30:80"))
	if s.ForceNAT != nil || s.AccessTimeout != 30*time.Second {
		t.Fatalf("tunnel stanza %+v", s)
	}
}

// fwknopd numbers stanzas from 1 in file order; the placeholder is #1.
func TestSPASourcesFollowStanzaOrder(t *testing.T) {
	a := &Agent{grants: map[string]api.GatewayGrant{}, sources: map[string]map[string]bool{}}
	a.grants["b"] = grant("b", api.ModeTunnel, "10.0.1.30:80")
	a.grants["a"] = grant("a", api.ModeTunnel, "10.0.1.30:80")
	if n := len(a.stanzas(time.Now())); n != 3 {
		t.Fatalf("%d stanzas, want placeholder + 2", n)
	}
	a.onFwknopLine("(stanza #3) SPA Packet from IP: 10.232.0.40 received with access source match")
	a.onFwknopLine("(stanza #1) SPA Packet from IP: 10.232.0.66 received with access source match")
	a.onFwknopLine("unrelated line")
	if !a.sources["b"]["10.232.0.40"] {
		t.Fatalf("source not attributed to grant b: %v", a.sources)
	}
	if len(a.sources) != 1 {
		t.Fatalf("placeholder or noise attributed to a grant: %v", a.sources)
	}
}
