package controller_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
	"github.com/antoniopaya22/Secure-SDP/internal/client"
	"github.com/antoniopaya22/Secure-SDP/internal/controller"
	"github.com/antoniopaya22/Secure-SDP/internal/gateway"
	"github.com/antoniopaya22/Secure-SDP/internal/identity"
	"github.com/antoniopaya22/Secure-SDP/internal/pki"
)

// lab is an in-process SecureSDP deployment: a root controller (domain-a),
// a bridged controller (domain-b), one accepting host per domain and a
// protected HTTP service. fwknop and iptables are disabled; the SPA layer is
// covered by the Docker lab.
type lab struct {
	t        *testing.T
	dir      string
	root     *controller.Root
	bridge   *controller.Bridge
	gwA, gwB *gateway.Agent
	policy   string
	backend  *httptest.Server
	files    map[string]pki.TLSFiles
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func issue(t *testing.T, dir string, cas map[string]*pki.CA, root *pki.CA, domain string, role identity.Role, id string) pki.TLSFiles {
	t.Helper()
	ident, err := identity.New(domain, role, id)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := cas[domain].Issue(pki.LeafRequest{Identity: ident, IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, domain, id)
	if err := pki.SaveLeaf(out, leaf, root.Cert); err != nil {
		t.Fatal(err)
	}
	return pki.TLSFiles{Cert: filepath.Join(out, pki.CertFile), Key: filepath.Join(out, pki.KeyFile), CA: filepath.Join(out, pki.CAFile)}
}

const policyTmpl = `
defaults:
  access_timeout: 30s
  grant_ttl: 10m
  hardening: [base]
domains:
  - name: domain-a
  - name: domain-b
gateways:
  - id: gw-a
    domain: domain-a
    address: 127.0.0.1
    tunnel_port: %[1]s
  - id: gw-b
    domain: domain-b
    address: 127.0.0.1
    tunnel_port: %[2]s
services:
  - name: web
    gateway: gw-a
    target: %[3]s
    hardening: [web]
  - name: web-b
    gateway: gw-b
    target: %[3]s
  - name: web-nat
    gateway: gw-a
    target: %[3]s
    mode: forward
    port: 18080
clients:
  - id: alice
    domain: domain-b
    services: [%[4]s]
  - id: bob
    domain: domain-b
  - id: dave
    domain: domain-a
    services: [web]
hardening:
  base:
    sections: ["4.2"]
  web:
    tags: ["nginx"]
`

func (l *lab) writePolicy(aliceServices string) {
	_, pa, _ := net.SplitHostPort(l.gwA.TunnelAddr())
	_, pb, _ := net.SplitHostPort(l.gwB.TunnelAddr())
	target := strings.TrimPrefix(l.backend.URL, "http://")
	doc := fmt.Sprintf(policyTmpl, pa, pb, target, aliceServices)
	if err := os.WriteFile(l.policy, []byte(doc), 0o600); err != nil {
		l.t.Fatal(err)
	}
}

func newLab(t *testing.T) *lab {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	root, err := pki.NewRootCA("test root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cas := map[string]*pki.CA{}
	for _, d := range []string{"domain-a", "domain-b"} {
		if cas[d], err = root.NewDomainCA(d, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]pki.TLSFiles{
		"ctrl-a": issue(t, dir, cas, root, "domain-a", identity.RoleController, "ctrl-a"),
		"ctrl-b": issue(t, dir, cas, root, "domain-b", identity.RoleController, "ctrl-b"),
		"gw-a":   issue(t, dir, cas, root, "domain-a", identity.RoleGateway, "gw-a"),
		"gw-b":   issue(t, dir, cas, root, "domain-b", identity.RoleGateway, "gw-b"),
		"alice":  issue(t, dir, cas, root, "domain-b", identity.RoleClient, "alice"),
		"bob":    issue(t, dir, cas, root, "domain-b", identity.RoleClient, "bob"),
		"dave":   issue(t, dir, cas, root, "domain-a", identity.RoleClient, "dave"),
		"admin":  issue(t, dir, cas, root, "domain-a", identity.RoleAdmin, "admin"),
	}
	l := &lab{t: t, dir: dir, policy: filepath.Join(dir, "policy.yml")}
	l.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "protected resource")
	}))
	t.Cleanup(l.backend.Close)

	rootPeer, bridgePeer := freeAddr(t), freeAddr(t)
	startAgent := func(name, ctrl string) *gateway.Agent {
		cfg := &gateway.Config{Controller: ctrl, TLS: files[name], StateDir: filepath.Join(dir, "state-"+name)}
		cfg.Tunnel.Listen = "127.0.0.1:0"
		cfg.Hardening.Driver = "dry-run"
		me, err := pki.LoadMember(cfg.TLS)
		if err != nil {
			t.Fatal(err)
		}
		a, err := gateway.New(cfg, me, log.With("gw", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return a
	}
	l.gwA = startAgent("gw-a", rootPeer)
	l.gwB = startAgent("gw-b", bridgePeer)
	l.writePolicy("web, web-b, web-nat")

	meA, _ := pki.LoadMember(files["ctrl-a"])
	l.root, err = controller.NewRoot(&controller.Config{Role: "root", APIListen: "127.0.0.1:0", PeerListen: rootPeer, Policy: l.policy}, meA, log.With("c", "root"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.root.Start(ctx); err != nil {
		t.Fatal(err)
	}
	meB, _ := pki.LoadMember(files["ctrl-b"])
	l.bridge = controller.NewBridge(&controller.Config{Role: "bridge", APIListen: "127.0.0.1:0", PeerListen: bridgePeer,
		Upstream: l.root.PeerAddr(), UpstreamIdentity: "sdp://domain-a/controller/ctrl-a"}, meB, log.With("c", "bridge"))
	if err := l.bridge.Start(ctx); err != nil {
		t.Fatal(err)
	}
	l.files = files
	// Wait until both accepting hosts are online and hardened (dry run).
	l.eventually("accepting hosts online", func() bool {
		for _, g := range l.root.GatewayStatuses() {
			if !g.Online || g.Hardening == nil {
				return false
			}
		}
		return true
	})
	return l
}

func (l *lab) eventually(what string, cond func() bool) {
	l.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			l.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (l *lab) client(name, api string) *client.Client {
	l.t.Helper()
	c, err := client.New(&client.Config{Controller: api, TLS: l.files[name]})
	if err != nil {
		l.t.Fatal(err)
	}
	return c
}

// get performs an HTTP GET through a tunnel connection.
func get(t *testing.T, c *client.Client, g *api.AccessGrant) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialTunnel(ctx, g)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: web\r\nConnection: close\r\n\r\n"); err != nil {
		return "", err
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return string(b), err
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestBridgeRelayAndTunnel(t *testing.T) {
	l := newLab(t)
	alice := l.client("alice", l.bridge.APIAddr())

	who, err := alice.WhoAmI(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if who.Role != "bridge" || who.Identity != "sdp://domain-b/client/alice" {
		t.Fatalf("whoami = %+v", who)
	}
	svcs, err := alice.Services(ctx(t))
	if err != nil || len(svcs) != 3 {
		t.Fatalf("services = %+v, %v", svcs, err)
	}

	// web: AH in the root domain, reached via bridge -> root -> AH.
	g, err := alice.RequestAccess(ctx(t), "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Path) != 2 || !strings.HasPrefix(g.Path[0], "bridge sdp://domain-b/") || !strings.HasPrefix(g.Path[1], "root sdp://domain-a/") {
		t.Fatalf("path = %v", g.Path)
	}
	if g.SPA.KeyBase64 == "" || g.SPA.HMACKeyBase64 == "" || g.Mode != api.ModeTunnel || g.Gateway.ID != "gw-a" {
		t.Fatalf("grant = %+v", g)
	}
	body, err := get(t, alice, g)
	if err != nil || body != "protected resource" {
		t.Fatalf("tunnel GET: %q, %v", body, err)
	}

	// web-b: AH behind the bridge; the root reaches it through the peer link.
	gb, err := alice.RequestAccess(ctx(t), "web-b")
	if err != nil {
		t.Fatal(err)
	}
	if body, err := get(t, alice, gb); err != nil || body != "protected resource" {
		t.Fatalf("tunnel GET via bridged AH: %q, %v", body, err)
	}

	// Credentials are fresh per grant.
	g2, err := alice.RequestAccess(ctx(t), "web")
	if err != nil {
		t.Fatal(err)
	}
	if g2.SPA.KeyBase64 == g.SPA.KeyBase64 || g2.GrantID == g.GrantID {
		t.Fatal("grant credentials reused")
	}
	// The new grant replaced the old one on the accepting host; the tunnel
	// keeps working because it is bound to the client identity.
	var grants []api.GrantInfo
	admin := l.client("admin", l.root.APIAddr())
	if err := admin.Do(ctx(t), http.MethodGet, api.PathAdminGrants, nil, &grants); err != nil {
		t.Fatal(err)
	}
	for _, gi := range grants {
		if gi.ID == g.GrantID {
			t.Fatal("superseded grant still active")
		}
	}
	if body, err := get(t, alice, g2); err != nil || body != "protected resource" {
		t.Fatalf("tunnel GET with the new grant: %q, %v", body, err)
	}

	// Forward mode returns the gateway port of the service.
	gn, err := alice.RequestAccess(ctx(t), "web-nat")
	if err != nil || gn.Mode != api.ModeForward || gn.Port != 18080 {
		t.Fatalf("forward grant = %+v, %v", gn, err)
	}
}

func TestUnauthorizedClient(t *testing.T) {
	l := newLab(t)
	bob := l.client("bob", l.bridge.APIAddr())
	_, err := bob.RequestAccess(ctx(t), "web")
	var ae *client.APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusForbidden {
		t.Fatalf("bob access: %v", err)
	}
	if s, err := bob.Services(ctx(t)); err != nil || len(s) != 0 {
		t.Fatalf("bob services = %v, %v", s, err)
	}

	// Bob reuses the gateway details of Alice's grant: the AH accepts the
	// TLS handshake (valid PKI member) but has no grant for Bob's identity.
	alice := l.client("alice", l.bridge.APIAddr())
	g, err := alice.RequestAccess(ctx(t), "web")
	if err != nil {
		t.Fatal(err)
	}
	if body, err := get(t, bob, g); err == nil {
		t.Fatalf("bob reached the service: %q", body)
	}
}

func TestTopologyIsPreserved(t *testing.T) {
	l := newLab(t)
	// A domain-b client cannot bypass its bridged controller.
	alice := l.client("alice", l.root.APIAddr())
	if _, err := alice.RequestAccess(ctx(t), "web"); err == nil {
		t.Fatal("domain-b client served by the root controller directly")
	}
	// A domain-a client is served by the root directly.
	dave := l.client("dave", l.root.APIAddr())
	g, err := dave.RequestAccess(ctx(t), "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Path) != 1 {
		t.Fatalf("path = %v", g.Path)
	}
	// ...and not by the bridge of another domain.
	dave2 := l.client("dave", l.bridge.APIAddr())
	if _, err := dave2.RequestAccess(ctx(t), "web"); err == nil {
		t.Fatal("domain-a client served by the domain-b bridge")
	}
}

func TestAdminRevokeAndReload(t *testing.T) {
	l := newLab(t)
	admin := l.client("admin", l.root.APIAddr())
	alice := l.client("alice", l.bridge.APIAddr())

	var gws []api.GatewayStatus
	if err := admin.Do(ctx(t), http.MethodGet, api.PathAdminGateways, nil, &gws); err != nil {
		t.Fatal(err)
	}
	if len(gws) != 2 || gws[1].Via != "sdp://domain-b/controller/ctrl-b" || gws[0].Via != "direct" {
		t.Fatalf("gateways = %+v", gws)
	}
	if gws[0].Hardening.Status != api.HardeningDryRun {
		t.Fatalf("hardening = %+v", gws[0].Hardening)
	}
	var prof api.HardeningProfile
	if err := admin.Do(ctx(t), http.MethodGet, api.PathAdminProfile+"?gateway=gw-a", nil, &prof); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prof.Aspida, `tags: ["nginx"];`) {
		t.Fatalf("gw-a profile lacks the web service controls:\n%s", prof.Aspida)
	}

	// Non-admins cannot use the admin API.
	dave := l.client("dave", l.root.APIAddr())
	if err := dave.Do(ctx(t), http.MethodGet, api.PathAdminGrants, nil, nil); err == nil {
		t.Fatal("client used the admin API")
	}

	g, err := alice.RequestAccess(ctx(t), "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, alice, g); err != nil {
		t.Fatal(err)
	}
	var rr api.RevokeResult
	if err := admin.Do(ctx(t), http.MethodPost, api.PathAdminRevoke, api.AdminRevoke{Client: "domain-b/alice"}, &rr); err != nil || rr.Revoked != 1 {
		t.Fatalf("revoke: %+v, %v", rr, err)
	}
	if body, err := get(t, alice, g); err == nil {
		t.Fatalf("revoked grant still works: %q", body)
	}

	// Removing web from Alice's entitlements revokes her grants on reload.
	if _, err := alice.RequestAccess(ctx(t), "web"); err != nil {
		t.Fatal(err)
	}
	l.writePolicy("web-b")
	if err := admin.Do(ctx(t), http.MethodPost, api.PathAdminReload, struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	var grants []api.GrantInfo
	if err := admin.Do(ctx(t), http.MethodGet, api.PathAdminGrants, nil, &grants); err != nil {
		t.Fatal(err)
	}
	for _, gi := range grants {
		if gi.Service == "web" && strings.Contains(gi.Client, "alice") {
			t.Fatal("grant survived a policy change that forbids it")
		}
	}
	if _, err := alice.RequestAccess(ctx(t), "web"); err == nil {
		t.Fatal("access granted after the policy removed it")
	}
}
