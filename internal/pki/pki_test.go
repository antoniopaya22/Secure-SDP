package pki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/identity"
)

func mustID(t *testing.T, d string, r identity.Role, id string) identity.Identity {
	t.Helper()
	i, err := identity.New(d, r, id)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func setup(t *testing.T) (*CA, *CA, *CA) {
	t.Helper()
	root, err := NewRootCA("test root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a, err := root.NewDomainCA("domain-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := root.NewDomainCA("domain-b", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return root, a, b
}

func chain(l *Leaf) []*x509.Certificate { return []*x509.Certificate{l.Cert, l.Intermediate} }

func TestIssueAndVerify(t *testing.T) {
	root, _, b := setup(t)
	alice := mustID(t, "domain-b", identity.RoleClient, "alice")
	leaf, err := b.Issue(LeafRequest{Identity: alice})
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewVerifier(root.Cert).Verify(chain(leaf))
	if err != nil {
		t.Fatal(err)
	}
	if got != alice {
		t.Fatalf("identity = %v, want %v", got, alice)
	}
}

func TestDomainCACannotIssueForOtherDomain(t *testing.T) {
	_, a, _ := setup(t)
	if _, err := a.Issue(LeafRequest{Identity: mustID(t, "domain-b", identity.RoleClient, "mallory")}); err == nil {
		t.Fatal("domain-a CA issued a domain-b identity")
	}
}

// Even if a domain CA key is abused to sign a certificate for another domain
// (bypassing Issue), the X.509 name constraint makes verification fail.
func TestNameConstraintEnforced(t *testing.T) {
	root, a, _ := setup(t)
	forged := mustID(t, "domain-b", identity.RoleClient, "mallory")
	key, _ := newKey()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "mallory"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{forged.URI()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, key.Public(), a.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	if _, err := NewVerifier(root.Cert).Verify([]*x509.Certificate{cert, a.Cert}); err == nil {
		t.Fatal("certificate violating the name constraint was accepted")
	}
}

func TestRogueRootRejected(t *testing.T) {
	root, _, _ := setup(t)
	rogueRoot, _ := NewRootCA("rogue", time.Hour)
	rogueB, _ := rogueRoot.NewDomainCA("domain-b", time.Hour)
	leaf, err := rogueB.Issue(LeafRequest{Identity: mustID(t, "domain-b", identity.RoleClient, "alice")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerifier(root.Cert).Verify(chain(leaf)); err == nil {
		t.Fatal("chain from a rogue root accepted")
	}
}

func TestRootCannotIssueLeaves(t *testing.T) {
	root, _, _ := setup(t)
	if _, err := root.Issue(LeafRequest{Identity: mustID(t, "domain-a", identity.RoleClient, "x")}); err == nil {
		t.Fatal("root CA issued a member certificate")
	}
}

func TestSaveLoadMember(t *testing.T) {
	root, a, _ := setup(t)
	dir := t.TempDir()
	if err := SaveCA(filepath.Join(dir, "root"), root); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(filepath.Join(dir, "root"), nil)
	if err != nil || !loaded.Cert.Equal(root.Cert) {
		t.Fatalf("LoadCA: %v", err)
	}
	ctrl := mustID(t, "domain-a", identity.RoleController, "ctrl-a")
	leaf, err := a.Issue(LeafRequest{Identity: ctrl, DNSNames: []string{"ctrl-a"}})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "ctrl-a")
	if err := SaveLeaf(out, leaf, root.Cert); err != nil {
		t.Fatal(err)
	}
	m, err := LoadMember(TLSFiles{Cert: filepath.Join(out, CertFile), Key: filepath.Join(out, KeyFile), CA: filepath.Join(out, CAFile)})
	if err != nil {
		t.Fatal(err)
	}
	if m.Identity != ctrl {
		t.Fatalf("member identity = %v", m.Identity)
	}
	if len(m.Certificate.Certificate) != 2 {
		t.Fatalf("member chain has %d certificates, want leaf + domain CA", len(m.Certificate.Certificate))
	}
}

func TestExpectRole(t *testing.T) {
	gw := mustID(t, "domain-a", identity.RoleGateway, "gw-a")
	if err := ExpectRole(identity.RoleGateway, "domain-a", "gw-a")(gw); err != nil {
		t.Fatal(err)
	}
	err := ExpectRole(identity.RoleController, "", "")(gw)
	if err == nil || !strings.Contains(err.Error(), "unexpected peer") {
		t.Fatalf("got %v", err)
	}
}
