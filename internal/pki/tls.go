package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/antoniopaya22/Secure-SDP/internal/identity"
)

// TLSFiles points to the PEM files of a member.
type TLSFiles struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}

// Member is the loaded TLS material of a perimeter member.
type Member struct {
	Certificate tls.Certificate
	Identity    identity.Identity
	Verifier    *Verifier
}

// LoadMember reads a member bundle and checks that its certificate chains to
// the root CA.
func LoadMember(f TLSFiles) (*Member, error) {
	if f.Cert == "" || f.Key == "" || f.CA == "" {
		return nil, errors.New("pki: tls.cert, tls.key and tls.ca are required")
	}
	cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: load key pair: %w", err)
	}
	caPEM, err := os.ReadFile(f.CA)
	if err != nil {
		return nil, err
	}
	roots, err := ParseCerts(caPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: %s: %w", f.CA, err)
	}
	v := NewVerifier(roots...)
	chain := make([]*x509.Certificate, 0, len(cert.Certificate))
	for _, der := range cert.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	id, err := v.Verify(chain)
	if err != nil {
		return nil, fmt.Errorf("pki: own certificate %s: %w", f.Cert, err)
	}
	cert.Leaf = chain[0]
	return &Member{Certificate: cert, Identity: id, Verifier: v}, nil
}

// Verifier validates member certificate chains against the root CA and
// extracts their identity.
type Verifier struct {
	roots *x509.CertPool
}

// NewVerifier returns a verifier trusting the given root CAs.
func NewVerifier(roots ...*x509.Certificate) *Verifier {
	p := x509.NewCertPool()
	for _, r := range roots {
		p.AddCert(r)
	}
	return &Verifier{roots: p}
}

// Roots returns the trust anchors as a pool.
func (v *Verifier) Roots() *x509.CertPool { return v.roots }

// Verify checks that chain[0] is a member certificate issued by a domain CA
// that chains to the root, and that the identity domain is the one the domain
// CA is constrained to.
func (v *Verifier) Verify(chain []*x509.Certificate) (identity.Identity, error) {
	if len(chain) == 0 {
		return identity.Identity{}, errors.New("pki: empty certificate chain")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	verified, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return identity.Identity{}, err
	}
	id, err := identity.FromCertificate(chain[0])
	if err != nil {
		return identity.Identity{}, err
	}
	for _, path := range verified {
		// leaf -> domain CA -> root
		if len(path) == 3 && DomainOf(path[1]) == id.Domain {
			return id, nil
		}
	}
	return identity.Identity{}, fmt.Errorf("pki: %s is not issued by the CA of domain %q", id, id.Domain)
}

// VerifyDER is Verify for DER-encoded certificates (as relayed between controllers).
func (v *Verifier) VerifyDER(chain [][]byte) (identity.Identity, error) {
	certs := make([]*x509.Certificate, 0, len(chain))
	for _, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return identity.Identity{}, err
		}
		certs = append(certs, c)
	}
	return v.Verify(certs)
}

// PeerIdentity returns the identity of the peer of an established mTLS connection.
func PeerIdentity(cs tls.ConnectionState) (identity.Identity, error) {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return identity.Identity{}, errors.New("pki: peer presented no verified certificate")
	}
	return identity.FromCertificate(cs.VerifiedChains[0][0])
}

// RawChain returns the DER certificates a peer presented (leaf first).
func RawChain(cs tls.ConnectionState) [][]byte {
	out := make([][]byte, 0, len(cs.PeerCertificates))
	for _, c := range cs.PeerCertificates {
		out = append(out, c.Raw)
	}
	return out
}

// ServerConfig returns a TLS 1.3 server configuration that requires a client
// certificate from the same PKI and checks its identity with accept.
func (m *Member) ServerConfig(accept func(identity.Identity) error) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{m.Certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    m.Verifier.roots,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("pki: client certificate required")
			}
			id, err := m.Verifier.Verify(cs.PeerCertificates)
			if err != nil {
				return err
			}
			if accept != nil {
				return accept(id)
			}
			return nil
		},
	}
}

// ClientConfig returns a TLS 1.3 client configuration that presents the
// member certificate and verifies the server against the PKI. The server is
// authenticated by its identity (expect), not by its host name, so members
// can be reached by IP address. serverName is only sent as SNI.
func (m *Member) ClientConfig(serverName string, expect func(identity.Identity) error) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{m.Certificate},
		ServerName:         serverName,
		InsecureSkipVerify: true, // replaced by VerifyConnection below (chain + identity)
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := m.Verifier.Verify(cs.PeerCertificates)
			if err != nil {
				return err
			}
			if expect != nil {
				return expect(id)
			}
			return nil
		},
	}
}

// ExpectRole returns an identity check that requires a role (and optionally a domain and ID).
func ExpectRole(role identity.Role, domain, id string) func(identity.Identity) error {
	return func(got identity.Identity) error {
		if got.Role != role || (domain != "" && got.Domain != domain) || (id != "" && got.ID != id) {
			want := identity.Identity{Domain: domain, Role: role, ID: id}
			return fmt.Errorf("pki: unexpected peer %s (want role=%s domain=%q id=%q)", got, want.Role, want.Domain, want.ID)
		}
		return nil
	}
}
