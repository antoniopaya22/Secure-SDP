// Package pki implements the SecureSDP public key infrastructure.
//
// The PKI follows the Bridge model of the paper: a single root CA is the trust
// anchor shared by every SDP domain, and each domain (one per controller) has
// its own intermediate CA. Every domain CA carries an X.509 URI name
// constraint that only permits identities of its own domain
// (sdp://<domain>/...), so a compromised or misconfigured domain CA cannot
// mint identities for another domain. Bridged controllers can therefore relay
// requests from their members and the root controller can verify them
// end to end without trusting the bridge blindly.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/identity"
)

// Organization is written in the subject of every certificate.
const Organization = "SecureSDP"

// CA is a certificate authority: its certificate and private key.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	// Parent is the issuer of an intermediate CA (nil for the root CA).
	Parent *x509.Certificate
}

// Leaf is an end-entity certificate with its key and the intermediate that issued it.
type Leaf struct {
	Cert         *x509.Certificate
	Key          crypto.Signer
	Intermediate *x509.Certificate
}

// LeafRequest describes a member certificate to issue.
type LeafRequest struct {
	Identity identity.Identity
	DNSNames []string
	IPs      []net.IP
	Validity time.Duration
}

func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
}

func keyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:20], nil
}

// NewRootCA creates a self-signed root CA (the bridge trust anchor).
func NewRootCA(commonName string, validity time.Duration) (*CA, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	ski, err := keyID(key.Public())
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{Organization}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// NewDomainCA issues the intermediate CA of an SDP domain. The CA is
// constrained to identities whose URI host is the domain.
func (ca *CA) NewDomainCA(domain string, validity time.Duration) (*CA, error) {
	if ca.Parent != nil {
		return nil, errors.New("pki: domain CAs must be issued by the root CA")
	}
	if !identity.ValidDomain(domain) {
		return nil, fmt.Errorf("pki: invalid domain %q", domain)
	}
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	ski, err := keyID(key.Public())
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "SecureSDP domain CA " + domain, Organization: []string{Organization}, OrganizationalUnit: []string{domain}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              minTime(now.Add(validity), ca.Cert.NotAfter),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski,
		// Bridge-CA constraint: this CA can only vouch for its own domain.
		PermittedURIDomains: []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, Parent: ca.Cert}, nil
}

// Domain returns the domain a domain CA is constrained to ("" for the root CA).
func (ca *CA) Domain() string { return DomainOf(ca.Cert) }

// DomainOf returns the single URI domain a CA certificate is constrained to.
func DomainOf(c *x509.Certificate) string {
	if len(c.PermittedURIDomains) == 1 {
		return c.PermittedURIDomains[0]
	}
	return ""
}

// Issue signs a member certificate. Only domain CAs issue member
// certificates, and only for identities of their own domain.
func (ca *CA) Issue(req LeafRequest) (*Leaf, error) {
	if ca.Parent == nil {
		return nil, errors.New("pki: the root CA only issues domain CAs")
	}
	if err := req.Identity.Validate(); err != nil {
		return nil, err
	}
	if req.Identity.Domain != ca.Domain() {
		return nil, fmt.Errorf("pki: CA of domain %q cannot issue identity of domain %q", ca.Domain(), req.Identity.Domain)
	}
	if req.Validity <= 0 {
		req.Validity = 365 * 24 * time.Hour
	}
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:         req.Identity.ID,
			Organization:       []string{Organization},
			OrganizationalUnit: []string{req.Identity.Domain, string(req.Identity.Role)},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              minTime(now.Add(req.Validity), ca.Cert.NotAfter),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{req.Identity.URI()},
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Leaf{Cert: cert, Key: key, Intermediate: ca.Cert}, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// ---------------------------------------------------------------- encoding

// EncodeCert returns the PEM encoding of certificates, in order.
func EncodeCert(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// EncodeKey returns the PKCS#8 PEM encoding of a private key.
func EncodeKey(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseCerts decodes every CERTIFICATE block of a PEM file.
func ParseCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("pki: no certificate found")
	}
	return certs, nil
}

// ParseKey decodes a PKCS#8 (or SEC1 EC) private key.
func ParseKey(data []byte) (crypto.Signer, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("pki: no PEM key found")
	}
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("pki: key is not a signer")
	}
	return x509.ParseECPrivateKey(b.Bytes)
}

// ---------------------------------------------------------------- files

// File names used in CA and member directories.
const (
	CertFile = "cert.pem" // member cert followed by its domain CA cert
	KeyFile  = "key.pem"
	CAFile   = "ca.pem" // root CA (trust anchor)
)

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SaveCA writes a CA as dir/cert.pem and dir/key.pem.
func SaveCA(dir string, ca *CA) error {
	key, err := EncodeKey(ca.Key)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, KeyFile), key, 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, CertFile), EncodeCert(ca.Cert), 0o644)
}

// LoadCA reads a CA saved with SaveCA. parent is nil for the root CA.
func LoadCA(dir string, parent *x509.Certificate) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, err
	}
	certs, err := ParseCerts(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: certs[0], Key: key, Parent: parent}, nil
}

// SaveLeaf writes a member bundle: cert.pem (leaf + domain CA), key.pem and
// ca.pem (the root CA the member trusts).
func SaveLeaf(dir string, leaf *Leaf, root *x509.Certificate) error {
	key, err := EncodeKey(leaf.Key)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, KeyFile), key, 0o600); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, CertFile), EncodeCert(leaf.Cert, leaf.Intermediate), 0o644); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, CAFile), EncodeCert(root), 0o644)
}
