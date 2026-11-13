// Package identity defines how SecureSDP names the members of the perimeter.
//
// Every member (initiating host, accepting host, controller or operator) is
// identified by an X.509 certificate. The identity is carried in a URI
// Subject Alternative Name of the form
//
//	sdp://<domain>/<role>/<id>
//
// where <domain> is the SDP domain (one per controller in the Bridge model),
// <role> is one of client, gateway, controller or admin, and <id> is the
// member name inside that domain. The domain is the URI host, so the domain
// CA can be restricted to it with X.509 URI name constraints.
package identity

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Scheme is the URI scheme used in identity SANs.
const Scheme = "sdp"

// Role is the function a member plays in the perimeter.
type Role string

// Roles known to SecureSDP.
const (
	RoleClient     Role = "client"     // Initiating Host (IH)
	RoleGateway    Role = "gateway"    // Accepting Host (AH)
	RoleController Role = "controller" // root or bridged SDP controller
	RoleAdmin      Role = "admin"      // operator using the controller admin API
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleClient, RoleGateway, RoleController, RoleAdmin:
		return true
	}
	return false
}

var (
	domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	idRE     = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,62}[a-zA-Z0-9])?$`)
)

// ValidDomain reports whether s can be used as a domain name (a DNS label).
func ValidDomain(s string) bool { return domainRE.MatchString(s) }

// ValidID reports whether s can be used as a member ID.
func ValidID(s string) bool { return idRE.MatchString(s) }

// Identity is the parsed form of an identity URI.
type Identity struct {
	Domain string `json:"domain"`
	Role   Role   `json:"role"`
	ID     string `json:"id"`
}

// New returns a validated identity.
func New(domain string, role Role, id string) (Identity, error) {
	i := Identity{Domain: domain, Role: role, ID: id}
	return i, i.Validate()
}

// Validate checks every field.
func (i Identity) Validate() error {
	if !ValidDomain(i.Domain) {
		return fmt.Errorf("identity: invalid domain %q", i.Domain)
	}
	if !i.Role.Valid() {
		return fmt.Errorf("identity: invalid role %q", i.Role)
	}
	if !ValidID(i.ID) {
		return fmt.Errorf("identity: invalid id %q", i.ID)
	}
	return nil
}

// URI returns the identity as a URL suitable for a certificate SAN.
func (i Identity) URI() *url.URL {
	return &url.URL{Scheme: Scheme, Host: i.Domain, Path: "/" + string(i.Role) + "/" + i.ID}
}

// String returns the identity URI, e.g. sdp://domain-b/client/alice.
func (i Identity) String() string { return i.URI().String() }

// Name returns the short "<domain>/<id>" form used in policies and logs.
func (i Identity) Name() string { return i.Domain + "/" + i.ID }

// IsZero reports whether i is the zero value.
func (i Identity) IsZero() bool { return i == Identity{} }

// Parse parses an identity URI.
func Parse(s string) (Identity, error) {
	u, err := url.Parse(s)
	if err != nil {
		return Identity{}, fmt.Errorf("identity: %w", err)
	}
	return FromURI(u)
}

// FromURI converts an sdp:// URI to an Identity.
func FromURI(u *url.URL) (Identity, error) {
	if u.Scheme != Scheme {
		return Identity{}, fmt.Errorf("identity: scheme %q is not %q", u.Scheme, Scheme)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 2 || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Port() != "" {
		return Identity{}, fmt.Errorf("identity: malformed identity URI %q", u.String())
	}
	i := Identity{Domain: u.Host, Role: Role(parts[0]), ID: parts[1]}
	return i, i.Validate()
}

// ErrNoIdentity is returned when a certificate carries no sdp:// URI SAN.
var ErrNoIdentity = errors.New("identity: certificate has no sdp:// URI SAN")

// FromCertificate extracts the single identity of a certificate.
func FromCertificate(c *x509.Certificate) (Identity, error) {
	var found []Identity
	for _, u := range c.URIs {
		if u.Scheme != Scheme {
			continue
		}
		i, err := FromURI(u)
		if err != nil {
			return Identity{}, err
		}
		found = append(found, i)
	}
	switch len(found) {
	case 0:
		return Identity{}, ErrNoIdentity
	case 1:
		return found[0], nil
	default:
		return Identity{}, errors.New("identity: certificate has more than one sdp:// URI SAN")
	}
}
