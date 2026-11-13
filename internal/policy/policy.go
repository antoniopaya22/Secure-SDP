// Package policy holds the authorization policy of the root SDP controller,
// which acts as Policy Decision Point for every domain of the Bridge model.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
	"github.com/antoniopaya22/Secure-SDP/internal/hardening"
	"github.com/antoniopaya22/Secure-SDP/internal/identity"
)

// Duration is a time.Duration written as "30s", "10m"...
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// String formats the duration like time.Duration.
func (d Duration) String() string { return time.Duration(d).String() }

// Policy is the root controller policy file.
type Policy struct {
	Defaults  Defaults                  `yaml:"defaults"`
	Domains   []Domain                  `yaml:"domains"`
	Gateways  []Gateway                 `yaml:"gateways"`
	Services  []Service                 `yaml:"services"`
	Clients   []Client                  `yaml:"clients"`
	Hardening map[string]hardening.Spec `yaml:"hardening"`
}

// Defaults applies to every service unless overridden.
type Defaults struct {
	// AccessTimeout is FW_ACCESS_TIMEOUT: how long the firewall stays open
	// after a valid SPA packet.
	AccessTimeout Duration `yaml:"access_timeout"`
	// GrantTTL is how long the SPA credentials of a grant remain valid.
	GrantTTL Duration `yaml:"grant_ttl"`
	// Hardening profiles applied to every accepting host.
	Hardening []string `yaml:"hardening"`
	// EgidaHost is the HOST block of generated Aspida programs.
	EgidaHost string `yaml:"egida_host"`
}

// Domain is an SDP domain, fronted by one controller.
type Domain struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// Gateway is an accepting host.
type Gateway struct {
	ID      string `yaml:"id"`
	Domain  string `yaml:"domain"`
	Address string `yaml:"address"` // IP or name initiating hosts use to reach it
	SPAPort int    `yaml:"spa_port"`
	// TunnelPort is where the AH accepts mTLS tunnels (tunnel mode).
	TunnelPort int `yaml:"tunnel_port"`
}

// Service is a protected resource behind an accepting host.
type Service struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Gateway     string `yaml:"gateway"`
	// Target is host:port of the service as seen from the accepting host.
	Target string `yaml:"target"`
	// Mode is "forward" (fwknopd DNAT) or "tunnel" (mTLS tunnel on the AH).
	Mode string `yaml:"mode"`
	// Port is the gateway port clients connect to in forward mode.
	Port          int      `yaml:"port"`
	AccessTimeout Duration `yaml:"access_timeout"`
	// Hardening profiles this service requires on its accepting host.
	Hardening []string `yaml:"hardening"`
}

// Client is a registered initiating host and the services it may use.
type Client struct {
	ID       string   `yaml:"id"`
	Domain   string   `yaml:"domain"`
	Services []string `yaml:"services"`
	Disabled bool     `yaml:"disabled"`
}

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Parse decodes and validates a policy document.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p.applyDefaults()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) applyDefaults() {
	if p.Defaults.AccessTimeout == 0 {
		p.Defaults.AccessTimeout = Duration(30 * time.Second)
	}
	if p.Defaults.GrantTTL == 0 {
		p.Defaults.GrantTTL = Duration(10 * time.Minute)
	}
	if p.Defaults.EgidaHost == "" {
		p.Defaults.EgidaHost = "localhost"
	}
	for i := range p.Gateways {
		if p.Gateways[i].SPAPort == 0 {
			p.Gateways[i].SPAPort = 62201
		}
		if p.Gateways[i].TunnelPort == 0 {
			p.Gateways[i].TunnelPort = 8443
		}
	}
	for i := range p.Services {
		if p.Services[i].Mode == "" {
			p.Services[i].Mode = api.ModeTunnel
		}
		if p.Services[i].AccessTimeout == 0 {
			p.Services[i].AccessTimeout = p.Defaults.AccessTimeout
		}
	}
}

// Validate checks references and value ranges.
func (p *Policy) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("policy: "+format, a...)) }

	if len(p.Domains) == 0 {
		bad("at least one domain is required")
	}
	domains := map[string]bool{}
	for _, d := range p.Domains {
		if !identity.ValidDomain(d.Name) {
			bad("domain %q: invalid name", d.Name)
		}
		if domains[d.Name] {
			bad("domain %q: duplicated", d.Name)
		}
		domains[d.Name] = true
	}
	if time.Duration(p.Defaults.GrantTTL) < time.Minute {
		bad("defaults.grant_ttl must be at least 1m")
	}
	checkProfiles := func(where string, names []string) {
		for _, n := range names {
			if _, ok := p.Hardening[n]; !ok {
				bad("%s: unknown hardening profile %q", where, n)
			}
		}
	}
	checkProfiles("defaults.hardening", p.Defaults.Hardening)

	gateways := map[string]*Gateway{}
	for i := range p.Gateways {
		g := &p.Gateways[i]
		if !identity.ValidID(g.ID) {
			bad("gateway %q: invalid id", g.ID)
		}
		if gateways[g.ID] != nil {
			bad("gateway %q: duplicated", g.ID)
		}
		gateways[g.ID] = g
		if !domains[g.Domain] {
			bad("gateway %q: unknown domain %q", g.ID, g.Domain)
		}
		if g.Address == "" {
			bad("gateway %q: address is required", g.ID)
		}
		if !validPort(g.SPAPort) || !validPort(g.TunnelPort) {
			bad("gateway %q: invalid port", g.ID)
		}
	}

	services := map[string]bool{}
	usedPorts := map[string]string{}
	for _, s := range p.Services {
		if !identity.ValidDomain(s.Name) { // same charset as DNS labels (used as TLS SNI)
			bad("service %q: invalid name (lowercase letters, digits and '-')", s.Name)
		}
		if services[s.Name] {
			bad("service %q: duplicated", s.Name)
		}
		services[s.Name] = true
		g := gateways[s.Gateway]
		if g == nil {
			bad("service %q: unknown gateway %q", s.Name, s.Gateway)
		}
		host, port, err := net.SplitHostPort(s.Target)
		if err != nil || host == "" {
			bad("service %q: target must be host:port", s.Name)
		} else if n, _ := strconv.Atoi(port); !validPort(n) {
			bad("service %q: invalid target port", s.Name)
		}
		switch s.Mode {
		case api.ModeForward:
			if net.ParseIP(host) == nil {
				bad("service %q: forward mode needs an IP target (fwknop FORCE_NAT)", s.Name)
			}
			if !validPort(s.Port) {
				bad("service %q: forward mode needs a gateway port", s.Name)
			}
			if g != nil {
				if s.Port == g.TunnelPort || s.Port == g.SPAPort {
					bad("service %q: port %d is reserved on gateway %q", s.Name, s.Port, g.ID)
				}
				key := g.ID + ":" + strconv.Itoa(s.Port)
				if other, dup := usedPorts[key]; dup {
					bad("service %q: port %d already used by %q", s.Name, s.Port, other)
				}
				usedPorts[key] = s.Name
			}
		case api.ModeTunnel:
		default:
			bad("service %q: mode must be %q or %q", s.Name, api.ModeForward, api.ModeTunnel)
		}
		if t := time.Duration(s.AccessTimeout); t < time.Second || t > time.Hour {
			bad("service %q: access_timeout must be between 1s and 1h", s.Name)
		}
		checkProfiles("service "+s.Name, s.Hardening)
	}

	clients := map[string]bool{}
	for _, c := range p.Clients {
		if !identity.ValidID(c.ID) {
			bad("client %q: invalid id", c.ID)
		}
		if !domains[c.Domain] {
			bad("client %q: unknown domain %q", c.ID, c.Domain)
		}
		key := c.Domain + "/" + c.ID
		if clients[key] {
			bad("client %q: duplicated", key)
		}
		clients[key] = true
		for _, s := range c.Services {
			if !services[s] {
				bad("client %q: unknown service %q", key, s)
			}
		}
	}
	return errors.Join(errs...)
}

func validPort(p int) bool { return p > 0 && p < 65536 }

// Gateway returns the gateway with the given ID.
func (p *Policy) Gateway(id string) *Gateway {
	for i := range p.Gateways {
		if p.Gateways[i].ID == id {
			return &p.Gateways[i]
		}
	}
	return nil
}

// Service returns the service with the given name.
func (p *Policy) Service(name string) *Service {
	for i := range p.Services {
		if p.Services[i].Name == name {
			return &p.Services[i]
		}
	}
	return nil
}

// HasDomain reports whether the policy declares a domain.
func (p *Policy) HasDomain(name string) bool {
	return slices.ContainsFunc(p.Domains, func(d Domain) bool { return d.Name == name })
}

func (p *Policy) client(id identity.Identity) *Client {
	for i := range p.Clients {
		if p.Clients[i].Domain == id.Domain && p.Clients[i].ID == id.ID {
			return &p.Clients[i]
		}
	}
	return nil
}

// Decision is the outcome of an authorization request.
type Decision struct {
	Allowed bool
	Reason  string
	Service *Service
	Gateway *Gateway
}

// Decide authorizes (or not) an authenticated client to use a service.
// Access is denied by default: the client must be registered, enabled and
// explicitly entitled to the service.
func (p *Policy) Decide(client identity.Identity, service string) Decision {
	if client.Role != identity.RoleClient {
		return Decision{Reason: fmt.Sprintf("%s is not an initiating host", client)}
	}
	c := p.client(client)
	if c == nil {
		return Decision{Reason: fmt.Sprintf("%s is not registered", client.Name())}
	}
	if c.Disabled {
		return Decision{Reason: fmt.Sprintf("%s is disabled", client.Name())}
	}
	s := p.Service(service)
	if s == nil || !slices.Contains(c.Services, service) {
		// Unknown and forbidden services get the same answer, so clients
		// cannot enumerate the perimeter.
		return Decision{Reason: fmt.Sprintf("%s is not authorized for service %q", client.Name(), service)}
	}
	return Decision{Allowed: true, Reason: "granted by policy", Service: s, Gateway: p.Gateway(s.Gateway)}
}

// ServicesFor lists the services a client is entitled to.
func (p *Policy) ServicesFor(client identity.Identity) []Service {
	c := p.client(client)
	if c == nil || c.Disabled || client.Role != identity.RoleClient {
		return nil
	}
	var out []Service
	for _, name := range c.Services {
		if s := p.Service(name); s != nil {
			out = append(out, *s)
		}
	}
	return out
}

// GatewayServices lists the services exposed through a gateway.
func (p *Policy) GatewayServices(gatewayID string) []Service {
	var out []Service
	for _, s := range p.Services {
		if s.Gateway == gatewayID {
			out = append(out, s)
		}
	}
	return out
}

// HardeningProfile derives the Aspida program for a gateway from the default
// profiles and the profiles of every service it exposes. It returns nil when
// no profile applies.
func (p *Policy) HardeningProfile(gatewayID string) (*api.HardeningProfile, error) {
	names := slices.Clone(p.Defaults.Hardening)
	var services []string
	for _, s := range p.GatewayServices(gatewayID) {
		services = append(services, s.Name)
		for _, h := range s.Hardening {
			if !slices.Contains(names, h) {
				names = append(names, h)
			}
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	specs := make([]hardening.Spec, 0, len(names))
	for _, n := range names {
		specs = append(specs, p.Hardening[n])
	}
	name := "securesdp-" + gatewayID
	desc := fmt.Sprintf("SecureSDP dynamic hardening of accepting host %s (profiles: %v, services: %v)", gatewayID, names, services)
	src, err := hardening.RenderAspida(hardening.Program{
		Name: name, Description: desc, Host: p.Defaults.EgidaHost, Spec: hardening.Merge(specs...),
	})
	if err != nil {
		return nil, err
	}
	return &api.HardeningProfile{Name: name, Services: services, Aspida: src, Hash: hardening.Hash(src)}, nil
}
