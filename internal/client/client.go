// Package client implements the SecureSDP Initiating Host (IH), the
// sdp-client module of the paper: it authenticates to the controller of its
// domain with mutual TLS, requests access to services, knocks on the
// accepting host with a Single Packet Authorization packet and connects.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
	"github.com/antoniopaya22/Secure-SDP/internal/fwknop"
	"github.com/antoniopaya22/Secure-SDP/internal/identity"
	"github.com/antoniopaya22/Secure-SDP/internal/pki"
)

// Config is the sdp-client configuration file.
type Config struct {
	// Controller is host:port of the HTTPS API of this IH's domain controller.
	Controller string `yaml:"controller"`
	// ControllerIdentity optionally pins the controller identity URI.
	ControllerIdentity string       `yaml:"controller_identity"`
	TLS                pki.TLSFiles `yaml:"tls"`
	// Fwknop is the fwknop client binary.
	Fwknop string `yaml:"fwknop"`
	// AllowIP overrides the source address put in SPA packets.
	AllowIP string `yaml:"allow_ip"`
}

// LoadConfig reads a configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Controller == "" {
		return nil, errors.New("client: controller is required")
	}
	return &c, nil
}

// Client talks to the controller and to accepting hosts.
type Client struct {
	cfg  *Config
	me   *pki.Member
	http *http.Client
	base string
}

// New loads the member certificate and prepares the HTTPS client.
func New(cfg *Config) (*Client, error) {
	me, err := pki.LoadMember(cfg.TLS)
	if err != nil {
		return nil, err
	}
	if me.Identity.Role != identity.RoleClient && me.Identity.Role != identity.RoleAdmin {
		return nil, fmt.Errorf("client: certificate identity %s is not an initiating host or admin", me.Identity)
	}
	host, _, err := net.SplitHostPort(cfg.Controller)
	if err != nil {
		return nil, fmt.Errorf("client: controller must be host:port: %w", err)
	}
	expect := pki.ExpectRole(identity.RoleController, "", "")
	if cfg.ControllerIdentity != "" {
		want, err := identity.Parse(cfg.ControllerIdentity)
		if err != nil {
			return nil, fmt.Errorf("client: controller_identity: %w", err)
		}
		expect = pki.ExpectRole(want.Role, want.Domain, want.ID)
	}
	tr := &http.Transport{
		TLSClientConfig:     me.ClientConfig(host, expect),
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{cfg: cfg, me: me, http: &http.Client{Transport: tr}, base: "https://" + cfg.Controller}, nil
}

// Identity returns the IH identity.
func (c *Client) Identity() identity.Identity { return c.me.Identity }

// APIError is an error answered by the controller.
type APIError struct {
	Status int
	Body   api.ErrorBody
}

func (e *APIError) Error() string {
	return fmt.Sprintf("controller answered %d %s: %s", e.Status, e.Body.Code, e.Body.Message)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		e := &APIError{Status: res.StatusCode}
		if json.Unmarshal(data, &e.Body) != nil {
			e.Body.Message = string(data)
		}
		return e
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Do performs an arbitrary API call (used by the admin CLI).
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	return c.do(ctx, method, path, in, out)
}

// WhoAmI asks the controller who we are.
func (c *Client) WhoAmI(ctx context.Context) (*api.WhoAmI, error) {
	var w api.WhoAmI
	return &w, c.do(ctx, http.MethodGet, api.PathWhoAmI, nil, &w)
}

// Services lists the services this IH may access.
func (c *Client) Services(ctx context.Context) ([]api.ServiceInfo, error) {
	var s []api.ServiceInfo
	return s, c.do(ctx, http.MethodGet, api.PathServices, nil, &s)
}

// RequestAccess asks the controller for a grant.
func (c *Client) RequestAccess(ctx context.Context, service string) (*api.AccessGrant, error) {
	var g api.AccessGrant
	if err := c.do(ctx, http.MethodPost, api.PathAccess, api.AccessRequest{Service: service}, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// Knock sends the SPA packet of a grant to its accepting host.
func (c *Client) Knock(ctx context.Context, g *api.AccessGrant) error {
	return fwknop.SendSPA(ctx, fwknop.SPARequest{
		Binary: c.cfg.Fwknop, Server: g.Gateway.Address, SPAPort: g.Gateway.SPAPort,
		Protocol: g.Protocol, Port: g.Port, AllowIP: c.cfg.AllowIP,
		KeyBase64: g.SPA.KeyBase64, HMACKeyBase64: g.SPA.HMACKeyBase64, HMACDigest: g.SPA.HMACDigest,
	})
}

// Endpoint is the gateway address a grant opens.
func Endpoint(g *api.AccessGrant) string {
	return net.JoinHostPort(g.Gateway.Address, strconv.Itoa(g.Port))
}

// KnockAndWait sends SPA packets until a TCP connection to the opened port
// succeeds (fwknop gives no feedback, and UDP may be lost), up to attempts.
func (c *Client) KnockAndWait(ctx context.Context, g *api.AccessGrant, attempts int) error {
	if attempts < 1 {
		attempts = 1
	}
	var last error
	for i := 0; i < attempts; i++ {
		if err := c.Knock(ctx, g); err != nil {
			return err
		}
		for j := 0; j < 4; j++ {
			d := net.Dialer{Timeout: 700 * time.Millisecond}
			conn, err := d.DialContext(ctx, "tcp", Endpoint(g))
			if err == nil {
				_ = conn.Close()
				return nil
			}
			last = err
			if ctx.Err() != nil {
				return ctx.Err()
			}
			time.Sleep(150 * time.Millisecond)
		}
	}
	return fmt.Errorf("client: %s still closed after %d SPA attempts: %v", Endpoint(g), attempts, last)
}

// DialTunnel opens the mTLS data channel to the accepting host of a
// tunnel-mode grant. The accepting host is authenticated by its identity.
func (c *Client) DialTunnel(ctx context.Context, g *api.AccessGrant) (*tls.Conn, error) {
	conf := c.me.ClientConfig(g.Service, pki.ExpectRole(identity.RoleGateway, g.Gateway.Domain, g.Gateway.ID))
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: conf}
	nc, err := d.DialContext(ctx, "tcp", Endpoint(g))
	if err != nil {
		return nil, err
	}
	return nc.(*tls.Conn), nil
}

// Session keeps a grant fresh and knocks when the access window is over.
// It is used by the local forwarder of tunnel-mode services.
type Session struct {
	Client  *Client
	Service string
	// Log receives progress messages (optional).
	Log func(format string, args ...any)

	mu        sync.Mutex
	grant     *api.AccessGrant
	lastKnock time.Time
}

func (s *Session) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(format, args...)
	}
}

// Grant returns a valid grant, requesting a new one when needed.
func (s *Session) Grant(ctx context.Context) (*api.AccessGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grantLocked(ctx)
}

func (s *Session) grantLocked(ctx context.Context) (*api.AccessGrant, error) {
	if s.grant != nil && time.Until(s.grant.ExpiresAt) > 10*time.Second {
		return s.grant, nil
	}
	g, err := s.Client.RequestAccess(ctx, s.Service)
	if err != nil {
		return nil, err
	}
	s.logf("access to %q granted via %v (gateway %s, expires %s)", g.Service, g.Path, g.Gateway.ID, g.ExpiresAt.Format(time.RFC3339))
	s.grant, s.lastKnock = g, time.Time{}
	return g, nil
}

// Dial returns a tunnel connection, knocking first if the access window may
// have closed, and retrying with a fresh SPA packet if the port is closed.
func (s *Session) Dial(ctx context.Context) (*tls.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		g, err := s.grantLocked(ctx)
		if err != nil {
			return nil, err
		}
		window := time.Duration(g.AccessTimeout)*time.Second - 2*time.Second
		if attempt > 0 || time.Since(s.lastKnock) > window {
			if err := s.Client.Knock(ctx, g); err != nil {
				return nil, err
			}
			s.lastKnock = time.Now()
			time.Sleep(100 * time.Millisecond)
		}
		conn, err := s.Client.DialTunnel(ctx, g)
		if err == nil {
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}
