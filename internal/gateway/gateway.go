// Package gateway implements the SecureSDP Accepting Host (AH), the
// sdp-services module of the paper: the Policy Enforcement Point that keeps
// protected services dark (default-drop firewall + fwknop SPA), installs the
// per-client authorizations issued by the controller, terminates mTLS
// tunnels from initiating hosts and applies the hardening profile the
// controller sends (Egida master/slave model).
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
	"github.com/antoniopaya22/Secure-SDP/internal/firewall"
	"github.com/antoniopaya22/Secure-SDP/internal/fwknop"
	"github.com/antoniopaya22/Secure-SDP/internal/hardening"
	"github.com/antoniopaya22/Secure-SDP/internal/identity"
	"github.com/antoniopaya22/Secure-SDP/internal/pki"
	"github.com/antoniopaya22/Secure-SDP/internal/rpc"
)

// Config is the sdp-services configuration file.
type Config struct {
	// Controller is the peer-link address of the controller of this AH's domain.
	Controller string `yaml:"controller"`
	// ControllerIdentity optionally pins the controller identity URI.
	ControllerIdentity string       `yaml:"controller_identity"`
	TLS                pki.TLSFiles `yaml:"tls"`
	// PublicIP is the address initiating hosts send SPA packets to.
	PublicIP string `yaml:"public_ip"`
	// Interface fwknopd sniffs; derived from PublicIP when empty.
	Interface string `yaml:"interface"`
	StateDir  string `yaml:"state_dir"`
	ReadyFile string `yaml:"ready_file"`

	Fwknop struct {
		Enabled bool   `yaml:"enabled"`
		Binary  string `yaml:"binary"`
		SPAPort int    `yaml:"spa_port"`
		RunDir  string `yaml:"run_dir"`
	} `yaml:"fwknop"`
	Firewall struct {
		Manage bool   `yaml:"manage"`
		Binary string `yaml:"binary"`
	} `yaml:"firewall"`
	Tunnel struct {
		Listen string `yaml:"listen"`
	} `yaml:"tunnel"`
	Hardening struct {
		Driver string `yaml:"driver"` // egida | dry-run
		Egida  string `yaml:"egida"`  // egida binary
	} `yaml:"hardening"`
	Audit struct {
		Lynis string `yaml:"lynis"`
	} `yaml:"audit"`
}

// LoadConfig reads a configuration file and applies defaults.
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
		return nil, errors.New("gateway: controller address is required")
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/sdp-services"
	}
	if c.Fwknop.RunDir == "" {
		c.Fwknop.RunDir = "/run/fwknop"
	}
	if c.Fwknop.SPAPort == 0 {
		c.Fwknop.SPAPort = fwknop.DefaultSPAPort
	}
	if c.Tunnel.Listen == "" {
		c.Tunnel.Listen = ":8443"
	}
	if c.Fwknop.Enabled && c.PublicIP == "" && c.Interface == "" {
		return nil, errors.New("gateway: public_ip or interface is required with fwknop")
	}
	return &c, nil
}

// Agent is a running accepting host.
type Agent struct {
	cfg *Config
	me  *pki.Member
	log *slog.Logger

	mu     sync.Mutex
	grants map[string]api.GatewayGrant

	applyMu  sync.Mutex
	daemon   *fwknop.Daemon
	decoy    fwknop.Stanza
	hardener hardening.Hardener
	auditor  *hardening.Lynis

	dialer   *rpc.Dialer
	tunnelLn net.Listener
}

// New prepares an agent.
func New(cfg *Config, me *pki.Member, log *slog.Logger) (*Agent, error) {
	if me.Identity.Role != identity.RoleGateway {
		return nil, fmt.Errorf("gateway: certificate identity %s is not an accepting host", me.Identity)
	}
	h, err := hardening.New(cfg.Hardening.Driver, filepath.Join(cfg.StateDir, "hardening"), cfg.Hardening.Egida)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		cfg: cfg, me: me, log: log,
		grants:   map[string]api.GatewayGrant{},
		hardener: h,
		auditor:  &hardening.Lynis{Binary: cfg.Audit.Lynis},
	}
	tunnelPort := 8443
	if _, p, err := net.SplitHostPort(cfg.Tunnel.Listen); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			tunnelPort = n
		}
	}
	// fwknopd refuses to start without access stanzas. This placeholder has
	// random keys that are never shared, so it can never be satisfied.
	a.decoy = fwknop.Stanza{
		Comment:       "placeholder stanza with unshared random keys (fwknopd needs at least one)",
		OpenPorts:     []string{"tcp/" + strconv.Itoa(tunnelPort)},
		KeyBase64:     randB64(32),
		HMACKeyBase64: randB64(64),
		AccessTimeout: time.Second,
	}
	host, _, _ := net.SplitHostPort(cfg.Controller)
	expect := pki.ExpectRole(identity.RoleController, me.Identity.Domain, "")
	if cfg.ControllerIdentity != "" {
		want, err := identity.Parse(cfg.ControllerIdentity)
		if err != nil {
			return nil, fmt.Errorf("gateway: controller_identity: %w", err)
		}
		expect = pki.ExpectRole(want.Role, want.Domain, want.ID)
	}
	a.dialer = &rpc.Dialer{
		Addr:      cfg.Controller,
		TLSConfig: me.ClientConfig(host, expect),
		Handler:   a.handle,
		Logger:    log,
		OnConnect: func(context.Context, *rpc.Conn) error {
			writeReady(cfg.ReadyFile)
			return nil
		},
	}
	return a, nil
}

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func writeReady(path string) {
	if path != "" {
		_ = os.WriteFile(path, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644)
	}
}

// Start sets up the firewall, fwknopd and the tunnel listener, then connects
// to the controller.
func (a *Agent) Start(ctx context.Context) error {
	if err := os.MkdirAll(a.cfg.StateDir, 0o700); err != nil {
		return err
	}
	if a.cfg.Firewall.Manage {
		pub, private, err := interfaces(a.cfg.PublicIP, a.cfg.Interface)
		if err != nil {
			return err
		}
		if err := firewall.Apply(firewall.Exec{Binary: a.cfg.Firewall.Binary}, firewall.Plan(private)); err != nil {
			return fmt.Errorf("gateway: firewall: %w", err)
		}
		a.log.Info("firewall in default-drop state", "public", pub, "private", private)
	}
	if a.cfg.Fwknop.Enabled {
		iface := a.cfg.Interface
		if iface == "" {
			var err error
			if iface, _, err = interfaces(a.cfg.PublicIP, ""); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(a.cfg.Fwknop.RunDir, 0o755); err != nil {
			return err
		}
		conf := filepath.Join(a.cfg.StateDir, "fwknopd.conf")
		access := filepath.Join(a.cfg.StateDir, "access.conf")
		text, err := fwknop.RenderServerConfig(fwknop.ServerConfig{
			Interface: iface, SPAPort: a.cfg.Fwknop.SPAPort, AccessFile: access,
			RunDir: a.cfg.Fwknop.RunDir, Forwarding: true,
		})
		if err != nil {
			return err
		}
		if err := fwknop.WriteFileAtomic(conf, []byte(text)); err != nil {
			return err
		}
		if err := a.writeAccess(); err != nil {
			return err
		}
		a.daemon = &fwknop.Daemon{Binary: a.cfg.Fwknop.Binary, ConfigFile: conf, AccessFile: access, Logger: a.log}
		if err := a.daemon.Start(ctx); err != nil {
			return err
		}
		a.log.Info("fwknopd ready", "interface", iface, "spa_port", a.cfg.Fwknop.SPAPort)
	}
	if err := a.startTunnel(ctx); err != nil {
		return err
	}
	go a.expireLoop(ctx)
	go a.dialer.Run(ctx)
	return nil
}

// Run starts the agent and blocks until ctx is done.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	if a.daemon != nil {
		a.daemon.Stop()
	}
	return nil
}

// TunnelAddr returns the tunnel listener address.
func (a *Agent) TunnelAddr() string { return a.tunnelLn.Addr().String() }

// Connected reports whether the control channel is up.
func (a *Agent) Connected() bool { return a.dialer.Current() != nil }

// interfaces returns the interface holding publicIP (or named iface) and
// every other non-loopback IPv4 interface (the private side).
func interfaces(publicIP, iface string) (string, []string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", nil, err
	}
	pub := iface
	var others []string
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		hasV4, isPub := false, false
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			hasV4 = true
			if publicIP != "" && ipn.IP.String() == publicIP {
				isPub = true
			}
		}
		switch {
		case isPub && pub == "":
			pub = i.Name
		case i.Name == pub:
		case hasV4:
			others = append(others, i.Name)
		}
	}
	if pub == "" {
		return "", nil, fmt.Errorf("gateway: no interface has address %s", publicIP)
	}
	sort.Strings(others)
	return pub, others, nil
}

// ---------------------------------------------------------------- grants

func validateGrant(g api.GatewayGrant) error {
	id, err := identity.Parse(g.Client)
	if err != nil || id.Role != identity.RoleClient {
		return rpc.Errorf(rpc.CodeInvalid, "grant %s: invalid client %q", g.ID, g.Client)
	}
	if g.ID == "" || g.Port <= 0 || g.Port > 65535 || g.AccessTimeout <= 0 {
		return rpc.Errorf(rpc.CodeInvalid, "grant %q: incomplete", g.ID)
	}
	host, port, err := net.SplitHostPort(g.Target)
	if err != nil {
		return rpc.Errorf(rpc.CodeInvalid, "grant %s: invalid target", g.ID)
	}
	if g.Mode == api.ModeForward {
		if net.ParseIP(host) == nil {
			return rpc.Errorf(rpc.CodeInvalid, "grant %s: forward target must be an IP", g.ID)
		}
		if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
			return rpc.Errorf(rpc.CodeInvalid, "grant %s: invalid target port", g.ID)
		}
	} else if g.Mode != api.ModeTunnel {
		return rpc.Errorf(rpc.CodeInvalid, "grant %s: unknown mode %q", g.ID, g.Mode)
	}
	if _, err := toStanza(g); err != nil {
		return rpc.Errorf(rpc.CodeInvalid, "grant %s: %v", g.ID, err)
	}
	return nil
}

// toStanza converts a grant to its fwknop access stanza.
func toStanza(g api.GatewayGrant) (fwknop.Stanza, error) {
	proto := g.Protocol
	if proto == "" {
		proto = "tcp"
	}
	s := fwknop.Stanza{
		Comment:       fmt.Sprintf("grant %s: %s -> %s (%s)", g.ID, g.Client, g.Service, g.Mode),
		OpenPorts:     []string{fmt.Sprintf("%s/%d", proto, g.Port)},
		KeyBase64:     g.KeyBase64,
		HMACKeyBase64: g.HMACKeyBase64,
		HMACDigest:    g.HMACDigest,
		AccessTimeout: time.Duration(g.AccessTimeout) * time.Second,
		Expires:       g.ExpiresAt,
	}
	if g.Mode == api.ModeForward {
		host, port, _ := net.SplitHostPort(g.Target)
		n, _ := strconv.Atoi(port)
		s.ForceNAT = &fwknop.NAT{IP: host, Port: n}
	}
	return s, s.Validate()
}

// Stanzas renders the current grants (sorted) plus the placeholder.
func (a *Agent) stanzas(now time.Time) []fwknop.Stanza {
	a.mu.Lock()
	ids := make([]string, 0, len(a.grants))
	for id, g := range a.grants {
		if now.Before(g.ExpiresAt) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := []fwknop.Stanza{a.decoy}
	for _, id := range ids {
		if s, err := toStanza(a.grants[id]); err == nil {
			out = append(out, s)
		}
	}
	a.mu.Unlock()
	return out
}

func (a *Agent) writeAccess() error {
	text, err := fwknop.RenderAccess(a.stanzas(time.Now()))
	if err != nil {
		return err
	}
	return fwknop.WriteFileAtomic(filepath.Join(a.cfg.StateDir, "access.conf"), []byte(text))
}

// apply renders access.conf and reloads fwknopd. When it returns without
// error, fwknopd accepts SPA packets for every current grant.
func (a *Agent) apply(ctx context.Context) error {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	if a.daemon == nil {
		return nil
	}
	if err := a.writeAccess(); err != nil {
		return err
	}
	return a.daemon.Reload(ctx)
}

func (a *Agent) expireLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.mu.Lock()
			var expired []string
			for id, g := range a.grants {
				if !now.Before(g.ExpiresAt) {
					delete(a.grants, id)
					expired = append(expired, id)
				}
			}
			a.mu.Unlock()
			if len(expired) > 0 {
				a.log.Info("grants expired", "ids", expired)
				if err := a.apply(ctx); err != nil {
					a.log.Error("reload after expiry", "err", err)
				}
			}
		}
	}
}

// activeGrant returns the tunnel grant of client for service, if any.
func (a *Agent) activeGrant(client, service string, now time.Time) (api.GatewayGrant, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, g := range a.grants {
		if g.Client == client && g.Service == service && g.Mode == api.ModeTunnel && now.Before(g.ExpiresAt) {
			return g, true
		}
	}
	return api.GatewayGrant{}, false
}

// ---------------------------------------------------------------- control channel

func (a *Agent) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case api.MethodGrantInstall:
		var g api.GatewayGrant
		if err := rpc.Decode(params, &g); err != nil {
			return nil, err
		}
		if err := validateGrant(g); err != nil {
			return nil, err
		}
		a.mu.Lock()
		a.grants[g.ID] = g
		a.mu.Unlock()
		if err := a.apply(ctx); err != nil {
			return nil, rpc.Errorf(rpc.CodeInternal, "apply: %v", err)
		}
		a.log.Info("grant installed", "grant", g.ID, "client", g.Client, "service", g.Service,
			"mode", g.Mode, "port", g.Port, "expires", g.ExpiresAt)
		return struct{}{}, nil
	case api.MethodGrantRevoke:
		var req api.RevokeRequest
		if err := rpc.Decode(params, &req); err != nil {
			return nil, err
		}
		a.mu.Lock()
		n := 0
		for _, id := range req.IDs {
			if _, ok := a.grants[id]; ok {
				delete(a.grants, id)
				n++
			}
		}
		a.mu.Unlock()
		if n > 0 {
			if err := a.apply(ctx); err != nil {
				return nil, rpc.Errorf(rpc.CodeInternal, "apply: %v", err)
			}
			a.log.Info("grants revoked", "ids", req.IDs)
		}
		return struct{}{}, nil
	case api.MethodSync:
		var s api.Sync
		if err := rpc.Decode(params, &s); err != nil {
			return nil, err
		}
		now := time.Now()
		fresh := map[string]api.GatewayGrant{}
		for _, g := range s.Grants {
			if validateGrant(g) == nil && now.Before(g.ExpiresAt) {
				fresh[g.ID] = g
			}
		}
		a.mu.Lock()
		a.grants = fresh
		a.mu.Unlock()
		if err := a.apply(ctx); err != nil {
			return nil, rpc.Errorf(rpc.CodeInternal, "apply: %v", err)
		}
		res := api.SyncResult{Grants: len(fresh)}
		if s.Hardening != nil {
			a.log.Info("applying hardening profile", "profile", s.Hardening.Name, "hash", s.Hardening.Hash,
				"services", s.Hardening.Services, "driver", a.hardener.Name())
			rep := a.hardener.Apply(ctx, *s.Hardening)
			a.log.Info("hardening result", "status", rep.Status, "file", rep.File, "message", rep.Message)
			res.Hardening = &rep
		}
		return res, nil
	case api.MethodAudit:
		a.log.Info("running audit", "tool", "lynis")
		rep := a.auditor.Audit(ctx)
		rep.Gateway = a.me.Identity.ID
		a.log.Info("audit finished", "available", rep.Available, "hardening_index", rep.HardeningIndex, "message", rep.Message)
		return rep, nil
	}
	return nil, rpc.Errorf(rpc.CodeNotFound, "unknown method %q", method)
}
