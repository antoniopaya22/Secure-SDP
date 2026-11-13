package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
	"github.com/antoniopaya22/Secure-SDP/internal/identity"
	"github.com/antoniopaya22/Secure-SDP/internal/pki"
	"github.com/antoniopaya22/Secure-SDP/internal/policy"
	"github.com/antoniopaya22/Secure-SDP/internal/rpc"
)

// Timeouts of calls to accepting hosts.
var (
	installTimeout = 15 * time.Second
	syncTimeout    = time.Hour // hardening with Egida can take a while
	auditTimeout   = 20 * time.Minute
)

// route is how the root reaches an accepting host: directly or through the
// bridged controller of its domain.
type route struct {
	gateway     string
	domain      string
	via         string // "direct" or bridge identity
	call        func(ctx context.Context, method string, params, result any) error
	connectedAt time.Time
	seq         uint64
	bridge      *rpc.Conn // link the route goes through (nil when direct)
}

// Root is the root SDP controller: central authority of the Bridge model.
type Root struct {
	cfg *Config
	me  *pki.Member
	log *slog.Logger

	policy atomic.Pointer[policy.Policy]
	grants *grantStore

	mu        sync.Mutex
	routes    map[string]*route
	bridges   map[string]*rpc.Conn // by domain
	hardening map[string]*api.HardeningReport
	audits    map[string]*api.AuditReport
	seq       uint64

	apiLn, peerLn net.Listener
}

// NewRoot loads the policy and prepares a root controller.
func NewRoot(cfg *Config, me *pki.Member, log *slog.Logger) (*Root, error) {
	pol, err := policy.Load(cfg.Policy)
	if err != nil {
		return nil, err
	}
	if !pol.HasDomain(me.Identity.Domain) {
		return nil, fmt.Errorf("controller: own domain %q is not declared in the policy", me.Identity.Domain)
	}
	r := &Root{
		cfg: cfg, me: me, log: log,
		grants:    newGrantStore(),
		routes:    map[string]*route{},
		bridges:   map[string]*rpc.Conn{},
		hardening: map[string]*api.HardeningReport{},
		audits:    map[string]*api.AuditReport{},
	}
	r.policy.Store(pol)
	return r, nil
}

// Start opens the listeners and returns.
func (r *Root) Start(ctx context.Context) error {
	var err error
	r.peerLn, err = serveTLS(ctx, r.cfg.PeerListen, r.me, r.acceptPeer, r.handlePeer, r.log)
	if err != nil {
		return err
	}
	r.log.Info("peer link listening", "addr", r.peerLn.Addr().String())
	mux := apiMux(r, r.me, r.log)
	r.adminRoutes(mux)
	r.apiLn, err = serveAPI(ctx, r.cfg.APIListen, r, r.me, mux, r.log)
	if err != nil {
		return err
	}
	go r.janitor(ctx)
	writeReady(r.cfg.ReadyFile)
	return nil
}

// Run starts the controller and blocks until ctx is done.
func (r *Root) Run(ctx context.Context) error {
	if err := r.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// APIAddr returns the HTTPS API listener address.
func (r *Root) APIAddr() string { return r.apiLn.Addr().String() }

// PeerAddr returns the peer link listener address.
func (r *Root) PeerAddr() string { return r.peerLn.Addr().String() }

func (r *Root) domain() string { return r.me.Identity.Domain }

func (r *Root) role() string { return RoleRoot }

// ---------------------------------------------------------------- HTTPS API

// acceptAPI: the root serves the initiating hosts and admins of its own
// domain. Members of bridged domains must go through their own controller,
// preserving the topology of each SDP.
func (r *Root) acceptAPI(id identity.Identity) error {
	if id.Domain != r.domain() {
		return fmt.Errorf("%s belongs to domain %q: use the controller of that domain", id, id.Domain)
	}
	if id.Role != identity.RoleClient && id.Role != identity.RoleAdmin {
		return fmt.Errorf("%s may not use the controller API", id)
	}
	return nil
}

func (r *Root) services(_ context.Context, id identity.Identity, _ [][]byte) ([]api.ServiceInfo, error) {
	return r.servicesFor(id), nil
}

func (r *Root) access(ctx context.Context, id identity.Identity, _ [][]byte, service string) (*api.AccessGrant, error) {
	return r.authorize(ctx, id, service, nil)
}

func (r *Root) servicesFor(id identity.Identity) []api.ServiceInfo {
	pol := r.policy.Load()
	var out []api.ServiceInfo
	for _, s := range pol.ServicesFor(id) {
		out = append(out, api.ServiceInfo{
			Name: s.Name, Description: s.Description, Mode: s.Mode, Gateway: s.Gateway,
			Online: r.route(s.Gateway) != nil,
		})
	}
	return out
}

// authorize is the Policy Decision Point. On success it issues fresh SPA
// credentials, installs the grant on the accepting host and returns what the
// initiating host needs to knock and connect.
func (r *Root) authorize(ctx context.Context, client identity.Identity, service string, path []string) (*api.AccessGrant, error) {
	pol := r.policy.Load()
	d := pol.Decide(client, service)
	path = append(slices.Clone(path), "root "+r.me.Identity.String())
	if !d.Allowed {
		r.log.Info("authorization denied", "client", client.String(), "service", service, "reason", d.Reason, "path", path)
		return nil, rpc.Errorf(rpc.CodeDenied, "%s", d.Reason)
	}
	rt := r.route(d.Gateway.ID)
	if rt == nil {
		r.log.Warn("authorization failed: accepting host offline", "gateway", d.Gateway.ID, "client", client.String())
		return nil, rpc.Errorf(rpc.CodeUnavailable, "accepting host %s is offline", d.Gateway.ID)
	}
	s, g := d.Service, d.Gateway
	now := time.Now().UTC()
	gg := api.GatewayGrant{
		ID:            randomID(),
		Client:        client.String(),
		Service:       s.Name,
		Mode:          s.Mode,
		Protocol:      "tcp",
		Target:        s.Target,
		KeyBase64:     randomB64(32),
		HMACKeyBase64: randomB64(64),
		HMACDigest:    "SHA256",
		AccessTimeout: int(time.Duration(s.AccessTimeout) / time.Second),
		ExpiresAt:     now.Add(time.Duration(pol.Defaults.GrantTTL)).Truncate(time.Second),
	}
	if s.Mode == api.ModeForward {
		gg.Port = s.Port
	} else {
		gg.Port = g.TunnelPort
	}
	ictx, cancel := context.WithTimeout(ctx, installTimeout)
	err := rt.call(ictx, api.MethodGrantInstall, gg, nil)
	cancel()
	if err != nil {
		r.log.Warn("grant install failed", "gateway", g.ID, "err", err)
		return nil, rpc.Errorf(rpc.CodeUnavailable, "accepting host %s did not install the grant: %v", g.ID, err)
	}
	superseded := r.grants.add(&grantRecord{grant: gg, gateway: g.ID, issued: now, via: path})
	if len(superseded) > 0 {
		go r.revokeOnGateway(context.Background(), g.ID, superseded)
	}
	r.log.Info("authorization granted", "client", client.String(), "service", s.Name, "gateway", g.ID,
		"mode", s.Mode, "grant", gg.ID, "expires", gg.ExpiresAt, "path", path)
	return &api.AccessGrant{
		GrantID:  gg.ID,
		Client:   client.String(),
		Service:  s.Name,
		Mode:     s.Mode,
		Gateway:  api.GatewayEndpoint{ID: g.ID, Domain: g.Domain, Address: g.Address, SPAPort: g.SPAPort},
		Protocol: "tcp",
		Port:     gg.Port,
		SPA: api.SPACredentials{
			KeyBase64: gg.KeyBase64, HMACKeyBase64: gg.HMACKeyBase64, HMACDigest: gg.HMACDigest,
		},
		AccessTimeout: gg.AccessTimeout,
		ExpiresAt:     gg.ExpiresAt,
		Path:          path,
	}, nil
}

// ---------------------------------------------------------------- peers

func (r *Root) acceptPeer(id identity.Identity) error {
	switch id.Role {
	case identity.RoleGateway:
		if id.Domain != r.domain() {
			return fmt.Errorf("accepting host %s must connect to the controller of domain %q", id, id.Domain)
		}
		return nil
	case identity.RoleController:
		if id.Domain == r.domain() {
			return fmt.Errorf("%s: a bridged controller cannot belong to the root domain", id)
		}
		if !r.policy.Load().HasDomain(id.Domain) {
			return fmt.Errorf("%s: domain %q is not part of the perimeter", id, id.Domain)
		}
		return nil
	}
	return fmt.Errorf("%s may not open a peer link", id)
}

func (r *Root) handlePeer(nc net.Conn, id identity.Identity) {
	ctx := context.Background()
	switch id.Role {
	case identity.RoleGateway:
		if g := r.policy.Load().Gateway(id.ID); g == nil || g.Domain != id.Domain {
			r.log.Warn("unknown accepting host rejected", "identity", id.String())
			_ = nc.Close()
			return
		}
		c := rpc.New(ctx, nc, nil)
		go c.Keepalive(10*time.Second, 5*time.Second)
		seq := r.addRoute(id, "direct", nil, c.Call)
		r.log.Info("accepting host connected", "gateway", id.ID, "remote", nc.RemoteAddr().String())
		go r.syncGateway(id.ID)
		<-c.Done()
		r.removeRoute(id.ID, seq)
		r.log.Warn("accepting host disconnected", "gateway", id.ID, "err", c.Err())
	case identity.RoleController:
		var c *rpc.Conn
		ready := make(chan struct{})
		c = rpc.New(ctx, nc, r.bridgeHandler(id, func() *rpc.Conn { <-ready; return c }))
		close(ready)
		go c.Keepalive(10*time.Second, 5*time.Second)
		r.mu.Lock()
		if old := r.bridges[id.Domain]; old != nil {
			_ = old.Close()
		}
		r.bridges[id.Domain] = c
		r.mu.Unlock()
		r.log.Info("bridged controller connected", "bridge", id.String(), "remote", nc.RemoteAddr().String())
		<-c.Done()
		r.mu.Lock()
		if r.bridges[id.Domain] == c {
			delete(r.bridges, id.Domain)
		}
		for gid, rt := range r.routes {
			if rt.bridge == c {
				delete(r.routes, gid)
			}
		}
		r.mu.Unlock()
		r.log.Warn("bridged controller disconnected", "bridge", id.String(), "err", c.Err())
	}
}

// bridgeHandler serves requests relayed by a bridged controller. The root
// re-verifies every relayed certificate chain and only accepts members of
// the bridge's own domain.
func (r *Root) bridgeHandler(bridge identity.Identity, link func() *rpc.Conn) rpc.Handler {
	member := func(chain [][]byte, role identity.Role) (identity.Identity, error) {
		id, err := r.me.Verifier.VerifyDER(chain)
		if err != nil {
			return id, rpc.Errorf(rpc.CodeDenied, "relayed identity rejected: %v", err)
		}
		if id.Domain != bridge.Domain || id.Role != role {
			return id, rpc.Errorf(rpc.CodeDenied, "%s cannot vouch for %s", bridge, id)
		}
		return id, nil
	}
	return func(ctx context.Context, method string, params json.RawMessage) (any, error) {
		switch method {
		case api.MethodAuthorize:
			var req api.AuthorizeRequest
			if err := rpc.Decode(params, &req); err != nil {
				return nil, err
			}
			id, err := member(req.ClientChain, identity.RoleClient)
			if err != nil {
				r.log.Warn("relayed request rejected", "bridge", bridge.String(), "err", err)
				return nil, err
			}
			return r.authorize(ctx, id, req.Service, req.Path)
		case api.MethodServices:
			var req api.ServicesRequest
			if err := rpc.Decode(params, &req); err != nil {
				return nil, err
			}
			id, err := member(req.ClientChain, identity.RoleClient)
			if err != nil {
				return nil, err
			}
			out := r.servicesFor(id)
			if out == nil {
				out = []api.ServiceInfo{}
			}
			return out, nil
		case api.MethodGatewayAttached:
			var req api.GatewayAttached
			if err := rpc.Decode(params, &req); err != nil {
				return nil, err
			}
			id, err := member(req.Chain, identity.RoleGateway)
			if err != nil {
				return nil, err
			}
			if g := r.policy.Load().Gateway(id.ID); g == nil || g.Domain != id.Domain {
				return nil, rpc.Errorf(rpc.CodeDenied, "%s is not a registered accepting host", id)
			}
			bc := link()
			gid := id.ID
			r.addRoute(id, bridge.String(), bc, func(ctx context.Context, method string, params, result any) error {
				p, err := json.Marshal(params)
				if err != nil {
					return err
				}
				var raw json.RawMessage
				if err := bc.Call(ctx, api.MethodGatewayCall, api.GatewayCall{Gateway: gid, Method: method, Params: p}, &raw); err != nil {
					return err
				}
				if result != nil && len(raw) > 0 {
					return json.Unmarshal(raw, result)
				}
				return nil
			})
			r.log.Info("accepting host attached through bridge", "gateway", gid, "bridge", bridge.String())
			go r.syncGateway(gid)
			return struct{}{}, nil
		case api.MethodGatewayDetached:
			var ref api.GatewayRef
			if err := rpc.Decode(params, &ref); err != nil {
				return nil, err
			}
			r.mu.Lock()
			if rt := r.routes[ref.Gateway]; rt != nil && rt.bridge == link() {
				delete(r.routes, ref.Gateway)
			}
			r.mu.Unlock()
			r.log.Warn("accepting host detached from bridge", "gateway", ref.Gateway, "bridge", bridge.String())
			return struct{}{}, nil
		}
		return nil, rpc.Errorf(rpc.CodeNotFound, "unknown method %q", method)
	}
}

func (r *Root) addRoute(id identity.Identity, via string, bridge *rpc.Conn, call func(context.Context, string, any, any) error) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	r.routes[id.ID] = &route{gateway: id.ID, domain: id.Domain, via: via, bridge: bridge, call: call, connectedAt: time.Now().UTC(), seq: r.seq}
	return r.seq
}

func (r *Root) removeRoute(gateway string, seq uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rt := r.routes[gateway]; rt != nil && rt.seq == seq {
		delete(r.routes, gateway)
	}
}

func (r *Root) route(gateway string) *route {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.routes[gateway]
}

// syncGateway sends an accepting host its full desired state: active grants
// and the hardening profile derived from the services it exposes.
func (r *Root) syncGateway(gateway string) (*api.SyncResult, error) {
	rt := r.route(gateway)
	if rt == nil {
		return nil, rpc.Errorf(rpc.CodeUnavailable, "accepting host %s is offline", gateway)
	}
	prof, err := r.policy.Load().HardeningProfile(gateway)
	if err != nil {
		r.log.Error("hardening profile", "gateway", gateway, "err", err)
	}
	s := api.Sync{Grants: r.grants.forGateway(gateway, time.Now()), Hardening: prof}
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()
	var res api.SyncResult
	if err := rt.call(ctx, api.MethodSync, s, &res); err != nil {
		r.log.Warn("sync failed", "gateway", gateway, "err", err)
		return nil, err
	}
	if res.Hardening != nil {
		r.mu.Lock()
		r.hardening[gateway] = res.Hardening
		r.mu.Unlock()
		r.log.Info("accepting host synchronized", "gateway", gateway, "grants", res.Grants,
			"hardening", res.Hardening.Status, "driver", res.Hardening.Driver, "profile", res.Hardening.ProfileHash)
	} else {
		r.log.Info("accepting host synchronized", "gateway", gateway, "grants", res.Grants)
	}
	return &res, nil
}

func (r *Root) revokeOnGateway(ctx context.Context, gateway string, ids []string) {
	rt := r.route(gateway)
	if rt == nil || len(ids) == 0 {
		return // the accepting host expires grants on its own
	}
	cctx, cancel := context.WithTimeout(ctx, installTimeout)
	defer cancel()
	if err := rt.call(cctx, api.MethodGrantRevoke, api.RevokeRequest{IDs: ids}, nil); err != nil {
		r.log.Warn("revoke failed", "gateway", gateway, "err", err)
	}
}

// janitor drops expired grants and tells accepting hosts to remove them.
func (r *Root) janitor(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for gw, ids := range r.grants.expire(time.Now()) {
				r.log.Info("grants expired", "gateway", gw, "count", len(ids))
				go r.revokeOnGateway(ctx, gw, ids)
			}
		}
	}
}

// Reload re-reads the policy, revokes grants it no longer allows and
// re-synchronizes every accepting host (new hardening profiles included).
func (r *Root) Reload() error {
	pol, err := policy.Load(r.cfg.Policy)
	if err != nil {
		return err
	}
	if !pol.HasDomain(r.domain()) {
		return fmt.Errorf("controller: own domain %q is not declared in the policy", r.domain())
	}
	r.policy.Store(pol)
	revoked := r.grants.revokeIf(func(g *grantRecord) bool {
		id, err := identity.Parse(g.grant.Client)
		if err != nil {
			return true
		}
		d := pol.Decide(id, g.grant.Service)
		return !d.Allowed || d.Gateway.ID != g.gateway
	})
	for gw, ids := range revoked {
		r.log.Info("grants revoked by new policy", "gateway", gw, "count", len(ids))
		r.revokeOnGateway(context.Background(), gw, ids)
	}
	r.mu.Lock()
	ids := make([]string, 0, len(r.routes))
	for id := range r.routes {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	for _, id := range ids {
		go r.syncGateway(id)
	}
	r.log.Info("policy reloaded", "gateways", len(pol.Gateways), "services", len(pol.Services), "clients", len(pol.Clients))
	return nil
}

// ---------------------------------------------------------------- admin API

func (r *Root) adminRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			if peer(req).id.Role != identity.RoleAdmin {
				writeErr(w, rpc.Errorf(rpc.CodeDenied, "admin identity required"))
				return
			}
			h(w, req)
		}
	}
	mux.HandleFunc("GET "+api.PathAdminGateways, admin(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, r.GatewayStatuses())
	}))
	mux.HandleFunc("GET "+api.PathAdminGrants, admin(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, r.grants.list(time.Now()))
	}))
	mux.HandleFunc("POST "+api.PathAdminRevoke, admin(func(w http.ResponseWriter, req *http.Request) {
		var body api.AdminRevoke
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || (body.Grant == "" && body.Client == "") {
			writeErr(w, rpc.Errorf(rpc.CodeInvalid, "body must name a grant or a client"))
			return
		}
		byGW := r.grants.revokeIf(func(g *grantRecord) bool {
			if body.Grant != "" && g.grant.ID == body.Grant {
				return true
			}
			if body.Client != "" {
				id, err := identity.Parse(g.grant.Client)
				return err == nil && (id.Name() == body.Client || id.String() == body.Client)
			}
			return false
		})
		n := 0
		for gw, ids := range byGW {
			n += len(ids)
			r.revokeOnGateway(req.Context(), gw, ids)
		}
		r.log.Info("grants revoked by admin", "admin", peer(req).id.String(), "count", n)
		writeJSON(w, http.StatusOK, api.RevokeResult{Revoked: n})
	}))
	mux.HandleFunc("POST "+api.PathAdminAudit, admin(func(w http.ResponseWriter, req *http.Request) {
		var ref api.GatewayRef
		if err := json.NewDecoder(req.Body).Decode(&ref); err != nil {
			writeErr(w, rpc.Errorf(rpc.CodeInvalid, "body must be {\"gateway\": \"<id>\"}"))
			return
		}
		rep, err := r.Audit(req.Context(), ref.Gateway)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rep)
	}))
	mux.HandleFunc("POST "+api.PathAdminHarden, admin(func(w http.ResponseWriter, req *http.Request) {
		var ref api.GatewayRef
		if err := json.NewDecoder(req.Body).Decode(&ref); err != nil {
			writeErr(w, rpc.Errorf(rpc.CodeInvalid, "body must be {\"gateway\": \"<id>\"}"))
			return
		}
		res, err := r.syncGateway(ref.Gateway)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}))
	mux.HandleFunc("GET "+api.PathAdminProfile, admin(func(w http.ResponseWriter, req *http.Request) {
		gw := req.URL.Query().Get("gateway")
		pol := r.policy.Load()
		if pol.Gateway(gw) == nil {
			writeErr(w, rpc.Errorf(rpc.CodeNotFound, "unknown accepting host %q", gw))
			return
		}
		prof, err := pol.HardeningProfile(gw)
		if err != nil {
			writeErr(w, err)
			return
		}
		if prof == nil {
			writeErr(w, rpc.Errorf(rpc.CodeNotFound, "no hardening profile applies to %q", gw))
			return
		}
		writeJSON(w, http.StatusOK, prof)
	}))
	mux.HandleFunc("POST "+api.PathAdminReload, admin(func(w http.ResponseWriter, _ *http.Request) {
		if err := r.Reload(); err != nil {
			writeErr(w, rpc.Errorf(rpc.CodeInvalid, "%v", err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
	}))
}

// Audit runs Lynis on an accepting host and records the result.
func (r *Root) Audit(ctx context.Context, gateway string) (*api.AuditReport, error) {
	rt := r.route(gateway)
	if rt == nil {
		return nil, rpc.Errorf(rpc.CodeUnavailable, "accepting host %s is offline", gateway)
	}
	ctx, cancel := context.WithTimeout(ctx, auditTimeout)
	defer cancel()
	var rep api.AuditReport
	if err := rt.call(ctx, api.MethodAudit, struct{}{}, &rep); err != nil {
		return nil, err
	}
	rep.Gateway = gateway
	r.mu.Lock()
	r.audits[gateway] = &rep
	r.mu.Unlock()
	r.log.Info("audit completed", "gateway", gateway, "tool", rep.Tool, "available", rep.Available,
		"hardening_index", rep.HardeningIndex, "warnings", rep.Warnings, "suggestions", rep.Suggestions)
	return &rep, nil
}

// GatewayStatuses reports every accepting host of the policy.
func (r *Root) GatewayStatuses() []api.GatewayStatus {
	pol := r.policy.Load()
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]api.GatewayStatus, 0, len(pol.Gateways))
	for _, g := range pol.Gateways {
		st := api.GatewayStatus{ID: g.ID, Domain: g.Domain, Address: g.Address, Services: []string{}}
		for _, s := range pol.GatewayServices(g.ID) {
			st.Services = append(st.Services, s.Name)
		}
		if rt := r.routes[g.ID]; rt != nil {
			st.Online, st.Via = true, rt.via
			t := rt.connectedAt
			st.ConnectedAt = &t
		}
		st.Grants = len(r.grants.forGateway(g.ID, now))
		st.Hardening = r.hardening[g.ID]
		st.Audit = r.audits[g.ID]
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
