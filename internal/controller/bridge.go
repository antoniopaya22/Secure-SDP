package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
	"github.com/antoniopaya22/Secure-SDP/internal/identity"
	"github.com/antoniopaya22/Secure-SDP/internal/pki"
	"github.com/antoniopaya22/Secure-SDP/internal/rpc"
)

// upstreamWait bounds how long a relayed request waits for the root link.
var upstreamWait = 5 * time.Second

// Bridge is a bridged SDP controller. It authenticates the initiating hosts
// and accepting hosts of its own domain and relays authorization to the root
// controller over a persistent mTLS peer link.
type Bridge struct {
	cfg *Config
	me  *pki.Member
	log *slog.Logger
	up  *rpc.Dialer

	mu       sync.Mutex
	gateways map[string]*localGateway

	apiLn, peerLn net.Listener
}

type localGateway struct {
	conn  *rpc.Conn
	chain [][]byte
}

// NewBridge prepares a bridged controller.
func NewBridge(cfg *Config, me *pki.Member, log *slog.Logger) *Bridge {
	b := &Bridge{cfg: cfg, me: me, log: log, gateways: map[string]*localGateway{}}
	expect := pki.ExpectRole(identity.RoleController, "", "")
	if cfg.UpstreamIdentity != "" {
		want, err := identity.Parse(cfg.UpstreamIdentity)
		if err == nil {
			expect = pki.ExpectRole(want.Role, want.Domain, want.ID)
		}
	}
	host, _, _ := net.SplitHostPort(cfg.Upstream)
	b.up = &rpc.Dialer{
		Addr:      cfg.Upstream,
		TLSConfig: me.ClientConfig(host, expect),
		Handler:   b.upstreamHandler,
		Logger:    log,
		OnConnect: func(ctx context.Context, c *rpc.Conn) error {
			// (Re)announce the accepting hosts attached to this domain.
			b.mu.Lock()
			gws := make(map[string][][]byte, len(b.gateways))
			for id, g := range b.gateways {
				gws[id] = g.chain
			}
			b.mu.Unlock()
			for id, chain := range gws {
				if err := c.Call(ctx, api.MethodGatewayAttached, api.GatewayAttached{Chain: chain}, nil); err != nil {
					b.log.Warn("root refused accepting host", "gateway", id, "err", err)
				}
			}
			writeReady(cfg.ReadyFile)
			return nil
		},
	}
	return b
}

// Start opens the listeners, starts the upstream link and returns.
func (b *Bridge) Start(ctx context.Context) error {
	if b.cfg.UpstreamIdentity != "" {
		if _, err := identity.Parse(b.cfg.UpstreamIdentity); err != nil {
			return fmt.Errorf("controller: upstream_identity: %w", err)
		}
	}
	var err error
	b.peerLn, err = serveTLS(ctx, b.cfg.PeerListen, b.me, b.acceptPeer, b.handlePeer, b.log)
	if err != nil {
		return err
	}
	b.log.Info("peer link listening", "addr", b.peerLn.Addr().String())
	b.apiLn, err = serveAPI(ctx, b.cfg.APIListen, b, b.me, apiMux(b, b.me, b.log), b.log)
	if err != nil {
		return err
	}
	go b.up.Run(ctx)
	return nil
}

// Run starts the bridge and blocks until ctx is done.
func (b *Bridge) Run(ctx context.Context) error {
	if err := b.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// APIAddr returns the HTTPS API listener address.
func (b *Bridge) APIAddr() string { return b.apiLn.Addr().String() }

// PeerAddr returns the peer link listener address.
func (b *Bridge) PeerAddr() string { return b.peerLn.Addr().String() }

func (b *Bridge) role() string { return RoleBridge }

func (b *Bridge) acceptAPI(id identity.Identity) error {
	if id.Domain != b.me.Identity.Domain || id.Role != identity.RoleClient {
		return fmt.Errorf("%s is not an initiating host of domain %q", id, b.me.Identity.Domain)
	}
	return nil
}

func (b *Bridge) upstream(ctx context.Context) (*rpc.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamWait)
	defer cancel()
	c, err := b.up.Wait(ctx)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeUnavailable, "root controller unreachable")
	}
	return c, nil
}

func (b *Bridge) services(ctx context.Context, _ identity.Identity, chain [][]byte) ([]api.ServiceInfo, error) {
	c, err := b.upstream(ctx)
	if err != nil {
		return nil, err
	}
	var out []api.ServiceInfo
	err = c.Call(ctx, api.MethodServices, api.ServicesRequest{ClientChain: chain}, &out)
	return out, err
}

// access relays the request with the client certificate chain, so the root
// verifies the client itself instead of trusting the bridge's word.
func (b *Bridge) access(ctx context.Context, id identity.Identity, chain [][]byte, service string) (*api.AccessGrant, error) {
	c, err := b.upstream(ctx)
	if err != nil {
		return nil, err
	}
	b.log.Info("relaying authorization request to root", "client", id.String(), "service", service)
	var g api.AccessGrant
	path := []string{"bridge " + b.me.Identity.String()}
	if err := c.Call(ctx, api.MethodAuthorize, api.AuthorizeRequest{ClientChain: chain, Service: service, Path: path}, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// ---------------------------------------------------------------- peers

func (b *Bridge) acceptPeer(id identity.Identity) error {
	if id.Role != identity.RoleGateway || id.Domain != b.me.Identity.Domain {
		return fmt.Errorf("%s is not an accepting host of domain %q", id, b.me.Identity.Domain)
	}
	return nil
}

func (b *Bridge) handlePeer(nc net.Conn, id identity.Identity) {
	chain := pki.RawChain(tlsState(nc))
	c := rpc.New(context.Background(), nc, nil)
	go c.Keepalive(10*time.Second, 5*time.Second)
	b.mu.Lock()
	if old := b.gateways[id.ID]; old != nil {
		_ = old.conn.Close()
	}
	b.gateways[id.ID] = &localGateway{conn: c, chain: chain}
	b.mu.Unlock()
	b.log.Info("accepting host connected", "gateway", id.ID, "remote", nc.RemoteAddr().String())
	if up := b.up.Current(); up != nil {
		ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
		if err := up.Call(ctx, api.MethodGatewayAttached, api.GatewayAttached{Chain: chain}, nil); err != nil {
			b.log.Warn("root refused accepting host", "gateway", id.ID, "err", err)
		}
		cancel()
	}
	<-c.Done()
	b.mu.Lock()
	if g := b.gateways[id.ID]; g != nil && g.conn == c {
		delete(b.gateways, id.ID)
		b.mu.Unlock()
		if up := b.up.Current(); up != nil {
			ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
			_ = up.Call(ctx, api.MethodGatewayDetached, api.GatewayRef{Gateway: id.ID}, nil)
			cancel()
		}
	} else {
		b.mu.Unlock()
	}
	b.log.Warn("accepting host disconnected", "gateway", id.ID, "err", c.Err())
}

// upstreamHandler serves the root controller: it forwards commands to the
// accepting hosts of this domain.
func (b *Bridge) upstreamHandler(ctx context.Context, method string, params json.RawMessage) (any, error) {
	if method != api.MethodGatewayCall {
		return nil, rpc.Errorf(rpc.CodeNotFound, "unknown method %q", method)
	}
	var call api.GatewayCall
	if err := rpc.Decode(params, &call); err != nil {
		return nil, err
	}
	switch call.Method {
	case api.MethodSync, api.MethodGrantInstall, api.MethodGrantRevoke, api.MethodAudit:
	default:
		return nil, rpc.Errorf(rpc.CodeDenied, "method %q cannot be forwarded", call.Method)
	}
	b.mu.Lock()
	g := b.gateways[call.Gateway]
	b.mu.Unlock()
	if g == nil {
		return nil, rpc.Errorf(rpc.CodeUnavailable, "accepting host %s is not connected to %s", call.Gateway, b.me.Identity)
	}
	var raw json.RawMessage
	if err := g.conn.Call(ctx, call.Method, call.Params, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}
