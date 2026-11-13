// Package controller implements the SecureSDP controllers of the Bridge
// model: the root controller (central authority and Policy Decision Point)
// and bridged controllers that front their own SDP domain and relay their
// members' requests to the root over a persistent mTLS peer link.
package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
	"github.com/antoniopaya22/Secure-SDP/internal/identity"
	"github.com/antoniopaya22/Secure-SDP/internal/pki"
	"github.com/antoniopaya22/Secure-SDP/internal/rpc"
)

// Roles of a controller.
const (
	RoleRoot   = "root"
	RoleBridge = "bridge"
)

// Config is the controller configuration file.
type Config struct {
	Role string `yaml:"role"`
	// APIListen serves initiating hosts (and admins on the root) over HTTPS+mTLS.
	APIListen string `yaml:"api_listen"`
	// PeerListen accepts control channels from accepting hosts and, on the
	// root, from bridged controllers.
	PeerListen string       `yaml:"peer_listen"`
	TLS        pki.TLSFiles `yaml:"tls"`
	// Policy file (root only).
	Policy string `yaml:"policy"`
	// Upstream is the peer address of the root controller (bridge only).
	Upstream string `yaml:"upstream"`
	// UpstreamIdentity optionally pins the root controller identity URI.
	UpstreamIdentity string `yaml:"upstream_identity"`
	// ReadyFile is created once the controller is serving (for health checks).
	ReadyFile string `yaml:"ready_file"`
}

// LoadConfig reads a controller configuration file.
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
	if c.APIListen == "" {
		c.APIListen = ":7443"
	}
	if c.PeerListen == "" {
		c.PeerListen = ":7444"
	}
	switch c.Role {
	case RoleRoot:
		if c.Policy == "" {
			return nil, errors.New("controller: root role requires policy")
		}
	case RoleBridge:
		if c.Upstream == "" {
			return nil, errors.New("controller: bridge role requires upstream")
		}
	default:
		return nil, fmt.Errorf("controller: role must be %q or %q", RoleRoot, RoleBridge)
	}
	return &c, nil
}

// Run starts the controller described by cfg and blocks until ctx is done.
func Run(ctx context.Context, cfg *Config, log *slog.Logger) error {
	me, err := pki.LoadMember(cfg.TLS)
	if err != nil {
		return err
	}
	if me.Identity.Role != identity.RoleController {
		return fmt.Errorf("controller: certificate identity %s is not a controller", me.Identity)
	}
	log = log.With("controller", me.Identity.String(), "role", cfg.Role)
	switch cfg.Role {
	case RoleRoot:
		r, err := NewRoot(cfg, me, log)
		if err != nil {
			return err
		}
		return r.Run(ctx)
	default:
		return NewBridge(cfg, me, log).Run(ctx)
	}
}

// ---------------------------------------------------------------- helpers

func randomB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.StdEncoding.EncodeToString(b)
}

func randomID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writeReady(path string) {
	if path == "" {
		return
	}
	_ = os.WriteFile(path, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644)
}

// serveTLS accepts mTLS connections on addr and hands each verified
// connection to handle.
func serveTLS(ctx context.Context, addr string, me *pki.Member, accept func(identity.Identity) error, handle func(net.Conn, identity.Identity), log *slog.Logger) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	conf := me.ServerConfig(accept)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Warn("peer accept", "err", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go func() {
				tc := tlsServer(nc, conf)
				hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := tc.HandshakeContext(hctx)
				cancel()
				if err != nil {
					log.Warn("peer rejected", "remote", nc.RemoteAddr().String(), "err", err)
					_ = tc.Close()
					return
				}
				id, err := pki.PeerIdentity(tc.ConnectionState())
				if err != nil {
					_ = tc.Close()
					return
				}
				handle(tc, id)
			}()
		}
	}()
	return ln, nil
}

// ---------------------------------------------------------------- HTTPS API

// authority is what the HTTPS API needs from a root or bridge controller.
type authority interface {
	role() string
	acceptAPI(identity.Identity) error
	services(ctx context.Context, id identity.Identity, chain [][]byte) ([]api.ServiceInfo, error)
	access(ctx context.Context, id identity.Identity, chain [][]byte, service string) (*api.AccessGrant, error)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	code := rpc.CodeOf(err)
	status := map[string]int{
		rpc.CodeDenied:      http.StatusForbidden,
		rpc.CodeNotFound:    http.StatusNotFound,
		rpc.CodeUnavailable: http.StatusServiceUnavailable,
		rpc.CodeInvalid:     http.StatusBadRequest,
	}[code]
	if status == 0 {
		status = http.StatusInternalServerError
	}
	msg := err.Error()
	var e *rpc.Error
	if errors.As(err, &e) {
		msg = e.Message
	}
	writeJSON(w, status, api.ErrorBody{Code: code, Message: msg})
}

type ctxKey struct{}

type peerInfo struct {
	id    identity.Identity
	chain [][]byte
}

func peer(r *http.Request) peerInfo { return r.Context().Value(ctxKey{}).(peerInfo) }

// withPeer authenticates every request from its client certificate.
func withPeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			writeErr(w, rpc.Errorf(rpc.CodeDenied, "mutual TLS required"))
			return
		}
		id, err := pki.PeerIdentity(*r.TLS)
		if err != nil {
			writeErr(w, rpc.Errorf(rpc.CodeDenied, "%v", err))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		ctx := context.WithValue(r.Context(), ctxKey{}, peerInfo{id: id, chain: pki.RawChain(*r.TLS)})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func apiMux(a authority, me *pki.Member, log *slog.Logger) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+api.PathHealth, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET "+api.PathWhoAmI, func(w http.ResponseWriter, r *http.Request) {
		p := peer(r)
		writeJSON(w, http.StatusOK, api.WhoAmI{Identity: p.id.String(), Controller: me.Identity.String(), Role: a.role()})
	})
	mux.HandleFunc("GET "+api.PathServices, func(w http.ResponseWriter, r *http.Request) {
		p := peer(r)
		s, err := a.services(r.Context(), p.id, p.chain)
		if err != nil {
			writeErr(w, err)
			return
		}
		if s == nil {
			s = []api.ServiceInfo{}
		}
		writeJSON(w, http.StatusOK, s)
	})
	mux.HandleFunc("POST "+api.PathAccess, func(w http.ResponseWriter, r *http.Request) {
		p := peer(r)
		var req api.AccessRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Service == "" {
			writeErr(w, rpc.Errorf(rpc.CodeInvalid, "body must be {\"service\": \"<name>\"}"))
			return
		}
		g, err := a.access(r.Context(), p.id, p.chain, req.Service)
		if err != nil {
			log.Info("access refused", "client", p.id.String(), "service", req.Service, "err", err)
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, g)
	})
	return mux
}

func serveAPI(ctx context.Context, addr string, a authority, me *pki.Member, h http.Handler, log *slog.Logger) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           withPeer(h),
		TLSConfig:         me.ServerConfig(a.acceptAPI),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("api server", "err", err)
		}
	}()
	log.Info("api listening", "addr", ln.Addr().String())
	return ln, nil
}

func tlsServer(nc net.Conn, conf *tls.Config) *tls.Conn { return tls.Server(nc, conf) }

func tlsState(nc net.Conn) tls.ConnectionState {
	if tc, ok := nc.(*tls.Conn); ok {
		return tc.ConnectionState()
	}
	return tls.ConnectionState{}
}
