package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/identity"
	"github.com/antoniopaya22/Secure-SDP/internal/netutil"
	"github.com/antoniopaya22/Secure-SDP/internal/pki"
)

// startTunnel serves the mTLS data channel. The port is closed by the
// default-drop firewall: only a client that sent a valid SPA packet can
// reach it, and only for the access window. After the handshake the client
// identity (certificate) and the requested service (TLS SNI) must match an
// active tunnel grant, otherwise the connection is dropped.
func (a *Agent) startTunnel(ctx context.Context) error {
	conf := a.me.ServerConfig(func(id identity.Identity) error {
		if id.Role != identity.RoleClient {
			return errors.New("only initiating hosts may open tunnels")
		}
		return nil
	})
	ln, err := net.Listen("tcp", a.cfg.Tunnel.Listen)
	if err != nil {
		return err
	}
	a.tunnelLn = ln
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
				time.Sleep(50 * time.Millisecond)
				continue
			}
			go a.serveTunnel(ctx, tls.Server(nc, conf))
		}
	}()
	a.log.Info("tunnel listening", "addr", ln.Addr().String())
	return nil
}

func (a *Agent) serveTunnel(ctx context.Context, tc *tls.Conn) {
	defer tc.Close()
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		a.log.Warn("tunnel handshake rejected", "remote", tc.RemoteAddr().String(), "err", err)
		return
	}
	cs := tc.ConnectionState()
	id, err := pki.PeerIdentity(cs)
	if err != nil {
		return
	}
	service := cs.ServerName
	g, ok := a.activeGrant(id.String(), service, time.Now())
	if !ok {
		a.log.Warn("tunnel denied: no active grant", "client", id.String(), "service", service, "remote", tc.RemoteAddr().String())
		return
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	up, err := d.DialContext(ctx, "tcp", g.Target)
	if err != nil {
		a.log.Warn("tunnel: protected service unreachable", "service", service, "target", g.Target, "err", err)
		return
	}
	defer up.Close()
	a.log.Info("tunnel opened", "client", id.String(), "service", service, "grant", g.ID, "remote", tc.RemoteAddr().String())
	in, out := netutil.Pipe(tc, up)
	a.log.Info("tunnel closed", "client", id.String(), "service", service, "bytes_in", in, "bytes_out", out)
}
