package rpc

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Dialer keeps a control channel to a peer open, reconnecting with
// exponential backoff when it drops.
type Dialer struct {
	Addr      string
	TLSConfig *tls.Config
	Handler   Handler
	// OnConnect runs after every (re)connection, before Current returns the
	// new connection. Returning an error drops the connection.
	OnConnect func(ctx context.Context, c *Conn) error
	Logger    *slog.Logger

	// Keepalive settings (defaults: 10s interval, 5s timeout).
	PingInterval time.Duration
	PingTimeout  time.Duration

	mu      sync.Mutex
	current *Conn
	changed chan struct{}
}

// Current returns the live connection or nil.
func (d *Dialer) Current() *Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.current != nil {
		select {
		case <-d.current.Done():
			return nil
		default:
		}
	}
	return d.current
}

// Wait blocks until a connection is available or ctx is done.
func (d *Dialer) Wait(ctx context.Context) (*Conn, error) {
	for {
		if c := d.Current(); c != nil {
			return c, nil
		}
		d.mu.Lock()
		if d.changed == nil {
			d.changed = make(chan struct{})
		}
		ch := d.changed
		d.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ch:
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (d *Dialer) set(c *Conn) {
	d.mu.Lock()
	d.current = c
	if d.changed != nil {
		close(d.changed)
		d.changed = nil
	}
	d.mu.Unlock()
}

// Run dials and redials until ctx is cancelled.
func (d *Dialer) Run(ctx context.Context) {
	log := d.Logger
	if log == nil {
		log = slog.Default()
	}
	interval, timeout := d.PingInterval, d.PingTimeout
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	backoff := 500 * time.Millisecond
	for ctx.Err() == nil {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		nc, err := (&tls.Dialer{NetDialer: &net.Dialer{KeepAlive: 15 * time.Second}, Config: d.TLSConfig}).DialContext(dctx, "tcp", d.Addr)
		cancel()
		if err != nil {
			log.Warn("control channel: dial failed", "peer", d.Addr, "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 15*time.Second)
			continue
		}
		c := New(ctx, nc, d.Handler)
		if d.OnConnect != nil {
			if err := d.OnConnect(ctx, c); err != nil {
				log.Warn("control channel: handshake failed", "peer", d.Addr, "err", err)
				_ = c.Close()
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff = min(backoff*2, 15*time.Second)
				continue
			}
		}
		backoff = 500 * time.Millisecond
		log.Info("control channel: connected", "peer", d.Addr)
		d.set(c)
		go c.Keepalive(interval, timeout)
		<-c.Done()
		d.set(nil)
		if ctx.Err() == nil {
			log.Warn("control channel: lost", "peer", d.Addr, "err", c.Err())
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}
	}
}
