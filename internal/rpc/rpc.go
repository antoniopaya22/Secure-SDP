// Package rpc implements the persistent, bidirectional control channel used
// between SecureSDP controllers (bridge <-> root) and between a controller and
// its accepting hosts.
//
// A Conn wraps an established mTLS connection. Both ends can issue requests
// at any time; messages are newline-delimited JSON frames correlated by ID.
// The dialing side typically wraps it in a reconnect loop (see Dialer).
package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MaxFrameSize bounds the size of a single frame.
const MaxFrameSize = 4 << 20

// Error codes carried over the wire.
const (
	CodeDenied      = "denied"
	CodeNotFound    = "not_found"
	CodeUnavailable = "unavailable"
	CodeInvalid     = "invalid"
	CodeInternal    = "internal"
)

// Error is a remote (or local) error with a stable code.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf builds an *Error.
func Errorf(code, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// CodeOf returns the code of err (CodeInternal for foreign errors).
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if errors.Is(err, ErrClosed) || errors.Is(err, context.DeadlineExceeded) {
		return CodeUnavailable
	}
	return CodeInternal
}

// ErrClosed is returned by calls on a closed connection.
var ErrClosed = errors.New("rpc: connection closed")

// Handler serves requests from the peer. The returned value is sent as the
// result; an error is sent as an *Error.
type Handler func(ctx context.Context, method string, params json.RawMessage) (any, error)

type frame struct {
	ID     uint64          `json:"id"`
	Kind   string          `json:"kind"` // "req" or "res"
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Conn is one end of a control channel.
type Conn struct {
	nc      net.Conn
	handler Handler

	writeMu sync.Mutex
	nextID  atomic.Uint64

	mu      sync.Mutex
	pending map[uint64]chan *frame

	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

// MethodPing is answered by every Conn without reaching the Handler.
const MethodPing = "ping"

// New starts serving nc. The connection is closed when ctx is cancelled.
func New(ctx context.Context, nc net.Conn, h Handler) *Conn {
	cctx, cancel := context.WithCancel(ctx)
	c := &Conn{nc: nc, handler: h, pending: map[uint64]chan *frame{}, ctx: cctx, cancel: cancel}
	go func() {
		<-cctx.Done()
		c.closeWith(ErrClosed)
	}()
	go c.readLoop()
	return c
}

// Done is closed when the connection is closed.
func (c *Conn) Done() <-chan struct{} { return c.ctx.Done() }

// Err returns why the connection was closed.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// RemoteAddr returns the peer address.
func (c *Conn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

// Close closes the connection.
func (c *Conn) Close() error {
	c.closeWith(ErrClosed)
	return nil
}

func (c *Conn) closeWith(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		pending := c.pending
		c.pending = map[uint64]chan *frame{}
		c.mu.Unlock()
		_ = c.nc.Close()
		c.cancel()
		for _, ch := range pending {
			close(ch)
		}
	})
}

func (c *Conn) write(f *frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(b) > MaxFrameSize {
		return fmt.Errorf("rpc: frame of %d bytes exceeds limit", len(b))
	}
	b = append(b, '\n')
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.nc.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err = c.nc.Write(b)
	if err != nil {
		c.closeWith(err)
	}
	return err
}

func (c *Conn) readLoop() {
	sc := bufio.NewScanner(c.nc)
	sc.Buffer(make([]byte, 64*1024), MaxFrameSize+1)
	for sc.Scan() {
		var f frame
		if err := json.Unmarshal(sc.Bytes(), &f); err != nil {
			c.closeWith(fmt.Errorf("rpc: bad frame: %w", err))
			return
		}
		switch f.Kind {
		case "res":
			c.mu.Lock()
			ch, ok := c.pending[f.ID]
			delete(c.pending, f.ID)
			c.mu.Unlock()
			if ok {
				ch <- &f
				close(ch)
			}
		case "req":
			go c.serve(f)
		default:
			c.closeWith(fmt.Errorf("rpc: unknown frame kind %q", f.Kind))
			return
		}
	}
	err := sc.Err()
	if err == nil {
		err = ErrClosed
	}
	c.closeWith(err)
}

func (c *Conn) serve(req frame) {
	res := &frame{ID: req.ID, Kind: "res"}
	var (
		out any
		err error
	)
	if req.Method == MethodPing {
		out = struct{}{}
	} else if c.handler == nil {
		err = Errorf(CodeNotFound, "no handler for %q", req.Method)
	} else {
		out, err = c.handler(c.ctx, req.Method, req.Params)
	}
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = &Error{Code: CodeInternal, Message: err.Error()}
		}
		res.Error = e
	} else {
		b, merr := json.Marshal(out)
		if merr != nil {
			res.Error = &Error{Code: CodeInternal, Message: merr.Error()}
		} else {
			res.Result = b
		}
	}
	_ = c.write(res)
}

// Call sends a request and decodes the result into result (if non-nil).
func (c *Conn) Call(ctx context.Context, method string, params, result any) error {
	p, err := json.Marshal(params)
	if err != nil {
		return err
	}
	id := c.nextID.Add(1)
	ch := make(chan *frame, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return ErrClosed
	}
	c.pending[id] = ch
	c.mu.Unlock()
	if err := c.write(&frame{ID: id, Kind: "req", Method: method, Params: p}); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("rpc: %s: %w", method, err)
	}
	select {
	case res, ok := <-ch:
		if !ok {
			return ErrClosed
		}
		if res.Error != nil {
			return res.Error
		}
		if result != nil && len(res.Result) > 0 {
			return json.Unmarshal(res.Result, result)
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	case <-c.ctx.Done():
		return ErrClosed
	}
}

// Keepalive pings the peer every interval and closes the connection if a
// ping does not complete within timeout. It returns when the connection closes.
func (c *Conn) Keepalive(interval, timeout time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(c.ctx, timeout)
			err := c.Call(ctx, MethodPing, struct{}{}, nil)
			cancel()
			if err != nil {
				c.closeWith(fmt.Errorf("rpc: keepalive: %w", err))
				return
			}
		}
	}
}

// Decode unmarshals request parameters, mapping failures to CodeInvalid.
func Decode(params json.RawMessage, v any) error {
	if err := json.Unmarshal(params, v); err != nil {
		return Errorf(CodeInvalid, "bad parameters: %v", err)
	}
	return nil
}
