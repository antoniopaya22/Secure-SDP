package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

type echo struct {
	Msg string `json:"msg"`
}

func pair(t *testing.T, ha, hb Handler) (*Conn, *Conn) {
	t.Helper()
	a, b := net.Pipe()
	ca := New(context.Background(), a, ha)
	cb := New(context.Background(), b, hb)
	t.Cleanup(func() { ca.Close(); cb.Close() })
	return ca, cb
}

func TestBidirectionalCalls(t *testing.T) {
	h := func(prefix string) Handler {
		return func(_ context.Context, method string, params json.RawMessage) (any, error) {
			if method != "echo" {
				return nil, Errorf(CodeNotFound, "no %s", method)
			}
			var in echo
			if err := Decode(params, &in); err != nil {
				return nil, err
			}
			return echo{Msg: prefix + in.Msg}, nil
		}
	}
	a, b := pair(t, h("a:"), h("b:"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out echo
	if err := a.Call(ctx, "echo", echo{Msg: "hi"}, &out); err != nil || out.Msg != "b:hi" {
		t.Fatalf("a->b: %v %q", err, out.Msg)
	}
	if err := b.Call(ctx, "echo", echo{Msg: "yo"}, &out); err != nil || out.Msg != "a:yo" {
		t.Fatalf("b->a: %v %q", err, out.Msg)
	}
	err := a.Call(ctx, "nope", struct{}{}, nil)
	if CodeOf(err) != CodeNotFound {
		t.Fatalf("unknown method: got %v", err)
	}
	if err := a.Call(ctx, MethodPing, struct{}{}, nil); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestConcurrentCalls(t *testing.T) {
	slow := func(_ context.Context, _ string, params json.RawMessage) (any, error) {
		var in echo
		_ = json.Unmarshal(params, &in)
		if in.Msg == "slow" {
			time.Sleep(200 * time.Millisecond)
		}
		return in, nil
	}
	a, _ := pair(t, nil, slow)
	ctx := context.Background()
	done := make(chan string, 2)
	for _, m := range []string{"slow", "fast"} {
		go func(m string) {
			var out echo
			_ = a.Call(ctx, "x", echo{Msg: m}, &out)
			done <- out.Msg
		}(m)
	}
	if first := <-done; first != "fast" {
		t.Fatalf("calls are serialized: %q finished first", first)
	}
	<-done
}

func TestCloseFailsPendingCalls(t *testing.T) {
	block := make(chan struct{})
	a, b := pair(t, nil, func(context.Context, string, json.RawMessage) (any, error) {
		<-block
		return nil, nil
	})
	defer close(block)
	errc := make(chan error, 1)
	go func() { errc <- a.Call(context.Background(), "x", struct{}{}, nil) }()
	time.Sleep(50 * time.Millisecond)
	b.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("got %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending call not released on close")
	}
	if CodeOf(a.Call(context.Background(), "x", nil, nil)) != CodeUnavailable {
		t.Fatal("call on closed connection should be unavailable")
	}
}
