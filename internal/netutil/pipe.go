// Package netutil holds small networking helpers.
package netutil

import (
	"io"
	"net"
	"sync"
)

type closeWriter interface{ CloseWrite() error }

// Pipe copies data both ways until both directions are done, propagating
// half-closes. It returns the bytes copied a->b and b->a.
func Pipe(a, b net.Conn) (ab, ba int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn, n *int64) {
		defer wg.Done()
		*n, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(b, a, &ab)
	go cp(a, b, &ba)
	wg.Wait()
	return ab, ba
}
