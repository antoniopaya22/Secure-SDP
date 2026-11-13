package fwknop

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// readyMarker is logged by fwknopd once it is sniffing for SPA packets,
// both at start-up and after a SIGHUP reload.
const readyMarker = "Starting fwknopd main event loop"

// Daemon supervises an fwknopd process running in the foreground.
type Daemon struct {
	Binary     string
	ConfigFile string
	AccessFile string
	Logger     *slog.Logger
	// ReadyTimeout bounds how long Start and Reload wait for fwknopd.
	ReadyTimeout time.Duration

	mu      sync.Mutex
	cmd     *exec.Cmd
	ready   chan struct{} // receives one value per "ready" log line
	exited  chan struct{}
	exitErr error
}

func (d *Daemon) log() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

func (d *Daemon) timeout() time.Duration {
	if d.ReadyTimeout > 0 {
		return d.ReadyTimeout
	}
	return 10 * time.Second
}

// Start launches fwknopd and waits until it is ready.
func (d *Daemon) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.startLocked(ctx)
}

func (d *Daemon) startLocked(ctx context.Context) error {
	bin := d.Binary
	if bin == "" {
		bin = "fwknopd"
	}
	cmd := exec.Command(bin, "--foreground", "-c", d.ConfigFile, "-a", d.AccessFile)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("fwknop: start %s: %w", bin, err)
	}
	ready := make(chan struct{}, 16)
	exited := make(chan struct{})
	d.cmd, d.ready, d.exited = cmd, ready, exited
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := sc.Text()
			d.log().Info("fwknopd: " + line)
			if strings.Contains(line, readyMarker) {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		_ = pw.Close()
		d.mu.Lock()
		d.exitErr = err
		d.mu.Unlock()
		close(exited)
		d.log().Warn("fwknopd exited", "err", err)
	}()
	return d.waitReady(ctx, ready, exited)
}

func (d *Daemon) waitReady(ctx context.Context, ready, exited chan struct{}) error {
	t := time.NewTimer(d.timeout())
	defer t.Stop()
	select {
	case <-ready:
		return nil
	case <-exited:
		return errors.New("fwknop: fwknopd exited during start-up (see log)")
	case <-t.C:
		return errors.New("fwknop: timed out waiting for fwknopd to become ready")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Running reports whether fwknopd is alive.
func (d *Daemon) Running() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cmd == nil {
		return false
	}
	select {
	case <-d.exited:
		return false
	default:
		return true
	}
}

// Reload makes fwknopd re-read its access file (SIGHUP) and waits until it
// is sniffing again. If fwknopd is not running it is (re)started.
func (d *Daemon) Reload(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cmd == nil {
		return d.startLocked(ctx)
	}
	select {
	case <-d.exited:
		d.log().Warn("fwknopd was not running, restarting")
		return d.startLocked(ctx)
	default:
	}
	// drain stale ready signals
	for len(d.ready) > 0 {
		<-d.ready
	}
	if err := d.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("fwknop: SIGHUP: %w", err)
	}
	return d.waitReady(ctx, d.ready, d.exited)
}

// Stop terminates fwknopd.
func (d *Daemon) Stop() {
	d.mu.Lock()
	cmd, exited := d.cmd, d.exited
	d.mu.Unlock()
	if cmd == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
	}
}

// WriteFileAtomic writes data with mode 0600 through a rename.
func WriteFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
