package fwknop

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// SPARequest describes one SPA packet to send with the fwknop client.
type SPARequest struct {
	Binary        string // fwknop client binary (default "fwknop")
	Server        string
	SPAPort       int
	Protocol      string // tcp or udp
	Port          int
	AllowIP       string // address the gateway should open; detected when empty
	KeyBase64     string
	HMACKeyBase64 string
	HMACDigest    string
}

// SourceIPFor returns the local address used to reach server (no packet is sent).
func SourceIPFor(server string, port int) (string, error) {
	c, err := net.Dial("udp", net.JoinHostPort(server, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// SendSPA sends an SPA packet. Keys are written to a private, temporary rc
// file instead of the command line so they do not show up in the process list.
func SendSPA(ctx context.Context, r SPARequest) error {
	if r.SPAPort == 0 {
		r.SPAPort = DefaultSPAPort
	}
	if r.Protocol == "" {
		r.Protocol = "tcp"
	}
	if r.AllowIP == "" {
		ip, err := SourceIPFor(r.Server, r.SPAPort)
		if err != nil {
			return fmt.Errorf("fwknop: cannot determine source address: %w", err)
		}
		r.AllowIP = ip
	}
	rc, err := RenderClientRC(ClientStanza{
		Name: "sdp", Server: r.Server, SPAPort: r.SPAPort,
		Access:  fmt.Sprintf("%s/%d", r.Protocol, r.Port),
		AllowIP: r.AllowIP, KeyBase64: r.KeyBase64, HMACKeyBase64: r.HMACKeyBase64, HMACDigest: r.HMACDigest,
	})
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "sdp-spa-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "fwknoprc")
	if err := os.WriteFile(path, []byte(rc), 0o600); err != nil {
		return err
	}
	bin := r.Binary
	if bin == "" {
		bin = "fwknop"
	}
	cmd := exec.CommandContext(ctx, bin, "--rc-file", path, "-n", "sdp", "--no-save-args")
	cmd.Env = append(os.Environ(), "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fwknop: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
