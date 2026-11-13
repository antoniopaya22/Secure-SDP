// Command sdp-client is the SecureSDP Initiating Host (IH).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
	"github.com/antoniopaya22/Secure-SDP/internal/cli"
	"github.com/antoniopaya22/Secure-SDP/internal/client"
	"github.com/antoniopaya22/Secure-SDP/internal/netutil"
)

const usage = `sdp-client: SecureSDP initiating host

Usage:
  sdp-client [--config client.yml] [--json] COMMAND

Commands:
  whoami                      show the identity the controller sees
  services                    list the services you may access
  access SERVICE [--wait]     get a grant from your domain controller and send the
                              SPA packet; --wait retries until the port opens.
                              Forward-mode services are then reachable directly.
  connect SERVICE --listen ADDR
                              open a local port that tunnels (mTLS) to a
                              tunnel-mode service, knocking when needed
  version
`

func main() {
	g := flag.NewFlagSet("sdp-client", flag.ExitOnError)
	g.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	conf := g.String("config", cli.Env("SDP_CLIENT_CONFIG", "/etc/sdp/client.yml"), "configuration file")
	asJSON := g.Bool("json", false, "print JSON")
	_ = g.Parse(os.Args[1:])
	args := g.Args()
	if len(args) == 0 {
		g.Usage()
		os.Exit(2)
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Println("sdp-client", cli.Version)
		return
	}
	if args[0] == "help" {
		fmt.Print(usage)
		return
	}
	cfg, err := client.LoadConfig(*conf)
	if err != nil {
		cli.Fatal(err)
	}
	c, err := client.New(cfg)
	if err != nil {
		cli.Fatal(err)
	}
	switch args[0] {
	case "whoami":
		err = whoami(c, *asJSON)
	case "services":
		err = services(c, *asJSON)
	case "access":
		err = access(c, args[1:], *asJSON)
	case "connect":
		err = connect(c, args[1:])
	default:
		g.Usage()
		os.Exit(2)
	}
	if err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Body.Code == "denied" {
			fmt.Fprintln(os.Stderr, "access denied:", ae.Body.Message)
			os.Exit(3)
		}
		cli.Fatal(err)
	}
}

func timeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func whoami(c *client.Client, asJSON bool) error {
	ctx, cancel := timeout()
	defer cancel()
	w, err := c.WhoAmI(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return cli.PrintJSON(w)
	}
	fmt.Printf("identity:   %s\ncontroller: %s (%s)\n", w.Identity, w.Controller, w.Role)
	return nil
}

func services(c *client.Client, asJSON bool) error {
	ctx, cancel := timeout()
	defer cancel()
	s, err := c.Services(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return cli.PrintJSON(s)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tMODE\tGATEWAY\tONLINE\tDESCRIPTION")
	for _, x := range s {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\n", x.Name, x.Mode, x.Gateway, x.Online, x.Description)
	}
	return tw.Flush()
}

func access(c *client.Client, args []string, asJSON bool) error {
	fs := flag.NewFlagSet("access", flag.ExitOnError)
	wait := fs.Bool("wait", false, "resend SPA until the opened port accepts TCP connections")
	noKnock := fs.Bool("no-knock", false, "only request the grant, do not send SPA")
	service, rest := popArg(args)
	_ = fs.Parse(rest)
	if service == "" {
		return errors.New("access: missing service name")
	}
	ctx, cancel := timeout()
	defer cancel()
	g, err := c.RequestAccess(ctx, service)
	if err != nil {
		return err
	}
	if !*noKnock {
		if *wait {
			err = c.KnockAndWait(ctx, g, 4)
		} else {
			err = c.Knock(ctx, g)
		}
		if err != nil {
			return err
		}
	}
	if asJSON {
		// Do not print SPA keys: they are only needed by this process.
		g.SPA = api.SPACredentials{}
		return cli.PrintJSON(g)
	}
	fmt.Printf("granted:  %s -> %s (grant %s, credentials valid until %s)\n", g.Client, g.Service, g.GrantID, g.ExpiresAt.Local().Format(time.RFC3339))
	fmt.Printf("path:     %s\n", strings.Join(g.Path, " -> "))
	fmt.Printf("gateway:  %s (%s), SPA udp/%d\n", g.Gateway.ID, g.Gateway.Address, g.Gateway.SPAPort)
	switch {
	case *noKnock:
		fmt.Println("SPA not sent (--no-knock)")
	case g.Mode == api.ModeForward:
		fmt.Printf("open:     %s/%s for %ds -> connect now\n", g.Protocol, client.Endpoint(g), g.AccessTimeout)
	default:
		fmt.Printf("open:     mTLS tunnel port %s for %ds; use `sdp-client connect %s --listen 127.0.0.1:PORT`\n", client.Endpoint(g), g.AccessTimeout, g.Service)
	}
	return nil
}

// popArg extracts the first positional argument so flags may follow it.
func popArg(args []string) (string, []string) {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a, append(append([]string{}, args[:i]...), args[i+1:]...)
		}
	}
	return "", args
}

func connect(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "local address to listen on")
	service, rest := popArg(args)
	_ = fs.Parse(rest)
	if service == "" {
		return errors.New("connect: missing service name")
	}
	log := cli.Logger("info")
	s := &client.Session{Client: c, Service: service, Log: func(f string, a ...any) { log.Info(fmt.Sprintf(f, a...)) }}
	ctx, cancel := cli.SignalContext()
	defer cancel()
	// Fail fast if not authorized.
	gctx, gcancel := context.WithTimeout(ctx, 30*time.Second)
	g, err := s.Grant(gctx)
	gcancel()
	if err != nil {
		return err
	}
	if g.Mode != api.ModeTunnel {
		return fmt.Errorf("connect: %q is a %s-mode service; use `sdp-client access %s` and connect to %s", service, g.Mode, service, client.Endpoint(g))
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	log.Info("forwarding", "listen", ln.Addr().String(), "service", service, "gateway", client.Endpoint(g))
	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer local.Close()
			dctx, dcancel := context.WithTimeout(ctx, 20*time.Second)
			remote, err := s.Dial(dctx)
			dcancel()
			if err != nil {
				log.Warn("tunnel failed", "err", err)
				return
			}
			defer remote.Close()
			netutil.Pipe(local, remote)
		}()
	}
}
