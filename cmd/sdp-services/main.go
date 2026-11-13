// Command sdp-services runs a SecureSDP Accepting Host (AH): the gateway in
// front of protected services.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/antoniopaya22/Secure-SDP/internal/cli"
	"github.com/antoniopaya22/Secure-SDP/internal/gateway"
	"github.com/antoniopaya22/Secure-SDP/internal/pki"
)

const usage = `sdp-services: SecureSDP accepting host (gateway)

Usage:
  sdp-services serve --config services.yml   run the accepting host
  sdp-services version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(os.Args[2:]); err != nil {
			cli.Fatal(err)
		}
	case "version", "--version":
		fmt.Println("sdp-services", cli.Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	conf := fs.String("config", cli.Env("SDP_SERVICES_CONFIG", "/etc/sdp/services.yml"), "configuration file")
	level := fs.String("log-level", cli.Env("SDP_LOG_LEVEL", "info"), "debug, info, warn or error")
	_ = fs.Parse(args)
	cfg, err := gateway.LoadConfig(*conf)
	if err != nil {
		return err
	}
	me, err := pki.LoadMember(cfg.TLS)
	if err != nil {
		return err
	}
	log := cli.Logger(*level).With("gateway", me.Identity.String())
	a, err := gateway.New(cfg, me, log)
	if err != nil {
		return err
	}
	ctx, cancel := cli.SignalContext()
	defer cancel()
	return a.Run(ctx)
}
