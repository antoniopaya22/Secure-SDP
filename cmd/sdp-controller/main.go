// Command sdp-controller runs a SecureSDP controller (root or bridge role)
// and provides the PKI and administration tools.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
	"github.com/antoniopaya22/Secure-SDP/internal/cli"
	"github.com/antoniopaya22/Secure-SDP/internal/client"
	"github.com/antoniopaya22/Secure-SDP/internal/controller"
	"github.com/antoniopaya22/Secure-SDP/internal/identity"
	"github.com/antoniopaya22/Secure-SDP/internal/pki"
	"github.com/antoniopaya22/Secure-SDP/internal/policy"
)

const usage = `sdp-controller: SecureSDP controller (Bridge model)

Usage:
  sdp-controller serve   --config controller.yml      run a root or bridge controller
  sdp-controller pki init  --dir DIR --domains a,b    create the root CA and one CA per domain
  sdp-controller pki issue --dir DIR --domain D --role R --id ID --out OUT [--dns n1,n2] [--ip ip1]
  sdp-controller policy check  --policy policy.yml    validate a policy file
  sdp-controller policy aspida --policy policy.yml --gateway ID
                                                      print the hardening program of an AH
  sdp-controller admin --config admin.yml COMMAND     administer the root controller:
      gateways | grants | revoke (--grant ID | --client DOMAIN/ID) |
      audit GATEWAY | harden GATEWAY | profile GATEWAY | reload
  sdp-controller version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "pki":
		err = pkiCmd(os.Args[2:])
	case "policy":
		err = policyCmd(os.Args[2:])
	case "admin":
		err = adminCmd(os.Args[2:])
	case "version", "--version":
		fmt.Println("sdp-controller", cli.Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		cli.Fatal(err)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	conf := fs.String("config", cli.Env("SDP_CONTROLLER_CONFIG", "/etc/sdp/controller.yml"), "configuration file")
	level := fs.String("log-level", cli.Env("SDP_LOG_LEVEL", "info"), "debug, info, warn or error")
	_ = fs.Parse(args)
	cfg, err := controller.LoadConfig(*conf)
	if err != nil {
		return err
	}
	log := cli.Logger(*level)
	ctx, cancel := cli.SignalContext()
	defer cancel()
	if cfg.Role == controller.RoleRoot {
		me, err := pki.LoadMember(cfg.TLS)
		if err != nil {
			return err
		}
		if me.Identity.Role != identity.RoleController {
			return fmt.Errorf("certificate identity %s is not a controller", me.Identity)
		}
		root, err := controller.NewRoot(cfg, me, log.With("controller", me.Identity.String(), "role", cfg.Role))
		if err != nil {
			return err
		}
		// SIGHUP reloads the policy (dynamic hardening follows policy changes).
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				if err := root.Reload(); err != nil {
					log.Error("policy reload failed", "err", err)
				}
			}
		}()
		return root.Run(ctx)
	}
	return controller.Run(ctx, cfg, log)
}

// ---------------------------------------------------------------- pki

func pkiCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("pki: expected init or issue")
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("pki init", flag.ExitOnError)
		dir := fs.String("dir", "pki", "CA directory")
		domains := fs.String("domains", "", "comma-separated SDP domains")
		years := fs.Int("years", 10, "CA validity in years")
		_ = fs.Parse(args[1:])
		ds := cli.SplitList(*domains)
		if len(ds) == 0 {
			return errors.New("pki init: --domains is required")
		}
		validity := time.Duration(*years) * 365 * 24 * time.Hour
		rootDir := filepath.Join(*dir, "root")
		root, err := pki.LoadCA(rootDir, nil)
		if errors.Is(err, os.ErrNotExist) {
			if root, err = pki.NewRootCA("SecureSDP root CA", validity); err != nil {
				return err
			}
			if err := pki.SaveCA(rootDir, root); err != nil {
				return err
			}
			fmt.Println("created root CA", rootDir)
		} else if err != nil {
			return err
		}
		for _, d := range ds {
			ddir := filepath.Join(*dir, "domains", d)
			if _, err := os.Stat(filepath.Join(ddir, pki.CertFile)); err == nil {
				fmt.Println("domain CA exists", ddir)
				continue
			}
			ca, err := root.NewDomainCA(d, validity)
			if err != nil {
				return err
			}
			if err := pki.SaveCA(ddir, ca); err != nil {
				return err
			}
			fmt.Println("created domain CA", ddir, "(name constraint: sdp://"+d+"/...)")
		}
		return nil
	case "issue":
		fs := flag.NewFlagSet("pki issue", flag.ExitOnError)
		dir := fs.String("dir", "pki", "CA directory")
		domain := fs.String("domain", "", "SDP domain")
		role := fs.String("role", "", "client, gateway, controller or admin")
		id := fs.String("id", "", "member ID")
		out := fs.String("out", "", "output directory (cert.pem, key.pem, ca.pem)")
		dns := fs.String("dns", "", "comma-separated DNS SANs")
		ips := fs.String("ip", "", "comma-separated IP SANs")
		days := fs.Int("days", 365, "validity in days")
		_ = fs.Parse(args[1:])
		if *out == "" {
			return errors.New("pki issue: --out is required")
		}
		ident, err := identity.New(*domain, identity.Role(*role), *id)
		if err != nil {
			return err
		}
		root, err := pki.LoadCA(filepath.Join(*dir, "root"), nil)
		if err != nil {
			return err
		}
		ca, err := pki.LoadCA(filepath.Join(*dir, "domains", *domain), root.Cert)
		if err != nil {
			return fmt.Errorf("domain %q: %w", *domain, err)
		}
		req := pki.LeafRequest{Identity: ident, DNSNames: cli.SplitList(*dns), Validity: time.Duration(*days) * 24 * time.Hour}
		for _, s := range cli.SplitList(*ips) {
			ip := net.ParseIP(s)
			if ip == nil {
				return fmt.Errorf("invalid IP %q", s)
			}
			req.IPs = append(req.IPs, ip)
		}
		leaf, err := ca.Issue(req)
		if err != nil {
			return err
		}
		if err := pki.SaveLeaf(*out, leaf, root.Cert); err != nil {
			return err
		}
		fmt.Println("issued", ident.String(), "->", *out)
		return nil
	}
	return fmt.Errorf("pki: unknown command %q", args[0])
}

// ---------------------------------------------------------------- policy

func policyCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("policy: expected check or aspida")
	}
	fs := flag.NewFlagSet("policy", flag.ExitOnError)
	file := fs.String("policy", "/etc/sdp/policy.yml", "policy file")
	gw := fs.String("gateway", "", "accepting host ID (aspida)")
	_ = fs.Parse(args[1:])
	pol, err := policy.Load(*file)
	if err != nil {
		return err
	}
	switch args[0] {
	case "check":
		fmt.Printf("policy OK: %d domains, %d accepting hosts, %d services, %d clients, %d hardening profiles\n",
			len(pol.Domains), len(pol.Gateways), len(pol.Services), len(pol.Clients), len(pol.Hardening))
		return nil
	case "aspida":
		if pol.Gateway(*gw) == nil {
			return fmt.Errorf("unknown accepting host %q", *gw)
		}
		prof, err := pol.HardeningProfile(*gw)
		if err != nil {
			return err
		}
		if prof == nil {
			return fmt.Errorf("no hardening profile applies to %q", *gw)
		}
		fmt.Print(prof.Aspida)
		return nil
	}
	return fmt.Errorf("policy: unknown command %q", args[0])
}

// ---------------------------------------------------------------- admin

func adminCmd(args []string) error {
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	conf := fs.String("config", cli.Env("SDP_ADMIN_CONFIG", "/etc/sdp/admin.yml"), "admin client configuration (same format as sdp-client)")
	asJSON := fs.Bool("json", false, "print raw JSON")
	grant := fs.String("grant", "", "grant ID (revoke)")
	clientName := fs.String("client", "", "client domain/id (revoke)")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("admin: missing command")
	}
	cfg, err := client.LoadConfig(*conf)
	if err != nil {
		return err
	}
	c, err := client.New(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	arg := func() (string, error) {
		if len(rest) < 2 {
			return "", fmt.Errorf("admin %s: missing gateway ID", rest[0])
		}
		return rest[1], nil
	}
	switch rest[0] {
	case "gateways":
		var out []api.GatewayStatus
		if err := c.Do(ctx, http.MethodGet, api.PathAdminGateways, nil, &out); err != nil {
			return err
		}
		if *asJSON {
			return cli.PrintJSON(out)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "GATEWAY\tDOMAIN\tONLINE\tVIA\tSERVICES\tGRANTS\tHARDENING\tLYNIS INDEX")
		for _, g := range out {
			h, l := "-", "-"
			if g.Hardening != nil {
				h = g.Hardening.Status + " (" + g.Hardening.Driver + ", " + g.Hardening.ProfileHash + ")"
			}
			if g.Audit != nil && g.Audit.Available {
				l = fmt.Sprint(g.Audit.HardeningIndex)
			}
			fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%v\t%d\t%s\t%s\n", g.ID, g.Domain, g.Online, g.Via, g.Services, g.Grants, h, l)
		}
		return tw.Flush()
	case "grants":
		var out []api.GrantInfo
		if err := c.Do(ctx, http.MethodGet, api.PathAdminGrants, nil, &out); err != nil {
			return err
		}
		if *asJSON {
			return cli.PrintJSON(out)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "GRANT\tCLIENT\tSERVICE\tGATEWAY\tEXPIRES")
		for _, g := range out {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", g.ID, g.Client, g.Service, g.Gateway, g.ExpiresAt.Format(time.RFC3339))
		}
		return tw.Flush()
	case "revoke":
		var out api.RevokeResult
		if err := c.Do(ctx, http.MethodPost, api.PathAdminRevoke, api.AdminRevoke{Grant: *grant, Client: *clientName}, &out); err != nil {
			return err
		}
		fmt.Printf("revoked %d grant(s)\n", out.Revoked)
		return nil
	case "audit":
		gw, err := arg()
		if err != nil {
			return err
		}
		var rep api.AuditReport
		if err := c.Do(ctx, http.MethodPost, api.PathAdminAudit, api.GatewayRef{Gateway: gw}, &rep); err != nil {
			return err
		}
		if *asJSON || !rep.Available {
			return cli.PrintJSON(rep)
		}
		fmt.Printf("Lynis %s on %s: hardening index %d (tests %d, warnings %d, suggestions %d, took %s)\n",
			rep.Version, rep.Gateway, rep.HardeningIndex, rep.TestsPerformed, rep.Warnings, rep.Suggestions, rep.Duration)
		return nil
	case "harden":
		gw, err := arg()
		if err != nil {
			return err
		}
		var res api.SyncResult
		if err := c.Do(ctx, http.MethodPost, api.PathAdminHarden, api.GatewayRef{Gateway: gw}, &res); err != nil {
			return err
		}
		return cli.PrintJSON(res)
	case "profile":
		gw, err := arg()
		if err != nil {
			return err
		}
		var p api.HardeningProfile
		if err := c.Do(ctx, http.MethodGet, api.PathAdminProfile+"?gateway="+url.QueryEscape(gw), nil, &p); err != nil {
			return err
		}
		if *asJSON {
			return cli.PrintJSON(p)
		}
		fmt.Print(p.Aspida)
		return nil
	case "reload":
		if err := c.Do(ctx, http.MethodPost, api.PathAdminReload, struct{}{}, nil); err != nil {
			return err
		}
		fmt.Println("policy reloaded")
		return nil
	}
	return fmt.Errorf("admin: unknown command %q", rest[0])
}
