// Package firewall puts an accepting host in the SDP default-drop state with
// iptables: nothing is reachable until fwknopd opens access for an
// authorized client after a valid SPA packet.
package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// Rule is an iptables invocation. Ensure rules are added only if missing
// (checked with -C), so Setup is idempotent.
type Rule struct {
	Args   []string
	Ensure bool // add with -A only if `-C` fails
}

// Plan returns the rules that make a host default-drop.
//
//   - INPUT and FORWARD drop by default; loopback and established flows pass.
//   - fwknopd inserts its own FWKNOP_* jump rules at the top of INPUT,
//     FORWARD and nat PREROUTING when it starts.
//   - Traffic forwarded to the protected network (forward-mode services) is
//     masqueraded on the private interfaces so replies come back through
//     the accepting host.
//
// Outgoing traffic (control channel to the controller, tunnel connections to
// protected services) is allowed.
func Plan(privateIfaces []string) []Rule {
	r := []Rule{
		{Args: []string{"-P", "INPUT", "DROP"}},
		{Args: []string{"-P", "FORWARD", "DROP"}},
		{Args: []string{"-F", "INPUT"}},
		{Args: []string{"-F", "FORWARD"}},
		// Clear rules left by a previous fwknopd (FLUSH_IPT_AT_INIT is N).
		{Args: []string{"-t", "filter", "-F", "FWKNOP_INPUT"}},
		{Args: []string{"-t", "filter", "-F", "FWKNOP_FORWARD"}},
		{Args: []string{"-t", "nat", "-F", "FWKNOP_PREROUTING"}},
		{Args: []string{"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"}},
		{Args: []string{"-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
		{Args: []string{"-A", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
	}
	for _, i := range privateIfaces {
		r = append(r, Rule{Args: []string{"-t", "nat", "-A", "POSTROUTING", "-o", i, "-j", "MASQUERADE"}, Ensure: true})
	}
	return r
}

// Runner executes iptables.
type Runner interface {
	Run(args ...string) error
}

// Exec runs the iptables binary.
type Exec struct{ Binary string }

// Run implements Runner.
func (e Exec) Run(args ...string) error {
	bin := e.Binary
	if bin == "" {
		bin = "iptables"
	}
	out, err := exec.Command(bin, append([]string{"-w"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Apply runs a plan. Flushing a chain that does not exist yet is not an error.
func Apply(r Runner, plan []Rule) error {
	for _, rule := range plan {
		if rule.Ensure {
			check := replaceAction(rule.Args, "-C")
			if r.Run(check...) == nil {
				continue
			}
		}
		if err := r.Run(rule.Args...); err != nil {
			if isFlushOfFWKNOPChain(rule.Args) {
				continue
			}
			return err
		}
	}
	return nil
}

func replaceAction(args []string, action string) []string {
	out := append([]string(nil), args...)
	for i, a := range out {
		if a == "-A" || a == "-I" {
			out[i] = action
			break
		}
	}
	return out
}

func isFlushOfFWKNOPChain(args []string) bool {
	for i, a := range args {
		if a == "-F" && i+1 < len(args) && strings.HasPrefix(args[i+1], "FWKNOP_") {
			return true
		}
	}
	return false
}

// Plan6 makes IPv6 default-drop. fwknop and SecureSDP authorize IPv4 only,
// so nothing is opened over IPv6 (otherwise listeners bound to [::] such as
// the tunnel would be reachable without SPA on dual-stack hosts).
func Plan6() []Rule {
	return []Rule{
		{Args: []string{"-P", "INPUT", "DROP"}},
		{Args: []string{"-P", "FORWARD", "DROP"}},
		{Args: []string{"-F", "INPUT"}},
		{Args: []string{"-F", "FORWARD"}},
		{Args: []string{"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"}},
		{Args: []string{"-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
	}
}

// Lister is a Runner that can also return command output (iptables -S).
type Lister interface {
	Runner
	Output(args ...string) (string, error)
}

// Output implements Lister.
func (e Exec) Output(args ...string) (string, error) {
	bin := e.Binary
	if bin == "" {
		bin = "iptables"
	}
	out, err := exec.Command(bin, append([]string{"-w"}, args...)...).Output()
	return string(out), err
}

// Access identifies firewall rules fwknopd opened for one client.
type Access struct {
	Source string // client address (from the SPA packet)
	Ports  []int  // destination ports of the rules (gateway port, DNAT target port)
}

// fwknopChains are the chains where fwknopd adds per-client rules.
var fwknopChains = []struct{ table, chain string }{
	{"filter", "FWKNOP_INPUT"},
	{"filter", "FWKNOP_FORWARD"},
	{"nat", "FWKNOP_PREROUTING"},
}

// CloseAccess deletes the rules fwknopd added for a client before their
// FW_ACCESS_TIMEOUT, so that a revoked grant stops working immediately.
// It returns the number of rules removed.
func CloseAccess(l Lister, a Access) (int, error) {
	src := a.Source + "/32"
	removed := 0
	for _, c := range fwknopChains {
		out, err := l.Output("-t", c.table, "-S", c.chain)
		if err != nil {
			continue // chain not created yet
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || f[0] != "-A" || !hasPair(f, "-s", src) || !matchesPort(f, a.Ports) {
				continue
			}
			f[0] = "-D"
			if err := l.Run(append([]string{"-t", c.table}, f...)...); err != nil {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}

func hasPair(f []string, k, v string) bool {
	for i := 0; i+1 < len(f); i++ {
		if f[i] == k && f[i+1] == v {
			return true
		}
	}
	return false
}

func matchesPort(f []string, ports []int) bool {
	for _, p := range ports {
		if hasPair(f, "--dport", fmt.Sprint(p)) {
			return true
		}
	}
	return false
}
