package firewall

import (
	"errors"
	"strings"
	"testing"
)

type fake struct {
	ran      []string
	existing map[string]bool // rules for which -C succeeds
	fail     map[string]bool
}

func (f *fake) Run(args ...string) error {
	line := strings.Join(args, " ")
	f.ran = append(f.ran, line)
	for _, a := range args {
		if a == "-C" {
			if f.existing[strings.Replace(line, "-C", "-A", 1)] {
				return nil
			}
			return errors.New("no such rule")
		}
	}
	if f.fail[line] {
		return errors.New("failed")
	}
	return nil
}

func TestPlanIsDefaultDrop(t *testing.T) {
	plan := Plan([]string{"eth1"})
	var lines []string
	for _, r := range plan {
		lines = append(lines, strings.Join(r.Args, " "))
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{"-P INPUT DROP", "-P FORWARD DROP", "-A INPUT -i lo -j ACCEPT", "--ctstate ESTABLISHED,RELATED", "-t nat -A POSTROUTING -o eth1 -j MASQUERADE"} {
		if !strings.Contains(all, want) {
			t.Errorf("plan lacks %q", want)
		}
	}
	if strings.Index(all, "-P INPUT DROP") > strings.Index(all, "-A INPUT -i lo") {
		t.Error("policy must be set to DROP before any accept rule is added")
	}
}

func TestApplyIdempotentAndTolerant(t *testing.T) {
	masq := "-t nat -A POSTROUTING -o eth1 -j MASQUERADE"
	f := &fake{
		existing: map[string]bool{masq: true},
		fail:     map[string]bool{"-t nat -F FWKNOP_PREROUTING": true}, // chain does not exist yet
	}
	if err := Apply(f, Plan([]string{"eth1"})); err != nil {
		t.Fatal(err)
	}
	for _, l := range f.ran {
		if l == masq {
			t.Fatal("existing MASQUERADE rule added twice")
		}
	}
	f2 := &fake{fail: map[string]bool{"-P INPUT DROP": true}}
	if err := Apply(f2, Plan(nil)); err == nil {
		t.Fatal("failure of a required rule ignored")
	}
}

type fakeLister struct {
	fake
	chains map[string]string
}

func (f *fakeLister) Output(args ...string) (string, error) {
	out, ok := f.chains[args[1]+" "+args[3]]
	if !ok {
		return "", errors.New("no chain")
	}
	return out, nil
}

func TestCloseAccess(t *testing.T) {
	f := &fakeLister{chains: map[string]string{
		"nat FWKNOP_PREROUTING": "-N FWKNOP_PREROUTING\n" +
			"-A FWKNOP_PREROUTING -s 10.0.0.40/32 -p tcp -m tcp --dport 8080 -m comment --comment _exp_1 -j DNAT --to-destination 10.0.1.30:80\n" +
			"-A FWKNOP_PREROUTING -s 10.0.0.41/32 -p tcp -m tcp --dport 8080 -m comment --comment _exp_1 -j DNAT --to-destination 10.0.1.30:80\n",
		"filter FWKNOP_FORWARD": "-N FWKNOP_FORWARD\n" +
			"-A FWKNOP_FORWARD -s 10.0.0.40/32 -p tcp -m tcp --dport 80 -m comment --comment _exp_1 -j ACCEPT\n",
		"filter FWKNOP_INPUT": "-N FWKNOP_INPUT\n" +
			"-A FWKNOP_INPUT -s 10.0.0.40/32 -p tcp -m tcp --dport 8443 -m comment --comment _exp_1 -j ACCEPT\n",
	}}
	n, err := CloseAccess(f, Access{Source: "10.0.0.40", Ports: []int{8080, 80}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("removed %d rules, want 2 (DNAT + FORWARD of 10.0.0.40): %v", n, f.ran)
	}
	for _, l := range f.ran {
		if strings.Contains(l, "10.0.0.41") || strings.Contains(l, "8443") {
			t.Fatalf("removed an unrelated rule: %s", l)
		}
		if !strings.Contains(l, "-D FWKNOP_") {
			t.Fatalf("unexpected command %s", l)
		}
	}
}
