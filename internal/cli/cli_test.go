package cli

import (
	"flag"
	"io"
	"slices"
	"testing"
)

func TestParseInterspersed(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	j := fs.Bool("json", false, "")
	c := fs.String("client", "", "")
	pos, err := ParseInterspersed(fs, []string{"revoke", "--client", "domain-b/alice", "x", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pos, []string{"revoke", "x"}) || !*j || *c != "domain-b/alice" {
		t.Fatalf("pos=%v json=%v client=%q", pos, *j, *c)
	}
	if _, err := ParseInterspersed(fs, []string{"a", "--nope"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestSplitList(t *testing.T) {
	if got := SplitList(" a, ,b ,"); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("got %v", got)
	}
}
