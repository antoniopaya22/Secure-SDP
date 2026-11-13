package identity

import "testing"

func TestRoundTrip(t *testing.T) {
	id, err := New("domain-b", RoleClient, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := id.String(), "sdp://domain-b/client/alice"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	back, err := Parse(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if back != id {
		t.Fatalf("Parse(String()) = %+v, want %+v", back, id)
	}
	if id.Name() != "domain-b/alice" {
		t.Fatalf("Name() = %q", id.Name())
	}
}

func TestParseRejects(t *testing.T) {
	for _, s := range []string{
		"https://domain-b/client/alice",    // wrong scheme
		"sdp://domain-b/client",            // missing id
		"sdp://domain-b/client/alice/x",    // extra segment
		"sdp://Domain_B/client/alice",      // invalid domain
		"sdp://domain-b/root/alice",        // unknown role
		"sdp://domain-b/client/al ice",     // invalid id
		"sdp://domain-b:8443/client/alice", // port
		"sdp://domain-b/client/alice?x=1",  // query
		"sdp://user@domain-b/client/alice", // userinfo
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", s)
		}
	}
}
