package fwknop

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var (
	key  = base64.StdEncoding.EncodeToString(make([]byte, 32))
	hmac = base64.StdEncoding.EncodeToString(make([]byte, 64))
)

func TestRenderAccess(t *testing.T) {
	exp := time.Unix(1800000000, 0)
	out, err := RenderAccess([]Stanza{
		{Comment: "grant g1", OpenPorts: []string{"tcp/8443"}, KeyBase64: key, HMACKeyBase64: hmac, AccessTimeout: 30 * time.Second, Expires: exp},
		{OpenPorts: []string{"tcp/8080"}, KeyBase64: key, HMACKeyBase64: hmac, AccessTimeout: 15 * time.Second, ForceNAT: &NAT{IP: "10.0.1.30", Port: 80}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# grant g1\nSOURCE                   ANY\n",
		"REQUIRE_SOURCE_ADDRESS   Y\n",
		"OPEN_PORTS               tcp/8443\n",
		"KEY_BASE64               " + key + "\n",
		"HMAC_KEY_BASE64          " + hmac + "\n",
		"HMAC_DIGEST_TYPE         SHA256\n",
		"FW_ACCESS_TIMEOUT        30\n",
		"ACCESS_EXPIRE_EPOCH      1800000000\n",
		"FORCE_NAT                10.0.1.30 80\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("access.conf lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "SOURCE ") != 2 {
		t.Errorf("expected two stanzas:\n%s", out)
	}
}

func TestStanzaValidation(t *testing.T) {
	ok := Stanza{OpenPorts: []string{"tcp/8443"}, KeyBase64: key, HMACKeyBase64: hmac, AccessTimeout: time.Second}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Stanza{
		{OpenPorts: nil, KeyBase64: key, HMACKeyBase64: hmac, AccessTimeout: time.Second},
		{OpenPorts: []string{"tcp/8443\nSOURCE ANY"}, KeyBase64: key, HMACKeyBase64: hmac, AccessTimeout: time.Second},
		{OpenPorts: []string{"tcp/8443"}, KeyBase64: "not base64!", HMACKeyBase64: hmac, AccessTimeout: time.Second},
		{OpenPorts: []string{"tcp/8443"}, KeyBase64: key, HMACKeyBase64: hmac, AccessTimeout: 0},
		{OpenPorts: []string{"tcp/8443"}, KeyBase64: key, HMACKeyBase64: hmac, AccessTimeout: time.Second, ForceNAT: &NAT{IP: "nginx", Port: 80}},
		{OpenPorts: []string{"tcp/8443"}, KeyBase64: key, HMACKeyBase64: hmac, AccessTimeout: time.Second, Comment: "x\nOPEN_PORTS tcp/1-65535"},
	}
	for i, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("bad stanza %d accepted", i)
		}
	}
}

func TestRenderServerConfig(t *testing.T) {
	out, err := RenderServerConfig(ServerConfig{Interface: "eth0", AccessFile: "/var/lib/sdp/access.conf", RunDir: "/run/fwknop", Forwarding: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PCAP_INTF                    eth0;", "udp dst port 62201;", "ENABLE_IPT_FORWARDING        Y;", "FLUSH_IPT_AT_INIT            N;", "ENABLE_IPT_SNAT              N;"} {
		if !strings.Contains(out, want) {
			t.Errorf("fwknopd.conf lacks %q:\n%s", want, out)
		}
	}
	if _, err := RenderServerConfig(ServerConfig{Interface: "eth0; X", AccessFile: "/a", RunDir: "/r"}); err == nil {
		t.Fatal("unsafe interface accepted")
	}
}

func TestRenderClientRC(t *testing.T) {
	out, err := RenderClientRC(ClientStanza{Name: "sdp", Server: "10.0.0.20", Access: "tcp/8443", AllowIP: "10.0.0.40", KeyBase64: key, HMACKeyBase64: hmac})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[sdp]\n", "SPA_SERVER           10.0.0.20\n", "ACCESS               tcp/8443\n", "ALLOW_IP             10.0.0.40\n", "USE_HMAC             Y\n", "SPA_SERVER_PORT      62201\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("rc lacks %q:\n%s", want, out)
		}
	}
	if _, err := RenderClientRC(ClientStanza{Name: "sdp", Server: "10.0.0.20", Access: "tcp/8443", AllowIP: "nope", KeyBase64: key, HMACKeyBase64: hmac}); err == nil {
		t.Fatal("invalid allow IP accepted")
	}
}
