# Components

SecureSDP is a single Go module (`github.com/antoniopaya22/Secure-SDP`) that builds three binaries, one per SDP component, plus shared internal packages.

```text
cmd/
  sdp-controller/   root or bridged controller, PKI and admin CLI
  sdp-services/     accepting host (gateway)
  sdp-client/       initiating host
internal/
  identity/   sdp://<domain>/<role>/<id> identities
  pki/        root CA, name-constrained domain CAs, mTLS configurations
  rpc/        persistent bidirectional control channel (JSON frames over mTLS)
  api/        messages and endpoints
  policy/     root controller policy and decisions
  controller/ root and bridge roles, HTTPS API, admin API
  gateway/    accepting host agent, mTLS tunnel
  client/     initiating host library (API client, SPA, tunnel)
  fwknop/     fwknopd/access.conf rendering, daemon supervision, SPA client
  firewall/   iptables default-drop and revocation
  hardening/  Aspida rendering, Egida and dry-run hardeners, Lynis audit
lab/          Docker lab configuration and PKI bootstrap
scripts/      demo.sh (end-to-end checks), bench.sh (response times)
```

The only third-party Go dependency is a YAML parser (`go.yaml.in/yaml/v3`). SPA is delegated to the fwknop binaries from Debian (`fwknop-server` 2.6.10 on accepting hosts, `fwknop-client` on initiating hosts).

| Page | Contents |
|---|---|
| [Controller](controller.md) | `sdp-controller serve`, roles, configuration, admin and PKI commands |
| [Accepting host](services.md) | `sdp-services serve`, firewall, fwknopd, tunnel, hardening and audit configuration |
| [Initiating host](client.md) | `sdp-client` commands and configuration |
| [Policy reference](policy.md) | the root controller policy file |
