# Initiating host (`sdp-client`)

```text
sdp-client [--config client.yml] [--json] COMMAND

  whoami                      show the identity the controller sees
  services                    list the services you may access
  access SERVICE [--wait] [--no-knock]
                              get a grant and send the SPA packet
  connect SERVICE --listen ADDR
                              local port forwarded over mTLS (tunnel-mode services)
  version
```

- `access` asks the controller of the client's domain for a grant, writes the per-grant keys to a private temporary fwknop rc file (keys never appear on a command line) and sends the SPA packet with `fwknop`. The allowed address is the local address used to reach the accepting host (override with `allow_ip`). With `--wait` it re-sends the SPA packet until a TCP connection to the opened port succeeds, because SPA gives no feedback. Exit code `3` means *denied by policy*.
- `connect` keeps a grant fresh, knocks again when the access window may have closed, and forwards each local connection through a TLS 1.3 tunnel to the accepting host, which it authenticates by identity (`sdp://<domain>/gateway/<id>` from the grant).
- `--json` prints machine-readable output (SPA keys are omitted).

## Configuration (`client.yml`)

| Key | Default | Description |
|---|---|---|
| `controller` | — | `host:port` of the HTTPS API of the controller of this domain |
| `controller_identity` | any controller | pin, e.g. `sdp://domain-b/controller/ctrl-bridge` |
| `tls.cert` / `tls.key` / `tls.ca` | — | member bundle with a `client` identity |
| `fwknop` | `fwknop` | fwknop client binary (Debian package `fwknop-client`) |
| `allow_ip` | auto | address to authorize in SPA packets (e.g. behind NAT) |

Environment: `SDP_CLIENT_CONFIG` (default `/etc/sdp/client.yml`).
