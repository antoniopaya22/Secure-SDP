# Accepting host (`sdp-services`)

```text
sdp-services serve --config services.yml
sdp-services version
```

`sdp-services` is the Policy Enforcement Point. At start-up it:

1. puts the host in **default-drop** (`iptables -P INPUT DROP`, `-P FORWARD DROP`, loopback and established traffic allowed, `MASQUERADE` on the private interfaces; the same for `ip6tables` without any opening);
2. writes `fwknopd.conf` and an `access.conf` that only contains a placeholder stanza with random, never shared keys (fwknopd refuses to start without stanzas), and starts `fwknopd` in the foreground, waiting until it sniffs;
3. listens for mTLS tunnels (port closed by the firewall until SPA);
4. dials the controller of its domain and waits for its state.

It then serves the controller:

| Method | Effect |
|---|---|
| `gateway.sync` | replace all grants with the controller's list, reload fwknopd, apply the hardening profile, answer with the hardening report |
| `grant.install` | add one grant (and drop the grants it replaces), reload fwknopd and only then answer, so the client can knock immediately |
| `grant.revoke` | remove grants; when `enforce` is set, also close their tunnels, delete the fwknop rules still open for the addresses that knocked with them, and drop their DNAT flows (`conntrack -D`) |
| `audit.run` | run Lynis and return the hardening index |

Grants also expire locally at `expires_at` (`ACCESS_EXPIRE_EPOCH` in the stanza as well), so access ends even if the controller is unreachable.

## Access stanzas

One stanza per grant, for example (forward mode):

```text
# grant 64a5dc8a83f1c13151241ad3: sdp://domain-b/client/alice -> web-nat (forward)
SOURCE                   ANY
REQUIRE_SOURCE_ADDRESS   Y
OPEN_PORTS               tcp/8080
KEY_BASE64               <per-grant key>
HMAC_KEY_BASE64          <per-grant HMAC key>
HMAC_DIGEST_TYPE         SHA256
FW_ACCESS_TIMEOUT        30
ACCESS_EXPIRE_EPOCH      1794563196
FORCE_NAT                10.232.1.30 80
```

`SOURCE ANY` with `REQUIRE_SOURCE_ADDRESS` means: any address may knock, but the encrypted packet must name the address it comes from, and only that address is opened. Clients are told apart by their keys. Tunnel-mode stanzas open the tunnel port (`OPEN_PORTS tcp/8443`) without `FORCE_NAT`.

fwknopd's own SNAT is disabled (it uses a fixed source port that breaks back-to-back connections); the accepting host adds a plain `MASQUERADE` on its private side instead. `FLUSH_IPT_AT_INIT` is `N` so that reloading fwknopd (SIGHUP) keeps the access windows of other clients; `sdp-services` flushes the fwknop chains itself before the first start.

!!! note "Reload latency"
    fwknopd 2.6.10 waits about one second when it restarts after SIGHUP. An authorization therefore takes roughly one second end to end in the lab (see [Evaluation](../evaluation.md)).

## Tunnel

In tunnel mode the accepting host terminates TLS 1.3 with client certificates. The service name travels as SNI. A connection is proxied to the service only if the client identity has an active tunnel grant for that service; otherwise it is closed after the handshake. The tunnel is bound to the identity, not to the SPA keys: a client that learned another client's SPA keys still cannot use its tunnel.

## Configuration (`services.yml`)

| Key | Default | Description |
|---|---|---|
| `controller` | — | `host:port` of the peer port of the controller of this domain |
| `controller_identity` | any controller of the domain | pin, e.g. `sdp://domain-a/controller/ctrl-root` |
| `tls.cert` / `tls.key` / `tls.ca` | — | member bundle with a `gateway` identity |
| `public_ip` | — | address initiating hosts send SPA to (selects the sniffing interface) |
| `interface` | from `public_ip` | interface fwknopd sniffs |
| `state_dir` | `/var/lib/sdp-services` | `fwknopd.conf`, `access.conf`, rendered Aspida programs |
| `ready_file` | none | created once connected to the controller |
| `fwknop.enabled` | `false` | run fwknopd (disable only for tests) |
| `fwknop.binary` | `fwknopd` | |
| `fwknop.spa_port` | `62201` | UDP port of SPA packets |
| `fwknop.run_dir` | `/run/fwknop` | |
| `firewall.manage` | `false` | apply the default-drop plan and enforce revocations |
| `firewall.binary` / `firewall.binary6` | `iptables` / `ip6tables` | |
| `tunnel.listen` | `:8443` | must match `tunnel_port` of the gateway in the policy |
| `hardening.driver` | `dry-run` | `egida` or `dry-run` (see [Dynamic hardening](../hardening.md)) |
| `hardening.egida` | `egida` | Egida binary |
| `audit.lynis` | `lynis` | Lynis binary |

The accepting host must run as root (iptables and libpcap). In containers it needs `NET_ADMIN`, `NET_RAW` and `net.ipv4.ip_forward=1` for forward-mode services.
