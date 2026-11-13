# Policy reference

The root controller reads one YAML policy file (`policy:` in its configuration). Unknown keys are rejected. Validate a file with:

```bash
sdp-controller policy check --policy policy.yml
sdp-controller policy aspida --policy policy.yml --gateway gw-a   # hardening program of an AH
```

Reload a running root with `SIGHUP` or `sdp-controller admin reload`: grants the new policy no longer allows are revoked (and enforced), and every accepting host is re-synchronized with its new hardening profile.

## Example

```yaml
defaults:
  access_timeout: 30s
  grant_ttl: 10m
  hardening: [sdp-accepting-host]

domains:
  - name: domain-a
  - name: domain-b

gateways:
  - id: gw-a
    domain: domain-a
    address: 10.232.0.20
    spa_port: 62201
    tunnel_port: 8443

services:
  - name: web
    gateway: gw-a
    target: 10.232.1.30:80
    mode: tunnel
    hardening: [http-service]
  - name: web-nat
    gateway: gw-a
    target: 10.232.1.30:80
    mode: forward
    port: 8080

clients:
  - id: alice
    domain: domain-b
    services: [web, web-nat]
  - id: bob
    domain: domain-b

hardening:
  sdp-accepting-host:
    sections: ["1.1", "1.6", "1.8", "3.1", "3.2", "4.2", "5.2", "5.4", "6.1"]
    exclusions: ["3.1.2"]
  http-service:
    sections: ["2.2"]
    exclusions: ["2.2.10", "2.2.13"]
```

The full lab policy, with comments, is [`lab/config/policy.yml`](https://github.com/antoniopaya22/Secure-SDP/blob/main/lab/config/policy.yml).

## Keys

### `defaults`

| Key | Default | Description |
|---|---|---|
| `access_timeout` | `30s` | `FW_ACCESS_TIMEOUT`: how long the firewall stays open after a valid SPA packet |
| `grant_ttl` | `10m` | validity of the SPA credentials of a grant (min. `1m`) |
| `hardening` | `[]` | hardening profiles applied to every accepting host |
| `egida_host` | `localhost` | `HOST` block of generated Aspida programs (Egida host group) |

### `domains[]`

| Key | Description |
|---|---|
| `name` | DNS-label name (`[a-z0-9-]`); must match the domain of the controllers' and members' certificates |
| `description` | free text |

The root controller's own domain must be declared. Any other declared domain may connect one bridged controller.

### `gateways[]`

| Key | Default | Description |
|---|---|---|
| `id` | — | accepting host ID (the `id` of its `gateway` certificate) |
| `domain` | — | its domain; it must connect to the controller of that domain |
| `address` | — | address initiating hosts use for SPA and connections |
| `spa_port` | `62201` | |
| `tunnel_port` | `8443` | must match `tunnel.listen` of `sdp-services` |

### `services[]`

| Key | Default | Description |
|---|---|---|
| `name` | — | DNS-label name, also used as TLS SNI in tunnel mode |
| `description` | | |
| `gateway` | — | accepting host that protects the service |
| `target` | — | `host:port` of the service as seen from the accepting host (IP required in forward mode) |
| `mode` | `tunnel` | `tunnel` (mTLS tunnel terminated on the AH) or `forward` (fwknop `FORCE_NAT`) |
| `port` | — | forward mode: gateway port clients connect to (not the SPA or tunnel port) |
| `access_timeout` | `defaults.access_timeout` | between `1s` and `1h` |
| `hardening` | `[]` | profiles this service needs on its accepting host |

### `clients[]`

| Key | Description |
|---|---|
| `id`, `domain` | identity of the initiating host (`sdp://<domain>/client/<id>`) |
| `services` | services it may access; anything else is denied |
| `disabled` | `true` denies everything without removing the entry |

A valid certificate is not enough: an initiating host must be registered here and entitled to the service.

### `hardening.<name>`

Selections use the keywords of Egida's Aspida DSL and the numbering of the CIS points implemented by the Egida CIS role.

| Key | Description |
|---|---|
| `description` | why the profile exists |
| `sections`, `points`, `controls`, `tags` | CIS sections (e.g. `"5.2"`), points (`"5.2.10"`), CIS controls, or role tags to apply |
| `exclusions` | CIS points never applied |
| `vars` | Egida role variables (nested maps, lists, strings, numbers, booleans) |

When several profiles apply to an accepting host (defaults + one per exposed service) they are merged: selections are united, **exclusions from any profile win** (a service can veto a control that would break it) and variables are deep-merged. See [Dynamic hardening](../hardening.md).
