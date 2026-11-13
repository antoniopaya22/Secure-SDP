# Controller (`sdp-controller`)

```text
sdp-controller serve   --config controller.yml      run a root or bridge controller
sdp-controller pki init  --dir DIR --domains a,b    create the root CA and one CA per domain
sdp-controller pki issue --dir DIR --domain D --role R --id ID --out OUT [--dns n1,n2] [--ip ip1]
sdp-controller policy check  --policy policy.yml    validate a policy file
sdp-controller policy aspida --policy policy.yml --gateway ID
sdp-controller admin --config admin.yml COMMAND     gateways | grants | revoke | audit | harden | profile | reload
sdp-controller version
```

## Roles

=== "root"

    - Loads the [policy](policy.md) and is the Policy Decision Point of every domain.
    - Serves the initiating hosts and administrators **of its own domain** on the HTTPS API (others are rejected during the TLS handshake and must use their own controller).
    - Accepts peer links from bridged controllers of the other domains declared in the policy, and control channels from the accepting hosts of its domain.
    - On each authorization: generates a grant ID, a 256-bit Rijndael key and a 512-bit HMAC key, installs them on the accepting host and returns them to the client.
    - Keeps grants in memory, expires them (`grant_ttl`) and tells accepting hosts to drop them.
    - Pushes the hardening profile of each accepting host when it connects and after every policy reload (SIGHUP or `admin reload`).

=== "bridge"

    - Serves the initiating hosts of its own domain on the HTTPS API.
    - Relays `services` and `access` requests to the root over the peer link, forwarding the client certificate chain.
    - Accepts control channels from the accepting hosts of its domain, announces them to the root (with their certificate chain) and forwards the root's commands to them.
    - Holds no policy and no secrets other than its own key.

## Configuration (`controller.yml`)

| Key | Role | Default | Description |
|---|---|---|---|
| `role` | both | — | `root` or `bridge` |
| `api_listen` | both | `:7443` | HTTPS + mTLS API |
| `peer_listen` | both | `:7444` | peer links (root) and accepting host control channels |
| `tls.cert` / `tls.key` / `tls.ca` | both | — | member bundle: certificate + domain CA, key, root CA |
| `policy` | root | — | policy file |
| `upstream` | bridge | — | `host:port` of the root `peer_listen` |
| `upstream_identity` | bridge | any controller | pin the root identity, e.g. `sdp://domain-a/controller/ctrl-root` |
| `ready_file` | both | none | created when serving (root) or connected to the root (bridge); used by health checks |

The certificate must carry a `controller` identity. Environment variables: `SDP_CONTROLLER_CONFIG` (default config path), `SDP_LOG_LEVEL`.

## HTTPS API

All endpoints require a client certificate from the SecureSDP PKI.

| Method and path | Who | Description |
|---|---|---|
| `GET /v1/whoami` | client | identity seen by the controller and controller role |
| `GET /v1/services` | client | services the client is entitled to, with accepting host status |
| `POST /v1/access` `{"service": "..."}` | client | authorization; returns the grant (gateway, port, SPA keys, expiry, controller path) |
| `GET /v1/admin/gateways` | admin (root) | accepting hosts: online, route (direct or via bridge), grants, last hardening and audit |
| `GET /v1/admin/grants` | admin (root) | active grants (without secrets) |
| `POST /v1/admin/revoke` `{"grant": id}` or `{"client": "domain/id"}` | admin (root) | revoke and enforce |
| `POST /v1/admin/audit` `{"gateway": id}` | admin (root) | run Lynis on the accepting host |
| `POST /v1/admin/harden` `{"gateway": id}` | admin (root) | re-send the full state and hardening profile |
| `GET /v1/admin/profile?gateway=id` | admin (root) | the Aspida program derived for an accepting host |
| `POST /v1/admin/reload` | admin (root) | reload the policy, revoke grants it no longer allows, re-sync accepting hosts |

Errors are JSON `{"code", "message"}` with `403` (denied), `404`, `400` or `503` (root or accepting host unreachable).

## Admin CLI

`sdp-controller admin` uses the same configuration format as `sdp-client`, with an `admin` identity of the root domain:

```bash
sdp-controller admin --config admin.yml gateways
sdp-controller admin --config admin.yml grants --json
sdp-controller admin --config admin.yml revoke --client domain-b/alice
sdp-controller admin --config admin.yml audit gw-a
sdp-controller admin --config admin.yml profile gw-a
```

## PKI commands

```bash
sdp-controller pki init  --dir pki --domains domain-a,domain-b
sdp-controller pki issue --dir pki --domain domain-a --role controller --id ctrl-root \
    --dns ctrl-root --ip 10.232.0.10 --out members/ctrl-root
sdp-controller pki issue --dir pki --domain domain-b --role client --id alice --out members/alice
```

`pki init` is idempotent (existing CAs are kept). Each `pki issue` writes `cert.pem` (member + domain CA), `key.pem` (0600) and `ca.pem` (root CA). Keep `pki/ca` offline in production.
