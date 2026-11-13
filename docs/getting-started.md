# Getting started

## Requirements

- Docker Engine with the Compose plugin (v2.30 or later: the lab uses volume `subpath` mounts and `--wait`).
- Linux host (the accepting host container uses `iptables`, `NET_ADMIN` and `NET_RAW`).
- Go 1.24 or later only if you want to build or test the binaries outside Docker.

## Run the lab

```bash
git clone https://github.com/antoniopaya22/Secure-SDP.git
cd Secure-SDP
docker compose up -d --build --wait
./scripts/demo.sh
```

The first command builds three images (controller, accepting host, initiating host), generates a fresh PKI inside a Docker volume and starts:

| Container | Domain | Role | Address |
|---|---|---|---|
| `ctrl-root` | domain-a | root controller | 10.232.0.10 |
| `ctrl-bridge` | domain-b | bridged controller | 10.232.0.11 |
| `gw-a` | domain-a | accepting host | 10.232.0.20 (public), 10.232.1.20 (private) |
| `web` | — | protected nginx | 10.232.1.30 (private network only) |
| `ih-alice` | domain-b | initiating host, authorized | 10.232.0.40 |
| `ih-bob` | domain-b | initiating host, not authorized | 10.232.0.41 |

`scripts/demo.sh` then checks, and prints `PASS`/`FAIL` for, each property of the perimeter: the service is hidden before SPA, Alice authenticates through the bridged controller and is authorized by the root, the service answers HTTP 200 after SPA (DNAT and tunnel modes), Bob is denied and still sees nothing, a domain-b client cannot bypass its controller, and a revocation cuts access immediately. `RUN_AUDIT=1 ./scripts/demo.sh` adds a Lynis audit of the accepting host.

See [Lab & demo](lab.md) for a step-by-step walkthrough.

## Try it by hand

```bash
# Who am I for my (bridged) controller, and what may I use?
docker compose exec ih-alice sdp-client whoami
docker compose exec ih-alice sdp-client services

# Forward mode: grant + SPA, then plain HTTP through fwknop DNAT
docker compose exec ih-alice sdp-client access web-nat --wait
docker compose exec ih-alice curl -s http://10.232.0.20:8080/ | head -4

# Tunnel mode: local port forwarded over mTLS to the accepting host
docker compose exec -d ih-alice sdp-client connect web --listen 127.0.0.1:9000
docker compose exec ih-alice curl -s http://127.0.0.1:9000/ | head -4

# Bob has a valid certificate but no entitlement
docker compose exec ih-bob sdp-client access web      # access denied (exit code 3)

# Operator view on the root controller
docker compose exec ctrl-root sdp-controller admin --config /etc/sdp/admin.yml gateways
docker compose exec ctrl-root sdp-controller admin --config /etc/sdp/admin.yml grants
docker compose exec ctrl-root sdp-controller admin --config /etc/sdp/admin.yml profile gw-a
```

## Build and test the binaries

```bash
go vet ./...
go test -race ./...
go build -o bin/ ./cmd/...
ls bin/   # sdp-client  sdp-controller  sdp-services
```

The unit and integration tests run a complete root + bridge + two accepting hosts + clients deployment in-process (real mTLS, no fwknop/iptables), so they need no privileges.

## Clean up

```bash
docker compose --profile bench down -v
```

`-v` also deletes the `pki` volume, so the next start creates a new PKI.
