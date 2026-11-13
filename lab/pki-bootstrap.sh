#!/bin/sh
# Creates the PKI of the SecureSDP lab on first start (idempotent).
# Keys are generated inside the `pki` volume and never leave it except as
# per-member bundles mounted read-only into each container.
set -eu

DIR="${PKI_DIR:-/pki}"
CA="$DIR/ca"
OUT="$DIR/members"

if [ -f "$DIR/.done" ]; then
    echo "[pki] PKI already initialized in $DIR"
    exit 0
fi

# Root CA (bridge trust anchor) + one name-constrained CA per SDP domain.
sdp-controller pki init --dir "$CA" --domains domain-a,domain-b

issue() { # domain role id [dns] [ip]
    set -- "$1" "$2" "$3" "${4:-}" "${5:-}"
    sdp-controller pki issue --dir "$CA" --domain "$1" --role "$2" --id "$3" \
        --out "$OUT/$3" --dns "$4" --ip "$5"
}

issue domain-a controller ctrl-root   ctrl-root   10.232.0.10
issue domain-b controller ctrl-bridge ctrl-bridge 10.232.0.11
issue domain-a gateway    gw-a        gw-a        10.232.0.20
issue domain-a admin      admin
issue domain-b client     alice
issue domain-b client     bob

# Controllers and clients run as uid 10001; the gateway runs as root.
for m in ctrl-root ctrl-bridge admin alice bob; do
    chown -R 10001:10001 "$OUT/$m"
done
chmod -R go-rwx "$CA"
touch "$DIR/.done"
echo "[pki] done"
