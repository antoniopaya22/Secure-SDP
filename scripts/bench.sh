#!/usr/bin/env bash
# HTTP response times through SecureSDP vs. direct access, on the local lab.
#
#   direct  : a host on the private network fetches from nginx (no SDP)
#   forward : alice (domain-b) after SPA, fwknop DNAT through the accepting host
#   tunnel  : alice through the mTLS tunnel terminated by the accepting host
#             (includes the local sdp-client forwarder)
#
# Every request opens a new TCP connection (and, for the tunnel, a new mTLS
# session to the accepting host). Payload sizes match the HTTP response sizes
# used in the paper's scalability test (47.3, 71, 73 and 94.6 KB), but this is
# NOT a reproduction of that experiment (which compared Bridge, Mesh and
# Hybrid topologies with three layers): numbers depend on this machine and on
# Docker networking.
#
# Usage: ./scripts/bench.sh [requests-per-size]   (default 50)
set -euo pipefail

N="${1:-50}"
SIZES=(47300 71000 73000 94600)
GW=10.232.0.20
PORT=$((20000 + RANDOM % 20000))

ex() { docker compose exec -T "$@"; }

docker compose --profile bench up -d --wait probe >/dev/null

# stats <file-with-seconds> -> "mean p50 p95" in milliseconds
stats() {
    sort -n | awk '{ v[NR] = $1 * 1000; s += $1 * 1000 }
        END { if (NR == 0) { print "n/a n/a n/a"; exit }
              p50 = v[int((NR + 1) / 2)]; i = int(NR * 0.95); if (i < 1) i = 1
              printf "%.2f %.2f %.2f\n", s / NR, p50, v[i] }'
}

# fetch <service> <url>: N sequential requests, prints one time per line
fetch() {
    ex "$1" sh -c "for i in \$(seq $N); do curl -s -f -o /dev/null -w '%{time_total}\n' '$2' || echo FAIL; done"
}

declare -A R
for s in "${SIZES[@]}"; do
    file="payload-$s.bin"
    R[direct,$s]="$(fetch probe "http://10.232.1.30/$file" | grep -v FAIL | stats)"

    ex ih-alice sdp-client access web-nat --wait >/dev/null
    out="$(fetch ih-alice "http://$GW:8080/$file")"
    if grep -q FAIL <<<"$out"; then echo "forward-mode request failed (size $s)" >&2; exit 1; fi
    R[forward,$s]="$(stats <<<"$out")"
done

ex -d ih-alice sh -c "timeout 300 sdp-client connect web --listen 127.0.0.1:$PORT >/tmp/bench-connect.log 2>&1"
for _ in $(seq 1 20); do
    ex ih-alice curl -s -f -o /dev/null "http://127.0.0.1:$PORT/" && break
    sleep 0.5
done
for s in "${SIZES[@]}"; do
    out="$(fetch ih-alice "http://127.0.0.1:$PORT/payload-$s.bin")"
    if grep -q FAIL <<<"$out"; then echo "tunnel request failed (size $s)" >&2; exit 1; fi
    R[tunnel,$s]="$(stats <<<"$out")"
done

# Authorization round trip: IH -> bridged controller -> root controller ->
# accepting host (stanza installed, fwknopd reloaded) -> back to the IH.
auth="$(ex ih-alice sh -c "for i in \$(seq 10); do s=\$(date +%s%N); sdp-client access web-nat --no-knock >/dev/null; e=\$(date +%s%N); echo \"\$(( (e - s) / 1000 ))e-6\"; done" | stats)"

echo
echo "SecureSDP lab, local measurement ($N requests per cell, new connection per request)"
echo "Machine: $(uname -sr), $(nproc) CPUs, Docker $(docker version --format '{{.Server.Version}}')"
echo
printf '%-10s | %-24s | %-24s | %-24s\n' "payload" "direct mean/p50/p95 ms" "forward mean/p50/p95 ms" "tunnel mean/p50/p95 ms"
printf -- '-----------+--------------------------+--------------------------+-------------------------\n'
for s in "${SIZES[@]}"; do
    # shellcheck disable=SC2086
    printf '%-10s | %-24s | %-24s | %-24s\n' "$(awk -v b="$s" 'BEGIN{printf "%.1f KB", b/1000}')" \
        "$(printf '%s / %s / %s' ${R[direct,$s]})" "$(printf '%s / %s / %s' ${R[forward,$s]})" "$(printf '%s / %s / %s' ${R[tunnel,$s]})"
done
echo
# shellcheck disable=SC2086
printf 'Authorization (sdp-client access, 10 runs): mean/p50/p95 = %s / %s / %s ms\n' $auth
echo "These are measurements of this lab on this machine, not the results reported in the paper."
