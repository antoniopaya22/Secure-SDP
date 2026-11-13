#!/usr/bin/env bash
# End-to-end check of the SecureSDP lab started with
#   docker compose up -d --build --wait
#
# Proves that:
#   - the protected service and the accepting host are dark before SPA;
#   - an initiating host of domain-b authenticates (mTLS) with its bridged
#     controller, which relays the request to the root controller;
#   - after the SPA packet the service answers 200 for that client only,
#     through fwknop DNAT (forward mode) and through the mTLS tunnel;
#   - an unauthorized initiating host is denied and still sees nothing;
#   - a domain-b client cannot bypass its bridged controller;
#   - revoking a grant cuts the tunnel immediately.
# Exits non-zero if any expectation fails, so it can be used in CI.
# Set RUN_AUDIT=1 to also run a Lynis audit of the accepting host (~1 min).
set -uo pipefail

GW=10.232.0.20
WEB_PRIVATE=10.232.1.30
NAT_URL="http://${GW}:8080/"
PORT=$((20000 + RANDOM % 20000)) # local port of the tunnel forwarder

failures=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; failures=$((failures + 1)); }
# check <0 = success> <pass message> <fail message>
check() { if [ "$1" -eq 0 ]; then pass "$2"; else fail "$3"; fi; }
is() { [ "$1" = "$2" ]; echo $?; }
step() { printf '\n\033[1m[%s] %s\033[0m\n' "$1" "$2"; }
indent() { sed 's/^/    /'; }
ex() { docker compose exec -T "$@"; }
http_code() { ex "$1" curl -s -m 4 -o /dev/null -w '%{http_code}' "$2" 2>/dev/null; }
tcp_closed() { if ex "$1" timeout 3 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null; then echo 1; else echo 0; fi; }
admin() { ex ctrl-root sdp-controller admin --config /etc/sdp/admin.yml "$@"; }

step 1 "Before SPA: the accepting host and the service are dark"
code="$(http_code ih-alice "$NAT_URL")"
check "$(is "$code" 000)" "alice: $NAT_URL does not answer" "alice: got HTTP $code before SPA"
check "$(tcp_closed ih-alice "$GW" 8443)" "alice: tunnel port 8443 filtered" "tunnel port 8443 reachable before SPA"
code="$(http_code ih-alice "http://${WEB_PRIVATE}/")"
check "$(is "$code" 000)" "alice: private network unreachable" "private network answered HTTP $code"

step 2 "Alice (domain-b) authenticates with her bridged controller"
out="$(ex ih-alice sdp-client whoami 2>&1)"
printf '%s\n' "$out" | indent
grep -q "ctrl-bridge (bridge)" <<<"$out"
check $? "mTLS identity accepted by the bridged controller" "whoami failed"
out="$(ex ih-alice sdp-client services 2>&1)"
printf '%s\n' "$out" | indent
grep -q "^web " <<<"$out"
check $? "service list relayed from the root controller" "services failed"

step 3 "Forward mode: request access, SPA, fwknop DNAT to nginx"
out="$(ex ih-alice sdp-client access web-nat --wait 2>&1)"
rc=$?
printf '%s\n' "$out" | indent
[ $rc -eq 0 ] && grep -q "bridge sdp://domain-b/controller/ctrl-bridge -> root sdp://domain-a/controller/ctrl-root" <<<"$out"
check $? "authorized by the root controller through the bridge" "access web-nat failed (rc=$rc)"
code="$(http_code ih-alice "$NAT_URL")"
check "$(is "$code" 200)" "alice: $NAT_URL -> HTTP 200" "alice: got HTTP $code after SPA"
code="$(http_code ih-bob "$NAT_URL")"
check "$(is "$code" 000)" "bob: $NAT_URL still dark while alice's window is open" "bob: got HTTP $code"

step 4 "Tunnel mode: mTLS data channel to nginx through the accepting host"
ex -d ih-alice sh -c "timeout 120 sdp-client connect web --listen 127.0.0.1:$PORT > /tmp/connect-$PORT.log 2>&1"
code=000
for _ in $(seq 1 20); do
    code="$(http_code ih-alice "http://127.0.0.1:$PORT/")"
    [ "$code" = "200" ] && break
    sleep 0.5
done
check "$(is "$code" 200)" "alice: GET through the tunnel -> HTTP 200" "alice: tunnel got HTTP $code"
[ "$code" = "200" ] || ex ih-alice cat "/tmp/connect-$PORT.log" | indent

step 5 "Bob: valid certificate of domain-b, but no entitlement"
out="$(ex ih-bob sdp-client access web 2>&1)"
rc=$?
printf '%s\n' "$out" | indent
check "$(is "$rc" 3)" "bob: access to web denied by the root controller" "bob: access returned rc=$rc"
ex ih-bob sdp-client access web-nat >/dev/null 2>&1
rc=$?
check "$(is "$rc" 3)" "bob: access to web-nat denied" "bob: web-nat returned rc=$rc"
check "$(tcp_closed ih-bob "$GW" 8443)" "bob: tunnel port 8443 filtered" "bob reached the tunnel port"

step 6 "Topology: a domain-b client cannot bypass its bridged controller"
ex ih-alice sh -c 'sed -e "s/ctrl-bridge:7443/ctrl-root:7443/" -e "s#sdp://domain-b/controller/ctrl-bridge#sdp://domain-a/controller/ctrl-root#" /etc/sdp/client.yml > /tmp/direct.yml'
out="$(ex ih-alice sdp-client --config /tmp/direct.yml access web 2>&1)"
rc=$?
printf '%s\n' "${out:0:200}" | indent
if [ $rc -ne 0 ]; then pass "root controller refused a domain-b client"; else fail "root controller served a domain-b client"; fi

step 7 "Controller view (admin API on the root controller)"
admin gateways | indent
admin gateways --json | grep -q '"status": "dry-run"'
check $? "hardening profile synced to gw-a (dry-run driver)" "no hardening report for gw-a"
admin grants | indent

step 8 "Revocation cuts the tunnel immediately"
admin revoke --client domain-b/alice | indent
code="$(http_code ih-alice "http://127.0.0.1:$PORT/")"
if [ "$code" != "200" ]; then pass "alice: tunnel refused after revocation (HTTP $code)"; else fail "tunnel still works after revocation"; fi

if [ "${RUN_AUDIT:-0}" = "1" ]; then
    step 9 "Lynis audit of the accepting host (a container, not a hardened VM)"
    out="$(admin audit gw-a 2>&1)"
    printf '%s\n' "$out" | indent
    grep -q "hardening index" <<<"$out"
    check $? "audit reported to the controller" "audit failed"
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "All checks passed."
else
    echo "$failures check(s) failed. Inspect: docker compose logs ctrl-root ctrl-bridge gw-a"
    exit 1
fi
