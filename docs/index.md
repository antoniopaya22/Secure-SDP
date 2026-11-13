---
template: home.html
title: SecureSDP
hide:
  - navigation
  - toc
hero:
  eyebrow: Go implementation · SecureSDP, IJIS 2024
  title: Many perimeters, <em>one</em> decision.
  lead: >-
    SecureSDP is a Software-Defined Perimeter that scales by bridging. Each
    domain keeps its own controller; a root controller decides for all of
    them over mutual TLS. Accepting hosts stay dark until a client presents
    a single packet signed with keys issued for that grant alone.
  buttons:
    - text: Get started
      link: getting-started/
    - text: The Bridge model
      link: architecture/
    - text: Read the paper
      link: https://doi.org/10.1007/s10207-024-00863-7
  meta:
    - Bridge-model controllers
    - Per-grant SPA keys (fwknop)
    - Egida dynamic hardening
  denied: "DROP  10.232.0.40 → gw-a:8080"
  granted: "GRANT  alice@domain-b → web  via bridge → root"
---

# SecureSDP

!!! info "Provenance"
    The original repository only contained a skeleton (empty Go modules) and an OpenSPA test bed. **This implementation was written in 2026** following the architecture described in the paper. Results quoted from the paper were obtained by the authors as reported there and **have not been regenerated with this code**. See [History and provenance](history.md).

## From request to open door

<p class="sdp-kicker">An initiating host in one domain reaches a service protected in another. Every hop is mutual TLS, and the decision is made once, at the root.</p>

<ol class="sdp-steps">
  <li><strong>Authenticate locally</strong>The client opens mTLS to the bridged controller of its own domain, whose CA can only vouch for that domain.</li>
  <li><strong>Relay to the root</strong>The bridge forwards the request and the client's certificate chain over a persistent peer link. The root verifies the chain again.</li>
  <li><strong>Decide and issue</strong>The root checks the policy and generates fresh SPA keys for this grant, then installs a dedicated stanza on the accepting host.</li>
  <li><strong>One packet, one path</strong>The client sends its SPA packet and the accepting host opens access for that address only, until the grant expires or is revoked.</li>
</ol>

## Three modules, as in the paper

<div class="grid cards" markdown>

- :material-laptop:{ .lg } **sdp-client**

    ---

    Initiating Host. It authenticates to its domain controller, requests access, sends the SPA packet and connects directly or through an mTLS tunnel.

- :material-source-branch:{ .lg } **sdp-controller**

    ---

    `root` is the Policy Decision Point, the SPA credential issuer and the Egida master. `bridge` is a domain front-end that relays to the root.

- :material-wall-fire:{ .lg } **sdp-services**

    ---

    Accepting Host and Policy Enforcement Point: default-drop iptables, fwknopd with a stanza per grant, mTLS tunnel, and the hardening and audit agent.

</div>

## Built to be verified

<div class="sdp-stats">
  <div class="sdp-stat"><span class="sdp-stat__value">15</span><span class="sdp-stat__label"><strong>End-to-end checks</strong> in <code>scripts/demo.sh</code>, run in CI on every change</span></div>
  <div class="sdp-stat"><span class="sdp-stat__value">mTLS</span><span class="sdp-stat__label"><strong>Every channel</strong>: client ↔ controller, controller ↔ controller, controller ↔ AH, tunnel</span></div>
  <div class="sdp-stat"><span class="sdp-stat__value">1/grant</span><span class="sdp-stat__label"><strong>SPA key pair</strong> per authorization. Nothing is shared between clients</span></div>
  <div class="sdp-stat"><span class="sdp-stat__value">0</span><span class="sdp-stat__label"><strong>Keys in git</strong>. The PKI is generated when the lab starts</span></div>
</div>

## Run the lab

<div class="sdp-terminal" markdown>

```console
$ docker compose up -d --build --wait
$ ./scripts/demo.sh
[1] Before SPA: the accepting host and the service are dark
  PASS alice: http://10.232.0.20:8080/ does not answer
[3] Forward mode: request access, SPA, fwknop DNAT to nginx
  PASS authorized by the root controller through the bridge
  PASS alice: http://10.232.0.20:8080/ -> HTTP 200
  PASS bob: http://10.232.0.20:8080/ still dark while alice's window is open
All checks passed.
```

</div>

## Key properties

- **Dark by default.** Accepting hosts drop every inbound packet. fwknopd opens access only for the source address of a valid Single Packet Authorization (SPA) packet, for `FW_ACCESS_TIMEOUT` seconds.
- **Identities are certificates.** Every member has an X.509 certificate with a `sdp://<domain>/<role>/<id>` URI SAN. Each domain CA is name-constrained to its own domain (the Bridge-CA model).
- **End-to-end verification.** A bridged controller forwards the client certificate chain, and the root verifies it again instead of trusting the bridge.
- **Revocation that bites.** Revoking a grant removes its stanza, closes live tunnels and deletes the firewall rules fwknopd had opened.

<div class="sdp-cta" markdown>

## Explore SecureSDP

Read how the Bridge model and dynamic hardening work, or start the lab and try it.

[Get started](getting-started.md){ .md-button .md-button--primary } [Architecture](architecture.md){ .md-button } [Dynamic hardening](hardening.md){ .md-button }

</div>
