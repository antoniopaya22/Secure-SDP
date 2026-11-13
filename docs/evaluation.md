# Evaluation

The paper evaluates SecureSDP in two scenarios: the scalability of the Bridge architecture and the hardening level of individual components. This page summarizes what the paper **reports** and explains how to take comparable measurements with this implementation. It does not claim that this code reproduces the paper's numbers.

!!! warning "Provenance of the numbers"
    The results in the two "Reported in the paper" sections were obtained by the authors with the setup described in the paper. They have **not** been regenerated with this implementation, which was written in 2026 (see [History and provenance](history.md)).

## Architecture scalability

### Reported in the paper

- **Method.** HTTP response times were measured for Bridge, Mesh and Hybrid SDP architectures, each built with a three-layer depth, for responses of 94.6 KB, 73 KB, 71 KB and 47.3 KB. The comparison framework builds on Palmo et al. and Singh et al.
- **Result.** The Bridge architecture gave the lowest response times for all four sizes, closely followed by Mesh. Considering also that a Mesh deployment costs substantially more (Palmo et al.), the paper selects the Bridge model for SecureSDP. The detailed values are plotted in Figures 7–9 of the paper.

### Measuring this implementation

`scripts/bench.sh` measures, on the lab, the cost of going through the perimeter for the same four payload sizes:

- **direct**: a host on the private network fetches the file from nginx (no SDP);
- **forward**: an authorized client in domain-b, after SPA, through fwknop DNAT on the accepting host;
- **tunnel**: the same client through the mTLS tunnel terminated by the accepting host (TLS 1.3 handshake with client certificate on every request, plus the local `sdp-client connect` forwarder);
- **authorization**: the round trip of `sdp-client access` (IH → bridged controller → root controller → accepting host installs the stanza and reloads fwknopd → back).

```bash
docker compose up -d --build --wait
./scripts/bench.sh 50
```

Example output on the author's workstation (Linux 7.0, 12 CPUs, Docker 29.7; 20 sequential requests per cell, a new connection per request; local measurement, **not** results from the paper):

| Payload | direct mean / p50 / p95 (ms) | forward mean / p50 / p95 (ms) | tunnel mean / p50 / p95 (ms) |
|---|---|---|---|
| 47.3 KB | 0.50 / 0.47 / 0.58 | 0.53 / 0.50 / 0.60 | 3.49 / 3.42 / 3.92 |
| 71.0 KB | 0.47 / 0.48 / 0.56 | 0.62 / 0.62 / 0.69 | 3.42 / 3.34 / 4.02 |
| 73.0 KB | 0.49 / 0.48 / 0.54 | 0.61 / 0.62 / 0.68 | 3.55 / 3.51 / 4.17 |
| 94.6 KB | 0.51 / 0.51 / 0.65 | 0.66 / 0.66 / 0.69 | 3.52 / 3.48 / 4.09 |

Authorization round trip: about 1.09 s (mean of 10), almost entirely fwknopd's restart delay after SIGHUP.

Reading these numbers:

- Once access is open, DNAT through the accepting host adds roughly a tenth of a millisecond on a local bridge network. The tunnel adds a few milliseconds per **new** connection, dominated by the TLS 1.3 handshake with client authentication; long-lived connections pay it once.
- Authorizing a client costs about one second, paid once per grant (default validity 10 minutes), not per request.
- The lab does **not** reproduce the paper's Bridge vs. Mesh vs. Hybrid comparison: it has one bridged domain and a single machine. Reproducing that experiment would need multi-level deployments on separate hosts.

## Component hardening

### Reported in the paper

The paper audited an SDP controller and an SDP accepting host before and after applying non-interfering security controls with Egida, using Lynis (executed, non-skipped tests; warnings and suggestions counted as failures), Chef InSpec (CIS Distribution Independent Linux Benchmark profile) and OpenSCAP (CIS Ubuntu 20.04 Level 1 Server profile). Scores reported in Tables 2 and 3 of the paper:

| Component | Tool | Before | After | Ratio |
|---|---|---|---|---|
| SDP controller | Lynis | 52.00 % | 86.00 % | 1.65× |
| SDP controller | Chef InSpec | 36.17 % | 64.25 % | 1.78× |
| SDP controller | OpenSCAP | 63.52 % | 82.94 % | 1.30× |
| SDP accepting host | Lynis | 54.00 % | 88.00 % | 1.63× |
| SDP accepting host | Chef InSpec | 36.17 % | 64.25 % | 1.78× |
| SDP accepting host | OpenSCAP | 63.52 % | 82.94 % | 1.30× |

The paper also reports that the hardened systems had no safety-critical test failures, only warnings.

### Measuring this implementation

- `sdp-controller admin audit <gateway>` runs Lynis on an accepting host and reports the hardening index, tests performed, warnings and suggestions to the root controller (see [Dynamic hardening](hardening.md#auditing-with-lynis)).
- To reproduce the before/after methodology: deploy an accepting host on a Debian VM, run the audit, enable the `egida` hardening driver so the controller's Aspida program is applied, and audit again. Chef InSpec and OpenSCAP are not integrated; run them on the host with the profiles named above.
- In the container lab the audit runs on a minimal Debian 12 container with the `dry-run` driver. It returned a hardening index of 55 on the author's workstation. This is **not** comparable to the paper's figures (different system, no Egida applied) and is only a check that the audit path works.
