# SecureSDP

[![Paper](https://img.shields.io/badge/IJIS_2024-10.1007%2Fs10207--024--00863--7-0E7490)](https://doi.org/10.1007/s10207-024-00863-7)
[![CI](https://github.com/antoniopaya22/Secure-SDP/actions/workflows/ci.yml/badge.svg)](https://github.com/antoniopaya22/Secure-SDP/actions/workflows/ci.yml)
[![Docs](https://github.com/antoniopaya22/Secure-SDP/actions/workflows/docs.yml/badge.svg)](https://antoniopaya22.github.io/Secure-SDP/)
[![License: GPL-3.0](https://img.shields.io/github/license/antoniopaya22/Secure-SDP?color=green)](LICENSE)

**SecureSDP** is a Software-Defined Perimeter written in Go that follows the architecture of the article **[SecureSDP: a novel software-defined perimeter implementation for enhanced network security and scalability](https://doi.org/10.1007/s10207-024-00863-7)** (*International Journal of Information Security* 23, 2024). Controllers are organized after the **Bridge model**: a root controller decides for every domain, and each existing SDP keeps its own bridged controller, which authenticates its members and relays their requests over a mutual-TLS peer link. Accepting hosts stay dark behind a default-drop firewall until a client sends a **Single Packet Authorization** packet (fwknop) with keys the root issued for that grant alone. The controller also drives **dynamic hardening** of each accepting host with [Egida](https://github.com/Egida-Kassandra/egida) and collects Lynis audits.

📖 **Documentation: <https://antoniopaya22.github.io/Secure-SDP/>**

> [!NOTE]
> **Provenance.** This repository originally held only a skeleton and an OpenSPA test bed. The implementation was **written in 2026** following the architecture described in the paper. Results quoted from the paper were obtained by the authors as reported there and **have not been regenerated with this code**. See [History and provenance](https://antoniopaya22.github.io/Secure-SDP/history/).

| Module | Binary | Role |
|---|---|---|
| Initiating host (IH) | `sdp-client` | mTLS to its domain controller, `access` (grant + SPA), `connect` (mTLS tunnel) |
| Controller | `sdp-controller` | `root`: policy decisions, per-grant SPA keys, Egida master, admin API · `bridge`: domain front-end relaying to the root · PKI tooling |
| Accepting host (AH) | `sdp-services` | default-drop iptables, fwknopd with per-client stanzas, mTLS tunnel, hardening and audit agent |

## Quick start

Requirements: Linux, Docker Engine 26+ with Compose 2.30+.

```bash
docker compose up -d --build --wait   # root + bridged controller, gateway, nginx, two clients; PKI generated at start-up
./scripts/demo.sh                     # end-to-end checks
```

```text
[1] Before SPA: the accepting host and the service are dark
  PASS alice: http://10.232.0.20:8080/ does not answer
...
[3] Forward mode: request access, SPA, fwknop DNAT to nginx
    path:     bridge sdp://domain-b/controller/ctrl-bridge -> root sdp://domain-a/controller/ctrl-root
  PASS alice: http://10.232.0.20:8080/ -> HTTP 200
  PASS bob: http://10.232.0.20:8080/ still dark while alice's window is open
...
All checks passed.
```

Build and test the Go code (Go 1.24+):

```bash
go vet ./... && go test -race ./...
go build -o bin/ ./cmd/...
```

More: [Getting started](https://antoniopaya22.github.io/Secure-SDP/getting-started/) · [Architecture](https://antoniopaya22.github.io/Secure-SDP/architecture/) · [Dynamic hardening](https://antoniopaya22.github.io/Secure-SDP/hardening/) · [Evaluation](https://antoniopaya22.github.io/Secure-SDP/evaluation/)

> [!WARNING]
> SecureSDP is research software. Review the policy, the PKI handling and the hardening profiles before using it outside a lab.

## Research line

| Year | Work | Code |
|---|---|---|
| 2022 | Egida: automated security configuration deployment ([Computers & Security](https://doi.org/10.1016/j.cose.2022.102638)) | [Egida-Kassandra/egida](https://github.com/Egida-Kassandra/egida) |
| 2024 | **SecureSDP**: Bridge-model SDP with dynamic hardening ([IJIS](https://doi.org/10.1007/s10207-024-00863-7)) | [Software-Defined-Perimeter](https://github.com/antoniopaya22/Software-Defined-Perimeter) (fwknop lab) · **this repository** |
| 2024 | Apollon: IDS robust to adversarial ML ([Computers & Security](https://doi.org/10.1016/j.cose.2023.103546)) | [apollon](https://github.com/antoniopaya22/apollon) |
| 2025 | IAM + IDS for SDP ([IJIS](https://doi.org/10.1007/s10207-025-01099-9)) | [iam-ids-sdp](https://github.com/antoniopaya22/iam-ids-sdp) |

Details: [Research line](https://antoniopaya22.github.io/Secure-SDP/research-line/).

## Citation

If you use SecureSDP, please cite the article (see also [`CITATION.cff`](CITATION.cff)):

```bibtex
@article{paya2024securesdp,
  title   = {SecureSDP: a novel software-defined perimeter implementation for enhanced network security and scalability},
  author  = {Pay{\'a}, Antonio and Garc{\'i}a-D{\'i}az, Vicente and G{\'o}mez, Alberto},
  journal = {International Journal of Information Security},
  volume  = {23},
  number  = {4},
  pages   = {2793--2808},
  year    = {2024},
  doi     = {10.1007/s10207-024-00863-7}
}
```

## License

[GPL-3.0](LICENSE). See [SECURITY.md](SECURITY.md) to report vulnerabilities and [CONTRIBUTING.md](CONTRIBUTING.md) to contribute.
