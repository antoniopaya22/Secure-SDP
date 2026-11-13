---
template: home.html
title: SecureSDP
description: Software-Defined Perimeter in Go with Bridge-model controllers, per-grant SPA keys (fwknop) and Egida dynamic hardening. Implementation of SecureSDP (IJIS 2024).
hide:
  - navigation
  - toc
---

# SecureSDP

SecureSDP is a Software-Defined Perimeter written in Go that follows the architecture of the article SecureSDP: a novel software-defined perimeter implementation for enhanced network security and scalability (International Journal of Information Security 23, 2793–2808, 2024, doi:10.1007/s10207-024-00863-7).

Controllers follow the Bridge model: a root controller decides for every domain, and each domain keeps a bridged controller that authenticates its members over mutual TLS and relays their requests. Accepting hosts (sdp-services) stay dark behind default-deny iptables until a client (sdp-client) sends a Single Packet Authorization packet with fwknop keys issued for that grant alone. The root controller (sdp-controller) also drives dynamic hardening of each accepting host with Egida and collects Lynis audits.

Provenance: the implementation was written in 2026 following the architecture described in the paper; results quoted from the paper were not regenerated with this code.

Quick start: `docker compose up -d --build --wait`, then `./scripts/demo.sh`.
