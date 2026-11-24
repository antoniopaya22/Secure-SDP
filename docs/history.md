# History and provenance

## What this repository contained before

The repository `antoniopaya22/Secure-SDP` is the one cited by the SecureSDP paper as the location of its implementation. Until the implementation was published it only contained:

- a skeleton: an `sdp-controller` Go module whose `main.go` had no logic, an empty `sdp-client` module and IDE project files;
- a test bed in `test/` built on a vendored copy of [OpenSPA](https://github.com/greenstatic/openspa) (MIT licence), with Docker files and test keys committed to the repository. An earlier prototype had experimented with OpenSPA as the SPA layer before the design settled on fwknop, which is what the paper describes.

That content was removed when the implementation was published. The committed test keys must be considered compromised; they were only used by that test bed.

## What this implementation is

The implementation was developed in a private working copy while the paper was being written, and it was not pushed to this repository at the time. It was **published here in 2026** and has been updated since, mainly with bug fixes and with the simplifications listed below. It follows the architecture described in the paper: the three modules named there (`sdp-client`, `sdp-controller`, `sdp-services`), the Bridge model with a root controller and bridged controllers, mTLS on control and data channels, SPA with fwknop on Debian with iptables, and dynamic hardening with Egida driven by the controller.

- Results quoted from the paper were obtained by the authors with the setup described there and **have not been regenerated** with the published version. Measurements produced by `scripts/bench.sh` or by the audit command are labelled as local measurements.

## Differences from the paper and simplifications

| Topic | Paper | This implementation |
|---|---|---|
| Controller hierarchy | Root controller connected peer to peer with hierarchical controllers; scalability evaluated with three-layer topologies | One root and any number of bridged controllers, each connected directly to the root (two levels). Bridges of bridges are not implemented. |
| Bridge CA | Bridge CA model among SDP instances | Single root CA with one name-constrained CA per domain (no cross-certification of independent roots). |
| Data channel | mTLS | mTLS tunnel mode (identity-bound) and, for comparison and for services that cannot be tunneled, fwknop DNAT forward mode without TLS. |
| SPA | fwknop | Debian 12 fwknop 2.6.10 (`fwknop-server`, `fwknop-client`); per-grant keys installed as access stanzas; fwknopd reloaded with SIGHUP (about 1 s). |
| Dynamic hardening | Egida applies and withdraws controls | Aspida programs derived from the policy are applied with Egida (`egida` driver) or rendered only (`dry-run`, used in the container lab). Withdrawing a control that was already applied is not automated. |
| Hardening of the controller | Controllers and accepting hosts evaluated | The controller pushes profiles to accepting hosts; hardening the controller host itself is left to running Egida on it directly. |
| Evaluation tools | Lynis, Chef InSpec, OpenSCAP | Lynis integrated (`audit`); InSpec and OpenSCAP must be run separately. |
| State | — | Grants are kept in memory by the root controller; a restart drops them (clients request access again). |
| Controller exposure | — | Controllers listen on TCP with mTLS; they are not themselves hidden behind SPA. |
| IP version | — | IPv4 only; accepting hosts drop all inbound IPv6. |
