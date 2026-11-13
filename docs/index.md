# SecureSDP

**SecureSDP** is a Software-Defined Perimeter (SDP) written in Go that follows the architecture of the paper
[*SecureSDP: a novel software-defined perimeter implementation for enhanced network security and scalability*](https://doi.org/10.1007/s10207-024-00863-7)
(International Journal of Information Security 23, 2793–2808, 2024).

It addresses the two limitations of classic SDPs the paper describes:

- **Scalability with the Bridge model.** A root SDP controller is the central authority. Every other SDP domain keeps its own *bridged* controller, which authenticates its members and relays their requests to the root over a persistent mutual-TLS peer link. Existing SDPs keep their topology; the root decides.
- **Security of each component (dynamic hardening).** The controller plays the master role of [Egida](https://github.com/Egida-Kassandra/egida): it derives, for each accepting host, an Aspida hardening program from the services that host exposes and pushes it over the control channel. Accepting hosts report Lynis audits back.

!!! info "Provenance"
    The original repository only contained a skeleton (empty Go modules) and an OpenSPA test bed. **This implementation was written in 2026** following the architecture described in the paper. Results quoted from the paper were obtained by the authors as reported there and **have not been regenerated with this code**. See [History and provenance](history.md).

## What is in the box

| Module | Binary | Role in the SDP |
|---|---|---|
| Initiating Host (IH) | `sdp-client` | Authenticates with mTLS to the controller of its domain, requests access to a service, sends the SPA packet (fwknop) and connects, directly or through an mTLS tunnel. |
| Controller | `sdp-controller` | `root` role: Policy Decision Point, SPA credential issuer, Egida master, admin API. `bridge` role: front controller of a domain that relays to the root. Also contains the PKI tooling. |
| Accepting Host (AH) | `sdp-services` | Policy Enforcement Point: default-drop iptables, fwknopd with one access stanza per authorized client, mTLS tunnel to protected services, hardening and audit agent. |

The module names (`sdp-client`, `sdp-controller`, `sdp-services`) are the ones used in the paper.

## Key properties

- **Dark by default.** Accepting hosts drop every inbound packet. fwknopd opens access for the source address of a valid Single Packet Authorization (SPA) packet only, for `FW_ACCESS_TIMEOUT` seconds.
- **Per-client, per-grant SPA keys.** The root controller generates fresh Rijndael and HMAC keys for each authorization and installs them on the accepting host as a dedicated `access.conf` stanza. Nothing is shared between clients.
- **Identities are certificates.** Every member has an X.509 certificate with a `sdp://<domain>/<role>/<id>` URI SAN. Each domain CA is name-constrained to its own domain, so a bridged domain can only vouch for its own members (Bridge-CA model).
- **End-to-end verification.** A bridged controller forwards the client certificate chain; the root verifies it again instead of trusting the bridge.
- **mTLS everywhere.** IH ↔ controller, controller ↔ controller, controller ↔ AH and, in tunnel mode, the data channel IH ↔ AH.
- **Revocation that bites.** Revoking a grant removes its stanza, closes live tunnels and deletes the firewall rules fwknopd had opened.

## Quick links

- [Getting started](getting-started.md): run the Docker lab and the end-to-end demo in two commands.
- [Architecture](architecture.md): the Bridge model, the PKI and the access sequence.
- [Dynamic hardening](hardening.md): Egida, Aspida and Lynis.
- [Evaluation](evaluation.md): what the paper reports and how to measure this implementation yourself.
- [Research](research.md): paper and citation.
