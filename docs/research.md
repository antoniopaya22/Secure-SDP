# Research

## The paper

**SecureSDP: a novel software-defined perimeter implementation for enhanced network security and scalability**
Antonio Payá, Vicente García-Díaz, Alberto Gómez.
*International Journal of Information Security* 23, 2793–2808 (2024).
DOI: [10.1007/s10207-024-00863-7](https://doi.org/10.1007/s10207-024-00863-7)

An earlier version is available as an SSRN preprint (2023): [10.2139/ssrn.4326496](https://doi.org/10.2139/ssrn.4326496).

!!! quote "Abstract (from the published article)"
    Software-defined perimeters (SDP) revolutionize network security by offering dynamic and adaptive access controls, focusing on user and device authentication to substantially reduce the attack surface. Despite their potential, traditional SDP models grapple with challenges in scalability and component-level security, limiting their effectiveness in complex digital environments. To overcome these limitations, this article introduces SecureSDP, a sophisticated evolution of the SDP framework designed to enhance scalability and bolster security for each network component. SecureSDP stands out for its seamless integration into varied organizational structures, delivering a robust and comprehensive security solution that strengthens the network's defenses across all layers. The key advancement of SecureSDP is evidenced by rigorous experimental evaluations, which demonstrate its superior performance in improving network security and scalability. Specifically, SecureSDP achieved substantial increases in the hardening scores across various tools: 65% in Lynis, 78% in Chef Inspec, and 30% in OpenSCAP for the SDP controller. These enhancements underscore SecureSDP's significant contributions to the field, marking a pivotal step forward in the development of more secure, scalable network infrastructures.

### Contributions, in short

- A Software-Defined Perimeter organized after the **Bridge model**: a root controller as central authority, connected peer to peer with the controllers of the existing SDPs, which keep their topology.
- **Dynamic hardening** of every component with Egida: the controller, as Egida master, commands accepting hosts to apply the security controls that suit the services they expose.
- An evaluation of response times for Bridge, Mesh and Hybrid architectures, and of hardening scores (Lynis, Chef InSpec, OpenSCAP) before and after hardening. See [Evaluation](evaluation.md).

How each concept maps to this code is listed in [Architecture](architecture.md#where-each-paper-concept-lives).

## How to cite

If you use SecureSDP, please cite the paper:

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

The repository also has a [`CITATION.cff`](https://github.com/antoniopaya22/Secure-SDP/blob/main/CITATION.cff) (GitHub shows a "Cite this repository" button).

Related works:

```bibtex
@misc{paya2023securing,
  title  = {Securing the Software-Defined Perimeter Framework with Automated Security Configuration Deployment Systems},
  author = {Pay{\'a} Gonz{\'a}lez, Antonio and Redondo L{\'o}pez, Jos{\'e} Manuel and Garc{\'i}a D{\'i}az, Vicente and G{\'o}mez G{\'o}mez, Alberto},
  year   = {2023},
  note   = {SSRN preprint; published version: SecureSDP (IJIS 2024)},
  doi    = {10.2139/ssrn.4326496}
}

@article{paya2022egida,
  title   = {Automated security configuration deployment systems with early error detection},
  author  = {Pay{\'a}, Antonio and Cotarelo, Alberto and Redondo, Jos{\'e} Manuel},
  journal = {Computers \& Security},
  volume  = {116},
  pages   = {102638},
  year    = {2022},
  doi     = {10.1016/j.cose.2022.102638}
}
```

The next step of this line of research, which adds identity management and intrusion detection to the SDP, is described in [Research line](research-line.md).
