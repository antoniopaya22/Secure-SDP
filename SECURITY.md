# Security Policy

SecureSDP is research software that implements the architecture of a published article. It has not been audited and is not intended for production use without your own review.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the **Security** tab of this repository and click **Report a vulnerability**. Do not open a public issue.

Include the affected component (`sdp-controller`, `sdp-services`, `sdp-client`, PKI tooling, lab configuration), the version or commit, steps to reproduce and the impact you observed.

## Scope

- Go code, lab configuration and scripts of this repository: in scope.
- fwknop: report to its maintainers ([mrash/fwknop](https://github.com/mrash/fwknop)) and to Debian if it concerns the packages.
- Egida and its Ansible roles: report in [Egida-Kassandra/egida](https://github.com/Egida-Kassandra/egida).

## Notes

- Earlier revisions of this repository contained test keys of an OpenSPA test bed (`test/data`, `test/client.yml`). They were never used by SecureSDP and must be considered compromised.
- The lab generates its PKI at start-up inside a Docker volume; never commit keys or certificates (`*.pem`, `*.key` are git-ignored).
