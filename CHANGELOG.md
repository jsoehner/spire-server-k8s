# Changelog

All notable changes to `spire-server-k8s` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2026-11-20

### Architecture & Major Changes
- **Major Version Bump (`v4.0.0`):** Reflects the complete architectural evolution from single-node SPIRE prototyping (`v3.0`) to a multi-node, RBAC-hardened, supply-chain-governed zero-trust workload identity platform.
- **2-Node KinD Topology & Traced Workload (`setup_demo-2node-web.sh`):** Updated primary generator to `v4.0.0` (`spire_k8s_demo_v4.0`), deploying a Control Plane (`spire-server` StatefulSet) + Worker (`spire-agent` DaemonSet with Kubernetes RBAC + `spire-workload` traced HTTP server with `-write` X.509 SVID extraction).
- **Fixed Python 3.12+ Escape Warning:** Escaped `\\;` in the generated `3.4-deploy-workload.py` manifest template to eliminate `SyntaxWarning: "\;"`.

### Governance, Security & Verification
- **Unified SBOM/CBOM/PQC CI Pipeline:** Migrated `.github/workflows/sbom-cbom.yml` to SHA-pinned `jsoehner/jsi-bom-actions@v1.1.1` with daily GitHub Actions Dependabot updates.
- **Trusted OSS Split-Horizon Registry:** Onboarded repository for local LAN cache (`http://oss.jsigroup.local:8080`) and WAN GitHub Actions (`https://jsigroup-oss.duckdns.org`) with strict `.git/info/exclude` hygiene.
- **Automated Functional Verification:** Verified via **Jeffs' Automated build and deploy agent** (`docs/BUILD_VERIFICATION.md`).

### Documentation & Decisions
- Added visual 16:9 architecture infographic (`docs/images/spire-server-k8s-architecture.png`) and Mermaid logical flow diagrams to `README.md` and `docs/architecture.md`.
- Added [ADR-0002](docs/adr/0002-multi-node-kind-spire-architecture-and-traced-workload.md) (Multi-Node KinD SPIRE Architecture & Traced Workload) and [ADR-0003](docs/adr/0003-unified-jsi-bom-actions-and-trusted-oss-governance.md) (Unified `jsi-bom-actions` & Trusted OSS Governance, superseding inline workflow details in ADR-0001).
- Added master ADR index at [docs/adr/README.md](docs/adr/README.md) and modernized `docs/architecture.md` and `README.md`.

## [3.3.0] - 2026-02-15

### Added
- `setup_demo-2node-web.sh` adding RBAC (`ServiceAccount`, `ClusterRole`, `ClusterRoleBinding`) for `spire-agent` and a traced Python web workload (`3.4-deploy-workload.py`) using `spire-agent api fetch x509 -write` to avoid stdout parsing fragility.

## [3.2.0] - 2026-02-14

### Added
- `setup_demo-2node.sh` introducing a 2-node KinD topology (Control Plane + Worker) with `--trusted_domain` substitution and control-plane node pinning for `spire-server`.

## [3.0.0] - 2026-02-14

### Added
- Initial `setup_demo-v3.0.sh` single-click KinD SPIRE demo with two-tier OpenSSL Root + Intermediate CA (`pathlen:1`) UpstreamAuthority PKI bootstrap.
