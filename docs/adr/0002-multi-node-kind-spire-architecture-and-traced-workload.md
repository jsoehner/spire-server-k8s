# ADR-0002: Multi-Node KinD SPIRE Architecture, RBAC Agent Attestation, and Traced SVID Workload

## Metadata

| Field | Value |
|---|---|
| ADR ID | ADR-0002 |
| Status | Accepted |
| Created Date | 2026-11-20 |
| Decision Date | 2026-11-20 |
| Effective Date | 2026-11-20 |
| Architecture Domain | Zero-Trust Identity / Kubernetes / PKI |
| Scope | SPIRE Server & Agent Kubernetes Deployment (`spire-server-k8s` v4.0.0) |
| Decision Owner | Platform & Security Engineering |
| Named Decision Maker | Lead Infrastructure Architect |
| Approval Authority | Architecture Review Board (ARB) |
| Tags | spire, spiffe, kind, kubernetes, rbac, svid, pki, workload-attestation |

---

## Business and Architecture Context

### Problem Statement

The initial `v3.0` single-click demo (`setup_demo-v3.0.sh`) deployed SPIRE Server and SPIRE Agent onto a single KinD `control-plane` node with a hardcoded `example.org` trust domain and no end-to-end workload SVID verification. While useful for smoke-testing SPIRE Server startup, it did not model real-world Kubernetes separation of duties:
1. **Control-Plane vs. Worker Separation:** Production SPIRE deployments isolate the SPIRE Server (`StatefulSet`) from workload nodes running `spire-agent` (`DaemonSet`).
2. **Least-Privilege Kubernetes Attestation:** The `k8s` Workload Attestor requires explicit Kubernetes RBAC (`ServiceAccount`, `ClusterRole`, `ClusterRoleBinding`) to query the Kubelet/API Server for pod and node metadata.
3. **Custom Enterprise Trust Domains:** Demonstrating multi-tenant or enterprise SPIFFE trust domains (e.g., `spiffe://<custom-domain>/workload/web-server`) requires deterministic trust-domain substitution across server, agent, and registration scripts.
4. **Reliable SVID Extraction:** Parsing `spire-agent api fetch x509` stdout output is fragile across CLI versions; writing PEM bundles directly to disk (`-write /tmp/certs`) provides deterministic OpenSSL inspection.

### Decision Drivers

- **Production-Representative Topology:** Separate `control-plane` (SPIRE Server) and `worker` (SPIRE Agent + Workloads) nodes inside a reproducible local KinD cluster.
- **Zero-Trust Upstream PKI:** Bootstrap a two-tier OpenSSL CA hierarchy (RSA-4096 Root CA -> RSA-2048 Intermediate CA with `basicConstraints=CA:TRUE,pathlen:1`) injected into Kubernetes via `Secret/spire-upstream-ca` and `ConfigMap/spire-bundle`.
- **RBAC-Enabled Node & Workload Attestation:** Explicitly provision `spire-agent` `ServiceAccount`, `ClusterRole` (`pods`, `nodes`, `nodes/proxy` read-only), and `ClusterRoleBinding`.
- **End-to-End Observable Verification:** Deploy a traced HTTP workload (`spire-workload`) that fetches its X.509 SVID over `/run/spire/sockets/agent.sock`, writes PEM files to `/tmp/certs`, inspects SAN/issuer/validity via `openssl x509`, and serves port `8000`.
- **Self-Contained Portability:** Preserve single-command self-extracting Bash generators while bumping the platform to `v4.0.0` to reflect the architectural shift.

---

## Alternatives Considered

| Option | Advantages | Disadvantages / Risks | Disposition |
|---|---|---|---|
| **Option 1: Single-Node KinD (`v3.0` baseline)** | Minimal memory footprint; simplest manifest set. | Conflates control plane and workloads; lacks RBAC and traced workload verification. | **Retained as legacy baseline (`setup_demo-v3.0.sh`)** |
| **Option 2: Helm Chart (`spiffe/helm-charts-hardened`)** | Production-grade upstream chart; rich customization. | Abstracts away PKI bootstrap, join-token mechanics, and workload attestation steps needed for educational/architectural demos; adds Helm/chart dependency drift. | **Rejected for demo generators** |
| **Option 3: 2-Node KinD + RBAC Agent + Write-to-Disk Traced Workload (`v4.0.0`)** | Clear separation of Control Plane and Worker; transparent, auditable PKI & RBAC manifests; deterministic `-write` SVID extraction; parameterized `--trusted_domain`. | Uses `join_token` node attestation and `sqlite3` datastore suitable for local/demo clusters (not HA production); classical RSA CA requires PQC roadmap tracking. | **Selected** |

---

## Decision

Adopt the **2-Node KinD + RBAC Agent + Write-to-Disk Traced Workload** architecture as the primary `v4.0.0` reference implementation in `setup_demo-2node-web.sh` (generating `spire_k8s_demo_v4.0`):

1. **Cluster Topology (`3.0-orchestrate.sh`):** Provision a 2-node KinD cluster (`control-plane` + `worker`) with `/var/run/docker.sock` mounted for optional Docker workload attestation and `--reset` / `--newroot` lifecycle flags.
2. **Two-Tier PKI Bootstrap (`3.1-pki.sh`):** Generate an RSA-4096 Root CA (10-year TTL) and RSA-2048 Intermediate CA (1-year TTL, `pathlen:1`), assemble `chain.crt`, and sync `Secret/spire-upstream-ca` and `ConfigMap/spire-bundle` into namespace `spire`.
3. **Control-Plane SPIRE Server (`3.2-deploy-server.sh`):** Pin `StatefulSet/spire-server` (`ghcr.io/spiffe/spire-server:1.5.1`, gRPC `:8081`) to `node-role.kubernetes.io/control-plane` using `UpstreamAuthority "disk"`, `DataStore "sql"` (`sqlite3`), `NodeAttestor "join_token"`, and `KeyManager "disk"`.
4. **RBAC-Enabled SPIRE Agent (`3.3-register-agent.py`):** Generate a one-time join token via the SPIRE Server private socket, store it in `Secret/spire-agent-token`, apply least-privilege read-only `ClusterRole` RBAC, and deploy `DaemonSet/spire-agent` with `config-injector` initContainer and `k8s` + `docker` workload attestors.
5. **Traced X.509 SVID Workload (`3.4-deploy-workload.py`):** Register `spiffe://<TRUST_DOMAIN>/workload/web-server` with selectors `k8s:ns:default` and `k8s:sa:default`, deploy `Deployment/spire-workload` with an architecture-aware `binary-downloader` initContainer, fetch X.509 SVIDs via `spire-agent api fetch x509 -write /tmp/certs`, inspect via `openssl x509`, and expose HTTP `:8000`.
6. **Backward Compatibility:** Keep `setup_demo-v3.0.sh` (1-node) and `setup_demo-2node.sh` (2-node without web workload) available as incremental reference stages.

---

## Consequences

### Benefits
- **End-to-End Zero-Trust Visibility:** Operators can observe the complete trust chain from offline Root CA -> Intermediate CA -> SPIRE Server -> SPIRE Agent -> Workload X.509 SVID in a single run.
- **Deterministic SVID Parsing:** The `-write` disk output eliminates brittle stdout regex parsing and surfaces exact OpenSSL subject, issuer, validity dates, and SPIFFE URI SAN.
- **Clean Python 3.12+ Compatibility:** Escaping `\\;` in the generated manifest template eliminates `SyntaxWarning` during execution.

### Trade-offs and Risks
- **Non-HA Demo Primitives:** `sqlite3` datastore, `hostPath` volumes, `join_token` node attestation, and `skip_kubelet_verification = true` are intentional for local KinD ergonomics and must be replaced with PostgreSQL/MySQL, `k8s_psat` node attestation, and verified Kubelet TLS in production.
- **Post-Quantum Cryptography (PQC) Debt:** The bootstrap OpenSSL PKI uses classical RSA-4096 / RSA-2048 keys (tracked by `docs/security/CRYPTOGRAPHIC_AUDIT.md`). Migration to FIPS 203 (ML-KEM-768) / FIPS 204 (ML-DSA-65) hybrid CAs is tracked under organizational PQC policy once upstream SPIRE/OpenSSL OQS support stabilizes.

---

## Review and Lifecycle

- **Review Schedule:** Semi-annual or upon major SPIRE release upgrades (e.g., SPIRE 1.10+ / PQC SVID support).
- **Supersedes:** None (establishes the v4.0.0 multi-node architecture baseline).
- **Superseded By:** None.
