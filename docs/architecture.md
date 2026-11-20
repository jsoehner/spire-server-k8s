# Architecture Overview (`v4.0.0`)

`spire-server-k8s` provides self-extracting, reproducible Bash/Python orchestrators for deploying **SPIFFE / SPIRE** zero-trust workload identity on **Kubernetes (KinD)** with a two-tier upstream OpenSSL PKI, RBAC-enabled SPIRE Agent DaemonSets, traced X.509 SVID workloads, and automated SBOM/CBOM/PQC supply chain governance.

![SPIRE Server on Kubernetes Architecture Overview](images/spire-server-k8s-architecture.jpg)

---

## 1. System Context & Logical Flow

```mermaid
flowchart LR
  subgraph PKI["1. Two-Tier PKI Bootstrap (3.1-pki.sh)"]
    ROOT["Root CA<br/>(RSA-4096 · 10y TTL)"]
    INT["Intermediate CA<br/>(RSA-2048 · 1y TTL · pathlen:1)"]
    SEC["K8s Secret: spire-upstream-ca<br/>ConfigMap: spire-bundle"]
    ROOT -- "Signs" --> INT
    INT --> SEC
    ROOT --> SEC
  end

  subgraph CP["2. Control Plane Node (spire-demo-control-plane)"]
    SRV["StatefulSet: spire-server (:8081)<br/>UpstreamAuthority: disk · DataStore: sqlite3<br/>NodeAttestor: join_token · KeyManager: disk"]
    SOCK["Admin API Socket<br/>/tmp/spire-server/private/api.sock"]
    SEC --> SRV
    SRV --- SOCK
  end

  subgraph WK["3. Worker Node (spire-demo-worker)"]
    RBAC["RBAC: ServiceAccount + ClusterRole<br/>(pods, nodes, nodes/proxy: get/list/watch)"]
    AGT["DaemonSet: spire-agent<br/>hostPID · hostNetwork<br/>k8s + docker Workload Attestors"]
    USOCK["Workload API Socket<br/>/run/spire/sockets/agent.sock"]
    WKL["Deployment: spire-workload (:8000)<br/>Init: binary-downloader<br/>Fetches X.509 SVID (-write /tmp/certs)"]
    RBAC --> AGT
    SRV -- "gRPC :8081 + Join Token" --> AGT
    AGT --- USOCK
    USOCK -- "X.509 SVID" --> WKL
  end

  subgraph GOV["4. Supply Chain & Verification Governance"]
    CI["GitHub Actions: jsi-bom-actions@v1.1.1<br/>CycloneDX + SPDX SBOM · CBOM · AST · PQC"]
    OSS["Trusted OSS Split-Horizon Registry<br/>LAN Cache + WAN mTLS"]
    VER["Jeffs' Automated Build & Deploy Agent<br/>docs/BUILD_VERIFICATION.md"]
  end
```

---

## 2. X.509 SVID Issuance & Verification Sequence

```mermaid
sequenceDiagram
  autonumber
  participant Orch as 3.0-orchestrate.sh
  participant PKI as 3.1-pki.sh (OpenSSL)
  participant Server as spire-server (Control Plane)
  participant Agent as spire-agent (Worker DaemonSet)
  participant Workload as spire-workload (Pod :8000)

  Orch->>PKI: Generate Root CA (RSA-4096) & Intermediate CA (RSA-2048, pathlen:1)
  PKI->>Server: Sync Secret/spire-upstream-ca & ConfigMap/spire-bundle
  Orch->>Server: Deploy StatefulSet (pinned to control-plane)
  Orch->>Server: spire-server token generate (spiffe://<domain>/agent/k8s-node)
  Orch->>Agent: Inject join_token secret, apply ClusterRole RBAC, deploy DaemonSet
  Agent->>Server: Node Attestation (join_token over gRPC :8081)
  Orch->>Server: Register entry spiffe://<domain>/workload/web-server (k8s:ns:default, k8s:sa:default)
  Workload->>Agent: api fetch x509 -socketPath /run/spire/sockets/agent.sock -write /tmp/certs
  Agent-->>Workload: Issue short-lived X.509 SVID (svid.0.pem)
  Workload->>Workload: Verify Subject, Issuer, Dates & URI SAN via OpenSSL, serve HTTP :8000
```

---

## 3. Generator Evolution & Topology Comparison

| Generator Script | Version | KinD Topology | Agent RBAC | Custom Trust Domain | Traced Web Workload |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `setup_demo-v3.0.sh` | `v3.0` | 1-Node (`control-plane`) | — | Fixed (`example.org`) | No |
| `setup_demo-2node.sh` | `v3.2` | 2-Node (`control-plane` + `worker`) | — | `--trusted_domain` | No |
| `setup_demo-2node-web.sh` | **`v4.0.0`** | 2-Node (`control-plane` + `worker`) | `ServiceAccount` + `ClusterRole` + `ClusterRoleBinding` | `--trusted_domain` | Yes (`3.4-deploy-workload.py`, `-write` SVID trace + HTTP `:8000`) |

---

## 4. Supply Chain, Cryptographic & PQC Governance

- **CI/CD Workflow (`.github/workflows/sbom-cbom.yml`):** Uses SHA-pinned [`jsoehner/jsi-bom-actions`](https://github.com/jsoehner/jsi-bom-actions) (`v1.1.1`) to generate CycloneDX/SPDX SBOMs, CycloneDX CBOMs, AST cryptographic call-site inventories, and PQC readiness reports.
- **Automated Audit Report:** Published to [`docs/security/CRYPTOGRAPHIC_AUDIT.md`](security/CRYPTOGRAPHIC_AUDIT.md). Currently tracks classical RSA-4096/RSA-2048 OpenSSL CA generation in the demo PKI scripts with NIST FIPS 203/204 PQC migration guidance.
- **Local Tooling (`scripts/`):** `generate_boms.sh`, `test_boms.sh`, `scan_crypto_ast.py`, `analyze_cbom.py`, `attach_oci_bom.sh`, and `fetch_oci_cbom.py` support local offline auditing.
- **Trusted OSS Split-Horizon & Functional Verification:** Configured for local LAN caching and WAN mTLS CI, with verification evidence recorded in [`docs/BUILD_VERIFICATION.md`](BUILD_VERIFICATION.md).

---

## 5. Architectural Decision Records (ADRs)

See the full index at [`docs/adr/README.md`](adr/README.md):

- [**ADR-0001: Automated SBOM and CBOM Supply Chain Governance**](adr/0001-automated-sbom-cbom-supply-chain-governance.md) *(Partially Superseded by ADR-0003)*
- [**ADR-0002: Multi-Node KinD SPIRE Architecture, RBAC Agent Attestation, and Traced SVID Workload**](adr/0002-multi-node-kind-spire-architecture-and-traced-workload.md) *(Accepted)*
- [**ADR-0003: Unified `jsi-bom-actions` Composite Governance & Trusted OSS Split-Horizon Registry**](adr/0003-unified-jsi-bom-actions-and-trusted-oss-governance.md) *(Accepted)*
