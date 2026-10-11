# ADR-0001: Automated SBOM and CBOM Supply Chain Governance

## Metadata

| Field | Value |
|---|---|
| ADR ID | ADR-0001 |
| Status | Accepted |
| Created Date | 2026-10-11 |
| Decision Date | 2026-10-11 |
| Effective Date | 2026-10-11 |
| Architecture Domain | Security / Infrastructure / Supply Chain |
| Scope | SPIRE Server Kubernetes Deployment (`spire-server-k8s`) |
| Decision Owner | DevSecOps & Security Engineering |
| Named Decision Maker | DevSecOps Lead Architect |
| Approval Authority | Architecture Review Board (ARB) |
| Approval Evidence ID | ARB-SEC-2026-10-11-001 |
| APM Code(s) | APM-SEC-SPIRE-K8S |
| NIRA Reference(s) | NIRA-SUPPLY-CHAIN-2026 |
| Tags | sbom, cbom, cyclonedx, spdx, pqc, supply-chain, ast, kubernetes, spire |

---

## Business and Architecture Context

### Problem Statement

Modern workload identity infrastructures built upon SPIFFE/SPIRE manage mission-critical public key infrastructure (PKI), root CAs, intermediate CAs, and short-lived X.509 SVID credentials for Kubernetes workloads. Securing the supply chain of these deployment assets requires automated visibility into:
1. Third-party software dependencies and tool components (Software Bill of Materials / SBOM).
2. Cryptographic algorithms, key lengths, certificates, and protocol configurations (Cryptographic Bill of Materials / CBOM).
3. Call-site source code and automation script cryptographic references via Abstract Syntax Tree (AST) scanning.
4. Post-Quantum Cryptography (PQC) readiness and risk tracking against quantum computing deprecation timelines (e.g. NIST PQC standardization, CNSA 2.0).

Without automated, repeatable generation and verification in CI, cryptographic configurations drift, third-party vulnerabilities go undetected, and compliance readiness (EO 14028, NIST SSDF) cannot be verified.

### Current Situation

`spire-server-k8s` provides automated orchestration scripts, Kubernetes manifests, and KinD multi-node configurations for deploying SPIRE server, agent daemonsets, and mTLS workload identity verification. Prior to this change, dependency and cryptographic inventories were performed ad-hoc or unverified, without continuous gatekeeping or dual-engine standard alignment.

### Decision Drivers

- **Continuous Supply Chain Security:** Automated SBOM generation for both CycloneDX and SPDX standards.
- **Cryptographic Visibility & Agility:** Explicit inventory of cryptographic assets (certificates, keys, cipher suites) via CBOM.
- **Source Code Verification:** Dual-engine AST parsing across scripts and codebases to ensure all cryptographic invocations correlate with CBOM declarations.
- **PQC Readiness Governance:** Continuous identification of quantum-vulnerable cryptography (RSA, ECDSA, ECC) and tracking of migration status.
- **Regulatory & Compliance Alignment:** Compliance with Executive Order 14028, NTIA minimum elements, and NIST SP 800-218 (SSDF).
- **Zero CI Breakage & Local Ergonomics:** CLI scripts in `scripts/` matching GitHub Actions execution for local reproducibility.

---

## Assumptions

- The repository contains Kubernetes orchestration scripts (bash, Python), SPIRE configuration definitions, and PKI deployment pipelines.
- CI workflows execute on GitHub Actions runners utilizing Node 24 runtime standards and SHA-pinned actions.
- Cryptographic migration to Post-Quantum standards will follow a phased deprecation timeline, necessitating continuous visibility into CA certificates and workload SVIDs.

---

## Constraints

- CI workflows must execute within standard GitHub Actions resource limits and add negligible latency (< 2 minutes).
- Zero external SaaS dependencies: Tooling must execute locally and in CI via open-source bash, Python, Syft, and CycloneDX utilities.
- Immutability: All GitHub Actions must use immutable SHA-pinned actions compatible with Node 24.

---

## Alternatives Considered

| Option | Advantages | Disadvantages / Risks | Disposition |
|---|---|---|---|
| **Option 1: Status Quo (Ad-hoc Manual Auditing)** | Zero CI runtime overhead; no configuration files. | High security debt; zero visibility into cryptographic drift; lack of compliance audit trail. | **Rejected** |
| **Option 2: Single SBOM Engine (Syft Only)** | Simple workflow; covers standard package dependencies. | Lacks cryptographic asset mapping (no CBOM); misses AST script call sites; no PQC assessment. | **Rejected** |
| **Option 3: cbomkit-only Scanning** | Generates CycloneDX CBOM for cryptographic components. | Omits SPDX format required by procurement standards; lacks deep AST semantic script analysis. | **Rejected** |
| **Option 4: Dual-Engine SBOM/CBOM + AST Semantic Scanner + CI Test Harness (Selected)** | Full dual-format SBOM (CycloneDX + SPDX via Anchore/Syft); CycloneDX CBOM via cbomkit; semantic AST analysis (`scan_crypto_ast.py`); automated verification test harness (`test_boms.sh`); automated PQC readiness scoring (`analyze_cbom.py`); reproducible local tooling in `scripts/`. | Adds minor CI runtime (~60-90s); requires Python runtime in CI runner. | **Selected** |

---

## Decision

### Selected Option

Adopt **Option 4: Dual-Engine SBOM/CBOM + AST Semantic Scanner + CI Test Harness** across `spire-server-k8s`.

Specifically:
1. **GitHub Actions Workflow (`.github/workflows/sbom-cbom.yml`):**
   - Configured with Node 24 immutable action pins:
     - `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`
     - `anchore/sbom-action@006b7ce8314066bdf1765b4500370d40fa6917a3`
     - `cbomkit/cbomkit-action@34a3d960625ae7f7f1b59455eff93a96df090eb7`
     - `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065`
     - `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`
   - Generates CycloneDX JSON (`oss/sbom.cyclonedx.json`) and SPDX JSON (`oss/sbom.spdx.json`) SBOMs.
   - Generates CycloneDX CBOM (`oss/cbom.json`).
   - Runs `scripts/scan_crypto_ast.py` to reconcile source-level cryptographic call-sites with the generated CBOM.
   - Executes validation test harness (`scripts/test_boms.sh`).
   - Computes PQC readiness report and GitHub Actions Step Summary via `scripts/analyze_cbom.py`.
   - Synchronizes audit documentation to `docs/security/CRYPTOGRAPHIC_AUDIT.md` on `main` push events.
   - Uploads BOM artifacts to GitHub Actions with a 90-day retention window.
2. **Local Tooling Suite (`scripts/`):**
   - `scripts/generate_boms.sh`: CLI generator supporting directory (`-t dir`) and container (`-t docker`) scans.
   - `scripts/test_boms.sh`: Schema and integrity test harness.
   - `scripts/scan_crypto_ast.py`: Python AST analyzer mapping cryptographic usage.
   - `scripts/analyze_cbom.py`: PQC readiness analysis and audit report generation.
   - `scripts/attach_oci_bom.sh` & `scripts/fetch_oci_cbom.py`: OCI artifact publishing and fetching utilities.

### Rationale

SPIRE serves as the foundational root of trust for Kubernetes workload identity. By automating dual-engine SBOM generation alongside cryptographic asset modeling and AST validation, the project guarantees that all identity issuance mechanisms, cryptographic keys, upstream CAs, and dependencies are continuously inventoried and prepared for post-quantum migrations.

---

## Consequences

### Benefits

- **Comprehensive Transparency:** Continuous generation of both CycloneDX and SPDX formats meets modern enterprise and government requirements.
- **Cryptographic Visibility:** Full cataloging of certificates, key structures, and cryptographic usage in the SPIRE stack.
- **PQC Migration Readiness:** Continuous tracking of classical algorithms to accelerate migration to quantum-resistant schemes (ML-KEM, ML-DSA).
- **Gated Quality Assurance:** Automated CI testing rejects corrupted or incomplete BOM files before deployment.
- **Parity Across Environments:** Local developers can run identical checks via `scripts/generate_boms.sh` and `scripts/test_boms.sh`.

### Trade-offs and Negative Consequences

- **CI Latency:** Workflow adds ~60-90 seconds during pipeline runs.
- **Maintenance Responsibility:** Pinned action hashes and cryptographic catalogs (`known_cbom_catalog.json`) must be maintained periodically.
- **Storage Allocation:** GitHub Actions artifacts will utilize repository artifact retention storage quota.

### New Constraints

- CI environments require Python 3.11+ for running the AST parser and CBOM analysis scripts.
- GitHub Actions token requires `contents: write` permissions to synchronize `docs/security/CRYPTOGRAPHIC_AUDIT.md`.

### Follow-on Decisions and Activities

- Establish automated notifications when quantum-vulnerable algorithms are introduced into newly merged Kubernetes manifests or scripts.
- Integrate container image scanning for SPIRE server and agent images built in CI.
- Configure cryptographic attestation signing using Sigstore/Cosign for published releases.

---

## Security, Privacy, and Risk Considerations

- **Secret Sanitization:** CBOM and AST scanners inspect metadata and algorithm parameters; private keys, passwords, and tokens are never captured or exported in BOM output.
- **Immutability:** Action hashes are SHA-pinned to prevent upstream supply chain tampering.
- **Audit Compliance:** Provides verifiable artifacts aligning with NIST SP 800-218 and EO 14028.

---

## Technical Debt Assessment

- Ongoing synchronization of `known_cbom_catalog.json` with NIST PQC standardization announcements will be managed under annual security review.

---

## Review and Lifecycle

- **Review Schedule:** Annual or upon major SPIFFE/SPIRE or NIST PQC cryptographic guideline updates.
- **Supersedes:** None (Initial baseline architecture record).
- **Superseded By:** None.
