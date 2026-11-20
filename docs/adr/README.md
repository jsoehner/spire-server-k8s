# Architectural Decision Records (ADRs)

This directory contains the Architectural Decision Records (ADRs) governing `spire-server-k8s`.

## Decision Log

| ADR | Title | Status | Date | Supersedes / Superseded By |
| :--- | :--- | :--- | :--- | :--- |
| [ADR-0001](0001-automated-sbom-cbom-supply-chain-governance.md) | Automated SBOM and CBOM Supply Chain Governance | Partially Superseded | 2026-10-11 | Superseded by [ADR-0003](0003-unified-jsi-bom-actions-and-trusted-oss-governance.md) |
| [ADR-0002](0002-multi-node-kind-spire-architecture-and-traced-workload.md) | Multi-Node KinD SPIRE Architecture, RBAC Agent Attestation, and Traced SVID Workload | Accepted | 2026-11-20 | — |
| [ADR-0003](0003-unified-jsi-bom-actions-and-trusted-oss-governance.md) | Unified `jsi-bom-actions` Composite Governance & Trusted OSS Split-Horizon Registry | Accepted | 2026-11-20 | Supersedes inline CI workflow in [ADR-0001](0001-automated-sbom-cbom-supply-chain-governance.md) |

## Governance Rules

- ADRs are immutable once accepted; changes to prior decisions are recorded via new ADRs with bidirectional `Supersedes` / `Superseded By` links.
- All significant changes to Kubernetes topology, SPIRE attestation, PKI/PQC posture, or CI/CD supply chain tooling require an ADR update.
