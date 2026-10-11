# Architecture Overview

This project is a SPIRE server implementation for Kubernetes.

## Components
- SPIRE Server
- Kubernetes Integration
- Identity Provider

## Data Flow
...

## Software Bill of Materials (SBOM) & Cryptographic Bill of Materials (CBOM)

The project now includes automated SBOM and CBOM generation to ensure security compliance and supply chain transparency.

### Overview
- **SBOM**: Provides a comprehensive list of all software components, licenses, and dependencies.
- **CBOM**: Specifically identifies cryptographic algorithms, keys, and certificates used within the system.

### Workflow
1. **Generation**: Triggered via GitHub Actions using sbom-cbom.yml. It uses nchore/sbom-action and cbomkit/cbomkit-action to generate artifacts.
2. **Analysis**: The scripts/analyze_cbom.py script provides a cryptographic audit report, calculating PQC migration progress and identifying quantum-vulnerable primitives.
3. **Verification**: The scripts/test_boms.sh harness validates the integrity of generated artifacts before they are published.

### Artifacts
- **Location**: All artifacts are stored in the oss/ directory.
- **Publication**: Artifacts are uploaded as GitHub Action artifacts and can be published as OCI artifacts for distribution.

### Audit Report
The full cryptographic audit report can be found in docs/security/CRYPTOGRAPHIC_AUDIT.md, which is automatically updated during the CI/CD process.

---

## ADRs Related to SBOM/CBOM
- [0016-SBOM-CBOM-Implementation](docs/adr/0016-SBOM-CBOM-Implementation.md)
