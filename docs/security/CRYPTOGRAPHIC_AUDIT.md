## 🛡️ Cryptographic Bill of Materials (CBOM) & PQC Migration Assessment

**Format**: CycloneDX (v1.7) | **First-Party Code Crypto Assets**: 8 | **Total Tracked Crypto Assets**: 2

### 📊 Post-Quantum Migration Scorecard

| Metric | Count | Migration Status |
|---|---|---|
| **Post-Quantum Ready (PQC)** | **0** | 🟢 Quantum-Resistant (NIST FIPS 203/204/205) |
| **Quantum-Vulnerable (Backlog)** | **0** | 🔴 At Risk of 'Harvest Now, Decrypt Later' |
| **Classical Symmetric / Digest** | **2** | 🟡 Classical Security (Requires AES-256 / SHA-256+) |
| **Asymmetric PQC Migration Progress** | **N/A (0 detected)** | (No asymmetric primitives detected in current scope) |

### 🎯 Cryptographic Supply Chain Coverage & Confidence

| Evaluation Layer | Coverage / Status | Audit Confidence Assessment |
|---|---|---|
| **First-Party Code (`src/`)** | **100% Audited** (0 Custom Primitives) | 🟢 **HIGH** (Direct AST & SAST verified clean) |
| **Third-Party Supply Chain** | **0.0%** (0 of 7 dependencies cataloged) | 🔴 LOW (Known profiles assimilated) |
| **Overall Audit Confidence Score** | **12.5%** | 🔴 LOW (7 unassimilated supply chain dependencies) |

| **System OS Inventory** | **Pending Update** | 🟡 **Warning** (Local OS crypto components not yet inventoried) |

### ✅ Post-Quantum Ready Assets

> ⚠️ **No Post-Quantum Ready assets detected.** Immediate migration planning recommended for asymmetric key exchanges and digital signatures.

### ⚠️ Quantum-Vulnerable Assets & Remediation Plan

> ℹ️ **No quantum-vulnerable asymmetric assets found.** Asymmetric cryptographic primitives were not detected in current scope.

### 🔒 Classical Symmetric & Digest Assets

| Component Name | Primitive | Key Length | Quantum Resistance Assessment | Provenance / Location(s) |
|---|---|---|---|---|
| `root.key` | unknown | N/A | Review key length for Grover resistance | First-Party Code (SAST/AST)<br>Dependencies / External |
| `intermediate.key` | unknown | N/A | Review key length for Grover resistance | First-Party Code (SAST/AST)<br>Dependencies / External |

### ⚠️ Unassimilated Third-Party Binaries & Cryptographic Blind Spots

> ℹ️ *The following third-party dependencies do not have verified upstream CBOM attestations in the catalog. They lower the audit confidence score until explicit CBOMs or attestations are published.* 

| Dependency Name | Version | Package URL (purl) | Status |
|---|---|---|---|
| `spire-server-k8s` | N/A | `N/A` | 🟡 Unassimilated (No upstream CBOM) |
| `checkout` | 3d3c42e5aac5ba805825da76410c181273ba90b1 | `pkg:github/actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` | 🟡 Unassimilated (No upstream CBOM) |
| `sbom-action` | 006b7ce8314066bdf1765b4500370d40fa6917a3 | `pkg:github/anchore/sbom-action@006b7ce8314066bdf1765b4500370d40fa6917a3` | 🟡 Unassimilated (No upstream CBOM) |
| `cbomkit-action` | 34a3d960625ae7f7f1b59455eff93a96df090eb7 | `pkg:github/cbomkit/cbomkit-action@34a3d960625ae7f7f1b59455eff93a96df090eb7` | 🟡 Unassimilated (No upstream CBOM) |
| `setup-python` | a26af69be951a213d495a4c3e4e4022e16d87065 | `pkg:github/actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065` | 🟡 Unassimilated (No upstream CBOM) |
| `upload-artifact` | ea165f8d65b6e75b540449e92b4886f43607fa02 | `pkg:github/actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` | 🟡 Unassimilated (No upstream CBOM) |
| `checkout` | v7 | `pkg:github/actions/checkout@v7` | 🟡 Unassimilated (No upstream CBOM) |
