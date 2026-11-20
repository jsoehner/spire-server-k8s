# ADR-0003: Unified `jsi-bom-actions` Composite Governance & Trusted OSS Split-Horizon Registry

## Metadata

| Field | Value |
|---|---|
| ADR ID | ADR-0003 |
| Status | Accepted |
| Created Date | 2026-11-20 |
| Decision Date | 2026-11-20 |
| Effective Date | 2026-11-20 |
| Architecture Domain | Security / Supply Chain / DevSecOps |
| Scope | CI/CD Governance, Registry Routing, and Build Verification (`spire-server-k8s` v4.0.0) |
| Decision Owner | DevSecOps & Security Engineering |
| Named Decision Maker | DevSecOps Lead Architect |
| Approval Authority | Architecture Review Board (ARB) |
| Tags | sbom, cbom, pqc, jsi-bom-actions, dependabot, trusted-oss, build-verification |

---

## Business and Architecture Context

### Problem Statement

[ADR-0001](0001-automated-sbom-cbom-supply-chain-governance.md) established automated SBOM/CBOM generation using five separate inline GitHub Actions steps (`anchore/sbom-action`, `cbomkit/cbomkit-action`, `actions/setup-python`, local analysis scripts, and `actions/upload-artifact`). Maintaining duplicated inline workflow logic across repositories created maintenance drift, inconsistent Node 24 SHA-pinning updates, and fragmented PQC reporting.

Additionally, local and CI builds require split-horizon dependency routing through the organizational **Trusted OSS Harbor / Gatekeeper** registry (local LAN cache vs. WAN mTLS endpoint) alongside repeatable functional verification (`docs/BUILD_VERIFICATION.md`).

### Decision Drivers

- **Single Source of Truth for BOM/PQC Governance:** Consolidate SBOM (CycloneDX + SPDX), CBOM, AST cryptographic call-site scanning, and PQC readiness auditing into the shared SHA-pinned composite action `jsoehner/jsi-bom-actions`.
- **Automated Dependency Hygiene:** Keep all SHA-pinned GitHub Actions current via daily Dependabot checks (`.github/dependabot.yml`).
- **Split-Horizon Trusted OSS Routing with Strict Git Hygiene:** Route local builds via `http://oss.jsigroup.local:8080` and GitHub Actions via `https://jsigroup-oss.duckdns.org` (`mode: virtual`), while preventing `.env` or `.local` registry configs from ever being committed (`.git/info/exclude`).
- **Verification-Gated Documentation:** Require automated static, generator, Kubernetes YAML, OpenSSL PKI chain, and AST scanner verification before publishing verification reports (`docs/BUILD_VERIFICATION.md`).

---

## Alternatives Considered

| Option | Advantages | Disadvantages / Risks | Disposition |
|---|---|---|---|
| **Option 1: Keep Inline Multi-Step Workflow (ADR-0001)** | Self-contained workflow YAML in this repo. | High maintenance overhead across repos; manual SHA bumps across 5+ actions; schema/reporting drift. | **Superseded** |
| **Option 2: Unified `jsoehner/jsi-bom-actions` + Daily Dependabot + Trusted OSS + Automated Verification (Selected)** | Two-step `.github/workflows/sbom-cbom.yml` (`actions/checkout` + `jsoehner/jsi-bom-actions@v1.1.1` SHA-pinned); automated daily Dependabot PRs; centralized PQC scoring; split-horizon Trusted OSS + repeatable verification harness. | Introduces versioned dependency on `jsoehner/jsi-bom-actions` (mitigated by immutable commit SHA pinning). | **Selected** |

---

## Decision

1. **Migrate CI Workflow to `jsoehner/jsi-bom-actions`:** Replace inline Anchore/cbomkit/Python steps in `.github/workflows/sbom-cbom.yml` with SHA-pinned `jsoehner/jsi-bom-actions@8aa45737262ef8de42a6bf817080aefef03090f1` (`v1.1.1`) publishing `docs/security/CRYPTOGRAPHIC_AUDIT.md` and uploading 90-day BOM artifacts.
2. **Daily GitHub Actions Dependabot:** Maintain `.github/dependabot.yml` with daily `github-actions` update checks to keep SHA pins current and Node 24 compliant.
3. **Trusted OSS Split-Horizon Onboarding:** Configure local LAN cache (`http://oss.jsigroup.local:8080`) in git-excluded `.env` and WAN mTLS secrets (`OSS_MTLS_CLIENT_CERT`, `OSS_MTLS_CLIENT_KEY`) in GitHub Actions, enforcing `.git/info/exclude` for `.env`, `uv.toml`, `.mvn/settings.xml`, `.mvn/maven.config`, and `.npmrc`.
4. **Automated Functional Verification:** Execute **Jeffs' Automated build and deploy agent** verification protocol (syntax, isolated generator extraction, trust-domain substitution, `yaml.safe_load_all` manifest validation, OpenSSL PKI chain verification, and CBOM AST scan) and record results in `docs/BUILD_VERIFICATION.md`.

---

## Consequences

### Benefits
- **90% Reduction in Workflow Boilerplate:** `.github/workflows/sbom-cbom.yml` dropped to 40 lines while gaining unified PQC scoring and PR commenting.
- **Consistent Organizational Governance:** Updates to CBOM/PQC catalogs roll out via a single Dependabot PR per repo.
- **Zero Secret/LAN Leakage:** `.git/info/exclude` guarantees LAN `.local` URLs and `.env` never enter git history.

### Trade-offs
- Local helper scripts in `scripts/` remain available for offline/air-gapped execution and must be kept aligned with `jsi-bom-actions` schemas during major upgrades.

---

## Review and Lifecycle

- **Review Schedule:** Annual or upon major `jsoehner/jsi-bom-actions` release.
- **Supersedes:** Inline GitHub Actions workflow implementation details in [ADR-0001](0001-automated-sbom-cbom-supply-chain-governance.md).
- **Superseded By:** None.
