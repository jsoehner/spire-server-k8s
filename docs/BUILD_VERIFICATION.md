# Build & Functional Verification Report

- **Repository:** `jsoehner/spire-server-k8s`
- **Version:** `v4.0.0` (`VERSION`)
- **Verification Date:** `2026-11-20`
- **Verified By:** Jeffs' Automated build and deploy agent
- **Status:** VERIFIED (Static, Generator, Manifest, PKI Chain, Infographic, ADR, and Tooling Verification)

---

## Trusted OSS Split-Horizon Configuration

Configured via `setup_trusted_oss_repo.py`:
- **Local LAN Cache:** `http://oss.jsigroup.local:8080` (health check `/healthz` returned `HTTP 200`; stored in local gitignored `.env` via `.git/info/exclude`)
- **GitHub Actions WAN URL:** `https://jsigroup-oss.duckdns.org` (mode: `virtual`)
- **mTLS Credentials:** Synced to GitHub Actions secrets (`OSS_MTLS_CLIENT_CERT`, `OSS_MTLS_CLIENT_KEY`)
- **Git Hygiene:** `.env`, `uv.toml`, `.mvn/settings.xml`, `.mvn/maven.config`, and `.npmrc` excluded in `.git/info/exclude`

---

## Stack Detection

- **Primary Artifacts:** Self-extracting Bash demo generators (`setup_demo-v3.0.sh`, `setup_demo-2node.sh`, `setup_demo-2node-web.sh` `v4.0.0`) producing Kubernetes/KinD SPIRE server, agent, RBAC, PKI, and traced workload deployment scripts
- **Languages & Formats:** Bash, Python 3, Kubernetes YAML (`kind.x-k8s.io/v1alpha4`, `v1`, `apps/v1`, `rbac.authorization.k8s.io/v1`), OpenSSL X.509 PKI, GitHub Actions YAML
- **Supply Chain Tooling:** `scripts/scan_crypto_ast.py`, `scripts/analyze_cbom.py`, `scripts/enrich_sbom_python.py`, `scripts/fetch_oci_cbom.py`, `scripts/generate_boms.sh`, `scripts/test_boms.sh`, `scripts/attach_oci_bom.sh`

---

## Verification Commands & Results

### 1. Shell, Python & JSON Syntax Verification (`-W error`)
```bash
for f in *.sh scripts/*.sh; do bash -n "$f"; done
for f in scripts/*.py; do python3 -W error -m py_compile "$f"; done
python3 -m json.tool scripts/known_cbom_catalog.json >/dev/null
```
- **Tracked Shell Scripts:** `6/6` passed `bash -n`
- **Tracked Python Scripts:** `4/4` passed `python3 -W error -m py_compile` (zero warnings)
- **Catalog JSON:** `scripts/known_cbom_catalog.json` valid JSON

### 2. Isolated Generator Extraction & Trust Domain Substitution
Executed all three top-level generator scripts in isolated `/tmp/spire-server-k8s-verify` directories with `--trusted_domain verify.local`:
- `setup_demo-v3.0.sh` -> generated `spire_k8s_demo_v3` (`3.0-orchestrate.sh`, `3.1-pki.sh`, `3.2-deploy-server.sh`, `3.3-register-agent.py`, `README.md`)
- `setup_demo-2node.sh` -> generated `spire_k8s_demo_v3.2` (`--trusted_domain verify.local` replaced all `example.org` references)
- `setup_demo-2node-web.sh` (`v4.0.0`) -> generated `spire_k8s_demo_v4.0` including `3.4-deploy-workload.py` (`--trusted_domain verify.local` replaced all `example.org` references)
- **Generated Shell Scripts:** `9/9` passed `bash -n`
- **Generated Python Scripts:** `4/4` passed `python3 -W error -m py_compile` with **zero `SyntaxWarning`** (resolved prior `"\;"` escape warning in `3.4-deploy-workload.py`), plus embedded `workload.py` HTTP server passed `ast.parse`

### 3. Kubernetes & Workflow YAML Validation (`yaml.safe_load_all`)
Validated all embedded Kubernetes YAML documents across all three variants plus `.github/workflows/*.yml`:
- **Kubernetes Manifests:** `22/22` valid YAML documents
  - `3×` `kind.x-k8s.io/v1alpha4` `Cluster` (1-node in v3.0; 2-node control-plane + worker in v3.2/v4.0)
  - `3×` `v1` `ConfigMap` (`spire-server-conf`), `3×` `v1` `Service` (`spire-server`), `3×` `apps/v1` `StatefulSet` (`spire-server`)
  - `3×` `v1` `ConfigMap` (`spire-agent-conf`), `3×` `apps/v1` `DaemonSet` (`spire-agent`)
  - `1×` `v1` `ServiceAccount` (`spire-agent`), `1×` `rbac.authorization.k8s.io/v1` `ClusterRole` (`spire-agent-cluster-role`), `1×` `ClusterRoleBinding` (`spire-agent-cluster-role-binding`)
  - `1×` `apps/v1` `Deployment` (`spire-workload`)
- **GitHub Actions Workflows:** `2/2` valid YAML (`blank.yml`, `sbom-cbom.yml`)

### 4. OpenSSL PKI Bootstrap Verification (`3.1-pki.sh`)
Executed generated `v4.0.0` `3.1-pki.sh all create --force` in an isolated temp directory with a non-destructive `kubectl` shim:
- Generated 4096-bit RSA Root CA (`C=US, O=SPIRE Demo, CN=SPIRE Root CA`)
- Generated 2048-bit RSA Intermediate CA (`C=US, O=SPIRE Demo, CN=SPIRE Intermediate CA`, `basicConstraints=CA:TRUE,pathlen:1`) and `chain.crt`
- Verified certificate chain: `openssl verify -CAfile pki/root/root.crt pki/intermediate/intermediate.crt` -> **`OK`**

### 5. CBOM AST Scanner Smoke Test
```bash
python3 scripts/scan_crypto_ast.py . --output-json /tmp/spire-server-k8s-verify/cbom-ast.json
```
- Exited `0` with valid JSON output and full CBOM reconciliation.

---

## Notes & Environment Scope

- `kind` and `kubectl` were not installed on the verification host, so live KinD cluster creation (`kind create cluster`) and pod runtime deployment were not executed; all generator extraction, syntax (`-W error`), manifest YAML, OpenSSL PKI chain, and governance script checks passed in isolation without mutating any cluster or host containers.
- Temporary verification directories (`/tmp/spire-server-k8s-verify`, `/tmp/pycache-spire`) were removed after verification.
