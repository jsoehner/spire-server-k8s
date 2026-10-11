Clone this repo and ensure you have KinD installed.
Run any one of three setup scripts and the necessary files are created.


(spire2) ➜  spire-server-k8s git:(main) ./setup_demo-2node-web.sh --trusted_domain scotiabank.local  --reset 
📂 Creating project directory: spire_k8s_demo_v3.3...
🔧 Configuration:
   - Trust Domain: scotiabank.local
   - Architecture: 2-Node (Control Plane + Worker)
   - Version:      v3.3 (Write-to-Disk Fix)
   - Capability:   Deep Tracing Enabled
📝 Generating 3.0-orchestrate.sh...
📝 Generating 3.1-pki.sh...
📝 Generating 3.2-deploy-server.sh...
📝 Generating 3.3-register-agent.py...
📝 Generating 3.4-deploy-workload.py...
🔧 Replacing 'example.org' with 'scotiabank.local' in all files...
✅ Package v3.3 (Write-to-Disk Fix) created in: spire_k8s_demo_v3.3
🚀 Running Master Orchestrator...
🚀 Starting 2-Node SPIRE Kubernetes Demo (v3.3)...
🧹 Tearing down existing cluster...
Deleting cluster "spire-demo" ...
Deleted nodes: ["spire-demo-worker" "spire-demo-control-plane"]
No kind clusters found.
📦 Creating 2-Node Kubernetes Cluster (Kind)...
Creating cluster "spire-demo" ...
 ✓ Ensuring node image (kindest/node:v1.35.0) 🖼
 ✓ Preparing nodes 📦 📦  
 ✓ Writing configuration 📜 
 ✓ Starting control-plane 🕹️ 
 ✓ Installing CNI 🔌 
 ✓ Installing StorageClass 💾 
 ✓ Joining worker nodes 🚜 
Set kubectl context to "kind-spire-demo"
You can now use your cluster with:

kubectl cluster-info --context kind-spire-demo

Have a question, bug, or feature request? Let us know! https://kind.sigs.k8s.io/#community 🙂
🔐 Initializing PKI...
namespace/spire created
   [PKI] Generating Root CA...
.....+.......+.....+.+...+..+...+............+............+.+.....+.+++++++++++++++++++++++++++++++++++++++++++++*.....+...+..+...+...+.......+.....+......+.....................+.............+...+..+...+++++++++++++++++++++++++++++++++++++++++++++*...+...+..+....+...+......+..+...............+...+..........+.....+...............+....+............+.......................+.+...............+..+.......+........+.....................................+............+...+..+.........+..........+..+.......+++++
.......+..+...+.+...+........+...+.+...........+.......+.....+...+....+.....+................+...+.....+......+...+.+++++++++++++++++++++++++++++++++++++++++++++*...+........+...+...+.+........+......+......+.........+....+...+.........+...+...+........+....+..+......+....+.........+..............+...+...+....+..+....+............+..+...+...+++++++++++++++++++++++++++++++++++++++++++++*.....+........+...+..........+.....+.......+......+...............+.........+.....+......+....+...+........+......................+.........+...+......+.................+.........+......+...+.+......+.........+......+..+...............+......+................+...+...........+....+..+....+..............+...+...................+........+..................+...+.......+........+.+.......................+...............+.+.........+...+.....+...+....+..................+........+....+..+..........+.....+....+..+............+.....................+.+++++
-----
   [PKI] Generating Intermediate CA...
.+...+...+...+++++++++++++++++++++++++++++++++++++++*.......+.....+...+.........+++++++++++++++++++++++++++++++++++++++*.......+...+........................+...+..........+...+.........+..+.+..+............+...+.+......+.....+.+.........+...+...........+....+...+..+...+...............++++++
........+........+++++++++++++++++++++++++++++++++++++++*.+..........+......+...+...........+......+.........+...+......+.+...+............+...+..+...............+.+.....+...+++++++++++++++++++++++++++++++++++++++*...........+...+...+.........+.+............+.....+...................+...+...............+..+......+.......+......+..+...+.+.........+...........+.+..+.+...........+.+..+...+...+.......+..+................+.....+............+.........+...+......+.+...........+...+.+......+..+.......+.....+....+......+...+..+.+........+....+...+...+...........+.+..............+.........+..........+......+...+...+...+.....+......+....+.........+...........+............+..........+...+......+........+...+...+.++++++
-----
Certificate request self-signature ok
subject=C=US, O=SPIRE Demo, CN=SPIRE Intermediate CA
   [PKI] Syncing PKI to Kubernetes...
secret/spire-upstream-ca created
configmap/spire-bundle created
☁️  Deploying SPIRE Server...
namespace/spire unchanged
configmap/spire-server-conf created
service/spire-server created
statefulset.apps/spire-server created
Waiting for 1 pods to be ready...
partitioned roll out complete: 1 new pods have been updated...
pod/spire-server-0 condition met
🤝 Registering Agent (RBAC Enabled)...

🔍 Locating SPIRE Server Pod...

🏥 Waiting for SPIRE Server Health...
   ✅ Server is healthy.

🎟️  Generating Join Token...

💾 Creating 'spire-agent-token' Secret...

🛡️  Applying RBAC for Agent...

🚀 Deploying SPIRE Agent DaemonSet...

⏳ Waiting for Agent to Register...
✅ Agent Registered and Running.
🌐 Deploying Traced Workload...
/Users/jsoehner/spire-server-k8s/spire_k8s_demo_v3.3/3.4-deploy-workload.py:176: SyntaxWarning: "\;" is an invalid escape sequence. Such sequences will not work in the future. Did you mean "\\;"? A raw string is also an option.
  """

🔍 Registering Workload Entry...
Exec: kubectl -n spire get pod -l app=spire-server -o jsonpath='{.items[0].metadata.name}'
Exec: kubectl -n spire exec spire-server-0 -- /opt/spire/bin/spire-server entry create \
        -spiffeID spiffe://scotiabank.local/workload/web-server \
        -parentID spiffe://scotiabank.local/agent/k8s-node \
        -selector k8s:ns:default \
        -selector k8s:sa:default \
        -socketPath /tmp/spire-server/private/api.sock
   ✅ Registered: spiffe://scotiabank.local/workload/web-server

📝 Creating Traced Workload Script (ConfigMap)...
Exec: kubectl delete configmap workload-script --ignore-not-found=true
Exec: kubectl create configmap workload-script --from-file=workload.py=internal_script.py
Exec: rm internal_script.py

🚀 Deploying Traced Workload Pod...
Exec: kubectl apply -f workload-gen.yaml

⏳ Waiting for Workload to be Ready...
Exec: kubectl rollout status deployment/spire-workload --timeout=120s
✅ Workload Deployed.
🎉 Demo Environment Ready!
📊 Tailing Workload Logs for Trace Output...
Defaulted container "web-server" out of: web-server, binary-downloader (init)
(1/1) Installing openssl (3.5.5-r0)
Executing busybox-1.37.0-r30.trigger
OK: 15.7 MiB in 39 packages
[TRACE] 12:31:19 | 🚀 Workload Started. Initializing Identity Loop...
[TRACE] 12:31:19 | 🔌 Connecting to SPIRE Agent Socket: /run/spire/sockets/agent.sock
[TRACE] 12:31:19 | ✅ RESPONSE RECEIVED: Identity fetched.
[TRACE] 12:31:19 | 📄 Reading SVID from: /tmp/certs/svid.0.pem
subject=C=US, O=SPIRE, x500UniqueIdentifier=24d6d4051a9a9ae5214b7c440172ca66
issuer=C=US, O=SPIRE Demo
notBefore=Feb 15 12:31:00 2026 GMT
notAfter=Feb 15 13:31:10 2026 GMT
X509v3 Subject Alternative Name: 
    URI:spiffe://scotiabank.local/workload/web-server

[TRACE] 12:31:19 | 🌍 Starting Web Server on Port 8000...



## 🛡️ Security & Cryptographic Posture

This project tracks Software & Cryptographic Bill of Materials (SBOM & CBOM) and Post-Quantum Cryptography (PQC) readiness. See the latest [Cryptographic Audit & PQC Migration Report](docs/security/CRYPTOGRAPHIC_AUDIT.md).

---

## Automated SBOM & CBOM Supply Chain Pipeline

This repository features an automated Software and Cryptographic Bill of Materials (SBOM & CBOM) pipeline ensuring comprehensive software supply chain transparency, continuous cryptographic posture visibility, and Post-Quantum Cryptography (PQC) readiness.

### CI Pipeline Overview (`.github/workflows/sbom-cbom.yml`)

The continuous integration workflow triggers on push and pull request events to `main` and `master` branches, as well as version tags and manual dispatches:

1. **Dual-Format SBOM Generation:** Employs Anchore / Syft to produce both CycloneDX JSON (`oss/sbom.cyclonedx.json`) and SPDX JSON (`oss/sbom.spdx.json`) dependency inventories.
2. **CBOM Generation:** Leverages `cbomkit` to generate a CycloneDX Cryptographic Bill of Materials (`oss/cbom.json`) identifying cryptographic algorithms, key assets, and digital certificates.
3. **Semantic AST Cryptographic Scan & Reconciliation:** Runs `scripts/scan_crypto_ast.py` to parse repository source files and scripts via Python AST, mapping cryptographic call-sites to CBOM declarations.
4. **Automated Verification & Test Harness:** Executes `scripts/test_boms.sh` in CI to enforce schema validity, JSON formatting, and minimum component inventory thresholds.
5. **PQC Migration Readiness Assessment:** Analyzes cryptographic assets with `scripts/analyze_cbom.py` to highlight classical/quantum-vulnerable algorithms and publish summaries directly to GitHub Actions Job Summaries.
6. **Continuous Cryptographic Audit Documentation:** Automatically synchronizes findings into `docs/security/CRYPTOGRAPHIC_AUDIT.md`.
7. **Artifact Archival:** Stores all generated BOM artifacts in GitHub Actions with a 90-day retention policy.

### Local Development & Verification Tooling

Developers and security engineers can run the entire SBOM/CBOM pipeline locally using the standalone scripts in `scripts/`:

#### 1. Generating SBOM & CBOM Artifacts (`scripts/generate_boms.sh`)

Generate dual-engine bills of materials for the repository directory or container images:

```bash
# Scan repository directory (outputs to oss/)
bash scripts/generate_boms.sh -t dir .

# Scan a container image
bash scripts/generate_boms.sh -t docker spire-server-k8s:local

# Custom output directory and format
bash scripts/generate_boms.sh -t dir -o build/boms -f cyclonedx-json .
```

#### 2. Running Verification & Test Harness (`scripts/test_boms.sh`)

Validate generated BOM artifacts against strict schema and integrity checks:

```bash
bash scripts/test_boms.sh oss
```

#### 3. Semantic AST Cryptographic Analysis (`scripts/scan_crypto_ast.py`)

Scan repository source code AST for cryptographic primitive invocations and reconcile with an existing CBOM:

```bash
python3 scripts/scan_crypto_ast.py . \
  --cbom oss/cbom.json \
  --output-json oss/crypto-callsites.json
```

#### 4. PQC Readiness Analysis (`scripts/analyze_cbom.py`)

Evaluate cryptographic posture and generate Markdown or JSON assessment reports:

```bash
python3 scripts/analyze_cbom.py oss/cbom.json \
  --sbom oss/sbom.cyclonedx.json \
  --json oss/crypto-analysis.json \
  --markdown docs/security/CRYPTOGRAPHIC_AUDIT.md
```

#### 5. OCI Artifact Management (`scripts/attach_oci_bom.sh` & `scripts/fetch_oci_cbom.py`)

Publish and fetch cryptographic bills of materials directly to/from OCI container registries:

```bash
# Attach CBOM to container image
bash scripts/attach_oci_bom.sh oss/cbom.json my-registry.io/spire-server-k8s:v1.0.0

# Retrieve CBOM from container image
python3 scripts/fetch_oci_cbom.py my-registry.io/spire-server-k8s:v1.0.0 --output-dir oss
```

---

## Architectural Decision Records (ADRs)

Key architectural decisions governing this repository's security, supply chain, and cryptography strategy are documented under [`docs/adr/`](docs/adr/):

- [**ADR-0001: Automated SBOM and CBOM Supply Chain Governance**](docs/adr/0001-automated-sbom-cbom-supply-chain-governance.md) - Context, alternatives considered, decision rationale, and downstream consequences for adopting automated dual-engine SBOM/CBOM scanning, AST call-site analysis, and CI gate verification.

