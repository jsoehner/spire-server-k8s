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
