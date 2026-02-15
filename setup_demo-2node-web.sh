#!/bin/bash
set -euo pipefail

# --- Defaults ---
TRUST_DOMAIN="example.org"
RESET_FLAG=""
NEWROOT_FLAG=""
PROJECT_DIR="spire_k8s_demo_v3.3"

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --trusted_domain)
      TRUST_DOMAIN="$2"
      shift 2
      ;;
    --reset)
      RESET_FLAG="--reset"
      shift
      ;;
    --newroot)
      NEWROOT_FLAG="--newroot"
      shift
      ;;
    *)
      echo "❌ Unknown argument: $1"
      echo "Usage: $0 [--trusted_domain <domain>] [--reset] [--newroot]"
      exit 1
      ;;
  esac
done

echo "📂 Creating project directory: ${PROJECT_DIR}..."
mkdir -p "${PROJECT_DIR}"
cd "${PROJECT_DIR}"

echo "🔧 Configuration:"
echo "   - Trust Domain: ${TRUST_DOMAIN}"
echo "   - Architecture: 2-Node (Control Plane + Worker)"
echo "   - Version:      v3.3 (Write-to-Disk Fix)"
echo "   - Capability:   Deep Tracing Enabled"

# --- 1. Create 3.0-orchestrate.sh ---
echo "📝 Generating 3.0-orchestrate.sh..."
cat << 'EOF' > 3.0-orchestrate.sh
#!/usr/bin/env bash
set -euo pipefail

RESET=0
NEWROOT=0
SHOW_LOGS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --newroot) NEWROOT=1; shift ;;
    --logs) SHOW_LOGS=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

echo "🚀 Starting 2-Node SPIRE Kubernetes Demo (v3.3)..."

command -v kind >/dev/null 2>&1 || { echo >&2 "❌ Error: 'kind' is not installed."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo >&2 "❌ Error: 'kubectl' is not installed."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo >&2 "❌ Error: 'python3' is not installed."; exit 1; }

if [[ "${RESET}" -eq 1 ]]; then
  echo "🧹 Tearing down existing cluster..."
  kind delete cluster --name spire-demo || true
  rm -rf ./pki
fi

if ! kind get clusters | grep -q "spire-demo"; then
  echo "📦 Creating 2-Node Kubernetes Cluster (Kind)..."
  cat <<KIND_CONFIG | kind create cluster --name spire-demo --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/run/docker.sock
    containerPath: /var/run/docker.sock
- role: worker
  extraMounts:
  - hostPath: /var/run/docker.sock
    containerPath: /var/run/docker.sock
KIND_CONFIG
else
  echo "✅ Cluster 'spire-demo' already running."
fi

echo "🔐 Initializing PKI..."
ARGS=""
if [[ "${NEWROOT}" -eq 1 ]]; then ARGS="--force"; fi
./3.1-pki.sh all create $ARGS

echo "☁️  Deploying SPIRE Server..."
./3.2-deploy-server.sh

echo "🤝 Registering Agent (RBAC Enabled)..."
python3 3.3-register-agent.py

echo "🌐 Deploying Traced Workload..."
python3 3.4-deploy-workload.py

echo "🎉 Demo Environment Ready!"
echo "📊 Tailing Workload Logs for Trace Output..."
kubectl logs -f deploy/spire-workload
EOF

# --- 2. Create 3.1-pki.sh ---
echo "📝 Generating 3.1-pki.sh..."
cat << 'EOF' > 3.1-pki.sh
#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="./pki"
ROOT_DIR="${BASE_DIR}/root"
INT_DIR="${BASE_DIR}/intermediate"
mkdir -p "${ROOT_DIR}" "${INT_DIR}"

ROOT_TTL_DAYS=3650
INT_TTL_DAYS=365
K8S_NAMESPACE="spire"

kubectl create namespace "${K8S_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

generate_root() {
    if [[ -f "${ROOT_DIR}/root.key" ]] && [[ "$1" != "--force" ]]; then return; fi
    echo "   [PKI] Generating Root CA..."
    openssl req -x509 -newkey rsa:4096 -keyout "${ROOT_DIR}/root.key" -out "${ROOT_DIR}/root.crt" \
        -days "${ROOT_TTL_DAYS}" -nodes -subj "/C=US/O=SPIRE Demo/CN=SPIRE Root CA"
}

generate_intermediate() {
    if [[ -f "${INT_DIR}/intermediate.key" ]] && [[ "$1" != "--force" ]]; then return; fi
    echo "   [PKI] Generating Intermediate CA..."
    openssl req -newkey rsa:2048 -keyout "${INT_DIR}/intermediate.key" -out "${INT_DIR}/intermediate.csr" \
        -nodes -subj "/C=US/O=SPIRE Demo/CN=SPIRE Intermediate CA"
    
    openssl x509 -req -in "${INT_DIR}/intermediate.csr" -CA "${ROOT_DIR}/root.crt" -CAkey "${ROOT_DIR}/root.key" \
        -CAcreateserial -out "${INT_DIR}/intermediate.crt" -days "${INT_TTL_DAYS}" -sha256 -extfile <(printf "basicConstraints=CA:TRUE,pathlen:1")
    
    cat "${INT_DIR}/intermediate.crt" "${ROOT_DIR}/root.crt" > "${INT_DIR}/chain.crt"
}

sync_secrets() {
    echo "   [PKI] Syncing PKI to Kubernetes..."
    if [[ -f "${INT_DIR}/chain.crt" ]]; then
        kubectl -n "${K8S_NAMESPACE}" create secret generic spire-upstream-ca \
            --from-file=upstream_ca.crt="${INT_DIR}/chain.crt" \
            --from-file=upstream_ca.key="${INT_DIR}/intermediate.key" \
            --dry-run=client -o yaml | kubectl apply -f -
    fi
    if [[ -f "${ROOT_DIR}/root.crt" ]]; then
         kubectl -n "${K8S_NAMESPACE}" create configmap spire-bundle \
            --from-file=bootstrap.crt="${ROOT_DIR}/root.crt" \
            --dry-run=client -o yaml | kubectl apply -f -
    fi
}

generate_root "${3:-}"
generate_intermediate "${3:-}"
sync_secrets
EOF

# --- 3. Create 3.2-deploy-server.sh ---
echo "📝 Generating 3.2-deploy-server.sh..."
cat << 'EOF' > 3.2-deploy-server.sh
#!/usr/bin/env bash
set -euo pipefail

kubectl create namespace spire --dry-run=client -o yaml | kubectl apply -f -

cat <<YAML | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-server-conf
  namespace: spire
data:
  server.conf: |
    server {
      bind_address = "0.0.0.0"
      bind_port = "8081"
      socket_path = "/tmp/spire-server/private/api.sock"
      trust_domain = "example.org"
      data_dir = "/run/spire/data"
      log_level = "DEBUG"
      ca_subject = {
        country = ["US"],
        organization = ["SPIRE Demo"],
        common_name = "",
      }
    }
    plugins {
      DataStore "sql" {
        plugin_data {
          database_type = "sqlite3"
          connection_string = "/run/spire/data/datastore.sqlite3"
        }
      }
      NodeAttestor "join_token" {
        plugin_data {}
      }
      KeyManager "disk" {
        plugin_data {
          keys_path = "/run/spire/data/keys.json"
        }
      }
      UpstreamAuthority "disk" {
        plugin_data {
          cert_file_path = "/run/spire/upstream/upstream_ca.crt"
          key_file_path = "/run/spire/upstream/upstream_ca.key"
          bundle_file_path = "/run/spire/upstream/upstream_ca.crt"
        }
      }
    }
---
apiVersion: v1
kind: Service
metadata:
  name: spire-server
  namespace: spire
spec:
  ports:
    - name: grpc
      port: 8081
      targetPort: 8081
      protocol: TCP
  selector:
    app: spire-server
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: spire-server
  namespace: spire
spec:
  replicas: 1
  selector:
    matchLabels:
      app: spire-server
  serviceName: spire-server
  template:
    metadata:
      labels:
        app: spire-server
    spec:
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
        - key: "node-role.kubernetes.io/control-plane"
          operator: "Exists"
          effect: "NoSchedule"
        - key: "node-role.kubernetes.io/master"
          operator: "Exists"
          effect: "NoSchedule"
      containers:
        - name: spire-server
          image: ghcr.io/spiffe/spire-server:1.5.1
          args: ["-config", "/run/spire/config/server.conf"]
          ports:
            - containerPort: 8081
          volumeMounts:
            - name: server-config
              mountPath: /run/spire/config
              readOnly: true
            - name: server-data
              mountPath: /run/spire/data
            - name: upstream-ca
              mountPath: /run/spire/upstream
              readOnly: true
            - name: server-socket
              mountPath: /tmp/spire-server/private
      volumes:
        - name: server-config
          configMap:
            name: spire-server-conf
        - name: server-data
          hostPath:
            path: /tmp/spire-data
            type: DirectoryOrCreate
        - name: upstream-ca
          secret:
            secretName: spire-upstream-ca
        - name: server-socket
          emptyDir: {}
YAML

kubectl -n spire rollout status statefulset/spire-server --timeout=90s
kubectl -n spire wait --for=condition=Ready pod/spire-server-0 --timeout=60s
EOF

# --- 4. Create 3.3-register-agent.py ---
echo "📝 Generating 3.3-register-agent.py..."
cat << 'EOF' > 3.3-register-agent.py
#!/usr/bin/env python3
import subprocess, sys, time, re

SOCKET_PATH = "/tmp/spire-server/private/api.sock"
TRUST_DOMAIN = "example.org"

def run_cmd(cmd, check=True):
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and result.returncode != 0: raise Exception(result.stderr)
    return result

def main():
    print("\n🔍 Locating SPIRE Server Pod...")
    try:
        pod_name = run_cmd("kubectl -n spire get pod -l app=spire-server -o jsonpath='{.items[0].metadata.name}'").stdout.strip()
    except Exception as e:
        print(f"❌ Error locating pod: {e}"); sys.exit(1)

    print("\n🏥 Waiting for SPIRE Server Health...")
    for i in range(12):
        res = run_cmd(f"kubectl -n spire exec {pod_name} -- /opt/spire/bin/spire-server healthcheck -socketPath {SOCKET_PATH}", check=False)
        if res.returncode == 0 and "Server is healthy" in res.stdout:
            print("   ✅ Server is healthy."); break
        time.sleep(5)
    else:
        print("\n❌ Timeout."); sys.exit(1)

    print("\n🎟️  Generating Join Token...")
    agent_id = f"spiffe://{TRUST_DOMAIN}/agent/k8s-node"
    cmd_res = run_cmd(f"kubectl -n spire exec {pod_name} -- /opt/spire/bin/spire-server token generate -spiffeID {agent_id} -socketPath {SOCKET_PATH}")
    token = re.search(r"Token:\s+([a-f0-9-]+)", cmd_res.stdout).group(1)
    
    print("\n💾 Creating 'spire-agent-token' Secret...")
    run_cmd("kubectl -n spire delete secret spire-agent-token --ignore-not-found=true", check=False)
    run_cmd(f"kubectl -n spire create secret generic spire-agent-token --from-literal=join_token={token}")

    print("\n🛡️  Applying RBAC for Agent...")
    rbac_manifest = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spire-agent
  namespace: spire
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-agent-cluster-role
rules:
- apiGroups: [""]
  resources: ["pods", "nodes", "nodes/proxy"]
  verbs: ["get", "list", "watch"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-agent-cluster-role-binding
subjects:
- kind: ServiceAccount
  name: spire-agent
  namespace: spire
roleRef:
  kind: ClusterRole
  name: spire-agent-cluster-role
  apiGroup: rbac.authorization.k8s.io
"""
    with open("agent-rbac.yaml", "w") as f: f.write(rbac_manifest)
    run_cmd("kubectl apply -f agent-rbac.yaml")

    print("\n🚀 Deploying SPIRE Agent DaemonSet...")
    manifest = f"""
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-agent-conf
  namespace: spire
data:
  agent.conf: |
    agent {{
      data_dir = "/run/spire/data"
      log_level = "DEBUG"
      server_address = "spire-server"
      server_port = "8081"
      socket_path = "/run/spire/sockets/agent.sock"
      trust_bundle_path = "/run/spire/config/bootstrap.crt"
      trust_domain = "{TRUST_DOMAIN}"
      join_token = "TOKEN_PLACEHOLDER"
    }}
    plugins {{
      NodeAttestor "join_token" {{ plugin_data {{}} }}
      KeyManager "disk" {{ plugin_data {{ directory = "/run/spire/data" }} }}
      WorkloadAttestor "k8s" {{ plugin_data {{ skip_kubelet_verification = true }} }}
      WorkloadAttestor "docker" {{ plugin_data {{}} }}
    }}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spire-agent
  namespace: spire
spec:
  selector:
    matchLabels:
      app: spire-agent
  template:
    metadata:
      labels:
        app: spire-agent
    spec:
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      serviceAccountName: spire-agent
      containers:
        - name: spire-agent
          image: ghcr.io/spiffe/spire-agent:1.5.1
          args: ["-config", "/run/spire/config/agent.conf"]
          volumeMounts:
            - name: agent-config
              mountPath: /run/spire/config
            - name: agent-token
              mountPath: /run/spire/secret
              readOnly: true
            - name: agent-socket
              mountPath: /run/spire/sockets
            - name: docker-sock
              mountPath: /var/run/docker.sock
            - name: kubelet-socket
              mountPath: /var/run/cri/cri.sock
      initContainers:
        - name: config-injector
          image: busybox
          command: ['sh', '-c', 'cp /config/agent.conf /run/spire/config/agent.conf && cp /bundle/bootstrap.crt /run/spire/config/bootstrap.crt && sed -i "s|TOKEN_PLACEHOLDER|$(cat /secret/join_token)|" /run/spire/config/agent.conf']
          volumeMounts:
            - name: agent-config-map
              mountPath: /config
            - name: agent-token
              mountPath: /secret
            - name: agent-config
              mountPath: /run/spire/config
            - name: agent-bundle
              mountPath: /bundle
      volumes:
        - name: agent-config-map
          configMap:
            name: spire-agent-conf
            items: [ {{ key: agent.conf, path: agent.conf }} ]
        - name: agent-config
          emptyDir: {{}}
        - name: agent-token
          secret: {{ secretName: spire-agent-token }}
        - name: agent-socket
          hostPath: {{ path: /run/spire/sockets, type: DirectoryOrCreate }}
        - name: docker-sock
          hostPath: {{ path: /var/run/docker.sock }}
        - name: kubelet-socket
          hostPath: {{ path: /run/containerd/containerd.sock }}
        - name: agent-bundle
          configMap: {{ name: spire-bundle }}
"""
    with open("spire-agent-gen.yaml", "w") as f: f.write(manifest)
    run_cmd("kubectl apply -f spire-agent-gen.yaml")
    print("\n⏳ Waiting for Agent to Register...")
    run_cmd("kubectl -n spire rollout status daemonset/spire-agent")
    print("✅ Agent Registered and Running.")

if __name__ == "__main__":
    main()
EOF

# --- 5. Create 3.4-deploy-workload.py ---
echo "📝 Generating 3.4-deploy-workload.py..."
cat << 'EOF' > 3.4-deploy-workload.py
#!/usr/bin/env python3
import subprocess, sys, time, re, os

TRUST_DOMAIN = "example.org"
NAMESPACE = "default"

def run_cmd(cmd, check=True):
    print(f"Exec: {cmd}")
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and result.returncode != 0: raise Exception(result.stderr)
    return result

def main():
    print("\n🔍 Registering Workload Entry...")
    try:
        pod_name = run_cmd("kubectl -n spire get pod -l app=spire-server -o jsonpath='{.items[0].metadata.name}'").stdout.strip()
    except Exception as e:
        print(f"❌ Error locating server pod: {e}"); sys.exit(1)

    workload_spiffe_id = f"spiffe://{TRUST_DOMAIN}/workload/web-server"
    parent_id = f"spiffe://{TRUST_DOMAIN}/agent/k8s-node"

    cmd = f"""kubectl -n spire exec {pod_name} -- /opt/spire/bin/spire-server entry create \\
        -spiffeID {workload_spiffe_id} \\
        -parentID {parent_id} \\
        -selector k8s:ns:{NAMESPACE} \\
        -selector k8s:sa:default \\
        -socketPath /tmp/spire-server/private/api.sock"""
    
    res = run_cmd(cmd, check=False)
    if res.returncode != 0 and "already exists" not in res.stdout:
        print(f"❌ Registration failed: {res.stderr}"); sys.exit(1)
    
    print(f"   ✅ Registered: {workload_spiffe_id}")

    print("\n📝 Creating Traced Workload Script (ConfigMap)...")
    workload_script = """
import time, subprocess, sys, os, glob
from http.server import SimpleHTTPRequestHandler, HTTPServer

def log(msg):
    print(f"[TRACE] {time.strftime('%H:%M:%S')} | {msg}", flush=True)

def fetch_svid():
    log("🔌 Connecting to SPIRE Agent Socket: /run/spire/sockets/agent.sock")
    certs_dir = "/tmp/certs"
    
    # Clean previous run
    if not os.path.exists(certs_dir): os.makedirs(certs_dir)
    
    # Use -write to force file generation (Avoids stdout parsing issues)
    cmd = ["/opt/spire/bin/spire-agent", "api", "fetch", "x509", 
           "-socketPath", "/run/spire/sockets/agent.sock",
           "-write", certs_dir]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            log("✅ RESPONSE RECEIVED: Identity fetched.")
            
            # Find the SVID file (usually svid.0.pem)
            svid_files = glob.glob(f"{certs_dir}/svid.*.pem")
            if not svid_files:
                log("⚠️ Error: SVID file not found in output directory.")
                return False
                
            svid_path = svid_files[0]
            log(f"📄 Reading SVID from: {svid_path}")
            
            # Pass file directly to OpenSSL
            cmd_ssl = ["openssl", "x509", "-in", svid_path, "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"]
            ssl_res = subprocess.run(cmd_ssl, capture_output=True, text=True)
            
            if ssl_res.returncode == 0:
                print(ssl_res.stdout, flush=True)
                return True
            else:
                log(f"⚠️ OpenSSL scan failed: {ssl_res.stderr}")
                return False
        else:
            log(f"❌ FETCH FAILED: {result.stderr.strip()}")
            return False

    except Exception as e:
        log(f"❌ ERROR: {e}")
        return False

log("🚀 Workload Started. Initializing Identity Loop...")
while True:
    if fetch_svid(): break
    log("... Identity not yet available. Retrying in 5s ...")
    time.sleep(5)

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Hello! I am an authenticated SPIRE workload.")

log("🌍 Starting Web Server on Port 8000...")
httpd = HTTPServer(('0.0.0.0', 8000), Handler)
httpd.serve_forever()
"""

    run_cmd(f"kubectl delete configmap workload-script --ignore-not-found=true")
    with open("internal_script.py", "w") as f: f.write(workload_script)
    run_cmd(f"kubectl create configmap workload-script --from-file=workload.py=internal_script.py")
    run_cmd("rm internal_script.py")

    print("\n🚀 Deploying Traced Workload Pod...")
    manifest = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: spire-workload
  namespace: {NAMESPACE}
  labels:
    app: spire-workload
spec:
  replicas: 1
  selector:
    matchLabels:
      app: spire-workload
  template:
    metadata:
      labels:
        app: spire-workload
    spec:
      serviceAccountName: default
      initContainers:
        - name: binary-downloader
          image: alpine:3.18
          command: ["/bin/sh", "-c"]
          args:
            - |
              echo "⬇️ Detecting Architecture..."
              ARCH=$(uname -m)
              if [ "$ARCH" = "aarch64" ]; then SPIRE_ARCH="arm64"; else SPIRE_ARCH="amd64"; fi
              echo "⬇️ Downloading SPIRE Agent for $SPIRE_ARCH..."
              wget -qO spire.tar.gz https://github.com/spiffe/spire/releases/download/v1.8.2/spire-1.8.2-linux-$SPIRE_ARCH-musl.tar.gz
              echo "⬇️ Extracting..."
              tar -xzf spire.tar.gz
              mkdir -p /shared/bin
              echo "⬇️ Installing..."
              find . -name spire-agent -exec cp {{}} /shared/bin/spire-agent \;
              chmod +x /shared/bin/spire-agent
              echo "✅ Binary ready."
          volumeMounts:
            - name: shared-bin
              mountPath: /shared/bin
      containers:
        - name: web-server
          image: python:3.10-alpine
          command: ["/bin/sh", "-c"]
          args: ["apk add --no-cache openssl && python3 /opt/demo/workload.py"]
          ports:
            - containerPort: 8000
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
              readOnly: true
            - name: script-vol
              mountPath: /opt/demo
            - name: shared-bin
              mountPath: /opt/spire/bin
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
            type: Directory
        - name: script-vol
          configMap:
            name: workload-script
        - name: shared-bin
          emptyDir: {{}}
"""
    with open("workload-gen.yaml", "w") as f: f.write(manifest)
    run_cmd("kubectl apply -f workload-gen.yaml")

    print("\n⏳ Waiting for Workload to be Ready...")
    run_cmd("kubectl rollout status deployment/spire-workload --timeout=120s")
    print("✅ Workload Deployed.")

if __name__ == "__main__":
    main()
EOF

# --- 6. Set Permissions & Apply Domain ---
chmod +x *.sh *.py

if [[ "${TRUST_DOMAIN}" != "example.org" ]]; then
    echo "🔧 Replacing 'example.org' with '${TRUST_DOMAIN}' in all files..."
    find . -type f \( -name "*.sh" -o -name "*.py" \) -exec perl -pi -e "s/example.org/${TRUST_DOMAIN}/g" {} +
fi

echo "✅ Package v3.3 (Write-to-Disk Fix) created in: ${PROJECT_DIR}"
echo "🚀 Running Master Orchestrator..."
./3.0-orchestrate.sh ${RESET_FLAG} ${NEWROOT_FLAG}
