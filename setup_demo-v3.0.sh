#!/bin/bash
set -euo pipefail

# Define the project directory
PROJECT_DIR="spire_k8s_demo_v3"

echo "📂 Creating project directory: ${PROJECT_DIR}..."
mkdir -p "${PROJECT_DIR}"
cd "${PROJECT_DIR}"

# --- 1. Create 3.0-orchestrate.sh ---
echo "📝 Generating 3.0-orchestrate.sh..."
cat << 'EOF' > 3.0-orchestrate.sh
#!/usr/bin/env bash
set -euo pipefail

# 3.0-orchestrate.sh - Single Click Kubernetes SPIRE Demo
# Usage: ./3.0-orchestrate.sh [--reset] [--newroot]

RESET=0
NEWROOT=0

# Argument Parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --newroot) NEWROOT=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

echo "🚀 Starting Single-Click SPIRE Kubernetes Demo..."

# Check for prerequisites
command -v kind >/dev/null 2>&1 || { echo >&2 "❌ Error: 'kind' is not installed. Please install it first."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo >&2 "❌ Error: 'kubectl' is not installed. Please install it first."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo >&2 "❌ Error: 'python3' is not installed. Please install it first."; exit 1; }

# Step 1: Cluster Management
if [[ "${RESET}" -eq 1 ]]; then
  echo "🧹 Tearing down existing cluster..."
  kind delete cluster --name spire-demo || true
  
  # CRITICAL FIX: If we reset the cluster, we must wipe the local PKI
  # to ensure we don't reuse old certs with bad pathlen constraints.
  echo "🧹 Cleaning up local PKI artifacts..."
  rm -rf ./pki
fi

if ! kind get clusters | grep -q "spire-demo"; then
  echo "📦 Creating Kubernetes Cluster (Kind)..."
  # We mount the docker socket so we can use the docker workload attestor if needed
  cat <<KIND_CONFIG | kind create cluster --name spire-demo --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/run/docker.sock
    containerPath: /var/run/docker.sock
KIND_CONFIG
else
  echo "✅ Cluster 'spire-demo' already running."
fi

# Ensure context is set
kubectl cluster-info --context kind-spire-demo

# Step 2: PKI Generation & Secret Injection
echo "🔐 Initializing PKI..."
ARGS=""
if [[ "${NEWROOT}" -eq 1 ]]; then ARGS="--force"; fi
./3.1-pki.sh all create $ARGS

# Step 3: Deploy SPIRE Server
echo "☁️  Deploying SPIRE Server..."
./3.2-deploy-server.sh

# Step 4: Register Agent & Deploy
echo "🤝 Registering Agent..."
python3 3.3-register-agent.py

echo "🎉 Demo Environment Ready!"
echo "   - Test Server Health: kubectl -n spire exec -it spire-server-0 -- /opt/spire/bin/spire-server healthcheck -socketPath /tmp/spire-server/private/api.sock"
echo "   - View Agent Logs:    kubectl -n spire logs -l app=spire-agent"
EOF

# --- 2. Create 3.1-pki.sh ---
echo "📝 Generating 3.1-pki.sh..."
cat << 'EOF' > 3.1-pki.sh
#!/usr/bin/env bash
set -euo pipefail

# 3.1-pki.sh (v3.0) - Root+Intermediate PKI + K8s Secret Sync
# Generates a Root CA and an Intermediate CA for SPIRE, then syncs them to K8s Secrets.

BASE_DIR="./pki"
ROOT_DIR="${BASE_DIR}/root"
INT_DIR="${BASE_DIR}/intermediate"
mkdir -p "${ROOT_DIR}" "${INT_DIR}"

# Configuration
ROOT_TTL_DAYS=3650
INT_TTL_DAYS=365
K8S_NAMESPACE="spire"

log() { echo -e "   [PKI] $1"; }

# Ensure namespace exists
kubectl create namespace "${K8S_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

generate_root() {
    local force=$1
    if [[ -f "${ROOT_DIR}/root.key" ]] && [[ "${force}" != "--force" ]]; then
        log "Root CA exists. Skipping generation."
        return
    fi

    log "Generating Root CA..."
    openssl req -x509 -newkey rsa:4096 -keyout "${ROOT_DIR}/root.key" -out "${ROOT_DIR}/root.crt" \
        -days "${ROOT_TTL_DAYS}" -nodes -subj "/C=US/O=SPIRE Demo/CN=SPIRE Root CA"
}

generate_intermediate() {
    local force=$1
    if [[ -f "${INT_DIR}/intermediate.key" ]] && [[ "${force}" != "--force" ]]; then
        log "Intermediate CA exists. Skipping generation."
        return
    fi

    log "Generating Intermediate CA..."
    openssl req -newkey rsa:2048 -keyout "${INT_DIR}/intermediate.key" -out "${INT_DIR}/intermediate.csr" \
        -nodes -subj "/C=US/O=SPIRE Demo/CN=SPIRE Intermediate CA"

    # FIX: Changed pathlen:0 to pathlen:1
    # SPIRE Server acts as a CA (signing SVIDs). 
    # The Intermediate CA must allow at least 1 level of CA below it.
    openssl x509 -req -in "${INT_DIR}/intermediate.csr" -CA "${ROOT_DIR}/root.crt" -CAkey "${ROOT_DIR}/root.key" \
        -CAcreateserial -out "${INT_DIR}/intermediate.crt" -days "${INT_TTL_DAYS}" -sha256 -extfile <(printf "basicConstraints=CA:TRUE,pathlen:1")

    # Create the chain (Intermediate + Root)
    cat "${INT_DIR}/intermediate.crt" "${ROOT_DIR}/root.crt" > "${INT_DIR}/chain.crt"
}

sync_secrets() {
    log "⚡ Syncing PKI artifacts to Kubernetes Secrets..."

    # 1. Upstream CA Secret (The Intermediate Key/Cert for the Server to sign X509-SVIDs)
    # The server uses the intermediate key to sign, and presents the chain.
    if [[ -f "${INT_DIR}/chain.crt" ]]; then
        kubectl -n "${K8S_NAMESPACE}" create secret generic spire-upstream-ca \
            --from-file=upstream_ca.crt="${INT_DIR}/chain.crt" \
            --from-file=upstream_ca.key="${INT_DIR}/intermediate.key" \
            --dry-run=client -o yaml | kubectl apply -f -
        log "✅ Secret 'spire-upstream-ca' updated."
    fi

    # 2. Bootstrap Bundle (The Root CA certificate for Agents to trust the Server)
    if [[ -f "${ROOT_DIR}/root.crt" ]]; then
         kubectl -n "${K8S_NAMESPACE}" create configmap spire-bundle \
            --from-file=bootstrap.crt="${ROOT_DIR}/root.crt" \
            --dry-run=client -o yaml | kubectl apply -f -
         log "✅ ConfigMap 'spire-bundle' updated."
    fi
}

# Execution
REALM="${1:-all}"
ACTION="${2:-create}"
FORCE="${3:-}"

if [[ "$REALM" == "all" && "$ACTION" == "create" ]]; then
    generate_root "$FORCE"
    generate_intermediate "$FORCE"
    sync_secrets
else
    echo "Usage: ./3.1-pki.sh all create [--force]"
fi
EOF

# --- 3. Create 3.2-deploy-server.sh ---
echo "📝 Generating 3.2-deploy-server.sh..."
cat << 'EOF' > 3.2-deploy-server.sh
#!/usr/bin/env bash
set -euo pipefail

# 3.2-deploy-server.sh - Deploys SPIRE Server to K8s
# Idempotent deployment of Server resources

echo "📄 Applying SPIRE Server Manifests..."

# Ensure namespace (redundant but safe)
kubectl create namespace spire --dry-run=client -o yaml | kubectl apply -f -

# Server ConfigMap, Service, and StatefulSet
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
      # We use the upstream CA plugin to load our disk-based intermediate CA
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

echo "⏳ Waiting for SPIRE Server rollout..."
kubectl -n spire rollout status statefulset/spire-server --timeout=90s

echo "⏳ Verifying Pod is fully ready..."
kubectl -n spire wait --for=condition=Ready pod/spire-server-0 --timeout=60s
EOF

# --- 4. Create 3.3-register-agent.py ---
echo "📝 Generating 3.3-register-agent.py..."
cat << 'EOF' > 3.3-register-agent.py
#!/usr/bin/env python3
"""
3.3-register-agent.py - K8s Adapted Agent Registration
1. Finds running SPIRE Server pod.
2. WAITS for the server to be healthy (checks socket availability).
3. Generates a Join Token via kubectl exec.
4. Creates a K8s Secret with the token.
5. Deploys/Restarts the Agent DaemonSet.
"""

import subprocess
import sys
import time
import re

SOCKET_PATH = "/tmp/spire-server/private/api.sock"

def run_cmd(cmd, check=True):
    # Wrapper to run shell commands
    print(f"Exec: {cmd}")
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and result.returncode != 0:
        return result # Return the full result object on failure so caller can inspect stderr
    return result

def main():
    print("\n🔍 Locating SPIRE Server Pod...")
    try:
        cmd = "kubectl -n spire get pod -l app=spire-server -o jsonpath='{.items[0].metadata.name}'"
        res = run_cmd(cmd)
        if res.returncode != 0: raise Exception(res.stderr)
        pod_name = res.stdout.strip()
    except Exception as e:
        print(f"❌ Error locating pod: {e}")
        sys.exit(1)
        
    print(f"   Found Pod: {pod_name}")

    print("\n🏥 Waiting for SPIRE Server Health...")
    # Health Check Loop
    # We use the built-in healthcheck command inside the container to verify the socket is active.
    max_retries = 12 # 12 * 5 seconds = 60 seconds timeout
    healthy = False
    
    for i in range(max_retries):
        health_cmd = f"kubectl -n spire exec {pod_name} -- /opt/spire/bin/spire-server healthcheck -socketPath {SOCKET_PATH}"
        res = run_cmd(health_cmd, check=False)
        
        if res.returncode == 0 and "Server is healthy" in res.stdout:
            print("   ✅ Server is healthy.")
            healthy = True
            break
        else:
            print(f"   ⏳ Server not ready yet (Attempt {i+1}/{max_retries})...")
            time.sleep(5)

    if not healthy:
        print("\n❌ SPIRE Server failed to become healthy. Dumping logs for debugging:")
        print("="*50)
        subprocess.run(f"kubectl -n spire logs {pod_name}", shell=True)
        print("="*50)
        sys.exit(1)

    print("\n🎟️  Generating Join Token...")
    agent_id = "spiffe://example.org/agent/k8s-node"
    
    # We explicitly pass -socketPath to ensure we match the config
    token_cmd = f"kubectl -n spire exec {pod_name} -- /opt/spire/bin/spire-server token generate -spiffeID {agent_id} -socketPath {SOCKET_PATH}"
    
    res = run_cmd(token_cmd, check=False)
    if res.returncode != 0:
        print(f"❌ Failed to generate token: {res.stderr}")
        sys.exit(1)
        
    output = res.stdout.strip()
    
    # Extract token using Regex
    match = re.search(r"Token:\s+([a-f0-9-]+)", output)
    if not match:
        print(f"❌ Failed to parse token from output: {output}")
        sys.exit(1)
    
    token = match.group(1)
    print(f"   Token: {token}")

    print("\n💾 Creating 'spire-agent-token' Secret...")
    subprocess.run("kubectl -n spire delete secret spire-agent-token --ignore-not-found=true", shell=True, check=False)
    
    # Create new secret
    subprocess.run(f"kubectl -n spire create secret generic spire-agent-token --from-literal=join_token={token}", shell=True, check=True)

    print("\n🚀 Deploying SPIRE Agent DaemonSet...")
    
    # We now mount the spire-bundle ConfigMap and copy bootstrap.crt to the shared config dir
    agent_manifest = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-agent-conf
  namespace: spire
data:
  agent.conf: |
    agent {
      data_dir = "/run/spire/data"
      log_level = "DEBUG"
      server_address = "spire-server"
      server_port = "8081"
      socket_path = "/run/spire/sockets/agent.sock"
      trust_bundle_path = "/run/spire/config/bootstrap.crt"
      trust_domain = "example.org"
      # Reads token from the mounted secret file
      join_token = "TOKEN_PLACEHOLDER"
    }
    plugins {
      NodeAttestor "join_token" {
        plugin_data {}
      }
      KeyManager "disk" {
        plugin_data {
          directory = "/run/spire/data"
        }
      }
      WorkloadAttestor "k8s" {
        plugin_data {
          skip_kubelet_verification = true
        }
      }
      WorkloadAttestor "docker" {
        plugin_data {}
      }
    }
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
          # Copy agent.conf AND bootstrap.crt to the shared volume, then inject token
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
            items:
              - key: agent.conf
                path: agent.conf
        - name: agent-config
          emptyDir: {}
        - name: agent-token
          secret:
            secretName: spire-agent-token
        - name: agent-socket
          hostPath:
            path: /run/spire/sockets
            type: DirectoryOrCreate
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
        - name: kubelet-socket
          hostPath:
            path: /run/containerd/containerd.sock 
        - name: agent-bundle
          configMap:
            name: spire-bundle
"""
    
    with open("spire-agent-gen.yaml", "w") as f:
        f.write(agent_manifest)

    subprocess.run("kubectl apply -f spire-agent-gen.yaml", shell=True, check=True)
    
    print("\\n⏳ Waiting for Agent to Register...")
    subprocess.run("kubectl -n spire rollout status daemonset/spire-agent", shell=True, check=True)
    print("✅ Agent Registered and Running.")

if __name__ == "__main__":
    main()
EOF

# --- 5. Create README.md ---
echo "📝 Generating README.md..."
cat << 'EOF' > README.md
# Single Click SPIRE Kubernetes Demo (v3.0)

## Quick Start
Run the orchestrator script to build everything:

\`\`\`bash
chmod +x *.sh *.py
./3.0-orchestrate.sh
\`\`\`
EOF

# --- 6. Set Permissions ---
echo "🔒 Setting permissions..."
chmod +x *.sh *.py

echo "✅ Package created successfully in: ${PROJECT_DIR}"
echo "🚀 Running Master Orchestrator (Reset Mode)..."
./3.0-orchestrate.sh --reset
