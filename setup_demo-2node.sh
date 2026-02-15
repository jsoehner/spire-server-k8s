#!/bin/bash
set -euo pipefail

# --- Defaults ---
TRUST_DOMAIN="example.org"
RESET_FLAG=""
NEWROOT_FLAG=""
PROJECT_DIR="spire_k8s_demo_v3.2"

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
echo "   - Topology:     2-Node (Control Plane + Worker)"
echo "   - Flags:        ${RESET_FLAG} ${NEWROOT_FLAG}"

# --- 1. Create 3.0-orchestrate.sh ---
echo "📝 Generating 3.0-orchestrate.sh..."
cat << 'EOF' > 3.0-orchestrate.sh
#!/usr/bin/env bash
set -euo pipefail

# 3.0-orchestrate.sh - 2-Node Kubernetes SPIRE Demo (v3.2)
# Usage: ./3.0-orchestrate.sh [--reset] [--newroot]

RESET=0
NEWROOT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1; shift ;;
    --newroot) NEWROOT=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

echo "🚀 Starting 2-Node SPIRE Kubernetes Demo (v3.2)..."

command -v kind >/dev/null 2>&1 || { echo >&2 "❌ Error: 'kind' is not installed."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo >&2 "❌ Error: 'kubectl' is not installed."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo >&2 "❌ Error: 'python3' is not installed."; exit 1; }

if [[ "${RESET}" -eq 1 ]]; then
  echo "🧹 Tearing down existing cluster..."
  kind delete cluster --name spire-demo || true
  echo "🧹 Cleaning up local PKI artifacts..."
  rm -rf ./pki
fi

if ! kind get clusters | grep -q "spire-demo"; then
  echo "📦 Creating 2-Node Kubernetes Cluster (Kind)..."
  # Node 1: Control Plane (Cluster + Server)
  # Node 2: Worker (Agent + Workloads)
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

kubectl cluster-info --context kind-spire-demo

echo "🔐 Initializing PKI..."
ARGS=""
if [[ "${NEWROOT}" -eq 1 ]]; then ARGS="--force"; fi
./3.1-pki.sh all create $ARGS

echo "☁️  Deploying SPIRE Server (Pinned to Control Plane)..."
./3.2-deploy-server.sh

echo "🤝 Registering Agent (Runs on Worker Node)..."
python3 3.3-register-agent.py

echo "🎉 Demo Environment Ready!"
echo "   - Server (Control Plane): kubectl -n spire exec -it spire-server-0 -- /opt/spire/bin/spire-server healthcheck -socketPath /tmp/spire-server/private/api.sock"
echo "   - Agent (Worker Node):    kubectl -n spire logs -l app=spire-agent"
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

log() { echo -e "   [PKI] $1"; }
kubectl create namespace "${K8S_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

generate_root() {
    local force=$1
    if [[ -f "${ROOT_DIR}/root.key" ]] && [[ "${force}" != "--force" ]]; then
        log "Root CA exists. Skipping."
        return
    fi
    log "Generating Root CA..."
    openssl req -x509 -newkey rsa:4096 -keyout "${ROOT_DIR}/root.key" -out "${ROOT_DIR}/root.crt" \
        -days "${ROOT_TTL_DAYS}" -nodes -subj "/C=US/O=SPIRE Demo/CN=SPIRE Root CA"
}

generate_intermediate() {
    local force=$1
    if [[ -f "${INT_DIR}/intermediate.key" ]] && [[ "${force}" != "--force" ]]; then
        log "Intermediate CA exists. Skipping."
        return
    fi
    log "Generating Intermediate CA..."
    openssl req -newkey rsa:2048 -keyout "${INT_DIR}/intermediate.key" -out "${INT_DIR}/intermediate.csr" \
        -nodes -subj "/C=US/O=SPIRE Demo/CN=SPIRE Intermediate CA"
    
    # pathlen:1 required to sign Server CA
    openssl x509 -req -in "${INT_DIR}/intermediate.csr" -CA "${ROOT_DIR}/root.crt" -CAkey "${ROOT_DIR}/root.key" \
        -CAcreateserial -out "${INT_DIR}/intermediate.crt" -days "${INT_TTL_DAYS}" -sha256 -extfile <(printf "basicConstraints=CA:TRUE,pathlen:1")
    
    cat "${INT_DIR}/intermediate.crt" "${ROOT_DIR}/root.crt" > "${INT_DIR}/chain.crt"
}

sync_secrets() {
    log "⚡ Syncing PKI to Kubernetes..."
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

echo "📄 Applying SPIRE Server Manifests..."
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
      # PINNING: Ensure Server runs on the Control Plane node
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      # TOLERATION: Allow scheduling on tainted control-plane node
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

echo "⏳ Waiting for SPIRE Server rollout..."
kubectl -n spire rollout status statefulset/spire-server --timeout=90s
echo "⏳ Verifying Pod is fully ready..."
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
    print(f"Exec: {cmd}")
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and result.returncode != 0: raise Exception(result.stderr)
    return result

def main():
    print("\n🔍 Locating SPIRE Server Pod...")
    try:
        # Since we pinned server to Control Plane, we look there.
        pod_name = run_cmd("kubectl -n spire get pod -l app=spire-server -o jsonpath='{.items[0].metadata.name}'").stdout.strip()
    except Exception as e:
        print(f"❌ Error locating pod: {e}"); sys.exit(1)
    print(f"   Found Pod: {pod_name}")

    print("\n🏥 Waiting for SPIRE Server Health...")
    for i in range(12):
        res = run_cmd(f"kubectl -n spire exec {pod_name} -- /opt/spire/bin/spire-server healthcheck -socketPath {SOCKET_PATH}", check=False)
        if res.returncode == 0 and "Server is healthy" in res.stdout:
            print("   ✅ Server is healthy."); break
        print(f"   ⏳ Server not ready yet ({i+1}/12)..."); time.sleep(5)
    else:
        print("\n❌ Timeout. Dumping logs:"); subprocess.run(f"kubectl -n spire logs {pod_name}", shell=True); sys.exit(1)

    print("\n🎟️  Generating Join Token...")
    # NOTE: In a multi-node cluster, normally you need one token per agent (per node).
    # Since the Control Plane node is tainted, the DaemonSet will ONLY run on the 'worker' node.
    # So we only need one token for now.
    agent_id = f"spiffe://{TRUST_DOMAIN}/agent/k8s-node"
    token = re.search(r"Token:\s+([a-f0-9-]+)", run_cmd(f"kubectl -n spire exec {pod_name} -- /opt/spire/bin/spire-server token generate -spiffeID {agent_id} -socketPath {SOCKET_PATH}").stdout).group(1)
    print(f"   Token: {token}")

    print("\n💾 Creating 'spire-agent-token' Secret...")
    run_cmd("kubectl -n spire delete secret spire-agent-token --ignore-not-found=true", check=False)
    run_cmd(f"kubectl -n spire create secret generic spire-agent-token --from-literal=join_token={token}")

    print("\n🚀 Deploying SPIRE Agent DaemonSet (Targets Worker Node)...")
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
      # In Kind 2-node, CP has taint. Agent will schedule only on Worker.
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
    print("\\n⏳ Waiting for Agent to Register...")
    run_cmd("kubectl -n spire rollout status daemonset/spire-agent")
    print("✅ Agent Registered and Running.")

if __name__ == "__main__":
    main()
EOF

# --- 6. Set Permissions & Apply Domain ---
echo "🔒 Setting permissions..."
chmod +x *.sh *.py

if [[ "${TRUST_DOMAIN}" != "example.org" ]]; then
    echo "🔧 Replacing 'example.org' with '${TRUST_DOMAIN}' in all files..."
    # FIX: Use perl for cross-platform compatibility (macOS/BSD vs Linux/GNU)
    find . -type f \( -name "*.sh" -o -name "*.py" \) -exec perl -pi -e "s/example.org/${TRUST_DOMAIN}/g" {} +
fi

echo "✅ Package v3.2 (2-Node + Domain) created in: ${PROJECT_DIR}"
echo "🚀 Running Master Orchestrator..."
# Pass the collected flags explicitly
./3.0-orchestrate.sh ${RESET_FLAG} ${NEWROOT_FLAG}
