#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

#
# Helper functions
#
function log_note() {
  GREEN='\033[0;32m'
  NC='\033[0m'
  if [[ ${COLORTERM:-unknown} =~ ^(truecolor|24bit)$ ]]; then
    echo -e "${GREEN}$*${NC}"
  else
    echo "$*"
  fi
}

function log_error() {
  RED='\033[0;31m'
  NC='\033[0m'
  if [[ ${COLORTERM:-unknown} =~ ^(truecolor|24bit)$ ]]; then
    echo -e "🙁${RED} Error: $* ${NC}"
  else
    echo ":( Error: $*"
  fi
}

log_note "begin setting up kind cluster with local registry..."

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "${ROOT}"

log_note "creating local registry..."

# part of the configuration enabling kind access to a local running docker registry
# this will eventually be replaced by a built-in kind feature:
# - https://kind.sigs.k8s.io/docs/user/local-registry/
# - https://github.com/kubernetes-sigs/kind/issues/1213
reg_name='kind-registry'
reg_port='5001'
if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != 'true' ]; then
  docker run \
    -d --restart=always -p "127.0.0.1:${reg_port}:5000" --name "${reg_name}" \
    registry:2
  log_note "registry created..."
fi

KIND_CLUSTER_NAME="pinniped"

log_note "creating kind cluster..."

# To choose a specific version of kube, add this option to the command below: `--image kindest/node:v1.28.0`.
# To debug the kind config, add this option to the command below: `-v 10`
kind create cluster --config "hack/lib/kind-config/single-node.yaml" --name "${KIND_CLUSTER_NAME}"

REGISTRY_DIR="/etc/containerd/certs.d/localhost:${reg_port}"
for node in $(kind get nodes --name "${KIND_CLUSTER_NAME}"); do
  log_note "setting up node ${node} with registry....."
  docker exec "${node}" mkdir -p "${REGISTRY_DIR}"
  cat <<EOF | docker exec -i "${node}" cp /dev/stdin "${REGISTRY_DIR}/hosts.toml"
[host."http://${reg_name}:5000"]
EOF
  log_note "hosts.toml on node: ${node}....."
  docker exec "${node}" tail "${REGISTRY_DIR}/hosts.toml"
done

if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = 'null' ]; then
  log_note "setting up docker network with kind..."
  docker network connect "kind" "${reg_name}"
fi

log_note "documenting registry with configmap..."
# 5. Document the local registry
# https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

kubectl get cm local-registry-hosting -n kube-public -o yaml

log_note "finished setting up kind cluster with local registry"
