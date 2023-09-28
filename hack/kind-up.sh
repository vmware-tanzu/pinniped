#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# create registry container unless it already exists
reg_name='kind-registry.local'
reg_port='5000'
if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != 'true' ]; then
  docker run \
    -d --restart=always -p "127.0.0.1:${reg_port}:5000" --name "${reg_name}" \
    registry:2
fi

if [[ "${PINNIPED_USE_CONTOUR:-}" != "" ]]; then
  echo "Adding Contour port mapping to Kind config."
  ytt -f "${ROOT}/hack/lib/kind-config/single-node.yaml" \
    -f "${ROOT}/hack/lib/kind-config/contour-overlay.yaml" >/tmp/kind-config.yaml
  kind create cluster --config /tmp/kind-config.yaml --name pinniped
else
  # To choose a specific version of kube, add this option to the command below: `--image kindest/node:v1.28.0`.
  # To debug the kind config, add this option to the command below: `-v 10`
  kind create cluster --config "hack/lib/kind-config/single-node.yaml" --name pinniped
fi


# connect the registry to the cluster network if not already connected
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = 'null' ]; then
  docker network connect "kind" "${reg_name}"
fi

# Document the local registry
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
