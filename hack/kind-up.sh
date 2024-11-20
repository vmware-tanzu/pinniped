#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

source hack/lib/helpers.sh

if [[ "${PINNIPED_USE_LOCAL_KIND_REGISTRY:-}" != "" ]]; then
  # Create registry container unless it already exists.
  reg_name='kind-registry.local'
  reg_port='5000'
  if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != 'true' ]; then
    log_note "Running the registry:2 docker image..."
    docker run \
      --detach \
      --restart=always \
      --publish "127.0.0.1:${reg_port}:5000" \
      --name "${reg_name}" \
      registry:2
  fi
fi

use_contour_registry=""
if [[ "${PINNIPED_USE_CONTOUR:-}" != "" ]]; then
  log_note "Adding Contour port mapping to Kind config."
  use_contour_registry="--file=${ROOT}/hack/lib/kind-config/contour-overlay.yaml"
fi

use_kind_registry=""
if [[ "${PINNIPED_USE_LOCAL_KIND_REGISTRY:-}" != "" ]]; then
  log_note "Adding local registry to Kind config."
  use_kind_registry="--file=${ROOT}/hack/lib/kind-config/kind-registry-overlay.yaml"
fi

cp "${ROOT}/hack/lib/kind-config/metadata-audit-policy.yaml" /tmp/metadata-audit-policy.yaml

# Do not quote ${use_kind_registry} ${use_contour_registry} in this command because they might be empty.
ytt ${use_kind_registry} ${use_contour_registry} \
  --data-value-yaml enable_audit_logs=${ENABLE_KIND_AUDIT_LOGS:-false} \
  --file="${ROOT}"/hack/lib/kind-config/single-node.yaml >/tmp/kind-config.yaml

# To choose a specific version of kube, add this option to the command below: `--image kindest/node:v1.28.0`.
# To use the "latest-main" version of kubernetes builds by the pipeline, use `--image ghcr.io/pinniped-ci-bot/kind-node-image:latest`
# To debug the kind config, add this option to the command below: `-v 10`
kind create cluster --config /tmp/kind-config.yaml --name pinniped

if [[ "${PINNIPED_USE_LOCAL_KIND_REGISTRY:-}" != "" ]]; then
  # Connect the registry to the cluster network if not already connected.
  if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" == 'null' ]; then
    docker network connect "kind" "${reg_name}"
  fi

  # Document the local registry.
  # See https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
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

fi
