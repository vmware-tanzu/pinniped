#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

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
