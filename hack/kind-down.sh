#!/usr/bin/env bash

# Copyright 2020 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "${ROOT}"

if [[ "${PINNIPED_USE_LOCAL_KIND_REGISTRY:-}" != "" ]]; then
  reg_name='kind-registry.local'
  docker network disconnect "kind" "${reg_name}" || true
  docker stop "${reg_name}" || true
  docker rm "${reg_name}" || true
fi

kind delete cluster --name pinniped
