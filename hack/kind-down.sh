#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

source hack/lib/helpers.sh

if [[ "${PINNIPED_USE_LOCAL_KIND_REGISTRY:-}" != "" ]]; then
  reg_name='kind-registry.local'

  # If the container is running...
  if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" == 'true' ]; then
    # Disconnect it from the kind network, if it was connected.
    if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" != 'null' ]; then
      docker network disconnect "kind" "${reg_name}" >/dev/null
    fi

    log_note "Stopping container $reg_name ..."
    docker stop "${reg_name}" >/dev/null

    # Delete it.
    docker rm "${reg_name}" >/dev/null
  fi
fi

kind delete cluster --name pinniped
