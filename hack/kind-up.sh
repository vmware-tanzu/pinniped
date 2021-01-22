#!/usr/bin/env bash

# Copyright 2020 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "${ROOT}"

# To choose a specific version of kube, add this option to the command below: `--image kindest/node:v1.18.8`.
kind create cluster --config "hack/lib/kind-config/single-node.yaml" --name pinniped
