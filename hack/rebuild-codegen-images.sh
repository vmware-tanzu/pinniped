#!/usr/bin/env bash

# Copyright 2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define some env vars
source "$script_dir/fly-helpers.sh"

# Setup and login if needed
"$ROOT_DIR"/hack/setup-fly.sh

# Start all the build-k8s-code-generator-* jobs in the dockerfile-builders pipeline.
for j in $($FLY_CLI --target "$CONCOURSE_TARGET" jobs --pipeline dockerfile-builders --json | jq -r '.[].name' | grep build-k8s-code-generator-); do
  $FLY_CLI --target "$CONCOURSE_TARGET" trigger-job --job "dockerfile-builders/$j"
done
