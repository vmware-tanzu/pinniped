#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define some env vars
source "$script_dir/fly-helpers.sh"

# Setup and login if needed
"$ROOT_DIR"/hack/setup-fly.sh

# List all jobs that are currently running in CI.
# An empty result means that there are no jobs running.
for p in $($FLY_CLI --target "$CONCOURSE_TARGET" pipelines --json | jq -r ".[].name"); do
  $FLY_CLI --target "$CONCOURSE_TARGET" jobs -p "$p" --json | jq -r ".[] | select(.next_build.status == \"started\") | (\"$p/\" + .name)"
done
