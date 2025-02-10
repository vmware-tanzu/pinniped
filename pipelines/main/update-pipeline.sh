#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pipeline=$(basename "$script_dir")
source "$script_dir/../../hack/fly-helpers.sh"

set_pipeline "$pipeline" "$script_dir/pipeline.yml"
ensure_time_resource_has_at_least_one_version "$pipeline" weekdays

# Make the pipeline visible to non-authenticated users in the web UI.
# TODO: make this pipeline public again in the future
#$FLY_CLI --target "$CONCOURSE_TARGET" expose-pipeline --pipeline "$pipeline"
