#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pipeline=$(basename "$script_dir")
source "$script_dir/../../hack/fly-helpers.sh"

set_pipeline "$pipeline" "$script_dir/pipeline.yml"
