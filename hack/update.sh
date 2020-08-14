#!/usr/bin/env bash

# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

"$ROOT/hack/module.sh" tidy
"$ROOT/hack/update-codegen.sh"
