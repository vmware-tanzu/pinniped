#!/usr/bin/env bash

# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(realpath "$(dirname "${BASH_SOURCE[0]}")/..")"

"$ROOT/hack/module.sh" test