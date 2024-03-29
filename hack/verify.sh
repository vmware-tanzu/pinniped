#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

cat "${ROOT}/hack/lib/kube-versions.txt" | grep -v '^#' | xargs "$ROOT/hack/lib/verify-codegen.sh"

"$ROOT/hack/module.sh" lint
