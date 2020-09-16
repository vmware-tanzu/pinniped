#!/usr/bin/env bash

# Copyright 2020 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

xargs "$ROOT/hack/lib/verify-codegen.sh" < "${ROOT}/hack/lib/kube-versions.txt"
"$ROOT/hack/module.sh" lint
