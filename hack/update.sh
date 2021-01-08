#!/usr/bin/env bash

# Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Generate code.
xargs -n 1 -P 8 "$ROOT/hack/lib/update-codegen.sh" < "${ROOT}/hack/lib/kube-versions.txt"

# Copy each CRD yaml to the app which should cause it to be installed.
cp "$ROOT"/generated/1.20/crds/*.supervisor.*.yaml "$ROOT/deploy/supervisor"
cp "$ROOT"/generated/1.20/crds/*.concierge.*.yaml "$ROOT/deploy/concierge"

# Tidy.
"$ROOT/hack/module.sh" tidy
