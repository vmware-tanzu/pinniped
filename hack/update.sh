#!/usr/bin/env bash

# Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Generate code.
xargs -n 1 -P 8 "$ROOT/hack/lib/update-codegen.sh" < "${ROOT}/hack/lib/kube-versions.txt"

# Copy the latest version into a ./generated/latest directory so we can depend on it without nested modules.
LATEST_VERSION="$(head -1 < "${ROOT}/hack/lib/kube-versions.txt" | cut -d"." -f1-2)"
LATEST_ROOT="$ROOT/generated/latest"
rm -rf "$LATEST_ROOT"
cp -r "$ROOT/generated/$LATEST_VERSION/" "$LATEST_ROOT"
find "$LATEST_ROOT" \( -name "go.mod" -or -name "go.sum" -or -name "README.adoc" \) -delete
rm -r "$LATEST_ROOT/crds"
find "$LATEST_ROOT" -type f -print0 | xargs -0 sed -i '' -e "s|go.pinniped.dev/generated/$LATEST_VERSION|go.pinniped.dev/generated/latest|g"

# Copy each CRD yaml to the app which should cause it to be installed.
cp "$ROOT"/generated/1.20/crds/*.supervisor.*.yaml "$ROOT/deploy/supervisor"
cp "$ROOT"/generated/1.20/crds/*.concierge.*.yaml "$ROOT/deploy/concierge"

# Tidy.
"$ROOT/hack/module.sh" tidy
