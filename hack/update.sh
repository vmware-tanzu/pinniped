#!/usr/bin/env bash

# Copyright 2020 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Generate code.
xargs -n 1 -P 8 "$ROOT/hack/lib/update-codegen.sh" < "${ROOT}/hack/lib/kube-versions.txt"

# Copy each CRD yaml to the app which should cause it to be installed.
cp "$ROOT"/generated/1.19/crds/*oidcproviderconfigs.yaml "$ROOT/deploy/supervisor"
cp "$ROOT"/generated/1.19/crds/*credentialissuerconfigs.yaml "$ROOT/deploy/concierge"
cp "$ROOT"/generated/1.19/crds/*webhookauthenticators.yaml "$ROOT/deploy/concierge"

# Make sure we didn't miss any new CRDs.
crdCount=$(find "$ROOT"/generated/1.19/crds/ -maxdepth 1 -type f -name '*.yaml' | wc -l | tr -d ' ')
if [[ "$crdCount" != "3" ]]; then
  echo "Looks like you added a new CRD. Please update this update.sh script to decide where to copy it and then run it again."
  exit 1
fi

# Tidy.
"$ROOT/hack/module.sh" tidy
