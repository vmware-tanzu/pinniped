#!/usr/bin/env bash

# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

xargs "$ROOT/hack/lib/update-codegen.sh" < "${ROOT}/hack/lib/kube-versions.txt"
cp "$ROOT/generated/1.19/crds/crd.pinniped.dev_credentialissuerconfigs.yaml" "$ROOT/deploy/crd.yaml"
"$ROOT/hack/module.sh" tidy
