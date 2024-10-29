#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

pinniped_ci_root="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
pinniped_path="${1-$PWD}"
pinniped_ci_path="${2-$pinniped_ci_root}"

cd "$pinniped_path" || exit 1

if [[ ! -f "./hack/module.sh" ]]; then
  echo "$pinniped_path does not appear to be the path to the source code repo directory"
  exit 1
fi

if [[ ! -f "$pinniped_ci_path/hack/run-integration-tests.sh" ]]; then
  echo "$pinniped_ci_path does not appear to be the path to the ci repo directory"
  exit 1
fi

echo
echo "Running linters..."
./hack/module.sh lint

echo
echo "Running units..."
./hack/module.sh unittest

echo
echo "Running integrations..."
"$pinniped_ci_path"/hack/run-integration-tests.sh --from-clean-cluster

echo
echo "ALL TESTS PASSED"
