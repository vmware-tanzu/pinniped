#!/usr/bin/env bash

# Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# Print the PINNIPED_TEST_* env vars from /tmp/integration-test-env in a format that can be used in GoLand.
#

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

source /tmp/integration-test-env

printenv | grep PINNIPED_TEST_ | sed 's/=.*//g' | grep -v CLUSTER_CAPABILITY_YAML | while read -r var ; do
    echo -n "${var}="
    echo -n "${!var}" | tr -d '\n'
    echo -n ";"
done

echo -n "PINNIPED_TEST_CLUSTER_CAPABILITY_FILE=${ROOT}/test/cluster_capabilities/kind.yaml"
