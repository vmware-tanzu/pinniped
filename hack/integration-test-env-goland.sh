#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# Print the PINNIPED_TEST_* env vars from /tmp/integration-test-env in a format that can be used in GoLand.
#

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

source /tmp/integration-test-env

echo -n "PINNIPED_TEST_GOLAND_RUNNER=true;"

printenv | grep PINNIPED_TEST_ | sed 's/=.*//g' | grep -v CLUSTER_CAPABILITY_YAML | while read -r var ; do
    echo -n "${var}="
    # Goland will treat semicolons as key/value pair separators.
    # Within a value, a semicolon needs to be escaped with a backslash for Goland.
    echo -n "${!var}" | sed 's/;/\\;/g' | tr -d '\n'
    echo -n ";"
done

echo -n "PINNIPED_TEST_CLUSTER_CAPABILITY_FILE=${ROOT}/test/cluster_capabilities/kind.yaml"
