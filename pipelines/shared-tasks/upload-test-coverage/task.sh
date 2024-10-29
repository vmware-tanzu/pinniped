#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
COVERAGE_OUTPUT="$PWD/unit-test-coverage/coverage.txt"
cd pinniped
codecov -t ${CODECOV_TOKEN} -f "${COVERAGE_OUTPUT}"
