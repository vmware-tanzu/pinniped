#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Copy everything to output.
git clone ./pinniped-in ./pinniped-out

cd pinniped-out

./hack/update-go-mod/update-go-mod.sh

# Print diff output to the screen so it is shown in the job output.
echo
git --no-pager diff
