#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

go version

cd pinniped

echo "Running 'module.sh tidy'"
./hack/module.sh tidy
echo

diffs=$(git --no-pager diff)
if [[ "$diffs" == "" ]]; then
  echo "Running 'module.sh tidy' did not cause any diffs. Done."
  exit 0
fi

echo "Running 'module.sh tidy' caused the following diffs:"
echo
echo "$diffs"
echo
echo "Please resolve these diffs, for example by running 'module.sh tidy' and committing the changes."

exit 1
