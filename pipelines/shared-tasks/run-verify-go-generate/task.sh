#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

go version

cd pinniped

echo "Running 'go generate ./...'"
go generate ./...
echo

diffs=$(git --no-pager diff)
if [[ "$diffs" == "" ]]; then
  echo "Running 'go generate ./...' did not cause any diffs. Done."
  exit 0
fi

echo "Running 'go generate ./...' caused the following diffs:"
echo
echo "$diffs"
echo
echo "Please resolve these diffs, for example by running 'go generate ./...' and committing the changes."

exit 1
