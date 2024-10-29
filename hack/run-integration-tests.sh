#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This script will prepare to run the integration tests and then run them.
# Is is a wrapper for prepare-for-integration-tests.sh to make it convenient
# to run the integration tests, potentially running them repeatedly.

set -euo pipefail

help=no
skip_build=no
delete_kind_cluster=no

PARAMS=""
while (("$#")); do
  case "$1" in
  -h | --help)
    help=yes
    shift
    ;;
  -s | --skip-build)
    skip_build=yes
    shift
    ;;
  -c | --from-clean-cluster)
    delete_kind_cluster=yes
    shift
    ;;
  -*)
    echo "Error: Unsupported flag $1" >&2
    exit 1
    ;;
  *)
    PARAMS="$PARAMS $1"
    shift
    ;;
  esac
done
eval set -- "$PARAMS"

if [[ "$help" == "yes" ]]; then
  me="$(basename "${BASH_SOURCE[0]}")"
  echo "Usage:"
  echo "   $me [flags] [path/to/pinniped]"
  echo
  echo "   path/to/pinniped    default: \$PWD ($PWD)"
  echo
  echo "Flags:"
  echo "   -h, --help:               print this usage"
  echo "   -s, --skip-build:         reuse the most recently built image of the app instead of building"
  echo "   -c, --from-clean-cluster: delete and rebuild the kind cluster before running tests"
  exit 1
fi

pinniped_path="${1-$PWD}"
cd "$pinniped_path" || exit 1

if [[ ! -f Dockerfile || ! -d deploy ]]; then
  echo "$pinniped_path does not appear to be the path to the source code repo directory"
  exit 1
fi

if ! command -v kind >/dev/null; then
  echo "Please install kind. e.g. 'brew install kind' for MacOS"
  exit 1
fi
if [[ "$delete_kind_cluster" == "yes" ]]; then
  echo "Deleting running kind clusters to prepare a clean slate..."
  "$pinniped_path"/hack/kind-down.sh
fi

if [[ "$skip_build" == "yes" ]]; then
  "$pinniped_path"/hack/prepare-for-integration-tests.sh --skip-build
else
  "$pinniped_path"/hack/prepare-for-integration-tests.sh
fi

source /tmp/integration-test-env

ulimit -n 512

echo
echo "Running integration tests..."
go test -race -v -count 1 -timeout 0 ./test/integration
echo "ALL INTEGRATION TESTS PASSED"
