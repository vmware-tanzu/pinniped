#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This script can be used to prepare a kind cluster and deploy the app
# in preparation for running the uninstall test.
# It will also output instructions on how to run the uninstall test.

set -euo pipefail

help=no
skip_build=no
pinniped_ci_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
  echo "   $me [flags] [path/to/pinniped] [path/to/pinniped-ci-branch]"
  echo
  echo "   path/to/pinniped           default: \$PWD ($PWD)"
  echo "   path/to/pinniped-ci-branch default: the parent directory of this script ($pinniped_ci_root)"
  echo
  echo "Flags:"
  echo "   -h, --help:              print this usage"
  echo "   -s, --skip-build:        reuse the most recently built image of the app instead of building"
  exit 1
fi

pinniped_path="${1-$PWD}"
pinniped_ci_path="${2-$pinniped_ci_root}"

if ! command -v kind >/dev/null; then
  echo "Please install kind. e.g. 'brew install kind' for MacOS"
  exit 1
fi

if ! command -v ytt >/dev/null; then
  log_error "Please install ytt. e.g. 'brew tap k14s/tap && brew install ytt' for MacOS"
  exit 1
fi

if ! command -v kapp >/dev/null; then
  log_error "Please install kapp. e.g. 'brew tap k14s/tap && brew install kapp' for MacOS"
  exit 1
fi

if ! command -v kubectl >/dev/null; then
  log_error "Please install kubectl. e.g. 'brew install kubectl' for MacOS"
  exit 1
fi

cd "$pinniped_path" || exit 1

if [[ ! -f Dockerfile || ! -d deploy ]]; then
  echo "$pinniped_path does not appear to be the path to the source code repo directory"
  exit 1
fi

if [[ ! -d "$pinniped_ci_path/pipelines/shared-helpers" ]]; then
  echo "$pinniped_ci_path does not appear to be the path to the ci repo directory"
  exit 1
fi

echo "Deleting running kind clusters to prepare a clean slate for the install+uninstall test..."
kind delete cluster --name pinniped

echo "Creating a kind cluster..."
kind create cluster --name pinniped

registry="docker.io"
repo="test/build"
registry_repo="$registry/$repo"
tag=$(uuidgen) # always a new tag to force K8s to reload the image on redeploy

if [[ "$skip_build" == "yes" ]]; then
  most_recent_tag=$(docker images "$repo" --format "{{.Tag}}" | head -1)
  if [[ -n "$most_recent_tag" ]]; then
    tag="$most_recent_tag"
    do_build=no
  else
    # Oops, there was no previous build. Need to build anyway.
    do_build=yes
  fi
else
  do_build=yes
fi

registry_repo_tag="${registry_repo}:${tag}"

if [[ "$do_build" == "yes" ]]; then
  # Rebuild the code
  echo "Docker building the app..."
  docker build . --tag "$registry_repo_tag"
fi

# Load it into the cluster
echo "Loading the app's container image into the kind cluster..."
kind load docker-image "$registry_repo_tag" --name pinniped

cat <<EOF >/tmp/uninstall-test-env
# The following env vars should be set before running $pinniped_ci_path/pipelines/shared-tasks/run-uninstall-test/run-uninstall-test.sh
export IMAGE_REPO="$registry_repo"
export IMAGE_TAG="$tag"
EOF

echo "Done!"
echo
echo "Ready to run an uninstall test."
echo "  cd $pinniped_path"
echo "Then either"
echo "  source /tmp/uninstall-test-env && $pinniped_ci_path/pipelines/shared-tasks/run-uninstall-test/run-uninstall-test.sh"
echo "or"
echo "  source /tmp/uninstall-test-env && $pinniped_ci_path/pipelines/shared-tasks/run-uninstall-test/run-uninstall-from-existing-namespace-test.sh"
echo
echo "When you're finished, use 'kind delete cluster --name pinniped to tear down the cluster."
