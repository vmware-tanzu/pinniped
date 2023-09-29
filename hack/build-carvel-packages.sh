#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script can be used to prepare a kind cluster and deploy the app.
# You can call this script again to redeploy the app.
# It will also output instructions on how to run the integration.
#

set -euo pipefail

#
# Helper functions
#
function log_note() {
  GREEN='\033[0;32m'
  NC='\033[0m'
  if [[ ${COLORTERM:-unknown} =~ ^(truecolor|24bit)$ ]]; then
    echo -e "${GREEN}$*${NC}"
  else
    echo "$*"
  fi
}

function log_error() {
  RED='\033[0;31m'
  NC='\033[0m'
  if [[ ${COLORTERM:-unknown} =~ ^(truecolor|24bit)$ ]]; then
    echo -e "🙁${RED} Error: $* ${NC}"
  else
    echo ":( Error: $*"
  fi
}

function check_dependency() {
  if ! command -v "$1" >/dev/null; then
    log_error "Missing dependency..."
    log_error "$2"
    exit 1
  fi
}

# registry="pinniped.local"
registry="kind-registry.local:5000"
repo="test/build"
registry_repo="$registry/$repo"
tag=$(uuidgen) # always a new tag to force K8s to reload the image on redeploy
registry_repo_tag="${registry_repo}:${tag}"

# Generate the OpenAPI v3 Schema files
declare -a arr=("supervisor" "concierge" "local-user-authenticator")
for resource_name in "${arr[@]}"
do
  log_note "Generating OpenAPI v3 schema for ${resource_name}..."
  ytt \
    --file "deploy/${resource_name}" \
    --data-values-schema-inspect \
    --output openapi-v3 > \
    "deploy_carvel/${resource_name}/schema-openapi.yaml"
done


log_note "Finished."
log_note "Now run hack/prepare-for-integration-tests.sh to create a kind cluster!"
