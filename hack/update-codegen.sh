#!/usr/bin/env bash

# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

BASE_PKG="github.com/suzerain-io/placeholder-name"
CODEGEN_IMAGE=${CODEGEN_IMAGE:-gcr.io/tanzu-user-authentication/k8s-code-generator-1.19:latest}

function codegen() {
    PKG="$1"
    shift 1
    if [[ ${IN_DOCKER:-0} -eq 1 ]]; then
        # Already in a container ($CODEGEN_IMAGE).
        mkdir -p "$(dirname /go/src/$BASE_PKG/$PKG)"
        test -e "/go/src/$BASE_PKG/$PKG" || ln -s "$ROOT/$PKG" "/go/src/$BASE_PKG/$PKG"
        cd "/go/src/$BASE_PKG/$PKG"
        /codegen/entrypoint.sh "$@" 2>&1 \
          | sed "s|^|$1 ($PKG) > |"
    else
        # Local workstation.
        docker run \
          --rm \
          --volume "$ROOT:/go/src/$BASE_PKG" \
          --workdir "/go/src/$BASE_PKG/$PKG" \
          "${CODEGEN_IMAGE}" \
          /codegen/entrypoint.sh "$@" 2>&1 \
          | sed "s|^|$1 ($PKG) > |"
    fi
}

codegen kubernetes/1.19/api generate-groups deepcopy,defaulter \
    $BASE_PKG/kubernetes/1.19/api/generated \
    $BASE_PKG/kubernetes/1.19/api/apis \
    "placeholder:v1alpha1 crdsplaceholder:v1alpha1"
codegen kubernetes/1.19/api generate-internal-groups deepcopy,defaulter,conversion,openapi \
    $BASE_PKG/kubernetes/1.19/api/generated \
    $BASE_PKG/kubernetes/1.19/api/apis \
    $BASE_PKG/kubernetes/1.19/api/apis \
    "placeholder:v1alpha1 crdsplaceholder:v1alpha1"
codegen kubernetes/1.19/client-go generate-groups client,lister,informer \
    $BASE_PKG/kubernetes/1.19/client-go \
    $BASE_PKG/kubernetes/1.19/api/apis \
    "placeholder:v1alpha1 crdsplaceholder:v1alpha1"
