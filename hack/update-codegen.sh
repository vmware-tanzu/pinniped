#!/usr/bin/env bash

# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT="$(realpath "$(dirname "${BASH_SOURCE[0]}")/..")"
BASE_PKG="github.com/suzerain-io/placeholder-name"
CODEGEN_IMAGE=${CODEGEN_IMAGE:-gcr.io/tanzu-user-authentication/k8s-code-generator-1.19:latest}

function codegen() {
    PKG="$1"
    shift 1
    docker run --rm -v "$ROOT:/go/src/$BASE_PKG" -w "/go/src/$BASE_PKG/$PKG" "${CODEGEN_IMAGE}" "$@" 2>&1 | sed "s|^|$1 ($PKG) > |"
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
