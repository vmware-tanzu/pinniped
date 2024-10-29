#!/bin/bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [ -z "$GO_VERSION" ]; then
  echo "missing GO_VERSION"
  exit 1
fi
if [ -z "$K8S_PKG_VERSION" ]; then
  echo "missing K8S_PKG_VERSION"
  exit 1
fi
if [ -z "$CONTROLLER_GEN_VERSION" ]; then
  echo "missing CONTROLLER_GEN_VERSION"
  exit 1
fi

# Debugging output for CI...
echo "GO_VERSION: $GO_VERSION"
echo "K8S_PKG_VERSION: $K8S_PKG_VERSION"
echo "CONTROLLER_GEN_VERSION: $CONTROLLER_GEN_VERSION"
echo "CRD_REF_DOCS_COMMIT_SHA: $CRD_REF_DOCS_COMMIT_SHA"

apt-get update -y && apt-get dist-upgrade -y

cd /codegen/

cat <<EOF >tools.go
package tools

import (
	_ "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/api/core/v1"
	_ "k8s.io/code-generator"
)
EOF

cat <<EOF >go.mod
module codegen

go 1.21

require (
	k8s.io/apimachinery v$K8S_PKG_VERSION
	k8s.io/code-generator v$K8S_PKG_VERSION
	k8s.io/api v$K8S_PKG_VERSION
)
EOF

# Resolve dependencies and download the modules.
go mod tidy
go mod download

# Copy the downloaded source code of k8s.io/code-generator so we can "go install" all its commands.
rm -rf "$(go env GOPATH)/src"
mkdir -p "$(go env GOPATH)/src/k8s.io"
cp -pr "$(go env GOMODCACHE)/k8s.io/code-generator@v$K8S_PKG_VERSION" "$(go env GOPATH)/src/k8s.io/code-generator"

# Install the commands to $GOPATH/bin. Also sed the related shell scripts, but leave those in the src dir.
# Note that update-codegen.sh invokes these shell scripts at this src path.
# The sed is a dirty hack to avoid having the code-generator shell scripts run go install again.
# In version 0.23.0 the line inside the shell script that previously said "go install ..." started
# to instead say "GO111MODULE=on go install ..." so this sed is a little wrong, but still seems to work.
(cd "$(go env GOPATH)/src/k8s.io/code-generator" &&
  go install -v ./cmd/... &&
  sed -i -E -e 's/(go install.*)/# \1/g' ./*.sh)

if [[ ! -f "$(go env GOPATH)/bin/openapi-gen" ]]; then
  # Starting in Kube 1.30, openapi-gen moved from k8s.io/code-generator to k8s.io/kube-openapi.
  # Assuming that we are still in the /codegen directory, get the specific version of kube-openapi
  # that is selected as an indirect dependency by the go.mod.
  kube_openapi_version=$(go list -m k8s.io/kube-openapi | cut -f2 -d' ')
  # Install that version of its openapi-gen command.
  go install -v "k8s.io/kube-openapi/cmd/openapi-gen@$kube_openapi_version"
fi

go install -v sigs.k8s.io/controller-tools/cmd/controller-gen@v$CONTROLLER_GEN_VERSION

# We use a commit sha instead of a release semver because this project does not create
# releases very often. They seem to only release 1-2 times per year, but commit to
# main more often.
go install -v github.com/elastic/crd-ref-docs@$CRD_REF_DOCS_COMMIT_SHA

# List all the commands that we just installed.
echo "Installed the following commands to $(go env GOPATH)/bin:"
ls "$(go env GOPATH)/bin"
