#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

pinniped_version="v$(cat release-semver/version)"

# Use an image_tag with both the actual tag (human-readable) and the digest (to statically pin the contents).
# When both are specified, the image tag ends up acting like a comment to help the user understand what version
# they have installed, but does not affect which image is pulled.
image_digest="$(cat ci-build-image/digest)"
image_tag="${pinniped_version}@${image_digest}"
echo "Using image_repo=${IMAGE_REPO} with image_tag=${image_tag}"

# Note that this is assuming that all required options in the values.yaml files have good defaults.
echo "Templating install-pinniped-concierge.yaml..."
pushd pinniped/deploy/concierge >/dev/null
ytt --file . --data-value "image_repo=${IMAGE_REPO}" --data-value "image_tag=${image_tag}" >../../../deployment-yamls/install-pinniped-concierge.yaml
popd >/dev/null

# Create a subset of the Concierge YAML containing only the CRDs, the namespace, and the ServiceAccount (for use with kubectl apply and kubectl delete).
echo "Templating install-pinniped-concierge-crds.yaml..."
yq eval 'select(.kind == "CustomResourceDefinition" or .kind == "Namespace" or .kind == "ServiceAccount")' deployment-yamls/install-pinniped-concierge.yaml >deployment-yamls/install-pinniped-concierge-crds.yaml

# Create a subset with everything that isn't in the other yaml file (for kubectl apply and kubectl delete)
echo "Templating install-pinniped-concierge-resources.yaml"
yq eval 'select(.kind != "CustomResourceDefinition" and .kind != "Namespace" and .kind != "ServiceAccount")' deployment-yamls/install-pinniped-concierge.yaml >deployment-yamls/install-pinniped-concierge-resources.yaml

echo "Templating install-pinniped-supervisor.yaml..."
pushd pinniped/deploy/supervisor >/dev/null
ytt --file . --data-value "image_repo=${IMAGE_REPO}" --data-value "image_tag=${image_tag}" >../../../deployment-yamls/install-pinniped-supervisor.yaml
popd >/dev/null

echo "Templating install-local-user-authenticator.yaml..."
pushd pinniped/deploy/local-user-authenticator >/dev/null
ytt --file . --data-value "image_repo=${IMAGE_REPO}" --data-value "image_tag=${image_tag}" >../../../deployment-yamls/install-local-user-authenticator.yaml
popd >/dev/null
