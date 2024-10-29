#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export KUBECONFIG="$PWD/cluster-pool/metadata"

# See https://github.com/concourse/registry-image-resource#in-fetch-the-images-rootfs-and-metadata
export IMAGE_DIGEST="$(cat ci-build-image/digest)"
export IMAGE_REPO="$(cat ci-build-image/repository)"

pinniped_ci="$PWD/pinniped-ci"

CLUSTER_CAPABILITIES_PATH="$PWD/$CLUSTER_CAPABILITIES_PATH"
if [ -n "$CLUSTER_CAPABILITIES" ]; then
  echo "$CLUSTER_CAPABILITIES" >/tmp/cluster-capabilities.yaml
  CLUSTER_CAPABILITIES_PATH=/tmp/cluster-capabilities.yaml
fi

if [[ -f pinniped-password/pinniped-dex-password ]]; then
  pinniped_dex_test_user_password=$(cat pinniped-password/pinniped-dex-password)
  pinniped_ldap_test_user_password=$(cat pinniped-password/pinniped-ldap-password)
else
  pinniped_dex_test_user_password=""
  pinniped_ldap_test_user_password=""
fi

# If we are deploying this workload a second time, make sure we use a different
# app name and namespace for the Concierge and the Supervisor so that the two
# kapp apps don't clash with each other.
concierge_app_name=${PINNIPED_CONCIERGE_APP_NAME:-"concierge"}
supervisor_app_name=${PINNIPED_SUPERVISOR_APP_NAME:-"supervisor"}
concierge_namespace=${concierge_app_name}
supervisor_namespace=${supervisor_app_name}

pushd pinniped >/dev/null

PINNIPED_TEST_CLUSTER_CAPABILITY_FILE="$CLUSTER_CAPABILITIES_PATH" \
  DEPLOY_LOCAL_USER_AUTHENTICATOR=yes \
  DEPLOY_TEST_TOOLS=yes \
  CONCIERGE_APP_NAME="${concierge_app_name}" \
  CONCIERGE_NAMESPACE="${concierge_namespace}" \
  SUPERVISOR_APP_NAME="${supervisor_app_name}" \
  SUPERVISOR_NAMESPACE="${supervisor_namespace}" \
  PINNIPED_DEX_TEST_USER_PASSWORD="${pinniped_dex_test_user_password}" \
  PINNIPED_LDAP_TEST_USER_PASSWORD="${pinniped_ldap_test_user_password}" \
  "$pinniped_ci/pipelines/shared-helpers/prepare-cluster-for-integration-tests.sh"

popd >/dev/null

# Copy the env vars file that was output by the previous script which are needed during integration tests
cp /tmp/integration-test-env integration-test-env-vars/
cp "$KUBECONFIG" kubeconfig/kubeconfig
cp "$PWD/cluster-pool/name" kubeconfig/cluster-name
