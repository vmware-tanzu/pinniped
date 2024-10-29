#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

# See https://github.com/concourse/registry-image-resource#in-fetch-the-images-rootfs-and-metadata
digest=$(cat ci-build-image/digest)

pinniped_ci="$PWD/pinniped-ci"
pinniped_cluster_capability_file="$PWD/pinniped/test/cluster_capabilities/gke.yaml"

gcloud auth activate-service-account "$GKE_USERNAME" --key-file <(echo "$GKE_JSON_KEY") --project "$PINNIPED_GCP_PROJECT"

# https://cloud.google.com/blog/products/containers-kubernetes/kubectl-auth-changes-in-gke
export USE_GKE_GCLOUD_AUTH_PLUGIN=True
gcloud container clusters get-credentials "$GKE_CLUSTER_NAME" --zone us-central1-c --project "$PINNIPED_GCP_PROJECT"

pushd pinniped >/dev/null

# Create the image pull secret to template using ytt
image_pull_secret=$(kubectl create secret docker-registry dummy \
  --docker-server="$CI_BUILD_IMAGE_SERVER" \
  --docker-username="$CI_BUILD_IMAGE_USERNAME" \
  --docker-password="$CI_BUILD_IMAGE_PASSWORD" \
  --dry-run=client -o json | jq -r '.data[".dockerconfigjson"]')

if [[ "${TMC_API_TOKEN:-}" == "" ]]; then
  # If the TMC API token is not set, then assume that we want to use the local user authenticator
  # instead of the TMC webhook authenticator.
  export DEPLOY_LOCAL_USER_AUTHENTICATOR="yes"
fi

# This script uses the API token from the environment variable TMC_API_TOKEN,
# and the cluster name from the environment variable TMC_CLUSTER_NAME.
#
# Set the serving cert parameters to 1h20m and 1h so that we can validate that
# an aggressive cert rotation schedule doesn't mess up the cluster too bad.
CONCIERGE_NAMESPACE=concierge-acceptance \
  SUPERVISOR_NAMESPACE=supervisor-acceptance \
  SUPERVISOR_LOAD_BALANCER=yes \
  SUPERVISOR_LOAD_BALANCER_DNS_NAME="$LOAD_BALANCER_DNS_NAME" \
  SUPERVISOR_LOAD_BALANCER_STATIC_IP="$RESERVED_LOAD_BALANCER_STATIC_IP" \
  SUPERVISOR_INGRESS=yes \
  SUPERVISOR_INGRESS_DNS_NAME="$INGRESS_DNS_ENTRY_GCLOUD_NAME" \
  SUPERVISOR_INGRESS_STATIC_IP_NAME="$INGRESS_STATIC_IP_GCLOUD_NAME" \
  SUPERVISOR_INGRESS_PATH_PATTERN='/*' \
  IMAGE_PULL_SECRET="$image_pull_secret" \
  IMAGE_REPO="$CI_BUILD_IMAGE_NAME" \
  IMAGE_DIGEST="$digest" \
  API_SERVING_CERT_DURATION=4800 \
  API_SERVING_CERT_RENEW_BEFORE=3600 \
  PINNIPED_TEST_CLUSTER_CAPABILITY_FILE="$pinniped_cluster_capability_file" \
  "$pinniped_ci/pipelines/shared-helpers/prepare-cluster-for-integration-tests.sh"

if [[ "${TMC_API_TOKEN:-}" != "" ]]; then
  # Create a long-lived webhook IDP allowing TMC login via the TUA organization.
  source /tmp/integration-test-env
  cat <<EOF | kubectl apply -f -
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: WebhookAuthenticator
metadata:
  name: tua-tmc
spec:
  endpoint: ${PINNIPED_TEST_WEBHOOK_ENDPOINT}
  tls:
    certificateAuthorityData: ${PINNIPED_TEST_WEBHOOK_CA_BUNDLE}
EOF
fi

popd >/dev/null

# Copy the env vars file that was output by the previous script which are needed during integration tests
cp /tmp/integration-test-env integration-test-env-vars/

# So that the tests can avoid using the GKE auth plugin, create an admin kubeconfig which uses certs (without the plugin).
# Get the cluster details back, including the admin certificate:
gcloud container clusters describe "$GKE_CLUSTER_NAME" --zone us-central1-c --format json >/tmp/cluster.json
# Make a new kubeconfig user "cluster-admin" using the admin cert.
jq -r .masterAuth.clientCertificate /tmp/cluster.json | base64 -d >/tmp/client.crt
jq -r .masterAuth.clientKey /tmp/cluster.json | base64 -d >/tmp/client.key
kubectl config set-credentials cluster-admin --client-certificate=/tmp/client.crt --client-key=/tmp/client.key
# Give the "client" user cluster-admin access in an idempotent way.
kubectl create clusterrolebinding test-client-is-admin --clusterrole cluster-admin --user client --dry-run=client -o yaml | kubectl apply -f -
# Set the kubeconfig context to use the cluster-admin user.
kubectl config set-context --current --user cluster-admin
# Write out the admin kubeconfig file to the task's output directory.
kubectl config view --minify --flatten -o yaml >kubeconfig/kubeconfig
# Give it the appropriate permissions.
chmod 0644 kubeconfig/kubeconfig
