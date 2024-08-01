#!/usr/bin/env bash

# Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script deploys a WebhookAuthenticator to use for manual testing. It
# assumes that you have run hack/prepare-for-integration-tests.sh while pointed
# at the current cluster.
#

set -euo pipefail

# Change working directory to the top of the repo.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Read the env vars output by hack/prepare-for-integration-tests.sh.
source /tmp/integration-test-env

# Create WebhookAuthenticator.
echo "Creating WebhookAuthenticator..."
cat <<EOF | kubectl apply -f - 1>&2
kind: WebhookAuthenticator
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
metadata:
  name: my-webhook-authenticator
spec:
  endpoint: ${PINNIPED_TEST_WEBHOOK_ENDPOINT}
  tls:
    certificateAuthorityData: ${PINNIPED_TEST_WEBHOOK_CA_BUNDLE}
EOF

echo "Waiting for WebhookAuthenticator to be ready..."
kubectl wait --for=condition=Ready webhookauthenticator my-webhook-authenticator --timeout 60s

# Compile the CLI.
echo "Building the Pinniped CLI..."
go build ./cmd/pinniped

# Use the CLI to get a kubeconfig that will use this WebhookAuthenticator.
echo "Generating webhook kubeconfig..."
/tmp/pinniped get kubeconfig \
  --concierge-authenticator-type webhook \
  --concierge-authenticator-name my-webhook-authenticator \
  --static-token "$PINNIPED_TEST_USER_TOKEN" >kubeconfig-webhook.yaml

echo
echo "To log in using webhook:"
echo "PINNIPED_DEBUG=true ./pinniped whoami --kubeconfig ./kubeconfig-webhook.yaml"
echo
