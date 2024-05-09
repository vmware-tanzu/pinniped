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
cat <<EOF | kubectl apply -f - 1>&2
kind: WebhookAuthenticator
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
metadata:
  name: my-webhook
spec:
  endpoint: ${PINNIPED_TEST_WEBHOOK_ENDPOINT}
  tls:
    certificateAuthorityData: ${PINNIPED_TEST_WEBHOOK_CA_BUNDLE}
EOF

# Use the CLI to get a kubeconfig that will use this WebhookAuthenticator.
go build -o /tmp/pinniped ./cmd/pinniped
/tmp/pinniped get kubeconfig \
  --concierge-authenticator-type webhook \
  --concierge-authenticator-name my-webhook \
  --static-token "$PINNIPED_TEST_USER_TOKEN" >/tmp/kubeconfig-with-webhook-auth.yaml

echo "export KUBECONFIG=/tmp/kubeconfig-with-webhook-auth.yaml"
