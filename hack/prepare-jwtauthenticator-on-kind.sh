#!/usr/bin/env bash

# Copyright 2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script deploys a JWTAuthenticator to use for manual testing.
# The JWTAuthenticator will be configured to use Dex as the issuer.
#
# This is for manually testing using the Concierge with a JWTAuthenticator
# that points at some issuer other than the Pinniped Supervisor, as described in
# https://pinniped.dev/docs/howto/concierge/configure-concierge-jwt/
#
# This script assumes that you have run the following command first:
# PINNIPED_USE_CONTOUR=1 hack/prepare-for-integration-tests.sh
# Contour is used to provide ingress for Dex, so the web browser
# on your workstation can connect to Dex running inside the kind cluster.
#

set -euo pipefail

# Change working directory to the top of the repo.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Read the env vars output by hack/prepare-for-integration-tests.sh.
source /tmp/integration-test-env

# Install Contour.
kubectl apply -f https://projectcontour.io/quickstart/contour.yaml

# Wait for its pods to be ready.
echo "Waiting for Contour to be ready..."
kubectl wait --for 'jsonpath={.status.phase}=Succeeded' pods -l 'app=contour-certgen' -n projectcontour --timeout 60s
kubectl wait --for 'jsonpath={.status.phase}=Running' pods -l 'app!=contour-certgen' -n projectcontour --timeout 60s

# Capture just the hostname from a string that looks like https://host.name/foo.
dex_host=$(echo "$PINNIPED_TEST_CLI_OIDC_ISSUER" | sed -E 's#^https://([^/]+)/.*#\1#')

# Create an ingress for Dex which uses TLS passthrough to allow Dex to terminate TLS.
cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_TOOLS_NAMESPACE" -f -
apiVersion: projectcontour.io/v1
kind: HTTPProxy
metadata:
  name: dex-proxy
spec:
  virtualhost:
    fqdn: $dex_host
    tls:
      passthrough: true
  tcpproxy:
    services:
      - name: dex
        port: 443
EOF

# Check if the Dex hostname is defined in /etc/hosts.
dex_host_missing=no
if ! grep -q "$dex_host" /etc/hosts; then
  dex_host_missing=yes
fi
if [[ "$dex_host_missing" == "yes" ]]; then
  echo
  log_error "Please run this commands to edit /etc/hosts, and then run this script again with the same options."
  echo "sudo bash -c \"echo '127.0.0.1 $dex_host' >> /etc/hosts\""
  log_error "When you are finished with your Kind cluster, you can remove these lines from /etc/hosts."
  exit 1
fi

# Create the JWTAuthenticator.
cat <<EOF | kubectl apply -f - 1>&2
kind: JWTAuthenticator
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
metadata:
  name: my-jwt-authenticator
spec:
  issuer: $PINNIPED_TEST_CLI_OIDC_ISSUER
  tls:
    certificateAuthorityData: $PINNIPED_TEST_CLI_OIDC_ISSUER_CA_BUNDLE
  audience: $PINNIPED_TEST_CLI_OIDC_CLIENT_ID
  claims:
    username: $PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME_CLAIM
    groups: $PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_GROUPS_CLAIM
EOF

# Clear the local CLI cache to ensure that commands run after this script will need to perform a fresh login.
rm -f "$HOME/.config/pinniped/sessions.yaml"
rm -f "$HOME/.config/pinniped/credentials.yaml"

# Build the CLI.
go build ./cmd/pinniped

# Use the CLI to get a kubeconfig that will use this JWTAuthenticator.
# Note that port 48095 is configured in Dex as part of the allowed redirect URI for this client.
./pinniped get kubeconfig \
  --oidc-client-id "$PINNIPED_TEST_CLI_OIDC_CLIENT_ID" \
  --oidc-scopes "openid,offline_access,$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME_CLAIM,$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_GROUPS_CLAIM" \
  --oidc-listen-port 48095 \
  >kubeconfig-jwtauthenticator.yaml

echo "When prompted for username and password, use these values:"
echo "    OIDC Username: $PINNIPED_TEST_CLI_OIDC_USERNAME"
echo "    OIDC Password: $PINNIPED_TEST_CLI_OIDC_PASSWORD"
echo

echo "To log in using OIDC, run:"
echo "PINNIPED_DEBUG=true ./pinniped whoami --kubeconfig ./kubeconfig-jwtauthenticator.yaml"
echo
