#!/usr/bin/env bash

# Copyright 2021 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# A script to perform the setup required to manually test using the supervisor on a kind cluster.
# Assumes that you installed the apps already using hack/prepare-for-integration-tests.sh.
#
# This uses the Supervisor and Concierge in the same cluster. Usually the Supervisor would be
# deployed in one cluster while each workload cluster would have a Concierge. All the workload
# cluster Concierge configurations would be similar to each other, all trusting the same Supervisor.
#
# Depends on `step` which can be installed by `brew install step` on MacOS.
#

set -euo pipefail

# Change working directory to the top of the repo.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Read the env vars output by hack/prepare-for-integration-tests.sh
source /tmp/integration-test-env

# Choose some filenames.
root_ca_crt_path=root_ca.crt
root_ca_key_path=root_ca.key
tls_crt_path=tls.crt
tls_key_path=tls.key

# Choose an audience name for the Concierge.
audience="my-workload-cluster-$(openssl rand -hex 4)"

# These settings align with how the Dex redirect URI is configured by hack/prepare-for-integration-tests.sh.
# Note that this hostname can only be resolved inside the cluster, so we will use a web proxy running inside
# the cluster whenever we want to be able to connect to it.
issuer_host="pinniped-supervisor-clusterip.supervisor.svc.cluster.local"
issuer="https://$issuer_host/some/path"

# Create a CA and TLS serving certificates for the Supervisor.
step certificate create \
  "Supervisor CA" "$root_ca_crt_path" "$root_ca_key_path" \
  --profile root-ca \
  --no-password --insecure --force
step certificate create \
  "$issuer_host" "$tls_crt_path" "$tls_key_path" \
  --profile leaf \
  --not-after 8760h \
  --ca "$root_ca_crt_path" --ca-key "$root_ca_key_path" \
  --no-password --insecure --force

# Put the TLS certificate into a Secret for the Supervisor.
kubectl create secret tls -n "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" my-federation-domain-tls --cert "$tls_crt_path" --key "$tls_key_path" \
  --dry-run=client --output yaml | kubectl apply -f -

# Make a FederationDomain using the TLS Secret from above.
cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" -f -
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: FederationDomain
metadata:
  name: my-federation-domain
spec:
  issuer: $issuer
  tls:
    secretName: my-federation-domain-tls
EOF

echo "Waiting for FederationDomain to initialize..."
sleep 5

# Test that the federation domain is working before we proceed.
echo "Fetching FederationDomain discovery info..."
https_proxy="$PINNIPED_TEST_PROXY" curl -fLsS --cacert "$root_ca_crt_path" "$issuer/.well-known/openid-configuration" | jq .

# Make an OIDCIdentityProvider which uses Dex to provide identity.
cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" -f -
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  name: my-oidc-provider
spec:
  issuer: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER"
  tls:
    certificateAuthorityData: "$(echo "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER_CA_BUNDLE" | base64)"
  authorizationConfig:
    additionalScopes: [ ${PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ADDITIONAL_SCOPES} ]
  claims:
    username: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME_CLAIM"
    groups: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_GROUPS_CLAIM"
  client:
    secretName: my-oidc-provider-client-secret
EOF

# Make a Secret for the above OIDCIdentityProvider to describe the OIDC client configured in Dex.
cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" -f -
apiVersion: v1
kind: Secret
metadata:
  name: my-oidc-provider-client-secret
stringData:
  clientID: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_ID"
  clientSecret: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_SECRET"
type: "secrets.pinniped.dev/oidc-client"
EOF

# Grant the test user some RBAC permissions so we can play with kubectl as that user.
kubectl create clusterrolebinding test-user-can-view --clusterrole view \
  --user "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME" \
  --dry-run=client --output yaml | kubectl apply -f -

# Make a JWTAuthenticator which respects JWTs from the Supervisor's issuer.
# The issuer URL must be accessible from within the cluster for OIDC discovery.
cat <<EOF | kubectl apply -f -
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: JWTAuthenticator
metadata:
  name: my-jwt-authenticator
spec:
  issuer: $issuer
  audience: $audience
  tls:
    certificateAuthorityData: $(cat "$root_ca_crt_path" | base64)
EOF

echo "Waiting for JWTAuthenticator to initialize..."
# Our integration tests wait 10 seconds, so use that same value here.
sleep 10

# Compile the CLI.
go build ./cmd/pinniped

# Use the CLI to get the kubeconfig. Tell it that you don't want the browser to automatically open for logins.
./pinniped get kubeconfig --oidc-skip-browser >kubeconfig

# Clear the local CLI cache to ensure that the kubectl command below will need to perform a fresh login.
rm -f "$HOME"/.config/pinniped/sessions.yaml

echo
echo "Ready! 🚀"
echo "To be able to access the login URL shown below, start Chrome like this:"
echo "    open -a \"Google Chrome\" --args --proxy-server=\"$PINNIPED_TEST_PROXY\""
echo "Then use these credentials at the Dex login page:"
echo "    Username: $PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME"
echo "    Password: $PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_PASSWORD"

# Perform a login using the kubectl plugin. This should print the URL to be followed for the Dex login page.
echo
echo "Running: https_proxy=\"$PINNIPED_TEST_PROXY\" no_proxy=\"127.0.0.1\" kubectl --kubeconfig ./kubeconfig get pods -A"
https_proxy="$PINNIPED_TEST_PROXY" no_proxy="127.0.0.1" kubectl --kubeconfig ./kubeconfig get pods -A

# Print the identity of the currently logged in user. The CLI has cached your tokens, and will automatically refresh
# your short-lived credentials whenever they expire, so you should not be prompted to log in again for the rest of the day.
echo
echo "Running: https_proxy=\"$PINNIPED_TEST_PROXY\" no_proxy=\"127.0.0.1\" ./pinniped whoami --kubeconfig ./kubeconfig"
https_proxy="$PINNIPED_TEST_PROXY" no_proxy="127.0.0.1" ./pinniped whoami --kubeconfig ./kubeconfig
