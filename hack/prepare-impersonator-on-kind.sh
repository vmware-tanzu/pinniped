#!/usr/bin/env bash

# Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# A script to perform the setup required to manually test using the impersonation proxy on a kind cluster.
# Assumes that you installed the apps already using hack/prepare-for-integration-tests.sh.
#

set -euo pipefail

# The name of the namespace in which the concierge is installed.
CONCIERGE_NAMESPACE=concierge
# The name of the concierge app's Deployment.
CONCIERGE_DEPLOYMENT=pinniped-concierge
# The namespace in which the local-user-authenticator app is installed.
LOCAL_USER_AUTHENTICATOR_NAMESPACE=local-user-authenticator
# The port on which the impersonation proxy runs in the concierge pods.
IMPERSONATION_PROXY_PORT=8444
# The port that we will use to access the impersonator from outside the cluster via `kubectl port-forward`.
LOCAL_PORT=8777
LOCAL_HOST="127.0.0.1:${LOCAL_PORT}"

# Change working directory to the top of the repo.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

source hack/lib/helpers.sh

# Build the CLI for use later in the script.
go build ./cmd/pinniped

# Create a test user and password.
if ! kubectl get secret pinny-the-seal --namespace $LOCAL_USER_AUTHENTICATOR_NAMESPACE; then
  kubectl create secret generic pinny-the-seal --namespace $LOCAL_USER_AUTHENTICATOR_NAMESPACE \
    --from-literal=groups=group1,group2 \
    --from-literal=passwordHash="$(htpasswd -nbBC 10 x password123 | sed -e "s/^x://")"
fi

# Get the CA of the local-user-authenticator.
LOCAL_USER_AUTHENTICATOR_CA=$(kubectl get secret local-user-authenticator-tls-serving-certificate \
  --namespace $LOCAL_USER_AUTHENTICATOR_NAMESPACE \
  -o jsonpath=\{.data.caCertificate\})

# Create a WebhookAuthenticator which points at the local-user-authenticator.
cat <<EOF | kubectl apply -f -
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: WebhookAuthenticator
metadata:
  name: local-user-authenticator
spec:
  endpoint: https://local-user-authenticator.local-user-authenticator.svc.cluster.local/authenticate
  tls:
    certificateAuthorityData: $LOCAL_USER_AUTHENTICATOR_CA
EOF

# Create an RBAC rule to allow the test user to do most things.
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name:  pinny-the-seal-can-edit
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
subjects:
- kind: User
  name: pinny-the-seal
EOF

# Create a configmap to enable the impersonation proxy and set the endpoint to match the
# host and port that we will use the access the impersonation proxy (via the port-forwarded port).
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: pinniped-concierge-impersonation-proxy-config
  namespace: $CONCIERGE_NAMESPACE
data:
  config.yaml: |
    endpoint: ${LOCAL_HOST}
    mode: enabled
EOF

# Wait for the CredentialIssuer's impersonator status to update to be successful.
while [[ -z "$(kubectl get credentialissuer pinniped-concierge-config -o json |
  jq '.status.strategies[] | select((.type=="ImpersonationProxy") and (.status=="Success"))')" ]]; do
  log_note "Waiting for a successful ImpersonationProxy strategy on CredentialIssuer..."
  sleep 2
done
log_note "Impersonator is available on https://${LOCAL_HOST}"

# Make the impersonation proxy's port from the inside the cluster available locally.
kubectl port-forward -n $CONCIERGE_NAMESPACE deployment/$CONCIERGE_DEPLOYMENT ${LOCAL_PORT}:${IMPERSONATION_PROXY_PORT} &
port_forward_pid=$!

# Kill the kubectl port-forward command whenever the script is control-c cancelled or otherwise ends.
function cleanup() {
  echo
  log_note "Cleaning up cluster resources..."
  kubectl delete secret -n $LOCAL_USER_AUTHENTICATOR_NAMESPACE pinny-the-seal
  kubectl delete configmap -n $CONCIERGE_NAMESPACE pinniped-concierge-impersonation-proxy-config
  kubectl delete clusterrolebinding pinny-the-seal-can-edit
  kubectl delete webhookauthenticator local-user-authenticator
  log_note "Stopping kubectl port-forward and exiting..."
  # It may have already shut down, so ignore errors.
  kill -9 $port_forward_pid &>/dev/null || true
}
trap cleanup EXIT

# Get a working kubeconfig that will send requests through the impersonation proxy.
./pinniped get kubeconfig \
  --static-token "pinny-the-seal:password123" \
  --concierge-mode ImpersonationProxy >/tmp/kubeconfig

log_note
log_note 'Ready. In another tab, use "kubectl --kubeconfig /tmp/kubeconfig <cmd>" to make requests through the impersonation proxy.'
log_note "When done, cancel with ctrl-C to clean up."
wait $port_forward_pid
