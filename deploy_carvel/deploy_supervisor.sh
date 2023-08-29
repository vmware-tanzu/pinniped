#!/usr/bin/env bash

# https://gist.github.com/mohanpedala/1e2ff5661761d3abd0385e8223e16425
set -e # immediately exit
set -u # error if variables undefined
set -o pipefail # prevent masking errors in a pipeline
# set -x # print all executed commands to terminal


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
DEFAULT='\033[0m'

echo_yellow() {
    echo -e "${YELLOW}>> $@${DEFAULT}\n"
    # printf "${GREEN}$@${DEFAULT}"
}

echo_green() {
    echo -e "${GREEN}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}
echo_red() {
    echo -e "${RED}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}
echo_blue() {
    echo -e "${BLUE}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}

# borrowed from /tmp/integration-test-env
# TODO: make new scripts work with the old script?
# or how to ensure we can install both
# - the old way, ytt or plain yamls
# - the new way, with the PackageRepository and Packages
# export PINNIPED_TEST_SUPERVISOR_NAMESPACE=supervisor
PINNIPED_TEST_SUPERVISOR_NAMESPACE=default
# export PINNIPED_TEST_PROXY=http://127.0.0.1:12346
PINNIPED_TEST_PROXY=http://127.0.0.1:12346

# from here forward borrowed from ${repo_root}/hack/prepare-supervisor-on-kind.sh

# NOPE! Not running this script, so we have to pull the env vars ourselves
# however, we can run it against another kind cluster and take a look at it to make sure
# we understand what the contents are
# Read the env vars output by hack/prepare-for-integration-tests.sh
# source /tmp/integration-test-env

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
# Sleeping is a race, but that's probably good enough for the purposes of this script.
sleep 5

# Test that the federation domain is working before we proceed.
echo "Fetching FederationDomain discovery info..."
echo "$PINNIPED_TEST_PROXY - curl -fLsS --cacert $root_ca_crt_path $issuer/.well-known/openid-configuration"
https_proxy="$PINNIPED_TEST_PROXY" curl -fLsS --cacert "$root_ca_crt_path" "$issuer/.well-known/openid-configuration" | jq .
