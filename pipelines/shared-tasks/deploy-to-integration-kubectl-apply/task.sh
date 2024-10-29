#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# extract_env takes a JSON object representing an client.authentication.k8s.io/v1beta1
# exec credential config (as parameter $1) and pulls out the env var value for the
# provided name (as parameter $2).
function extract_env_value() {
  filter=".env[] | select(.name==\"$2\") | .value"
  echo "$1" | jq -r "$filter"
}

function print_or_redact_doc() {
  doc_kind=$(echo "$1" | awk '/^kind: / {print $2}')
  if [[ -z "$doc_kind" ]]; then
    echo "warning: <empty kind>"
  elif [[ $doc_kind == "Secret" || $doc_kind == "secret" ]]; then
    echo
    echo "---"
    echo "<SECRET REDACTED>"
  else
    printf "%s\n" "$1"
  fi
}

function print_redacted_manifest() {
  doc=""
  while IFS="" read -r line || [ -n "$line" ]; do
    if [[ $line == "---" ]]; then
      if [[ -n "$doc" ]]; then
        print_or_redact_doc "$doc"
      fi
      doc=""
    fi
    doc=$(printf "%s\n%s" "$doc" "$line")
  done <"$1"

  print_or_redact_doc "$doc"
}

export KUBECONFIG="$PWD/cluster-pool/metadata"

# See https://github.com/concourse/registry-image-resource#in-fetch-the-images-rootfs-and-metadata
export IMAGE_DIGEST="$(cat ci-build-image/digest)"
export IMAGE_REPO="$(cat ci-build-image/repository)"

CLUSTER_CAPABILITIES_PATH="$PWD/$CLUSTER_CAPABILITIES_PATH"
if [ -n "$CLUSTER_CAPABILITIES" ]; then
  echo "$CLUSTER_CAPABILITIES" >/tmp/cluster-capabilities.yaml
  CLUSTER_CAPABILITIES_PATH=/tmp/cluster-capabilities.yaml
fi

concierge_app_name=${PINNIPED_CONCIERGE_APP_NAME:-"pinniped-concierge"}
concierge_namespace=${concierge_app_name}
concierge_custom_labels="{myConciergeCustomLabelName: myConciergeCustomLabelValue}"
supervisor_app_name=${PINNIPED_SUPERVISOR_APP_NAME:-"pinniped-supervisor"}
supervisor_namespace=${supervisor_app_name}
supervisor_custom_labels="{mySupervisorCustomLabelName: mySupervisorCustomLabelValue}"
discovery_url="${PINNIPED_DISCOVERY_URL:-null}"
manifest=/tmp/manifest.yaml

test_username="test-username"
test_groups="test-group-0,test-group-1"
set +o pipefail
test_password="$(cat /dev/urandom | env LC_CTYPE=C tr -dc 'a-z0-9' | fold -w 32 | head -n 1)"
set -o pipefail
if [[ ${#test_password} -ne 32 ]]; then
  log_error "Could not create random test user password"
  exit 1
fi
test_user_token="${test_username}:${test_password}"

# Print for debugging
kubectl config current-context
kubectl version
kubectl cluster-info

dex_test_password="${PINNIPED_DEX_TEST_USER_PASSWORD:-$(openssl rand -hex 16)}"
ldap_test_password="${PINNIPED_LDAP_TEST_USER_PASSWORD:-$(openssl rand -hex 16)}"

# deploy local user authenticator
pushd pinniped/deploy/local-user-authenticator >/dev/null
echo "Creating install-local-user-authenticator.yaml..."
ytt --file . \
    --data-value "image_repo=$IMAGE_REPO" \
    --data-value "image_digest=${IMAGE_DIGEST:-}" \
    --data-value "image_tag=${IMAGE_TAG:-}" >../../../deployment-yamls/install-local-user-authenticator.yaml
popd
pushd deployment-yamls >/dev/null
echo "Deploying local user authenticator to the cluster..."
kubectl apply -f install-local-user-authenticator.yaml
kubectl wait --for=condition=available --timeout=60s -n local-user-authenticator deployments/local-user-authenticator

# Always create a secret.
echo "Creating test user '$test_username'..."
kubectl create secret generic "$test_username" \
  --namespace local-user-authenticator \
  --from-literal=groups="$test_groups" \
  --from-literal=passwordHash="$(htpasswd -nbBC 10 x "$test_password" | sed -e "s/^x://")" \
  --dry-run=client \
  --output yaml |
  kubectl apply -f -

# Override the TMC webhook settings to use the local-user-authenticator instead
webhook_url="https://local-user-authenticator.local-user-authenticator.svc.cluster.local/authenticate"

# Sometimes the local-user-authenticator pod hasn't generated the serving certificate yet, so we poll until it has.
set +o pipefail
while ! kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator >/dev/null; do
  echo "Waiting for local-user-authenticator Secret to be created..."
  sleep 1
done
set -o pipefail

webhook_ca_bundle="$(kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator -o 'jsonpath={.data.caCertificate}')"

popd >/dev/null

# always deploy dex
#
# Deploy tools
#
pushd pinniped/test/deploy/tools >/dev/null

test_supervisor_upstream_oidc_callback_url="https://${supervisor_app_name}-clusterip.${supervisor_namespace}.svc.cluster.local/some/path/callback"

supervisor_redirect_uris="[
          ${test_supervisor_upstream_oidc_callback_url}
      ]"

echo "Deploying Tools to the cluster..."
ytt --file . \
  --data-value-yaml "supervisor_redirect_uris=${supervisor_redirect_uris}" \
  --data-value "pinny_ldap_password=$ldap_test_password" \
  --data-value "pinny_bcrypt_passwd_hash=$(htpasswd -nbBC 10 x "$dex_test_password" | sed -e "s/^x://")" \
  >"$manifest"

echo
echo "Full Tools manifest with Secrets redacted..."
echo "--------------------------------------------------------------------------------"
print_redacted_manifest $manifest
echo "--------------------------------------------------------------------------------"
echo

set -x
kapp deploy --yes --app tools --diff-changes --file "$manifest"
{ set +x; } 2>/dev/null

dex_ca_bundle="$(kubectl get secrets -n tools certs -o go-template='{{index .data "ca.pem" | base64decode}}' | base64)"
pinniped_test_tools_namespace="tools"
test_cli_oidc_callback_url="http://127.0.0.1:48095/callback"
test_cli_oidc_client_id="pinniped-cli"
test_cli_oidc_issuer_ca_bundle="${dex_ca_bundle}"
test_cli_oidc_issuer="https://dex.tools.svc.cluster.local/dex"
test_cli_oidc_password="${dex_test_password}"
test_cli_oidc_username="pinny@example.com"
test_proxy="http://127.0.0.1:12346"
test_supervisor_upstream_oidc_client_id="pinniped-supervisor"
test_supervisor_upstream_oidc_client_secret="pinniped-supervisor-secret"
test_supervisor_upstream_oidc_additional_scopes="offline_access,email"
test_supervisor_upstream_oidc_username_claim="email"
test_supervisor_upstream_oidc_groups_claim="groups"
test_supervisor_upstream_oidc_issuer_ca_bundle="${dex_ca_bundle}"
test_supervisor_upstream_oidc_issuer="https://dex.tools.svc.cluster.local/dex"
test_supervisor_upstream_oidc_password="${dex_test_password}"
test_supervisor_upstream_oidc_username="pinny@example.com"
test_supervisor_upstream_oidc_groups="" # Dex's local user store does not let us configure groups.
pinniped_test_ldap_host="ldap.tools.svc.cluster.local"
pinniped_test_ldap_starttls_only_host="ldapstarttls.tools.svc.cluster.local"
pinniped_test_ldap_ldaps_ca_bundle="${dex_ca_bundle}"
pinniped_test_ldap_bind_account_username="cn=admin,dc=pinniped,dc=dev"
pinniped_test_ldap_bind_account_password=password
pinniped_test_ldap_users_search_base="ou=users,dc=pinniped,dc=dev"
pinniped_test_ldap_groups_search_base="ou=groups,dc=pinniped,dc=dev"
pinniped_test_ldap_user_dn="cn=pinny,ou=users,dc=pinniped,dc=dev"
pinniped_test_ldap_user_cn="pinny"
pinniped_test_ldap_user_password=${ldap_test_password}
pinniped_test_ldap_user_unique_id_attribute_name="uidNumber"
pinniped_test_ldap_user_unique_id_attribute_value="1000"
pinniped_test_ldap_user_email_attribute_name="mail"
pinniped_test_ldap_user_email_attribute_value="pinny.ldap@example.com"
pinniped_test_ldap_expected_direct_groups_dn="cn=ball-game-players,ou=beach-groups,ou=groups,dc=pinniped,dc=dev;cn=seals,ou=groups,dc=pinniped,dc=dev"
pinniped_test_ldap_expected_indirect_groups_dn="cn=pinnipeds,ou=groups,dc=pinniped,dc=dev;cn=mammals,ou=groups,dc=pinniped,dc=dev"
pinniped_test_ldap_expected_direct_groups_cn="ball-game-players;seals"
pinniped_test_ldap_expected_direct_posix_groups_cn="ball-game-players-posix;seals-posix"
pinniped_test_ldap_expected_indirect_groups_cn="pinnipeds;mammals"

popd >/dev/null

# deploy concierge
pushd pinniped/deploy/concierge >/dev/null
echo "Creating concierge deployment yamls..."
ytt --file . \
  --data-value "app_name=$concierge_app_name" \
  --data-value "namespace=$concierge_namespace" \
  --data-value "image_repo=$IMAGE_REPO" \
  --data-value "image_digest=${IMAGE_DIGEST:-}" \
  --data-value "image_tag=${IMAGE_TAG:-}" \
  --data-value-yaml "image_pull_dockerconfigjson=${IMAGE_PULL_SECRET:-}" \
  --data-value "api_serving_certificate_duration_seconds=${API_SERVING_CERT_DURATION:-2592000}" \
  --data-value "api_serving_certificate_renew_before_seconds=${API_SERVING_CERT_RENEW_BEFORE:-2160000}" \
  --data-value "log_level=debug" \
  --data-value-yaml "custom_labels=$concierge_custom_labels" \
  --data-value "discovery_url=$discovery_url" >../../../deployment-yamls/install-pinniped-concierge.yaml

popd
pushd deployment-yamls >/dev/null

# create the two yaml files for kubectl based on the kapp one with everything in it
yq eval 'select(.kind == "CustomResourceDefinition" or .kind == "Namespace" or .kind == "ServiceAccount")' install-pinniped-concierge.yaml >install-pinniped-concierge-crds.yaml
yq eval 'select(.kind != "CustomResourceDefinition" and .kind != "Namespace" and .kind != "ServiceAccount")' install-pinniped-concierge.yaml > install-pinniped-concierge-resources.yaml

set -x
echo "Deploying concierge crds to the cluster..."
kubectl apply -f install-pinniped-concierge-crds.yaml
kubectl wait --for condition="established" --timeout=60s crd -l app=pinniped-concierge
echo "Deploying concierge resources to the cluster..."
kubectl apply -f install-pinniped-concierge-resources.yaml
kubectl wait --for condition="available" --timeout=60s -n pinniped-concierge deployments/pinniped-concierge

# deploy supervisor

# set ytt values related to ingress.
supervisor_ytt_service_flags=()

# We assume we are running on
# kind, and therefore expect to talk to the supervisor via NodePort and ClusterIP services.
# This nodePort is the same port number is hardcoded in the port forwarding of our kind configuration.
supervisor_ytt_service_flags+=("--data-value-yaml=service_https_nodeport_port=443")
supervisor_ytt_service_flags+=("--data-value-yaml=service_https_nodeport_nodeport=31243")
supervisor_ytt_service_flags+=("--data-value-yaml=service_https_clusterip_port=443")

popd

pushd pinniped/deploy/supervisor >/dev/null
echo "Creating install-pinniped-supervisor.yaml..."
ytt --file . \
  --data-value "app_name=$supervisor_app_name" \
  --data-value "namespace=$supervisor_namespace" \
  --data-value "image_repo=$IMAGE_REPO" \
  --data-value "image_digest=${IMAGE_DIGEST:-}" \
  --data-value "image_tag=${IMAGE_TAG:-}" \
  --data-value-yaml "image_pull_dockerconfigjson=${IMAGE_PULL_SECRET:-}" \
  --data-value "log_level=debug" \
  --data-value-yaml "custom_labels=$supervisor_custom_labels" \
  "${supervisor_ytt_service_flags[@]}" \
  >../../../deployment-yamls/install-pinniped-supervisor.yaml
popd
pushd deployment-yamls >/dev/null

echo "Deploying supervisor to the cluster..."
kubectl apply -f install-pinniped-supervisor.yaml
kubectl wait --for condition="available" --timeout=60s -n pinniped-supervisor deployments/pinniped-supervisor
popd >/dev/null
set +x

# When we test on kind, we use "kubectl port-forward" in the task script to expose these ports for the integration tests.
supervisor_https_address='https://localhost:12344'
supervisor_https_ingress_address=
supervisor_https_ingress_ca_bundle=

#
# Set up the integration test env vars
#
pinniped_cluster_capability_file_content=$(cat "pinniped/test/cluster_capabilities/kind.yaml")

cat <<EOF >/tmp/integration-test-env
export PINNIPED_TEST_TOOLS_NAMESPACE='${pinniped_test_tools_namespace}'
export PINNIPED_TEST_CONCIERGE_NAMESPACE='${concierge_namespace}'
export PINNIPED_TEST_CONCIERGE_APP_NAME='${concierge_app_name}'
export PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS='${concierge_custom_labels}'
export PINNIPED_TEST_USER_USERNAME='${test_username}'
export PINNIPED_TEST_USER_GROUPS='${test_groups}'
export PINNIPED_TEST_USER_TOKEN='${test_user_token}'
export PINNIPED_TEST_WEBHOOK_ENDPOINT='${webhook_url}'
export PINNIPED_TEST_WEBHOOK_CA_BUNDLE='${webhook_ca_bundle}'
export PINNIPED_TEST_SUPERVISOR_NAMESPACE='${supervisor_namespace}'
export PINNIPED_TEST_SUPERVISOR_APP_NAME='${supervisor_app_name}'
export PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS='${supervisor_custom_labels}'
export PINNIPED_TEST_SUPERVISOR_HTTPS_ADDRESS='${supervisor_https_address}'
export PINNIPED_TEST_SUPERVISOR_HTTPS_INGRESS_ADDRESS='${supervisor_https_ingress_address}'
export PINNIPED_TEST_SUPERVISOR_HTTPS_INGRESS_CA_BUNDLE='${supervisor_https_ingress_ca_bundle}'
export PINNIPED_TEST_PROXY='${test_proxy}'
export PINNIPED_TEST_LDAP_HOST='${pinniped_test_ldap_host}'
export PINNIPED_TEST_LDAP_STARTTLS_ONLY_HOST='${pinniped_test_ldap_starttls_only_host}'
export PINNIPED_TEST_LDAP_LDAPS_CA_BUNDLE='${pinniped_test_ldap_ldaps_ca_bundle}'
export PINNIPED_TEST_LDAP_BIND_ACCOUNT_USERNAME='${pinniped_test_ldap_bind_account_username}'
export PINNIPED_TEST_LDAP_BIND_ACCOUNT_PASSWORD='${pinniped_test_ldap_bind_account_password}'
export PINNIPED_TEST_LDAP_USERS_SEARCH_BASE='${pinniped_test_ldap_users_search_base}'
export PINNIPED_TEST_LDAP_GROUPS_SEARCH_BASE='${pinniped_test_ldap_groups_search_base}'
export PINNIPED_TEST_LDAP_USER_DN='${pinniped_test_ldap_user_dn}'
export PINNIPED_TEST_LDAP_USER_CN='${pinniped_test_ldap_user_cn}'
export PINNIPED_TEST_LDAP_USER_PASSWORD='${pinniped_test_ldap_user_password}'
export PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_NAME='${pinniped_test_ldap_user_unique_id_attribute_name}'
export PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_VALUE='${pinniped_test_ldap_user_unique_id_attribute_value}'
export PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_NAME='${pinniped_test_ldap_user_email_attribute_name}'
export PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_VALUE='${pinniped_test_ldap_user_email_attribute_value}'
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_GROUPS_DN='${pinniped_test_ldap_expected_direct_groups_dn}'
export PINNIPED_TEST_LDAP_EXPECTED_INDIRECT_GROUPS_DN='${pinniped_test_ldap_expected_indirect_groups_dn}'
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_GROUPS_CN='${pinniped_test_ldap_expected_direct_groups_cn}'
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_POSIX_GROUPS_CN='${pinniped_test_ldap_expected_direct_posix_groups_cn}'
export PINNIPED_TEST_LDAP_EXPECTED_INDIRECT_GROUPS_CN='${pinniped_test_ldap_expected_indirect_groups_cn}'
export PINNIPED_TEST_CLI_OIDC_CALLBACK_URL='${test_cli_oidc_callback_url}'
export PINNIPED_TEST_CLI_OIDC_CLIENT_ID='${test_cli_oidc_client_id}'
export PINNIPED_TEST_CLI_OIDC_ISSUER_CA_BUNDLE='${test_cli_oidc_issuer_ca_bundle}'
export PINNIPED_TEST_CLI_OIDC_ISSUER='${test_cli_oidc_issuer}'
export PINNIPED_TEST_CLI_OIDC_PASSWORD='${test_cli_oidc_password}'
export PINNIPED_TEST_CLI_OIDC_USERNAME='${test_cli_oidc_username}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CALLBACK_URL='${test_supervisor_upstream_oidc_callback_url}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ADDITIONAL_SCOPES='${test_supervisor_upstream_oidc_additional_scopes}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME_CLAIM='${test_supervisor_upstream_oidc_username_claim}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_GROUPS_CLAIM='${test_supervisor_upstream_oidc_groups_claim}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_ID='${test_supervisor_upstream_oidc_client_id}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_SECRET='${test_supervisor_upstream_oidc_client_secret}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER_CA_BUNDLE='${test_supervisor_upstream_oidc_issuer_ca_bundle}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER='${test_supervisor_upstream_oidc_issuer}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_PASSWORD='${test_supervisor_upstream_oidc_password}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME='${test_supervisor_upstream_oidc_username}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_EXPECTED_GROUPS='${test_supervisor_upstream_oidc_groups}'
export PINNIPED_TEST_SHELL_CONTAINER_IMAGE="ghcr.io/pinniped-ci-bot/test-kubectl:latest"

read -r -d '' PINNIPED_TEST_CLUSTER_CAPABILITY_YAML << PINNIPED_TEST_CLUSTER_CAPABILITY_YAML_EOF || true
${pinniped_cluster_capability_file_content}
PINNIPED_TEST_CLUSTER_CAPABILITY_YAML_EOF

export PINNIPED_TEST_CLUSTER_CAPABILITY_YAML
EOF

# Copy the env vars file that was output by the previous script which are needed during integration tests
cp /tmp/integration-test-env integration-test-env-vars/
cp "$KUBECONFIG" kubeconfig/kubeconfig
cp "$PWD/cluster-pool/name" kubeconfig/cluster-name
