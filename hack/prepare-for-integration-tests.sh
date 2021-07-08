#!/usr/bin/env bash

# Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script can be used to prepare a kind cluster and deploy the app.
# You can call this script again to redeploy the app.
# It will also output instructions on how to run the integration.
#

set -euo pipefail

#
# Helper functions
#
function log_note() {
  GREEN='\033[0;32m'
  NC='\033[0m'
  if [[ ${COLORTERM:-unknown} =~ ^(truecolor|24bit)$ ]]; then
    echo -e "${GREEN}$*${NC}"
  else
    echo "$*"
  fi
}

function log_error() {
  RED='\033[0;31m'
  NC='\033[0m'
  if [[ ${COLORTERM:-unknown} =~ ^(truecolor|24bit)$ ]]; then
    echo -e "🙁${RED} Error: $* ${NC}"
  else
    echo ":( Error: $*"
  fi
}

function check_dependency() {
  if ! command -v "$1" >/dev/null; then
    log_error "Missing dependency..."
    log_error "$2"
    exit 1
  fi
}

#
# Handle argument parsing and help message
#
help=no
skip_build=no
clean_kind=no
api_group_suffix="pinniped.dev" # same default as in the values.yaml ytt file
skip_chromedriver_check=no
test_active_directory=no

while (("$#")); do
  case "$1" in
  -h | --help)
    help=yes
    shift
    ;;
  -s | --skip-build)
    skip_build=yes
    shift
    ;;
  -c | --clean)
    clean_kind=yes
    shift
    ;;
  -g | --api-group-suffix)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "-g|--api-group-suffix requires a group name to be specified"
      exit 1
    fi
    api_group_suffix=$1
    shift
    ;;
  --live-dangerously)
    skip_chromedriver_check=yes
    shift
    ;;
  --test-active-directory)
    test_active_directory=yes
    shift
    ;;
  -*)
    log_error "Unsupported flag $1" >&2
    exit 1
    ;;
  *)
    log_error "Unsupported positional arg $1" >&2
    exit 1
    ;;
  esac
done

if [[ "$help" == "yes" ]]; then
  me="$(basename "${BASH_SOURCE[0]}")"
  log_note "Usage:"
  log_note "   $me [flags]"
  log_note
  log_note "Flags:"
  log_note "   -h, --help:              print this usage"
  log_note "   -c, --clean:             destroy the current kind cluster and make a new one"
  log_note "   -g, --api-group-suffix:  deploy Pinniped with an alternate API group suffix"
  log_note "   -s, --skip-build:        reuse the most recently built image of the app instead of building"
  exit 1
fi

pinniped_path="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$pinniped_path" || exit 1

#
# Check for dependencies
#
check_dependency docker "Please install docker. See https://docs.docker.com/get-docker"
check_dependency kind "Please install kind. e.g. 'brew install kind' for MacOS"
check_dependency ytt "Please install ytt. e.g. 'brew tap k14s/tap && brew install ytt' for MacOS"
check_dependency kapp "Please install kapp. e.g. 'brew tap k14s/tap && brew install kapp' for MacOS"
check_dependency kubectl "Please install kubectl. e.g. 'brew install kubectl' for MacOS"
check_dependency htpasswd "Please install htpasswd. Should be pre-installed on MacOS. Usually found in 'apache2-utils' package for linux."
check_dependency openssl "Please install openssl. Should be pre-installed on MacOS."
check_dependency chromedriver "Please install chromedriver. e.g. 'brew install chromedriver' for MacOS"

# Check that Chrome and chromedriver versions match. If chromedriver falls a couple versions behind
# then usually tests start to fail with strange error messages.
if [[ "$skip_chromedriver_check" == "no" ]]; then
  if [[ "$OSTYPE" == "darwin"* ]]; then
    chrome_version=$(/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --version | cut -d ' ' -f3 | cut -d '.' -f1)
  else
    chrome_version=$(google-chrome --version | cut -d ' ' -f3 | cut -d '.' -f1)
  fi
  chromedriver_version=$(chromedriver --version | cut -d ' ' -f2 | cut -d '.' -f1)
  if [[ "$chrome_version" != "$chromedriver_version" ]]; then
    log_error "It appears that you are using Chrome $chrome_version with chromedriver $chromedriver_version."
    log_error "Please use the same version of chromedriver as Chrome."
    log_error "If you are using the latest version of Chrome, then you can upgrade"
    log_error "to the latest chromedriver, e.g. 'brew upgrade chromedriver' on MacOS."
    log_error "Feeling lucky? Add --live-dangerously to skip this check."
    exit 1
  fi
fi

# Require kubectl >= 1.18.x
if [ "$(kubectl version --client=true --short | cut -d '.' -f 2)" -lt 18 ]; then
  log_error "kubectl >= 1.18.x is required, you have $(kubectl version --client=true --short | cut -d ':' -f2)"
  exit 1
fi

if [[ "$clean_kind" == "yes" ]]; then
  log_note "Deleting running kind cluster to prepare from a clean slate..."
  ./hack/kind-down.sh
fi

#
# Setup kind and build the app
#
log_note "Checking for running kind cluster..."
if ! kind get clusters | grep -q -e '^pinniped$'; then
  log_note "Creating a kind cluster..."
  # Our kind config exposes node port 31234 as 127.0.0.1:12345, 31243 as 127.0.0.1:12344, and 31235 as 127.0.0.1:12346
  ./hack/kind-up.sh
else
  if ! kubectl cluster-info | grep -E '(master|control plane)' | grep -q 127.0.0.1; then
    log_error "Seems like your kubeconfig is not targeting a local cluster."
    log_error "Exiting to avoid accidentally running tests against a real cluster."
    exit 1
  fi
fi

registry="pinniped.local"
repo="test/build"
registry_repo="$registry/$repo"
tag=$(uuidgen) # always a new tag to force K8s to reload the image on redeploy

if [[ "$skip_build" == "yes" ]]; then
  most_recent_tag=$(docker images "$registry/$repo" --format "{{.Tag}}" | head -1)
  if [[ -n "$most_recent_tag" ]]; then
    tag="$most_recent_tag"
    do_build=no
  else
    # Oops, there was no previous build. Need to build anyway.
    do_build=yes
  fi
else
  do_build=yes
fi

registry_repo_tag="${registry_repo}:${tag}"

if [[ "$do_build" == "yes" ]]; then
  # Rebuild the code
  log_note "Docker building the app..."
  # DOCKER_BUILDKIT=1 is optional on MacOS but required on linux.
  DOCKER_BUILDKIT=1 docker build . --tag "$registry_repo_tag"
fi

# Load it into the cluster
log_note "Loading the app's container image into the kind cluster..."
kind load docker-image "$registry_repo_tag" --name pinniped

manifest=/tmp/manifest.yaml

#
# Deploy local-user-authenticator
#
pushd deploy/local-user-authenticator >/dev/null

log_note "Deploying the local-user-authenticator app to the cluster..."
ytt --file . \
  --data-value "image_repo=$registry_repo" \
  --data-value "image_tag=$tag" >"$manifest"

kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
kapp deploy --yes --app local-user-authenticator --diff-changes --file "$manifest"

popd >/dev/null

#
# Deploy Tools
#
dex_test_password="$(openssl rand -hex 16)"
ldap_test_password="$(openssl rand -hex 16)"
pushd test/deploy/tools >/dev/null

log_note "Deploying Tools to the cluster..."
ytt --file . \
  --data-value-yaml "supervisor_redirect_uris=[https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/callback]" \
  --data-value "pinny_ldap_password=$ldap_test_password" \
  --data-value "pinny_bcrypt_passwd_hash=$(htpasswd -nbBC 10 x "$dex_test_password" | sed -e "s/^x://")" \
  >"$manifest"

kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
kapp deploy --yes --app tools --diff-changes --file "$manifest"

popd >/dev/null

test_username="test-username"
test_groups="test-group-0,test-group-1"
test_password="$(openssl rand -hex 16)"
log_note "Creating test user '$test_username'..."
kubectl create secret generic "$test_username" \
  --namespace local-user-authenticator \
  --from-literal=groups="$test_groups" \
  --from-literal=passwordHash="$(htpasswd -nbBC 10 x "$test_password" | sed -e "s/^x://")" \
  --dry-run=client \
  --output yaml |
  kubectl apply -f -

#
# Deploy the Pinniped Supervisor
#
supervisor_app_name="pinniped-supervisor"
supervisor_namespace="supervisor"
supervisor_custom_labels="{mySupervisorCustomLabelName: mySupervisorCustomLabelValue}"

pushd deploy/supervisor >/dev/null

log_note "Deploying the Pinniped Supervisor app to the cluster..."
ytt --file . \
  --data-value "app_name=$supervisor_app_name" \
  --data-value "namespace=$supervisor_namespace" \
  --data-value "api_group_suffix=$api_group_suffix" \
  --data-value "image_repo=$registry_repo" \
  --data-value "image_tag=$tag" \
  --data-value "log_level=debug" \
  --data-value-yaml "custom_labels=$supervisor_custom_labels" \
  --data-value-yaml 'service_http_nodeport_port=80' \
  --data-value-yaml 'service_http_nodeport_nodeport=31234' \
  --data-value-yaml 'service_https_nodeport_port=443' \
  --data-value-yaml 'service_https_nodeport_nodeport=31243' \
  --data-value-yaml 'service_https_clusterip_port=443' \
  >"$manifest"

kapp deploy --yes --app "$supervisor_app_name" --diff-changes --file "$manifest"

popd >/dev/null

#
# Deploy the Pinniped Concierge
#
concierge_app_name="pinniped-concierge"
concierge_namespace="concierge"
webhook_url="https://local-user-authenticator.local-user-authenticator.svc/authenticate"
webhook_ca_bundle="$(kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator -o 'jsonpath={.data.caCertificate}')"
discovery_url="$(TERM=dumb kubectl cluster-info | awk '/master|control plane/ {print $NF}')"
concierge_custom_labels="{myConciergeCustomLabelName: myConciergeCustomLabelValue}"

pushd deploy/concierge >/dev/null

log_note "Deploying the Pinniped Concierge app to the cluster..."
ytt --file . \
  --data-value "app_name=$concierge_app_name" \
  --data-value "namespace=$concierge_namespace" \
  --data-value "api_group_suffix=$api_group_suffix" \
  --data-value "log_level=debug" \
  --data-value-yaml "custom_labels=$concierge_custom_labels" \
  --data-value "image_repo=$registry_repo" \
  --data-value "image_tag=$tag" \
  --data-value "discovery_url=$discovery_url" >"$manifest"

kapp deploy --yes --app "$concierge_app_name" --diff-changes --file "$manifest"

popd >/dev/null

#
# Download the test CA bundle that was generated in the Dex pod.
# Note that this returns a base64 encoded value.
#
test_ca_bundle_pem="$(kubectl get secrets -n tools certs -o go-template='{{index .data "ca.pem"}}')"

#
# Create the environment file.
#
# Note that all values should not contains newlines, except for PINNIPED_TEST_CLUSTER_CAPABILITY_YAML,
# so that the environment can also be used in tools like GoLand. Therefore, multi-line values,
# such as PEM-formatted certificates, should be base64 encoded.
#
kind_capabilities_file="$pinniped_path/test/cluster_capabilities/kind.yaml"
pinniped_cluster_capability_file_content=$(cat "$kind_capabilities_file")

cat <<EOF >/tmp/integration-test-env
# The following env vars should be set before running 'go test -v -count 1 -timeout 0 ./test/integration'
export PINNIPED_TEST_TOOLS_NAMESPACE="tools"
export PINNIPED_TEST_CONCIERGE_NAMESPACE=${concierge_namespace}
export PINNIPED_TEST_CONCIERGE_APP_NAME=${concierge_app_name}
export PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS='${concierge_custom_labels}'
export PINNIPED_TEST_USER_USERNAME=${test_username}
export PINNIPED_TEST_USER_GROUPS=${test_groups}
export PINNIPED_TEST_USER_TOKEN=${test_username}:${test_password}
export PINNIPED_TEST_WEBHOOK_ENDPOINT=${webhook_url}
export PINNIPED_TEST_WEBHOOK_CA_BUNDLE=${webhook_ca_bundle}
export PINNIPED_TEST_SUPERVISOR_NAMESPACE=${supervisor_namespace}
export PINNIPED_TEST_SUPERVISOR_APP_NAME=${supervisor_app_name}
export PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS='${supervisor_custom_labels}'
export PINNIPED_TEST_SUPERVISOR_HTTP_ADDRESS="127.0.0.1:12345"
export PINNIPED_TEST_SUPERVISOR_HTTPS_ADDRESS="localhost:12344"
export PINNIPED_TEST_PROXY=http://127.0.0.1:12346
export PINNIPED_TEST_LDAP_HOST=ldap.tools.svc.cluster.local
export PINNIPED_TEST_LDAP_STARTTLS_ONLY_HOST=ldapstarttls.tools.svc.cluster.local
export PINNIPED_TEST_LDAP_LDAPS_CA_BUNDLE="${test_ca_bundle_pem}"
export PINNIPED_TEST_LDAP_BIND_ACCOUNT_USERNAME="cn=admin,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_BIND_ACCOUNT_PASSWORD=password
export PINNIPED_TEST_LDAP_USERS_SEARCH_BASE="ou=users,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_GROUPS_SEARCH_BASE="ou=groups,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_USER_DN="cn=pinny,ou=users,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_USER_CN="pinny"
export PINNIPED_TEST_LDAP_USER_PASSWORD=${ldap_test_password}
export PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_NAME="uidNumber"
export PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_VALUE="1000"
export PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_NAME="mail"
export PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_VALUE="pinny.ldap@example.com"
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_GROUPS_DN="cn=ball-game-players,ou=beach-groups,ou=groups,dc=pinniped,dc=dev;cn=seals,ou=groups,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_EXPECTED_INDIRECT_GROUPS_DN="cn=pinnipeds,ou=groups,dc=pinniped,dc=dev;cn=mammals,ou=groups,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_GROUPS_CN="ball-game-players;seals"
export PINNIPED_TEST_LDAP_EXPECTED_INDIRECT_GROUPS_CN="pinnipeds;mammals"
export PINNIPED_TEST_CLI_OIDC_ISSUER=https://dex.tools.svc.cluster.local/dex
export PINNIPED_TEST_CLI_OIDC_ISSUER_CA_BUNDLE="${test_ca_bundle_pem}"
export PINNIPED_TEST_CLI_OIDC_CLIENT_ID=pinniped-cli
export PINNIPED_TEST_CLI_OIDC_CALLBACK_URL=http://127.0.0.1:48095/callback
export PINNIPED_TEST_CLI_OIDC_USERNAME=pinny@example.com
export PINNIPED_TEST_CLI_OIDC_PASSWORD=${dex_test_password}
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER=https://dex.tools.svc.cluster.local/dex
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER_CA_BUNDLE="${test_ca_bundle_pem}"
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ADDITIONAL_SCOPES=email
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME_CLAIM=email
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_GROUPS_CLAIM=groups
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_ID=pinniped-supervisor
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_SECRET=pinniped-supervisor-secret
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CALLBACK_URL=https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/callback
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME=pinny@example.com
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_PASSWORD=${dex_test_password}
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_EXPECTED_GROUPS= # Dex's local user store does not let us configure groups.
export PINNIPED_TEST_API_GROUP_SUFFIX='${api_group_suffix}'

if [[ "$test_active_directory" == "yes" ]]; then

if [[ -z "$(gcloud config list account --format "value(core.account)")" ]]; then
  echo "Please run \`gcloud auth login\`"
  exit 1
fi

export PINNIPED_TEST_AD_HOST="$(gcloud secrets versions access latest --secret="concourse-secrets" --project tanzu-user-authentication | yq e '.aws-ad-host' -))"
export PINNIPED_TEST_AD_BIND_ACCOUNT_USERNAME="$(gcloud secrets versions access latest --secret="concourse-secrets" --project tanzu-user-authentication | yq e '.aws-ad-bind-account-username' -))"
export PINNIPED_TEST_AD_BIND_ACCOUNT_PASSWORD="$(gcloud secrets versions access latest --secret="concourse-secrets" --project tanzu-user-authentication | yq e '.aws-ad-bind-account-password' -)"
export PINNIPED_TEST_AD_USER_UNIQUE_ID_ATTRIBUTE_NAME="objectGUID"
export PINNIPED_TEST_AD_USER_UNIQUE_ID_ATTRIBUTE_VALUE="$(gcloud secrets versions access latest --secret="concourse-secrets" --project tanzu-user-authentication | yq e '.aws-ad-user-unique-id-attribute-value' -)"
export PINNIPED_TEST_AD_USERNAME_ATTRIBUTE_NAME="sAMAccountName"
export PINNIPED_TEST_AD_USERNAME_ATTRIBUTE_VALUE="$(gcloud secrets versions access latest --secret="concourse-secrets" --project tanzu-user-authentication | yq e '.aws-ad-user-sAMAccountName' -))"
export PINNIPED_TEST_AD_USER_PASSWORD="$(gcloud secrets versions access latest --secret="concourse-secrets" --project tanzu-user-authentication | yq e '.aws-ad-user-password' -)"
export PINNIPED_TEST_AD_LDAPS_CA_BUNDLE="$(gcloud secrets versions access latest --secret="concourse-secrets" --project tanzu-user-authentication | yq e '.aws-ad-ca-data' -))"
fi

read -r -d '' PINNIPED_TEST_CLUSTER_CAPABILITY_YAML << PINNIPED_TEST_CLUSTER_CAPABILITY_YAML_EOF || true
${pinniped_cluster_capability_file_content}
PINNIPED_TEST_CLUSTER_CAPABILITY_YAML_EOF

export PINNIPED_TEST_CLUSTER_CAPABILITY_YAML
EOF

#
# Print instructions for next steps.
#
log_note
log_note "🚀 Ready to run integration tests! For example..."
log_note "    cd $pinniped_path"
log_note '    source /tmp/integration-test-env && go test -v -race -count 1 -timeout 0 ./test/integration'
log_note
log_note "Using GoLand? Paste the result of this command into GoLand's run configuration \"Environment\"."
log_note "    hack/integration-test-env-goland.sh | pbcopy"
log_note
log_note "You can rerun this script to redeploy local production code changes while you are working."
log_note
log_note "To delete the deployments, run:"
log_note "  kapp delete -a local-user-authenticator -y && kapp delete -a $concierge_app_name -y &&  kapp delete -a $supervisor_app_name -y"
log_note "When you're finished, use './hack/kind-down.sh' to tear down the cluster."
