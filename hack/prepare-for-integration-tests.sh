#!/usr/bin/env bash

# This script can be used to prepare a kind cluster and deploy the app.
# You can call this script again to redeploy the app.
# It will also output instructions on how to run the integration.

set -euo pipefail

#
# Helper functions
#
TILT_MODE=${TILT_MODE:-no}
function tilt_mode() {
  if [[ "$TILT_MODE" == "yes" ]]; then
    return 0
  fi
  return 1
}

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
check_dependency chromedriver "Please install chromedriver. e.g. 'brew install chromedriver' for MacOS"

# Require kubectl >= 1.18.x
if [ "$(kubectl version --client=true --short | cut -d '.' -f 2)" -lt 18 ]; then
  log_error "kubectl >= 1.18.x is required, you have $(kubectl version --client=true --short | cut -d ':' -f2)"
  exit 1
fi

if ! tilt_mode; then
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
    docker build . --tag "$registry_repo_tag"
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
  # Deploy dex
  #
  pushd test/deploy/dex >/dev/null

  log_note "Deploying Dex to the cluster..."
  ytt --file . >"$manifest"
  ytt --file . \
    --data-value-yaml "supervisor_redirect_uris=[https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/callback]" \
    >"$manifest"

  kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
  kapp deploy --yes --app dex --diff-changes --file "$manifest"

  popd >/dev/null
fi

test_username="test-username"
test_groups="test-group-0,test-group-1"
set +o pipefail
test_password="$(cat /dev/urandom | env LC_ALL=C tr -dc 'a-z0-9' | fold -w 32 | head -n 1)"
set -o pipefail
if [[ ${#test_password} -ne 32 ]]; then
  log_error "Could not create test user's random password"
  exit 1
fi
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

if ! tilt_mode; then
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
fi

#
# Deploy the Pinniped Concierge
#
concierge_app_name="pinniped-concierge"
concierge_namespace="concierge"
webhook_url="https://local-user-authenticator.local-user-authenticator.svc/authenticate"
webhook_ca_bundle="$(kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator -o 'jsonpath={.data.caCertificate}')"
discovery_url="$(TERM=dumb kubectl cluster-info | awk '/master|control plane/ {print $NF}')"
concierge_custom_labels="{myConciergeCustomLabelName: myConciergeCustomLabelValue}"

if ! tilt_mode; then
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
fi

#
# Download the test CA bundle that was generated in the Dex pod.
#
test_ca_bundle_pem="$(kubectl get secrets -n dex certs -o go-template='{{index .data "ca.pem" | base64decode}}')"

#
# Create the environment file
#
kind_capabilities_file="$pinniped_path/test/cluster_capabilities/kind.yaml"
pinniped_cluster_capability_file_content=$(cat "$kind_capabilities_file")

cat <<EOF >/tmp/integration-test-env
# The following env vars should be set before running 'go test -v -count 1 ./test/integration'
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
export PINNIPED_TEST_CLI_OIDC_ISSUER=https://dex.dex.svc.cluster.local/dex
export PINNIPED_TEST_CLI_OIDC_ISSUER_CA_BUNDLE="${test_ca_bundle_pem}"
export PINNIPED_TEST_CLI_OIDC_CLIENT_ID=pinniped-cli
export PINNIPED_TEST_CLI_OIDC_CALLBACK_URL=http://127.0.0.1:48095/callback
export PINNIPED_TEST_CLI_OIDC_USERNAME=pinny@example.com
export PINNIPED_TEST_CLI_OIDC_PASSWORD=password
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER=https://dex.dex.svc.cluster.local/dex
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER_CA_BUNDLE="${test_ca_bundle_pem}"
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ADDITIONAL_SCOPES=email
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME_CLAIM=email
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_GROUPS_CLAIM=groups
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_ID=pinniped-supervisor
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_SECRET=pinniped-supervisor-secret
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CALLBACK_URL=https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/callback
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME=pinny@example.com
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_PASSWORD=password
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_EXPECTED_GROUPS= # Dex's local user store does not let us configure groups.
export PINNIPED_TEST_API_GROUP_SUFFIX='${api_group_suffix}'

read -r -d '' PINNIPED_TEST_CLUSTER_CAPABILITY_YAML << PINNIPED_TEST_CLUSTER_CAPABILITY_YAML_EOF || true
${pinniped_cluster_capability_file_content}
PINNIPED_TEST_CLUSTER_CAPABILITY_YAML_EOF

export PINNIPED_TEST_CLUSTER_CAPABILITY_YAML
EOF

#
# Print instructions for next steps
#
goland_vars=$(grep -v '^#' /tmp/integration-test-env | grep -E '^export .+=' | sed 's/export //g' | tr '\n' ';')

log_note
log_note "🚀 Ready to run integration tests! For example..."
log_note "    cd $pinniped_path"
log_note '    source /tmp/integration-test-env && go test -v -race -count 1 ./test/integration'
log_note
log_note 'Want to run integration tests in GoLand? Copy/paste this "Environment" value for GoLand run configurations:'
log_note "    ${goland_vars}PINNIPED_TEST_CLUSTER_CAPABILITY_FILE=${kind_capabilities_file}"
log_note

if ! tilt_mode; then
  log_note "You can rerun this script to redeploy local production code changes while you are working."
  log_note
  log_note "To delete the deployments, run:"
  log_note "  kapp delete -a local-user-authenticator -y && kapp delete -a $concierge_app_name -y &&  kapp delete -a $supervisor_app_name -y"
  log_note "When you're finished, use './hack/kind-down.sh' to tear down the cluster."
fi
