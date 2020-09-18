#!/usr/bin/env bash

# This script can be used to prepare a kind cluster and deploy the app.
# You can call this script again to redeploy the app.
# It will also output instructions on how to run the integration.

set -euo pipefail

#
# Helper functions
#
function log_note() {
  GREEN='\033[0;32m'
  NC='\033[0m'
  if [[ $COLORTERM =~ ^(truecolor|24bit)$ ]]; then
    echo -e "${GREEN}$*${NC}"
  else
    echo "$*"
  fi
}

function log_error() {
  RED='\033[0;31m'
  NC='\033[0m'
  if [[ $COLORTERM =~ ^(truecolor|24bit)$ ]]; then
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

# Require kubectl >= 1.18.x
if [ "$(kubectl version --client=true --short | cut -d '.' -f 2)" -lt 18 ]; then
  echo "kubectl >= 1.18.x is required, you have $(kubectl version --client=true --short | cut -d ':' -f2)"
  exit 1
fi

#
# Setup kind and build the app
#
log_note "Checking for running kind clusters..."
if ! kind get clusters | grep -q -e '^kind$'; then
  log_note "Creating a kind cluster..."
  kind create cluster
else
  if ! kubectl cluster-info | grep master | grep -q 127.0.0.1; then
    log_error "Seems like your kubeconfig is not targeting a local cluster."
    log_error "Exiting to avoid accidentally running tests against a real cluster."
    exit 1
  fi
fi

registry="docker.io"
repo="test/build"
registry_repo="$registry/$repo"
tag=$(uuidgen) # always a new tag to force K8s to reload the image on redeploy

if [[ "$skip_build" == "yes" ]]; then
  most_recent_tag=$(docker images "$repo" --format "{{.Tag}}" | head -1)
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
kind load docker-image "$registry_repo_tag"

manifest=/tmp/manifest.yaml

#
# Deploy local-user-authenticator
#
pushd deploy-local-user-authenticator >/dev/null

log_note "Deploying the local-user-authenticator app to the cluster..."
ytt --file . \
  --data-value "image_repo=$registry_repo" \
  --data-value "image_tag=$tag" >"$manifest"

kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
kapp deploy --yes --app local-user-authenticator --diff-changes --file "$manifest"

popd >/dev/null

test_username="test-username"
test_groups="test-group-0,test-group-1"
set +o pipefail
test_password="$(cat /dev/urandom | env LC_CTYPE=C tr -dc 'a-z0-9' | fold -w 32 | head -n 1)"
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

app_name="pinniped"
namespace="integration"
webhook_url="https://local-user-authenticator.local-user-authenticator.svc/authenticate"
webhook_ca_bundle="$(kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator -o 'jsonpath={.data.caCertificate}')"
discovery_url="$(TERM=dumb kubectl cluster-info | awk '/Kubernetes master/ {print $NF}')"

#
# Deploy Pinniped
#
pushd deploy >/dev/null

log_note "Deploying the Pinniped app to the cluster..."
ytt --file . \
  --data-value "app_name=$app_name" \
  --data-value "namespace=$namespace" \
  --data-value "image_repo=$registry_repo" \
  --data-value "image_tag=$tag" \
  --data-value "webhook_url=$webhook_url" \
  --data-value "webhook_ca_bundle=$webhook_ca_bundle" \
  --data-value "discovery_url=$discovery_url" >"$manifest"

kapp deploy --yes --app "$app_name" --diff-changes --file "$manifest"

popd >/dev/null

#
# Create the environment file
#
kind_capabilities_file="$pinniped_path/test/cluster_capabilities/kind.yaml"
pinniped_cluster_capability_file_content=$(cat "$kind_capabilities_file")

cat <<EOF >/tmp/integration-test-env
# The following env vars should be set before running 'go test -v -count 1 ./test/...'
export PINNIPED_NAMESPACE=${namespace}
export PINNIPED_APP_NAME=${app_name}
export PINNIPED_TEST_USER_USERNAME=${test_username}
export PINNIPED_TEST_USER_GROUPS=${test_groups}
export PINNIPED_TEST_USER_TOKEN=${test_username}:${test_password}

read -r -d '' PINNIPED_CLUSTER_CAPABILITY_YAML << PINNIPED_CLUSTER_CAPABILITY_YAML_EOF || true
${pinniped_cluster_capability_file_content}
PINNIPED_CLUSTER_CAPABILITY_YAML_EOF

export PINNIPED_CLUSTER_CAPABILITY_YAML
EOF

#
# Print instructions for next steps
#
goland_vars=$(grep -v '^#' /tmp/integration-test-env | grep -E '^export .+=' | sed 's/export //g' | tr '\n' ';')

log_note
log_note "🚀 Ready to run integration tests! For example..."
log_note "    cd $pinniped_path"
log_note '    source /tmp/integration-test-env && go test -v -count 1 ./test/...'
log_note
log_note 'Want to run integration tests in GoLand? Copy/paste this "Environment" value for GoLand run configurations:'
log_note "    ${goland_vars}PINNIPED_CLUSTER_CAPABILITY_FILE=${kind_capabilities_file}"
log_note
log_note "You can rerun this script to redeploy local production code changes while you are working."
log_note
log_note "To delete the deployments, run 'kapp delete -a local-user-authenticator -y && kapp delete -a pinniped -y'."
log_note "When you're finished, use 'kind delete cluster' to tear down the cluster."
