#!/usr/bin/env bash

# This script can be used to prepare a kind cluster and deploy the app.
# You can call this script again to redeploy the app.
# It will also output instructions on how to run the integration or uninstall tests.

# TODO: get rid of references to ci repo
# TODO: fix uninstall test setup
# TODO: add flag to let user provide registry/tag for their image
# \- (this can be used by kind integration tests from kind-load-and-docker-run-any-script.sh)
# TODO: add flag to setup current-context for integration tests

set -euo pipefail

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

function log_note() {
  GREEN='\033[0;32m'
  NC='\033[0m'
  if [[ $COLORTERM =~ ^(truecolor|24bit)$ ]]; then
    echo -e "${GREEN}$*${NC}"
  else
    echo "$*"
  fi
}

function log_warning() {
  YELLOW='\033[0;33m'
  NC='\033[0m'
  if [[ $COLORTERM =~ ^(truecolor|24bit)$ ]]; then
    echo -e "😒${YELLOW} Warning: $* ${NC}"
  else
    echo ":/ Warning: $*"
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

help=no
skip_build=no
prepare_for_uninstall_test=no

PARAMS=""
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
  -u | --prepare-uninstall)
    prepare_for_uninstall_test=yes
    shift
    ;;
  -*)
    log_error "Unsupported flag $1" >&2
    exit 1
    ;;
  *)
    PARAMS="$PARAMS $1"
    shift
    ;;
  esac
done
eval set -- "$PARAMS"

if [[ "$help" == "yes" ]]; then
  me="$(basename "${BASH_SOURCE[0]}")"
  echo "Usage:"
  echo "   $me [flags] [path/to/pinniped] [path/to/pinniped-ci]"
  echo
  echo "   path/to/pinniped    default: \$PWD ($PWD)"
  echo
  echo "Flags:"
  echo "   -h, --help:              print this usage"
  echo "   -s, --skip-build:        reuse the most recently built image of the app instead of building"
  echo "   -u, --prepare-uninstall: delete the kind cluster and prepare to run the install+uninstall test"
  exit 1
fi

pinniped_path="${1-$PWD}"

if ! command -v kind >/dev/null; then
  log_error "Please install kind. e.g. 'brew install kind' for MacOS"
  exit 1
fi

if ! command -v ytt >/dev/null; then
  log_error "Please install ytt. e.g. 'brew tap k14s/tap && brew install ytt' for MacOS"
  exit 1
fi

if ! command -v kapp >/dev/null; then
  log_error "Please install kapp. e.g. 'brew tap k14s/tap && brew install kapp' for MacOS"
  exit 1
fi

if ! command -v kubectl >/dev/null; then
  log_error "Please install kubectl. e.g. 'brew install kubectl' for MacOS"
  exit 1
fi

cd "$pinniped_path" || exit 1

if [[ ! -f Dockerfile || ! -d deploy ]]; then
  log_error "$pinniped_path does not appear to be the path to the source code repo directory"
  exit 1
fi

if [[ "$prepare_for_uninstall_test" == "yes" ]]; then
  log_note "Deleting running kind clusters to prepare a clean slate for the install+uninstall test..."
  kind delete cluster
fi

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

if [[ "$prepare_for_uninstall_test" == "yes" ]]; then
  cat <<EOF >/tmp/uninstall-test-env
# The following env vars should be set before running $pinniped_ci_path/pipelines/shared-tasks/run-uninstall-test/run-uninstall-test.sh
export IMAGE_REPO="$registry_repo"
export IMAGE_TAG="$tag"
export PINNIPED_DISCOVERY_URL="$discovery_url"
EOF

  log_note "Done!"
  log_note
  log_note "Ready to run the uninstall test."
  log_note "    cd $pinniped_path"
  log_note '    source /tmp/uninstall-test-env'
  log_note "    $pinniped_ci_path/pipelines/shared-tasks/run-uninstall-test/run-uninstall-test.sh"
  log_note
  log_note "When you're finished, use 'kind delete cluster' to tear down the cluster."

else
  manifest=/tmp/manifest.yaml

  #
  # Deploy test-webhook
  #
  pushd deploy-test-webhook >/dev/null

  log_note "Deploying the test-webhook app to the cluster..."
  ytt --file . \
    --data-value "image_repo=$registry_repo" \
    --data-value "image_tag=$tag" >"$manifest"

  echo
  log_note "Full test-webhook app manifest with Secrets redacted..."
  echo "--------------------------------------------------------------------------------"
  print_redacted_manifest $manifest
  echo "--------------------------------------------------------------------------------"
  echo

  kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
  kapp deploy --yes --app test-webhook --diff-changes --file "$manifest"

  popd >/dev/null

  log_note "Creating test user 'test-username'..."
  test_username="test-username"
  # TODO AUTO-GENERATE PASSWORD
  test_password="test-password"
  test_groups="test-group-0,test-group-1"
  kubectl create secret generic "$test_username" \
    --namespace test-webhook \
    --from-literal=groups="$test_groups" \
    --from-literal=passwordHash="$(htpasswd -nbBC 10 x "$test_password" | sed -e "s/^x://")" \
    --dry-run=client \
    --output yaml \
    | kubectl apply -f -

  app_name="pinniped"
  namespace="integration"
  webhook_url="https://test-webhook.test-webhook.svc/authenticate"
  webhook_ca_bundle="$(kubectl get secret api-serving-cert --namespace test-webhook -o 'jsonpath={.data.caCertificate}')"
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

  echo
  log_note "Full Pinniped app manifest with Secrets redacted..."
  echo "--------------------------------------------------------------------------------"
  print_redacted_manifest $manifest
  echo "--------------------------------------------------------------------------------"
  echo

  kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
  kapp deploy --yes --app "$app_name" --diff-changes --file "$manifest"

  popd >/dev/null

  kind_capabilities_file="$pinniped_path/test/cluster_capabilities/kind.yaml"
  pinniped_cluster_capability_file_content=$(cat "$kind_capabilities_file")

  cat <<EOF >/tmp/integration-test-env
# The following env vars should be set before running 'cd test && go test ./...'
export PINNIPED_NAMESPACE=${namespace}
export PINNIPED_APP_NAME=${app_name}
export PINNIPED_CREDENTIAL_REQUEST_TOKEN=${test_username}:${test_password}

read -r -d '' PINNIPED_CLUSTER_CAPABILITY_YAML << PINNIPED_CLUSTER_CAPABILITY_YAML_EOF || true
${pinniped_cluster_capability_file_content}
PINNIPED_CLUSTER_CAPABILITY_YAML_EOF

export PINNIPED_CLUSTER_CAPABILITY_YAML
EOF

  goland_vars=$(grep -v '^#' /tmp/integration-test-env | grep -E '^export .+=' | sed 's/export //g' | tr '\n' ';')

  log_note "Done!"
  log_note
  log_note "Ready to run integration tests. For example, you could run all tests using the following commands..."
  log_note "    cd $pinniped_path"
  log_note '    source /tmp/integration-test-env'
  log_note '    (cd test && go test -count 1 ./...)'
  log_note
  log_note '"Environment" setting for GoLand run configurations:'
  log_note "    ${goland_vars}PINNIPED_CLUSTER_CAPABILITY_FILE=${kind_capabilities_file}"
  log_note
  log_note
  log_note "You can run this script again to deploy local production code changes while you are working."
  log_note
  log_note "When you're finished, use 'kind delete cluster' to tear down the cluster."
  log_note
  log_note "To delete the deployments, run 'kapp delete -a test-webhook -y && kapp delete -a pinniped -y'."
fi
