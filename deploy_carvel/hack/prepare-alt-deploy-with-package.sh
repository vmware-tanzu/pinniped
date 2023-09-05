#!/usr/bin/env bash

#
# This script is intended to be used with:
# - $repo_root/hack/prepare-for-integration-test.sh --alternate-deploy deploy_carvel/prepare-alt-deploy-with-package.sh
# and originated with the following:
# - https://github.com/jvanzyl/pinniped-charts/blob/main/alternate-deploy-helm
# along with this PR to pinniped:
# - https://github.com/vmware-tanzu/pinniped/pull/1028
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

# two vars will be received by this script:
# Received: local-user-authenticator
# Received: D00A4537-80F1-4AF2-A3B3-5F20BDBB9AEB
log_note "passed this invocation:"
app=${1}
# tag is fed in from the prepare-for-integration-tests.sh script, just uuidgen to identify a
# specific docker build of the pinniped-server image.
tag=${2}

if [ "${app}" = "local-user-authenticator" ]; then
  #
  # TODO: continue on from here.
  #   get this to install correctly, exaclty as it did before
  #   and then do the rest?
  # OR TODO: correct the $alternate_deploy issue by creating 3 new flags:
  #   $alternate_deploy-supervisor
  #   $alternate_deploy-concierge
  #   $alternate_deploy-local-user-authenticator
  #
  # TODO step 1: test to ensure current change did not break the script!
  #
  log_note "🦄 🦄 🦄 where are we?!?!?"
  pwd
  log_note "Deploying the local-user-authenticator app to the cluster using kapp..."
  ytt --file . \
    --data-value "image_repo=$registry_repo" \
    --data-value "image_tag=$tag" >"$manifest"

  kapp deploy --yes --app local-user-authenticator --diff-changes --file "$manifest"
  kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
fi

if [ "${app}" = "pinniped-supervisor" ]; then
#  helm upgrade pinniped-supervisor charts/pinniped-supervisor \
#    --install \
#    --values source/pinniped-supervisor/values-lit.yaml \
#    --set image.version=${tag} \
#    --namespace supervisor \
#    --create-namespace \
#    --atomic
#    --atomic
  log_note "ignoring supervisor, so sad........."
fi

if [ "${app}" = "pinniped-concierge" ]; then
#  discovery_url="$(TERM=dumb kubectl cluster-info | awk '/master|control plane/ {print $NF}')"
#  helm upgrade pinniped-concierge charts/pinniped-concierge \
#    --install \
#    --values source/pinniped-concierge/values-lit.yaml \
#    --set image.version=${tag} \
#    --set config.discovery.url=${discovery_url} \
#    --set config.logLevel="debug" \
#    --namespace concierge \
#    --create-namespace \
#    --atomic
  log_note "ignoring concierge, so sad........."
fi
