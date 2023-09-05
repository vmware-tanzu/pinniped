#!/usr/bin/env bash

#
# This script is intended to be used with:
# - $repo_root/hack/prepare-for-integration-test.sh --alternate-deploy $(pwd)/deploy_carvel/hack/log-args.sh
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

log_note "log-args.sh 🐳 🐳 🐳"

# two vars will be received by this script:
# Received: local-user-authenticator
# Received: D00A4537-80F1-4AF2-A3B3-5F20BDBB9AEB
log_note "passed this invocation:"
app=${1}
# tag is fed in from the prepare-for-integration-tests.sh script, just uuidgen to identify a
# specific docker build of the pinniped-server image.
tag=${2}

registry="pinniped.local"
repo="test/build"
registry_repo="$registry/$repo"


if [ "${app}" = "local-user-authenticator" ]; then
  log_note "deploy-pachage.sh: local-user-authenticator 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠"
  log_note "deploy-pachage.sh: local-user-authenticator 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠"
  log_note "deploy-pachage.sh: local-user-authenticator 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠 🐠"
  pushd deploy/local-user-authenticator >/dev/null
  manifest=/tmp/pinniped-local-user-authenticator.yaml

  ytt --file . \
    --data-value "image_repo=$registry_repo" \
    --data-value "image_tag=$tag" >"$manifest"

  kapp deploy --yes --app local-user-authenticator --diff-changes --file "$manifest"
  kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
  popd >/dev/null
fi

if [ "${app}" = "pinniped-supervisor" ]; then
  log_note "deploy-pachage.sh: supervisor 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡"
  log_note "deploy-pachage.sh: supervisor 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡"
  log_note "deploy-pachage.sh: supervisor 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡 🐡"
fi

if [ "${app}" = "pinniped-concierge" ]; then
  log_note "deploy-pachage.sh: concierge 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼"
  log_note "deploy-pachage.sh: concierge 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼"
  log_note "deploy-pachage.sh: concierge 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼 🪼"
fi
