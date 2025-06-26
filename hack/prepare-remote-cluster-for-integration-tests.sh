#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Assuming that you have somehow got your hands on a remote GKE or kind cluster,
# and that you have an admin kubeconfig file for it,
# and that you have already built/pushed the Pinniped container image that you would like to test,
# then you can use this script to deploy in preparation for integration or manual testing.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

#
# Handle argument parsing and help message
#
help=no
kubeconfig=""
image_tag=""
image_repo=""
pinniped_repo=""
cluster_type=""
image_digest=""

while (("$#")); do
  case "$1" in
  -h | --help)
    help=yes
    shift
    ;;
  -k | --kubeconfig)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "-k|--kubeconfig requires a kubeconfig path to be specified"
      exit 1
    fi
    kubeconfig=$1
    shift
    ;;
  -t | --image-tag)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "-t|--image-tag requires a tag to be specified"
      exit 1
    fi
    image_tag=$1
    shift
    ;;
  -d | --image-digest)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "--d|--image-digest requires a digest to be specified"
      exit 1
    fi
    image_digest=$1
    shift
    ;;
  -r | --image-repo)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "-r|--image-repo requires an image repo to be specified"
      exit 1
    fi
    image_repo=$1
    shift
    ;;
  -p | --pinniped-repo)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "-p|--pinniped-repo requires a path to the pinniped repo to be specified"
      exit 1
    fi
    pinniped_repo=$1
    shift
    ;;
  -c | --cluster-type)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "-c|--cluster-type requires the type of the cluster to be specified"
      exit 1
    fi
    cluster_type=$1
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

# Note that if you are using a remote kind cluster then it might be more convenient to use this public repo:
#   ghcr.io/pinniped-ci-bot/manual-test-pinniped-images
# You can give yourself permission to push to that repo at:
#   https://github.com/users/pinniped-ci-bot/packages/container/manual-test-pinniped-images/settings
default_image_repo="gcr.io/$PINNIPED_GCP_PROJECT/manual-test-pinniped-images"
default_image_tag="latest"

if [[ "$help" == "yes" ]]; then
  me="$(basename "${BASH_SOURCE[0]}")"
  log_note "Usage:"
  log_note "   $me [flags]"
  log_note
  log_note "Flags:"
  log_note "   -h, --help:              print this usage"
  log_note "   -k, --kubeconfig:        path to the kubeconfig for your cluster (required)"
  log_note "   -c, --cluster-type:      the type of cluster targeted by the kubeconfig, either 'gke' or 'kind' (required)"
  log_note "   -r, --image-repo:        image registry/repository for Pinniped server container image to deploy (default: $default_image_repo)"
  log_note "   -t, --image-tag:         image tag for Pinniped server container image to deploy (default: $default_image_tag)"
  log_note "   -d, --image-digest:      image digest for Pinniped server container image to deploy. Takes precedence over --image-tag."
  log_note "   -p, --pinniped-repo:     path to pinniped git repo (default: a sibling directory called pinniped)"
  exit 1
fi

if [[ "$kubeconfig" == "" ]]; then
  log_error "no kubeconfig set. -k|--kubeconfig is a required option."
  exit 1
fi

if [[ "$kubeconfig" != "/"* ]]; then
  # If it looks like a relative path then make an an absolute path because we are going to pushd below.
  kubeconfig="$(pwd)/$kubeconfig"
fi

if [[ ! -f "$kubeconfig" ]]; then
  log_error "specified kubeconfig file does not exist: $kubeconfig"
  exit 1
fi

if [[ "$cluster_type" != "gke" && "$cluster_type" != "kind" && "$cluster_type" != "aks" && "$cluster_type" != "eks" ]]; then
  log_error "specified cluster type must be 'kind', 'eks', 'aks', or 'gke'. -c|--cluster-type is a required option."
  exit 1
fi

if [[ "$pinniped_repo" == "" ]]; then
  pinniped_repo="$ROOT/../pinniped"
  log_note "no pinniped repo path set, defaulting to $pinniped_repo"
fi

if [[ ! (-d "$pinniped_repo" && -d "$pinniped_repo/deploy" && -d "$pinniped_repo/test/cluster_capabilities") ]]; then
  log_error "$pinniped_repo does not appear to contain the pinniped source code repo"
fi

if [[ "$image_repo" == "" ]]; then
  image_repo="$default_image_repo"
  log_note "no image repo set, defaulting to $image_repo"
fi

if [[ "$image_tag" == "" ]]; then
  image_tag="$default_image_tag"
  log_note "no image tag set, defaulting to $image_tag"
fi

cluster_capabilities_path="$pinniped_repo/test/cluster_capabilities/$cluster_type.yaml"
if [[ ! -f "$cluster_capabilities_path" ]]; then
  log_error "cluster type capabilities file does not exist: $cluster_capabilities_path"
  exit 1
fi

check_dependency ytt "Please install ytt. e.g. 'brew tap k14s/tap && brew install ytt' for MacOS"
check_dependency kapp "Please install kapp. e.g. 'brew tap k14s/tap && brew install kapp' for MacOS"
check_dependency kubectl "Please install kubectl. e.g. 'brew install kubectl' for MacOS"
check_dependency htpasswd "Please install htpasswd. Should be pre-installed on MacOS. Usually found in 'apache2-utils' package for linux."
check_dependency openssl "Please install openssl. Should be pre-installed on MacOS."
check_dependency nmap "Please install nmap. e.g. 'brew install nmap' for MacOS"

#
# Finished checking arguments and dependencies. Now actually do the work...
#
export KUBECONFIG="$kubeconfig"
export IMAGE_TAG="$image_tag"
export IMAGE_REPO="$image_repo"
if [[ "$image_digest" != "" ]]; then
  export IMAGE_DIGEST="$image_digest"
fi

pushd "$pinniped_repo" >/dev/null

PINNIPED_TEST_CLUSTER_CAPABILITY_FILE="${cluster_capabilities_path}" \
  DEPLOY_LOCAL_USER_AUTHENTICATOR=yes \
  DEPLOY_TEST_TOOLS=yes \
  CONCIERGE_APP_NAME="concierge" \
  CONCIERGE_NAMESPACE="concierge" \
  SUPERVISOR_APP_NAME="supervisor" \
  SUPERVISOR_NAMESPACE="supervisor" \
  USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR="yes" \
  "$ROOT/pipelines/shared-helpers/prepare-cluster-for-integration-tests.sh"

popd >/dev/null

log_note
log_note "🚀 Ready to run integration tests! For example..."

case "$cluster_type" in
gke | aks | eks)
  log_note "KUBECONFIG='$KUBECONFIG' TEST_ENV_PATH='/tmp/integration-test-env' SOURCE_PATH='$pinniped_repo' $ROOT/pipelines/shared-tasks/run-integration-tests/task.sh"
  ;;
kind)
  log_note "KUBECONFIG='$KUBECONFIG' TEST_ENV_PATH='/tmp/integration-test-env' SOURCE_PATH='$pinniped_repo' START_GCLOUD_PROXY=yes GCP_PROJECT=$PINNIPED_GCP_PROJECT GCP_ZONE=us-west1-a $ROOT/pipelines/shared-tasks/run-integration-tests/task.sh"
  ;;
*)
  log_error "Huh? Should never get here."
  ;;
esac
