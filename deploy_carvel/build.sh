#!/usr/bin/env bash

set -e # immediately exit
set -u # error if variables undefined
set -o pipefail # prevent masking errors in a pipeline
# set -x # print all executed commands to terminal

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

app="${1:-undefined}"
tag="${2:-undefined}"
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
log_note "log-args.sh >>> script dir: ${SCRIPT_DIR}"
log_note "log-args.sh >>> app: ${app} tag: ${tag}"
exit 1

# Build the PackageRepository and Package resources
# - container images
# - yaml files
# Deploy the container images to a registry
# No need for a running cluster
#
# TODO: final resting place for these images (PackageRepository, Packge) will need to
# be in the same plate as our regular images:
# - https://github.com/vmware-tanzu/pinniped/releases/tag/v0.25.0
# namely docker.io/getpinniped/ and projects.registry.vmware.com/pinniped/
#
PACKAGE_REPO_HOST="benjaminapetersen/pinniped-package-repo"
# TODO: this variable is currently a little quirky as our values.yaml files do NOT pin pinniped to a specific
# hard-coded version.  Rather, Pinniped's values.yaml allows for a passed-in version.
PINNIPED_PACKAGE_VERSION="0.25.0"

# TODO: should we copy these directories:
# - ../deploy/supervisor/config/*
# - ../deploy/concierge/config/*
# rather than duplicating the files?
# in this exercise, I have transformed the values.yaml into a "values schema" so this would have to be
# migrated up.  There are some incompatibilities here, in that a values schema assesses the type of value
# by the default.  currently many of the values have no actual default.

log_note "Cleaning ./package-repository to generate new..."
PACKAGE_REPOSITORY_DIR="package-repository"
rm -rf "./${PACKAGE_REPOSITORY_DIR}"
mkdir -p "./${PACKAGE_REPOSITORY_DIR}/.imgpkg"
mkdir -p "./${PACKAGE_REPOSITORY_DIR}/packages/concierge.pinniped.dev"
mkdir -p "./${PACKAGE_REPOSITORY_DIR}/packages/supervisor.pinniped.dev"


log_note "Generating PackageRepository and Packages for Pinniped version ${PINNIPED_PACKAGE_VERSION}"
declare -a arr=("supervisor" "concierge")
for resource_name in "${arr[@]}"
do
  log_note "Generating for ${resource_name}..."

  log_note "Generating ${resource_name} imgpkg lock file... ${resource_name}/.imgpkg/images.yaml"
  kbld --file "./${resource_name}/config/" --imgpkg-lock-output "./${resource_name}/.imgpkg/images.yml"

  # generate a schema in each package directory
  log_note "Generating ${resource_name} OpenAPIv3 Schema... ./${resource_name}/schema-openapi.yaml"
  ytt \
    --file "${resource_name}/config/values.yaml" \
    --data-values-schema-inspect --output openapi-v3 > "${resource_name}/schema-openapi.yml"

  # TODO: this is not the pattern we want.
  # final resting place should be with our primary Pinniped image at:
  # - projects.registry.vmware.com/pinniped/pinniped-server:v0.25.0	VMware Harbor
  # - docker.io/getpinniped/pinniped-server:v0.25.0	DockerHub
  package_push_repo_location="${PACKAGE_REPO_HOST}-package-${resource_name}:${PINNIPED_PACKAGE_VERSION}"
  log_note "Pushing ${resource_name} package image: ${package_push_repo_location} ..."
  imgpkg push --bundle "${package_push_repo_location}" --file "./${resource_name}"

  resource_package_version="${resource_name}.pinniped.dev"
  log_note "Generating ${resource_name} PackageRepository yaml..."
  log_note "generating ./${PACKAGE_REPOSITORY_DIR}/packages/${resource_package_version}/${PINNIPED_PACKAGE_VERSION}.yml"
  ytt \
    --file "${resource_name}/package-template.yml" \
    --data-value-file openapi="$(pwd)/${resource_name}/schema-openapi.yml" \
    --data-value package_version="${PINNIPED_PACKAGE_VERSION}" \
    --data-value package_image_repo="${package_push_repo_location}" > "${PACKAGE_REPOSITORY_DIR}/packages/${resource_package_version}/${PINNIPED_PACKAGE_VERSION}.yml"

  log_note "generating ./${PACKAGE_REPOSITORY_DIR}/packages/${resource_package_version}/metadata.yml"
  ytt \
    --file "${resource_name}/metadata.yml" \
    --data-value-file openapi="$(pwd)/${resource_name}/schema-openapi.yml" \
    --data-value package_version="${PINNIPED_PACKAGE_VERSION}" \
    --data-value package_image_repo="${package_push_repo_location}" > "${PACKAGE_REPOSITORY_DIR}/packages/${resource_package_version}/metadata.yml"

done

log_note "Generating Pinniped PackageRepository..."
log_note "Generating ./${PACKAGE_REPOSITORY_DIR}/.imgpkg/images.yml"
kbld --file "./${PACKAGE_REPOSITORY_DIR}/packages/" --imgpkg-lock-output "${PACKAGE_REPOSITORY_DIR}/.imgpkg/images.yml"
package_repository_push_repo_location="${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"
log_note "Pushing Pinniped package repository image: ${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}..."
imgpkg push --bundle "${package_repository_push_repo_location}" --file "./${PACKAGE_REPOSITORY_DIR}"

# handy for a quick debug
# log_note "Validating imgpkg package bundle contents..."
# imgpkg pull --bundle "${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}" --output "/tmp/${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"
# ls -la "/tmp/${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"


log_note "Generating PackageRepository yaml file..."
PINNIPED_PACKGE_REPOSITORY_NAME="pinniped-package-repository"
PINNIPED_PACKGE_REPOSITORY_FILE="packagerepository.${PINNIPED_PACKAGE_VERSION}.yml"
echo -n "" > "${PINNIPED_PACKGE_REPOSITORY_FILE}"

cat <<EOT >> "${PINNIPED_PACKGE_REPOSITORY_FILE}"
---
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageRepository
metadata:
  name: "${PINNIPED_PACKGE_REPOSITORY_NAME}"
spec:
  fetch:
    imgpkgBundle:
      image: "${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"
EOT

log_note "To deploy the PackageRepository, run 'kapp deploy --app pinniped-repo --file ${PINNIPED_PACKGE_REPOSITORY_FILE}'"
log_note "Or use the sibling deploy.sh script"
