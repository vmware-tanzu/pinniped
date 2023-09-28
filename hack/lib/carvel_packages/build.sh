#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script can be used in conjunction with prepare-for-integration-tests.sh.
# When invoked with the PINNIPED_USE_LOCAL_KIND_REGISTRY environment variable set to a non-empty value,
# the integration tests script will create a local docker registry and configure kind to use the registry
# and will build the Pinniped binary and container image.
# This script will then create Carvel Packages for supervisor,concierge and local-user-authenticator.
# It will also create a Carvel PackageRepository.
# The PackageRepository will be installed on the kind cluster, then PackageInstall resources
# will be created to deploy an instance of each of the packages on the cluster.
# Once this script has completed, Pinniped can be interacted with as if it had been deployed in the usual way,
# for example by running tests or by preparing supervisor for manual interactions:
#  source /tmp/integration-test-env && go test -v -race -count 1 -timeout 0 ./test/integration -run  /TestE2EFullIntegration_Browser
#  hack/prepare-supervisor-on-kind.sh --oidc
#
# Example usage:
#   PINNIPED_USE_LOCAL_KIND_REGISTRY=1 ./hack/prepare-for-integration-tests.sh --clean --pre-install ./hack/lib/carvel_packages/build.sh --alternate-deploy ./hack/lib/carvel_packages/deploy.sh
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

# this script is best invoked from the root directory
# it is designed to be passed as --pre-install flag to hack/prepare-for-integration-tests.sh
hack_lib_path="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${hack_lib_path}/../../" || exit 1

# arguments provided to scripts called by hack/prepare-for-integration-tests.sh
# - app: unimportant, but always first
# - tag: uuidgen in hack/prepare-for-integration-tests.sh
#        if this script is run standalone, then auto-fill with a unique value
app=${1:-"app-argument-not-provided"}
tag=${2:-"tag-argument-not-provided"}
registry=${3:-"registry-argument-not-provided"}
repo=${4:-"repo-argument-not-provided"}

log_note "build.sh called with app: ${app} tag: ${tag} registry: ${registry} repo: ${repo}"

if [[ "${PINNIPED_USE_LOCAL_KIND_REGISTRY:-}" == "" ]]; then
  log_error "Building the Carvel package requires configuring kind with a local registry."
  log_error "please set the environment variable PINNIPED_USE_LOCAL_KIND_REGISTRY"
  log_error "for example:"
  log_error "    PINNIPED_USE_LOCAL_KIND_REGISTRY=1 ./hack/prepare-for-integration-tests.sh --clean --pre-install ./hack/lib/carvel_packages/build.sh --alternate-deploy ./hack/lib/carvel_packages/deploy.sh"
  exit 1
fi


pinniped_package_version="${tag}" # ie, "0.25.0"
registry_repo="$registry/$repo"
registry_repo_tag="${registry_repo}:${tag}"

api_group_suffix="pinniped.dev"

# Package prefix for pinniped-concierge, pinniped-supervisor, local-user-authenticator
package_repo_prefix="${registry_repo}/package" # + $resource_name + ":" + $tag

# Pinniped Package repository
package_repository_repo="pinniped-package-repository"
package_repository_repo_tag="${registry_repo}/${package_repository_repo}:${tag}"


dest_dir="deploy_carvel"
carvel_package_src="hack/lib/carvel_packages"
template_src_dir="${carvel_package_src}/tpl"


# clean the root carvel package directory
rm -rf "${dest_dir}"
mkdir "${dest_dir}"

# Generate the OpenAPI v3 Schema files, imgpkg images.yml files
declare -a packages_to_build=("local-user-authenticator" "pinniped-concierge" "pinniped-supervisor")
for resource_name in "${packages_to_build[@]}"
do
  resource_qualified_name="${resource_name}.${api_group_suffix}"
  package_repo_tag="${package_repo_prefix}-${resource_name}:${tag}"

  # sources
  resource_package_template_source_dir="${template_src_dir}/${resource_name}"
  resource_ytt_config_file_source_dir="deploy/${resource_name}" # copy from original ytt templates
  # destinations
  resource_destination_dir="${dest_dir}/${resource_name}"
  resource_config_destination_dir="${resource_destination_dir}/config"

  log_note "Copying static template files for ${resource_name}..."
  mkdir "${resource_destination_dir}"
  cp "${resource_package_template_source_dir}/metadata.yml" "${resource_destination_dir}/metadata.yml"
  cp "${resource_package_template_source_dir}/build.yml" "${resource_destination_dir}/build.yml"
  cp "${resource_package_template_source_dir}/vendir.yml" "${resource_destination_dir}/vendir.yml"
  cp "${resource_package_template_source_dir}/release_notes.txt" "${resource_destination_dir}/release_notes.txt" # dummy
  log_note "Vendir sync deploy directory for ${resource_name} to package bundle..."
  pushd "${resource_destination_dir}" > /dev/null
    vendir sync
  popd > /dev/null

  log_note "Generating OpenAPI v3 schema for ${resource_name}..."
  ytt \
    --file "${resource_config_destination_dir}" \
    --data-values-schema-inspect \
    --output openapi-v3 > \
    "${resource_destination_dir}/schema-openapi.yml"

  log_note "Generating .imgpkg/images.yml for ${resource_name}..."
  mkdir -p "${resource_destination_dir}/.imgpkg"
  ytt \
    --file "${resource_config_destination_dir}" | \
    kbld -f- --imgpkg-lock-output "${resource_destination_dir}/.imgpkg/images.yml"

  log_note "Pushing Pinniped ${resource_name} Package bundle..."
  imgpkg push --bundle "${package_repo_tag}" --file "${resource_destination_dir}"

  log_note "Generating PackageRepository Package entry for ${resource_name}"
  # publish package versions to package repository
  packages_dir="deploy_carvel/package_repository/packages/"
  package_repository_dir="${packages_dir}/${resource_qualified_name}"
  mkdir -p "${packages_dir}"
  rm -rf "${package_repository_dir}"
  mkdir "${package_repository_dir}"

  ytt \
    --file "${resource_package_template_source_dir}/package-template.yml" \
    --data-value-file openapi="${resource_destination_dir}/schema-openapi.yml" \
    --data-value-file releaseNotes="${resource_destination_dir}/release_notes.txt" \
    --data-value repo_host="${package_repo_prefix}-${resource_name}" \
    --data-value version="${pinniped_package_version}" > "${package_repository_dir}/${pinniped_package_version}.yml"
  cp "${resource_package_template_source_dir}/metadata.yml" "${package_repository_dir}/metadata.yml"
done

log_note "Generating .imgpkg/images.yml for  Pinniped PackageRepository bundle..."
mkdir -p "deploy_carvel/package_repository/.imgpkg"
kbld --file "deploy_carvel/package_repository/packages/" --imgpkg-lock-output "deploy_carvel/package_repository/.imgpkg/images.yml"

log_note "Pushing Pinniped PackageRepository bundle.... "
imgpkg push --bundle "${package_repository_repo_tag}" --file "deploy_carvel/package_repository"

# manually validate the package bundle by pulling it from the registry and examining its contents:
# imgpkg pull --bundle "${package_repository_repo_tag}" --output "/tmp/${package_repository_repo_tag}"

log_note "Building Carvel Packages for Supervisor, Concierge & local-user-authenticator complete."
