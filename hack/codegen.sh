#!/usr/bin/env bash

# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

GOPATH="${GOPATH:-$(mktemp -d)}"

K8S_PKG_VERSION="${K8S_PKG_VERSION:-"1.19"}" # TODO: set this in k8s-code-generator-{} image
CODEGEN_IMAGE=${CODEGEN_IMAGE:-"gcr.io/tanzu-user-authentication/k8s-code-generator-${K8S_PKG_VERSION}:latest"}

BASE_PKG="github.com/suzerain-io/placeholder-name"

function codegen::ensure_module_in_gopath() {
  # This should be something like "kubernetes/1.19/api".
  local pkg_name="$(realpath "--relative-to=$ROOT" "$MOD_DIR")"

  # Use --canonicalize-missing to since pkg_name could end up as "." - this would
  # lead to a pkg_gosrc_path like "foo/bar/bat/." which ln(1) (below) does not like.
  local pkg_gosrc_path="$(realpath --canonicalize-missing "${GOPATH}/src/${BASE_PKG}/${pkg_name}")"

  if [[ ! -e "${pkg_gosrc_path}" ]]; then
    mkdir -p "$(dirname "${pkg_gosrc_path}")"
    ln -s "${ROOT}/${pkg_name}" "${pkg_gosrc_path}"
  fi
}

function codegen::invoke_code_generator() {
  local generator_command="${1}"
  local mod_basename_for_version="${2}"
  shift 2 # generator args are now in $@

  if [ "${BASH_VERSINFO[0]}" -lt 5 ]; then
    echo "ERROR: invalid BASH version"
    echo "       using    v${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}.${BASH_VERSINFO[2]} @ ${BASH}"
    echo "       require  v5.0.0+"
    exit 1
  fi

  bash "${GOPATH}/src/k8s.io/code-generator/${generator_command}.sh" \
    "$@" \
    --go-header-file "${ROOT}/hack/boilerplate.go.txt" |
    sed "s|^|${mod_basename_for_version} > ${generator_command} > |"
}

function codegen::generate_for_module() {
  local mod_basename_for_version="${1}"

  case "${mod_basename_for_version}" in
  1.19/api)
    codegen::invoke_code_generator generate-groups "${mod_basename_for_version}" \
      deepcopy,defaulter \
      "${BASE_PKG}/kubernetes/1.19/api/generated" \
      "${BASE_PKG}/kubernetes/1.19/api/apis" \
      "placeholder:v1alpha1 crdsplaceholder:v1alpha1"
    codegen::invoke_code_generator generate-internal-groups "${mod_basename_for_version}" \
      deepcopy,defaulter,conversion,openapi \
      "${BASE_PKG}/kubernetes/1.19/api/generated" \
      "${BASE_PKG}/kubernetes/1.19/api/apis" \
      "${BASE_PKG}/kubernetes/1.19/api/apis" \
      "placeholder:v1alpha1 crdsplaceholder:v1alpha1"
    ;;
  1.19/client-go)
    codegen::invoke_code_generator generate-groups "${mod_basename_for_version}" \
      client,lister,informer \
      "${BASE_PKG}/kubernetes/1.19/client-go" \
      "${BASE_PKG}/kubernetes/1.19/api/apis" \
      "placeholder:v1alpha1 crdsplaceholder:v1alpha1"
    ;;
  esac
}

function codegen::generate() {
  local mod_basename_for_version
  mod_basename_for_version="${K8S_PKG_VERSION}/$(basename "${MOD_DIR}")"

  codegen::ensure_module_in_gopath
  codegen::generate_for_module "${mod_basename_for_version}"
}

function codegen::verify() {
  local have_stash=''
  if [[ "$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')" -ne "0" ]]; then
    # git stash requires the user.email and user.name to be set. We set these at
    # a global scope so they don't overwrite the .git/config in the mounted repo
    # from the host.
    git config --global user.email "codegen_verify@whatever.com"
    git config --global user.name "Codegen Verify"
    git stash --all >/dev/null 2>&1 && have_stash=1
  fi

  codegen::generate

  failure=0
  if [[ "$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')" -eq "0" ]]; then
    echo "Generated code in ${MOD_DIR} up to date."
  else
    echo "Generated code in ${MOD_DIR} is out of date."
    echo "Please run hack/module.sh codegen"
    git diff "${ROOT}"
    git checkout "${ROOT}"
    failure=1
  fi

  if [[ -n "${have_stash}" ]]; then
    git stash pop >/dev/null 2>&1
  fi

  if [[ "$failure" -eq 1 ]]; then
    exit 1
  fi
}

function codegen::usage() {
  echo "Error: <codegen command> must be specified"
  echo "       ${BASH_SOURCE[0]} <codegen command> [codegen::generate, codegen::verify]"
  exit 1
}

function codegen::main() {
  local codegen_command="${1}"

  if [[ -n "${CONTAINED:-}" ]]; then
    "${codegen_command}"
  else
    DOCKER_ROOT_DIR="/tmp/${RANDOM}/${BASE_PKG}"
    DOCKER_MOD_DIR="${DOCKER_ROOT_DIR}/$(realpath "--relative-to=$ROOT" "$MOD_DIR")"

    docker run --rm \
      --env CONTAINED=1 \
      --env MOD_DIR="${DOCKER_MOD_DIR}" \
      --volume "${ROOT}:${DOCKER_ROOT_DIR}" \
      --workdir "${DOCKER_MOD_DIR}" \
      "${CODEGEN_IMAGE}" \
      "${DOCKER_ROOT_DIR}/hack/$(basename "${BASH_SOURCE[0]}")" \
      "${codegen_command}"
  fi
}

codegen::main "${1:-"codegen::usage"}"
