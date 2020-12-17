#!/usr/bin/env bash

# Copyright 2020 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

function tidy_cmd() {
  echo 'go mod tidy -v'
}

function lint_cmd() {
  echo "golangci-lint run --modules-download-mode=readonly --timeout=10m"
}

function test_cmd() {
  if [ -x "$(command -v gotest)" ]; then
    cmd='gotest'
  else
    cmd='go test'
  fi
  echo "${cmd} -count 1 -race ./..."
}

function unittest_cmd() {
  if [ -x "$(command -v gotest)" ]; then
    cmd='gotest'
  else
    cmd='go test'
  fi
  echo "${cmd} -short -race ./..."
}

function with_modules() {
  local cmd_function="${1}"
  cmd="$(${cmd_function})"

  # start the cache mutation detector by default so that cache mutators will be found
  local kube_cache_mutation_detector="${KUBE_CACHE_MUTATION_DETECTOR:-true}"

  # panic the server on watch decode errors since they are considered coder mistakes
  local kube_panic_watch_decode_error="${KUBE_PANIC_WATCH_DECODE_ERROR:-true}"

  env_vars="KUBE_CACHE_MUTATION_DETECTOR=${kube_cache_mutation_detector} KUBE_PANIC_WATCH_DECODE_ERROR=${kube_panic_watch_decode_error}"

  pushd "${ROOT}" >/dev/null
  for mod_file in $(find . -maxdepth 4 -not -path "./generated/*" -name go.mod | sort); do
    mod_dir="$(dirname "${mod_file}")"
    (
      echo "=> "
      echo "   cd ${mod_dir} && ${env_vars} ${cmd}"
      cd "${mod_dir}" && env ${env_vars} ${cmd}
    )
  done
  popd >/dev/null
}

function usage() {
  echo "Error: <task> must be specified"
  echo "       module.sh <task> [tidy, lint, test, unittest]"
  exit 1
}

function main() {
  case "${1:-invalid}" in
  'tidy')
    with_modules 'tidy_cmd'
    ;;
  'lint' | 'linter' | 'linters')
    with_modules 'lint_cmd'
    ;;
  'test' | 'tests')
    with_modules 'test_cmd'
    ;;
  'unittest' | 'unittests' | 'units' | 'unit')
    with_modules 'unittest_cmd'
    ;;
  *)
    usage
    ;;
  esac

  echo "=> "
  echo "   \"module.sh $1\" Finished successfully."
}

main "$@"
