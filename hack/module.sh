#!/usr/bin/env bash

# Copyright 2020 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

function tidy_cmd() {
  echo 'go mod tidy -v'
}

function lint_cmd() {
  if [ -x "$(command -v golangci-lint)" ]; then
    cmd='golangci-lint'
  else
    cmd='go run github.com/golangci/golangci-lint/cmd/golangci-lint'
  fi
  echo "${cmd} run --modules-download-mode=readonly --timeout=10m"
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
  echo "${cmd} -count 1 -short -race ./..."
}

function with_modules() {
  local cmd_function="${1}"
  cmd="$(${cmd_function})"

  pushd "${ROOT}" >/dev/null
  for mod_file in $(find . -maxdepth 4 -not -path "./generated/*" -name go.mod | sort); do
    mod_dir="$(dirname "${mod_file}")"
    (
      echo "=> "
      echo "   cd ${mod_dir} && ${cmd}"
      cd "${mod_dir}" && ${cmd}
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
