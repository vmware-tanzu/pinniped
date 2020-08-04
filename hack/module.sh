#!/usr/bin/env bash
set -euo pipefail

root_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

function lint() {
  if [ -x "$(command -v golangci-lint)" ]; then
    cmd='golangci-lint'
  else
    cmd='go run github.com/golangci/golangci-lint/cmd/golangci-lint'
  fi
  echo "${cmd} run --modules-download-mode=readonly --timeout=10m"
}

function test() {
  if [ -x "$(command -v gotest)" ]; then
    cmd='gotest'
  else
    cmd='go test'
  fi
  echo "${cmd} -race ./..."
}

function tidy() {
  echo 'go mod tidy'
}

function update_codegen() {
  local script='hack/update-codegen.sh'
  if [ -x ${script} ]; then
    echo "${script}"
  fi
}

function verify_codegen() {
  local script='hack/verify-codegen.sh'
  if [ -x ${script} ]; then
    echo "${script}"
  fi
}

function with_modules() {
  local cmd_function="${1}"

  pushd "${root_dir}"
  for mod_file in $(find . -not -path "*vendor/*" -name go.mod); do
    cd_cmd="cd $(dirname "${mod_file}")"
    echo "=> "
    (
      ${cd_cmd}
      cmd=$(${cmd_function})
      echo -n "   ${cd_cmd}"
      if [ -n "${cmd}" ]; then
        echo " && ${cmd}"
        ${cmd}
        echo "   # finished '${cmd_function}'"
      else
        echo ''
        echo "   # nothing for '${cmd_function}'"
      fi
    )
  done
  popd
}

function usage() {
  echo "Error: <task> must be specified"
  echo "       do.sh <task> [lint, test, tidy, update_codegen, verify_codegen]"
  exit 1
}

function main() {
  task=${1:-invalid}
  case "${task}" in
    'lint'|'test'|'tidy'|'update_codegen'|'verify_codegen')
      with_modules "${task}"
      ;;
    *) usage ;;
  esac
}

main "$@"