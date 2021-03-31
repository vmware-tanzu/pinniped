#!/usr/bin/env bash

# Copyright 2014 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# This has been changed from kube's default version.sh to expect KUBE_GIT_VERSION to be set
# by the caller. If it is set, it must be a semver version number, and it will be included
# in the result. If it is not set, then defaults indicating that the version is unknown will
# be included in the result.
#
# These changes are to allow the CI build steps to set the version number at build time
# without using the original behavior of this script, which was to look at previous git
# tags to guess the version number.
#

kube::version::get_version_vars() {
  local git=(git --work-tree "${KUBE_ROOT}")

  if [[ -n ${KUBE_GIT_COMMIT-} ]] || KUBE_GIT_COMMIT=$("${git[@]}" rev-parse "HEAD^{commit}" 2>/dev/null); then
    if [[ -z ${KUBE_GIT_TREE_STATE-} ]]; then
      # Check if the tree is dirty.  default to dirty
      if git_status=$("${git[@]}" status --porcelain 2>/dev/null) && [[ -z ${git_status} ]]; then
        KUBE_GIT_TREE_STATE="clean"
      else
        KUBE_GIT_TREE_STATE="dirty"
      fi
    fi

    # If KUBE_GIT_VERSION is supplied
    if [[ -n "${KUBE_GIT_VERSION:-""}" ]]; then

      # If KUBE_GIT_VERSION is not a valid Semantic Version, then refuse to build.
      if ! [[ "${KUBE_GIT_VERSION}" =~ ^v([0-9]+)\.([0-9]+)(\.[0-9]+)?(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
        echo "KUBE_GIT_VERSION should be a valid Semantic Version starting with a \"v\". Current value: ${KUBE_GIT_VERSION}"
        echo "Please see more details here: https://semver.org"
        exit 1
      fi

      if [[ "${KUBE_GIT_VERSION}" =~ ^v([0-9]+)\.([0-9]+)(\.[0-9]+)?([-].*)?([+].*)?$ ]]; then
        KUBE_GIT_MAJOR=${BASH_REMATCH[1]}
        KUBE_GIT_MINOR=${BASH_REMATCH[2]}
      fi

    else
      # KUBE_GIT_VERSION was not supplied
      # These values need to pass the validation in k8s.io/component-base/metrics:
      # https://github.com/kubernetes/component-base/blob/v0.20.5/metrics/version_parser.go#L28-L50
      KUBE_GIT_VERSION='0.0.0'
      KUBE_GIT_MAJOR='0'
      KUBE_GIT_MINOR='0'
    fi
  fi
}

# Prints the value that needs to be passed to the -ldflags parameter of go build
# in order to set the Kubernetes based on the git tree status.
# IMPORTANT: if you update any of these, also update the lists in
# pkg/version/def.bzl and hack/print-workspace-status.sh.
kube::version::ldflags() {
  kube::version::get_version_vars

  local -a ldflags
  function add_ldflag() {
    local key=${1}
    local val=${2}
    # If you update these, also update the list component-base/version/def.bzl.
    ldflags+=(
      "-X 'k8s.io/client-go/pkg/version.${key}=${val}'"
      "-X 'k8s.io/component-base/version.${key}=${val}'"
    )
  }

  add_ldflag "buildDate" "$(date ${SOURCE_DATE_EPOCH:+"--date=@${SOURCE_DATE_EPOCH}"} -u +'%Y-%m-%dT%H:%M:%SZ')"
  if [[ -n ${KUBE_GIT_COMMIT-} ]]; then
    add_ldflag "gitCommit" "${KUBE_GIT_COMMIT}"
    add_ldflag "gitTreeState" "${KUBE_GIT_TREE_STATE}"
  fi

  if [[ -n ${KUBE_GIT_VERSION-} ]]; then
    add_ldflag "gitVersion" "${KUBE_GIT_VERSION}"
  fi

  if [[ -n ${KUBE_GIT_MAJOR-} && -n ${KUBE_GIT_MINOR-} ]]; then
    add_ldflag "gitMajor" "${KUBE_GIT_MAJOR}"
    add_ldflag "gitMinor" "${KUBE_GIT_MINOR}"
  fi

  # The -ldflags parameter takes a single string, so join the output.
  echo "${ldflags[*]-}"
}
