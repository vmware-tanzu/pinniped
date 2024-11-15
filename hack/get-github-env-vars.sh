#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# To be run before local integration tests.
# From the pinniped repo:
# hack/prepare-for-integration-tests.sh --get-github-vars "../pinniped-ci-branch/hack/get-github-env-vars.sh"
if ! gcloud auth print-access-token &>/dev/null; then
  echo "Please run \`gcloud auth login\` and try again."
  exit 1
fi

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

function _get_concourse_secret {
  gcloud secrets versions access latest --secret="concourse-secrets" --project "$PINNIPED_GCP_PROJECT" | yq e "$1"
}

export PINNIPED_TEST_GITHUB_APP_CLIENT_ID="$(_get_concourse_secret '.github-app-client-id')"
export PINNIPED_TEST_GITHUB_APP_CLIENT_SECRET="$(_get_concourse_secret '.github-app-client-secret')"

export PINNIPED_TEST_GITHUB_OAUTH_APP_CLIENT_ID="$(_get_concourse_secret '.github-oauth-app-client-id')"
export PINNIPED_TEST_GITHUB_OAUTH_APP_CLIENT_SECRET="$(_get_concourse_secret '.github-oauth-app-client-secret')"
export PINNIPED_TEST_GITHUB_OAUTH_APP_ALLOWED_CALLBACK_URL="$(_get_concourse_secret '.github-oauth-app-allowed-callback-url')"

export PINNIPED_TEST_GITHUB_USER_USERNAME="$(_get_concourse_secret '.github-username')"
export PINNIPED_TEST_GITHUB_USER_PASSWORD="$(_get_concourse_secret '.github-password')"
export PINNIPED_TEST_GITHUB_USER_OTP_SECRET="$(_get_concourse_secret '.github-user-otp-secret')"

export PINNIPED_TEST_GITHUB_USERID="$(_get_concourse_secret '.github-userid')"
export PINNIPED_TEST_GITHUB_ORG="$(_get_concourse_secret '.github-org')"
export PINNIPED_TEST_GITHUB_EXPECTED_TEAM_NAMES="$(_get_concourse_secret '.github-expected-team-names')"
export PINNIPED_TEST_GITHUB_EXPECTED_TEAM_SLUGS="$(_get_concourse_secret '.github-expected-team-slugs')"

unset -f _get_concourse_secret
