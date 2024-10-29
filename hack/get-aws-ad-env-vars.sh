#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# To be run before local integration tests.
# From the pinniped repo:
# hack/prepare-for-integration-tests.sh --get-active-directory-vars "../pinniped-ci-branch/hack/get-aws-ad-env-vars.sh"
if [[ -z "$(gcloud config list account --format "value(core.account)")" ]]; then
  echo "Please run \`gcloud auth login\`"
  exit 1
fi

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

function _get_concourse_secret {
  gcloud secrets versions access latest --secret="concourse-secrets" --project "$PINNIPED_GCP_PROJECT" | yq e "$1"
}

export PINNIPED_TEST_AD_HOST="$(_get_concourse_secret '.aws-ad-host')"
export PINNIPED_TEST_AD_DOMAIN="$(_get_concourse_secret '.aws-ad-domain')"
export PINNIPED_TEST_AD_BIND_ACCOUNT_USERNAME="$(_get_concourse_secret '.aws-ad-bind-account-username')"
export PINNIPED_TEST_AD_BIND_ACCOUNT_PASSWORD="$(_get_concourse_secret '.aws-ad-bind-account-password')"
export PINNIPED_TEST_AD_USER_UNIQUE_ID_ATTRIBUTE_NAME="objectGUID"
export PINNIPED_TEST_AD_USER_UNIQUE_ID_ATTRIBUTE_VALUE="$(_get_concourse_secret '.aws-ad-user-unique-id-attribute-value')"
export PINNIPED_TEST_AD_USER_USER_PRINCIPAL_NAME="$(_get_concourse_secret '.aws-ad-user-userprincipalname')"
export PINNIPED_TEST_AD_USER_PASSWORD="$(_get_concourse_secret '.aws-ad-user-password')"
export PINNIPED_TEST_AD_LDAPS_CA_BUNDLE="$(_get_concourse_secret '.aws-ad-ca-data')"
export PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_DN="$(_get_concourse_secret '.aws-ad-expected-direct-groups-dn')"
export PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_CN="$(_get_concourse_secret '.aws-ad-expected-direct-groups-cn')"
export PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_SAMACCOUNTNAME="$(_get_concourse_secret '.aws-ad-expected-direct-and-nested-groups-samaccountnames')"
export PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_SAMACCOUNTNAME_DOMAINNAMES="$(_get_concourse_secret '.aws-ad-expected-direct-and-nested-groups-samaccountname-domainnames')"
export PINNIPED_TEST_DEACTIVATED_AD_USER_SAMACCOUNTNAME="$(_get_concourse_secret '.aws-ad-deactivated-user-samaccountname')"
export PINNIPED_TEST_DEACTIVATED_AD_USER_PASSWORD="$(_get_concourse_secret '.aws-ad-deactivated-user-password')"
export PINNIPED_TEST_AD_USER_EMAIL_ATTRIBUTE_NAME="mail"
export PINNIPED_TEST_AD_USER_EMAIL_ATTRIBUTE_VALUE="$(_get_concourse_secret '.aws-ad-user-email-attribute-value')"
export PINNIPED_TEST_AD_DEFAULTNAMINGCONTEXT_DN="$(_get_concourse_secret '.aws-ad-defaultnamingcontext')"
export PINNIPED_TEST_AD_USERS_DN="$(_get_concourse_secret '.aws-ad-users-dn')"

unset -f _get_concourse_secret
