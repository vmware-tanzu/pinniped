#!/usr/bin/env bash

# Copyright 2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

STDIN_DUMP=`mktemp`
trap "rm $STDIN_DUMP" EXIT

# Read from STDIN
cat > $STDIN_DUMP

LDAP_IDENTITY_PROVIDER_FILE=`mktemp`
trap "rm $LDAP_IDENTITY_PROVIDER_FILE" EXIT

yq 'select(document_index == 0)' $STDIN_DUMP > $LDAP_IDENTITY_PROVIDER_FILE

LDAP_IDP_NAME=`yq '.metadata.name' $LDAP_IDENTITY_PROVIDER_FILE`
LDAP_IDP_NAMESPACE=`yq '.metadata.namespace' $LDAP_IDENTITY_PROVIDER_FILE`
LDAP_HOST=`yq '.spec.host' $LDAP_IDENTITY_PROVIDER_FILE`
LDAP_USER_SEARCH_BASE_DN=`yq '.spec.userSearch.base' $LDAP_IDENTITY_PROVIDER_FILE`
LDAP_USER_SEARCH_FILTER=`yq '.spec.userSearch.filter' $LDAP_IDENTITY_PROVIDER_FILE`
LDAP_CA_BUNDLE=`yq '.spec.tls.certificateAuthorityData | @base64d' $LDAP_IDENTITY_PROVIDER_FILE`
LDAP_BIND_SECRETNAME=`yq '.spec.bind.secretName' $LDAP_IDENTITY_PROVIDER_FILE`
LDAP_BIND_DN=""
LDAP_BIND_PASSWORD=""

if [[ -n "${LDAP_BIND_SECRETNAME}" ]]; then
  LDAP_BIND_SECRET_FILE=`mktemp`
  trap "rm $LDAP_BIND_SECRET_FILE" EXIT

  kubectl get secret "$LDAP_BIND_SECRETNAME" \
    --namespace "$LDAP_IDP_NAMESPACE" \
    --output yaml > $LDAP_BIND_SECRET_FILE

  LDAP_BIND_DN=`yq '.data.username | @base64d' $LDAP_BIND_SECRET_FILE`
  LDAP_BIND_PASSWORD=`yq '.data.password | @base64d' $LDAP_BIND_SECRET_FILE`
fi

if [[ "${1:-}" == "--debug" ]]; then
  echo LDAP_IDP_NAME="$LDAP_IDP_NAME"
  echo LDAP_IDP_NAMESPACE="$LDAP_IDP_NAMESPACE"
  echo LDAP_HOST="$LDAP_HOST"
  echo LDAP_USER_SEARCH_BASE_DN="$LDAP_USER_SEARCH_BASE_DN"
  echo LDAP_USER_SEARCH_FILTER="$LDAP_USER_SEARCH_FILTER"
  echo LDAP_CA_BUNDLE="$LDAP_CA_BUNDLE"
  echo LDAP_BIND_SECRETNAME="$LDAP_BIND_SECRETNAME"
  echo LDAP_BIND_DN="$LDAP_BIND_DN"
  echo LDAP_BIND_PASSWORD="$LDAP_BIND_PASSWORD"
fi

output=()

if [[ -n "${LDAP_CA_BUNDLE}" ]]; then
  LDAP_CA_BUNDLE_FILE=ldaptls_cacert.pem
  echo "$LDAP_CA_BUNDLE" > $LDAP_CA_BUNDLE_FILE

  output+=("LDAPTLS_CACERT=$LDAP_CA_BUNDLE_FILE")
fi

output+=("ldapsearch" "-x")
output+=("-H" "ldaps://$LDAP_HOST")

if [[ -n "${LDAP_BIND_DN}" ]]; then
  output+=("-D" "$LDAP_BIND_DN")
fi

if [[ -n "${LDAP_BIND_PASSWORD}" ]]; then
  output+=("-w" "'$LDAP_BIND_PASSWORD'")
fi

output+=("-b" "$LDAP_USER_SEARCH_BASE_DN")
output+=("-s" "sub")
output+=("$LDAP_USER_SEARCH_FILTER")

echo "${output[*]}"

#LDAPTLS_CACERT=/path/to/ca-bundle.pem ldapsearch \
#-x -H ldaps://LDAP_HOST -D LDAP_BIND_DN -w LDAP_BIND_PASSWORD \
#-b LDAP_USER_SEARCH_BASE_DN \
#-s sub (LDAP_USER_SEARCH_FILTER-with-placeholder-replaced-by-username)
#
