#!/usr/bin/env bash

# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# This script is a rough approximation of what the Pinniped Supervisor Golang code does to search an LDAP provider
# during an end-user's login. This is intended to be helpful for debugging your LDAPIdentityProvider spec settings.
# Because it is implemented in bash, it is not necessarily exactly the same as the actual Supervisor code.
# Note that this does not yet support ActiveDirectoryIdentityProvider, which has some more complex behavior to
# determine default values for some of the spec fields.

pinniped_path="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$pinniped_path" || exit 1

source hack/lib/helpers.sh

#
# Handle argument parsing and help message
#
help=no
resource_type_and_name=""
namespace=""
username=""

while (("$#")); do
  case "$1" in
  -h | --help)
    help=yes
    shift
    ;;
  -r | --resource)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "-r|--resource requires a resource type and name to be specified as type/name"
      exit 1
    fi
    resource_type_and_name=$1
    shift
    ;;
  -n | --namespace)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "-n|--namespace requires a namespace name to be specified"
      exit 1
    fi
    namespace=$1
    shift
    ;;
  -u | --username)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "-u|--username requires a username to be specified"
      exit 1
    fi
    username=$1
    shift
    ;;
  -*)
    log_error "Unsupported flag $1" >&2
    exit 1
    ;;
  *)
    log_error "Unsupported positional arg $1" >&2
    exit 1
    ;;
  esac
done

if [[ "$help" == "yes" ]]; then
  me="$(basename "${BASH_SOURCE[0]}")"
  log_note "Usage:"
  log_note "   $me [flags]"
  log_note
  log_note "Flags:"
  log_note "   -h, --help:      print this usage"
  log_note "   -r, --resource:  specify the resource type and name (e.g. ldapidentityprovider/my-ldap-idp) - required"
  log_note "   -n, --namespace: specify the namespace in which the resource exists - required"
  log_note "   -u, --username:  specify a username, as an end-user would type it during a login - required"
  exit 1
fi

if [[ -z "$namespace" ]]; then
  log_error "-n|--namespace is required"
  exit 1
fi

if [[ -z "$resource_type_and_name" ]]; then
  log_error "-r|--resource is required"
  exit 1
fi

if [[ "$resource_type_and_name" != ldapidentityprovider/* ]]; then
  log_error "-r|--resource currently only supports ldapidentityprovider type resources."
  log_error "Please specify the value as \"ldapidentityprovider/name-of-resource\"."
  exit 1
fi

if [[ -z "$username" ]]; then
  log_error "-u|--username is required"
  exit 1
fi

RESOURCE_FILE=$(mktemp)
trap "rm $RESOURCE_FILE" EXIT

kubectl get "$resource_type_and_name" \
  --namespace "$namespace" \
  --output yaml >"$RESOURCE_FILE"

# See docs for LDAPIdentityProvider.spec for details about these settings.
# https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.28/README.adoc#k8s-api-go-pinniped-dev-generated-1-28-apis-supervisor-idp-v1alpha1-ldapidentityproviderspec
LDAP_HOST=$(yq '.spec.host' "$RESOURCE_FILE")                                                                       # required
LDAP_CA_BUNDLE=$(yq '.spec.tls.certificateAuthorityData // ""' "$RESOURCE_FILE")                                    # optional
LDAP_BIND_SECRETNAME=$(yq '.spec.bind.secretName' "$RESOURCE_FILE")                                                 # required
LDAP_USER_SEARCH_BASE=$(yq '.spec.userSearch.base' "$RESOURCE_FILE")                                                # required
LDAP_USER_SEARCH_FILTER=$(yq '.spec.userSearch.filter // ""' "$RESOURCE_FILE")                                      # optional unless Attributes.Username is set to "dn"
LDAP_USER_SEARCH_ATTRIBUTES_USERNAME=$(yq '.spec.userSearch.attributes.username' "$RESOURCE_FILE")                  # required
LDAP_USER_SEARCH_ATTRIBUTES_UID=$(yq '.spec.userSearch.attributes.uid' "$RESOURCE_FILE")                            # required
LDAP_GROUP_SEARCH_BASE=$(yq '.spec.groupSearch.base // ""' "$RESOURCE_FILE")                                        # optional, disables group search when blank
LDAP_GROUP_SEARCH_FILTER=$(yq '.spec.groupSearch.filter // ""' "$RESOURCE_FILE")                                    # optional, defaults to member={}
LDAP_GROUP_SEARCH_USER_ATTRIBUTE_FOR_FILTER=$(yq '.spec.groupSearch.userAttributeForFilter // ""' "$RESOURCE_FILE") # optional, defaults to using dn
LDAP_GROUP_SEARCH_ATTRIBUTES_GROUPNAME=$(yq '.spec.groupSearch.attributes.groupName // ""' "$RESOURCE_FILE")        # optional, defaults to using dn

# Set defaults for missing optional values.
if [[ -z "$LDAP_USER_SEARCH_FILTER" ]]; then
  LDAP_USER_SEARCH_FILTER="${LDAP_USER_SEARCH_ATTRIBUTES_USERNAME}={}"
fi
if [[ -z "$LDAP_GROUP_SEARCH_FILTER" ]]; then
  LDAP_GROUP_SEARCH_FILTER="member={}"
fi
if [[ -z "$LDAP_GROUP_SEARCH_USER_ATTRIBUTE_FOR_FILTER" ]]; then
  LDAP_GROUP_SEARCH_USER_ATTRIBUTE_FOR_FILTER="dn"
fi
if [[ -z "$LDAP_GROUP_SEARCH_ATTRIBUTES_GROUPNAME" ]]; then
  LDAP_GROUP_SEARCH_ATTRIBUTES_GROUPNAME="dn"
fi

# LDAP filters must be surrounded by parens. Pinniped will automatically add
# the missing parens, if needed, as a convenience, so do that here too.
if [[ "$LDAP_USER_SEARCH_FILTER" != "("* ]]; then
  LDAP_USER_SEARCH_FILTER="(${LDAP_USER_SEARCH_FILTER})"
fi
if [[ "$LDAP_GROUP_SEARCH_FILTER" != "("* ]]; then
  LDAP_GROUP_SEARCH_FILTER="(${LDAP_GROUP_SEARCH_FILTER})"
fi

LDAP_BIND_SECRET_FILE=$(mktemp)
trap "rm $LDAP_BIND_SECRET_FILE" EXIT

kubectl get secret "$LDAP_BIND_SECRETNAME" \
  --namespace "$namespace" \
  --output yaml >"$LDAP_BIND_SECRET_FILE"

LDAP_BIND_DN=$(yq '.data.username | @base64d' "$LDAP_BIND_SECRET_FILE")       # required
LDAP_BIND_PASSWORD=$(yq '.data.password | @base64d' "$LDAP_BIND_SECRET_FILE") # required

basic_cmd=()

if [[ -n "${LDAP_CA_BUNDLE}" ]]; then
  LDAP_CA_BUNDLE_FILE="/tmp/ldap_tls_cacert.pem"
  echo "$LDAP_CA_BUNDLE" | base64 -d >$LDAP_CA_BUNDLE_FILE

  basic_cmd+=("LDAPTLS_CACERT=$LDAP_CA_BUNDLE_FILE")
fi

basic_cmd+=("ldapsearch" "-x")
basic_cmd+=("-H" "'ldaps://$LDAP_HOST'")

if [[ -n "${LDAP_BIND_DN}" ]]; then
  basic_cmd+=("-D" "'$LDAP_BIND_DN'")
fi

if [[ -n "${LDAP_BIND_PASSWORD}" ]]; then
  basic_cmd+=("-w" "'$LDAP_BIND_PASSWORD'")
fi

# Construct a command which will print the whole user record, if found.
find_user_cmd=${basic_cmd[*]}
find_user_cmd+=("-b" "'$LDAP_USER_SEARCH_BASE'")
find_user_cmd+=("-z" "1") # limit one result
find_user_cmd+=("-s" "sub")
find_user_cmd+=("'${LDAP_USER_SEARCH_FILTER//\{\}/"$username"}'")

log_note "# The following commands are provided to aid in debugging."
log_note "# Copy and paste these commands into a bash shell to run them."

echo
log_note "# Use the following command to search for the user's LDAP record."
log_note "# The value of the \"$LDAP_USER_SEARCH_ATTRIBUTES_USERNAME\" attribute will be their Kubernetes username"
log_note "# (not including any configured transformations on the FederationDomain),"
log_note "# and the value of the \"$LDAP_USER_SEARCH_ATTRIBUTES_UID\" attribute will be their Supervisor UID."
echo "${find_user_cmd[*]}"

if [[ -z "$LDAP_GROUP_SEARCH_BASE" ]]; then
  echo
  log_note "# Group search is not enabled because spec.groupSearch.base is empty."
  exit
fi

# Add more to the user search command to get only the value of the configured username attribute.
find_user_cmd+=("$LDAP_GROUP_SEARCH_USER_ATTRIBUTE_FOR_FILTER" "-LLL")
find_user_cmd+=("|" "grep" "-E" "'^${LDAP_GROUP_SEARCH_USER_ATTRIBUTE_FOR_FILTER}: '")
find_user_cmd+=("|" "sed" "'s/^${LDAP_GROUP_SEARCH_USER_ATTRIBUTE_FOR_FILTER}: //'")

# Construct a command that will print a list of group names to which the user belongs.
find_groups_cmd=${basic_cmd[*]}
find_groups_cmd+=("-b" "'$LDAP_GROUP_SEARCH_BASE'")
find_groups_cmd+=("-s" "sub")
find_groups_cmd+=('${LDAP_GROUP_SEARCH_FILTER//\{\}/"$GROUP_SEARCH_KEY"}')
find_groups_cmd+=("${LDAP_GROUP_SEARCH_ATTRIBUTES_GROUPNAME}")
find_groups_cmd+=("-LLL")
find_groups_cmd+=("|" "grep" "-E" "'^${LDAP_GROUP_SEARCH_ATTRIBUTES_GROUPNAME}: '")
find_groups_cmd+=("|" "sed" "'s/^${LDAP_GROUP_SEARCH_ATTRIBUTES_GROUPNAME}: //'")

echo
log_note "# Use the following three commands to search for the user's group memberships."
log_note "# The third command should result in their list of group names for Kubernetes"
log_note "# (not including any configured transformations on the FederationDomain)."
echo "LDAP_GROUP_SEARCH_FILTER=\"${LDAP_GROUP_SEARCH_FILTER}\""
echo
echo "GROUP_SEARCH_KEY=\$( ${find_user_cmd[*]} ) && echo \$GROUP_SEARCH_KEY"
echo
echo "${find_groups_cmd[*]}"
echo
