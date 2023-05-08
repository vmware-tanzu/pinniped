#!/usr/bin/env bash

# Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# A script to perform the setup required to manually test using the supervisor on a kind cluster.
# Assumes that you installed the apps already using hack/prepare-for-integration-tests.sh.
#
# This script is a little hacky to avoid setting up any kind of ingress or load balancer on Kind.
# It uses an http proxy server and port forwarding to route the requests into the cluster.
# This is only intended for quick manual testing of features by contributors and is not a
# representation of how to really deploy or configure Pinniped.
#
# This uses the Supervisor and Concierge in the same cluster. Usually the Supervisor would be
# deployed in one cluster while each workload cluster would have a Concierge. All the workload
# cluster Concierge configurations would be similar to each other, all trusting the same Supervisor.
#
# Depends on `step` which can be installed by `brew install step` on MacOS.
#

set -euo pipefail

# Change working directory to the top of the repo.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

function log_error() {
  RED='\033[0;31m'
  NC='\033[0m'
  if [[ ${COLORTERM:-unknown} =~ ^(truecolor|24bit)$ ]]; then
    echo -e "🙁${RED} Error: $* ${NC}"
  else
    echo ":( Error: $*"
  fi
}

use_oidc_upstream=no
use_ldap_upstream=no
use_ad_upstream=no
use_flow=""
while (("$#")); do
  case "$1" in
  --flow)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "--flow requires a flow name to be specified (e.g. cli_password or browser_authcode"
      exit 1
    fi
    if [[ "$1" != "browser_authcode" && "$1" != "cli_password" ]]; then
      log_error "--flow must be cli_password or browser_authcode"
      exit 1
    fi
    use_flow=$1
    shift
    ;;
  --ldap)
    use_ldap_upstream=yes
    shift
    ;;
  --oidc)
    use_oidc_upstream=yes
    shift
    ;;
  --ad)
    # Use an ActiveDirectoryIdentityProvider.
    # This assumes that you used the --get-active-directory-vars flag with hack/prepare-for-integration-tests.sh.
    use_ad_upstream=yes
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

if [[ "$use_oidc_upstream" == "no" && "$use_ldap_upstream" == "no" && "$use_ad_upstream" == "no" ]]; then
  log_error "Error: Please use --oidc, --ldap, or --ad to specify which type(s) of upstream identity provider(s) you would like. May use one or multiple."
  exit 1
fi

# Read the env vars output by hack/prepare-for-integration-tests.sh
source /tmp/integration-test-env

# Choose some filenames.
root_ca_crt_path=root_ca.crt
root_ca_key_path=root_ca.key
tls_crt_path=tls.crt
tls_key_path=tls.key

# Choose an audience name for the Concierge.
audience="my-workload-cluster-$(openssl rand -hex 4)"

# These settings align with how the Dex redirect URI is configured by hack/prepare-for-integration-tests.sh.
# Note that this hostname can only be resolved inside the cluster, so we will use a web proxy running inside
# the cluster whenever we want to be able to connect to it.
issuer_host="pinniped-supervisor-clusterip.supervisor.svc.cluster.local"
issuer="https://$issuer_host/some/path"

if [[ "$use_oidc_upstream" == "yes" ]]; then
  # Make an OIDCIdentityProvider which uses Dex to provide identity.
  cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" -f -
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  name: my-oidc-provider
spec:
  issuer: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER"
  tls:
    certificateAuthorityData: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER_CA_BUNDLE"
  authorizationConfig:
    additionalScopes: [ ${PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ADDITIONAL_SCOPES} ]
    allowPasswordGrant: true
  claims:
    username: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME_CLAIM"
    groups: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_GROUPS_CLAIM"
  client:
    secretName: my-oidc-provider-client-secret
EOF

  # Make a Secret for the above OIDCIdentityProvider to describe the OIDC client configured in Dex.
  cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" -f -
apiVersion: v1
kind: Secret
metadata:
  name: my-oidc-provider-client-secret
stringData:
  clientID: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_ID"
  clientSecret: "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_SECRET"
type: "secrets.pinniped.dev/oidc-client"
EOF

  # Grant the test user some RBAC permissions so we can play with kubectl as that user.
  kubectl create clusterrolebinding oidc-test-user-can-view --clusterrole view \
    --user "$PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME" \
    --dry-run=client --output yaml | kubectl apply -f -
fi

if [[ "$use_ldap_upstream" == "yes" ]]; then
  # Make an LDAPIdentityProvider which uses OpenLDAP to provide identity.
  cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" -f -
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: LDAPIdentityProvider
metadata:
  name: my-ldap-provider
spec:
  host: "$PINNIPED_TEST_LDAP_HOST"
  tls:
    certificateAuthorityData: "$PINNIPED_TEST_LDAP_LDAPS_CA_BUNDLE"
  bind:
    secretName: my-ldap-service-account
  groupSearch:
    base: "$PINNIPED_TEST_LDAP_GROUPS_SEARCH_BASE"
    attributes:
      groupName: "cn"
  userSearch:
    base: "$PINNIPED_TEST_LDAP_USERS_SEARCH_BASE"
    filter: "cn={}"
    attributes:
      uid: "$PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_NAME"
      username: "$PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_NAME"
EOF

  # Make a Secret for the above LDAPIdentityProvider to describe the bind account.
  cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" -f -
apiVersion: v1
kind: Secret
metadata:
  name: my-ldap-service-account
stringData:
  username: "$PINNIPED_TEST_LDAP_BIND_ACCOUNT_USERNAME"
  password: "$PINNIPED_TEST_LDAP_BIND_ACCOUNT_PASSWORD"
type: "kubernetes.io/basic-auth"
EOF

  # Grant the test user some RBAC permissions so we can play with kubectl as that user.
  kubectl create clusterrolebinding ldap-test-user-can-view --clusterrole view \
    --user "$PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_VALUE" \
    --dry-run=client --output yaml | kubectl apply -f -
fi

if [[ "$use_ad_upstream" == "yes" ]]; then
  # Make an ActiveDirectoryIdentityProvider. Needs to be pointed to a real AD server by env vars.
  cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" -f -
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: ActiveDirectoryIdentityProvider
metadata:
  name: my-ad-provider
spec:
  host: "$PINNIPED_TEST_AD_HOST"
  tls:
    certificateAuthorityData: "$PINNIPED_TEST_AD_LDAPS_CA_BUNDLE"
  bind:
    secretName: my-ad-service-account
EOF

  # Make a Secret for the above ActiveDirectoryIdentityProvider to describe the bind account.
  cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" -f -
apiVersion: v1
kind: Secret
metadata:
  name: my-ad-service-account
stringData:
  username: "$PINNIPED_TEST_AD_BIND_ACCOUNT_USERNAME"
  password: "$PINNIPED_TEST_AD_BIND_ACCOUNT_PASSWORD"
type: "kubernetes.io/basic-auth"
EOF

  # Grant the test user some RBAC permissions so we can play with kubectl as that user.
  kubectl create clusterrolebinding ldap-test-user-can-view --clusterrole view \
    --user "$PINNIPED_TEST_AD_USER_USER_PRINCIPAL_NAME" \
    --dry-run=client --output yaml | kubectl apply -f -
fi

# Create a CA and TLS serving certificates for the Supervisor's FederationDomain.
if [[ ! -f "$root_ca_crt_path" ]]; then
  step certificate create \
    "Supervisor CA" "$root_ca_crt_path" "$root_ca_key_path" \
    --profile root-ca \
    --no-password --insecure --force
fi
if [[ ! -f "$tls_crt_path" || ! -f "$tls_key_path" ]]; then
  step certificate create \
    "$issuer_host" "$tls_crt_path" "$tls_key_path" \
    --profile leaf \
    --not-after 8760h \
    --ca "$root_ca_crt_path" --ca-key "$root_ca_key_path" \
    --no-password --insecure --force
fi

# Put the TLS certificate into a Secret for the Supervisor's FederationDomain.
kubectl create secret tls -n "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" my-federation-domain-tls --cert "$tls_crt_path" --key "$tls_key_path" \
  --dry-run=client --output yaml | kubectl apply -f -

# Variable that will be used to build up the "identityProviders" yaml for the FederationDomain.
fd_idps=""

if [[ "$use_oidc_upstream" == "yes" ]]; then
  # Indenting the heredoc by 4 spaces to make it indented the correct amount in the FederationDomain below.
  fd_idps="${fd_idps}$(
    cat <<EOF

    - displayName: "My OIDC IDP"
      objectRef:
        apiGroup: idp.supervisor.pinniped.dev
        kind: OIDCIdentityProvider
        name: my-oidc-provider
      transforms:
        expressions:
          - type: username/v1
            expression: '"oidc:" + username'
          - type: groups/v1 # the pinny user doesn't belong to any groups in Dex, so this isn't strictly needed, but doesn't hurt
            expression: 'groups.map(group, "oidc:" + group)'
        examples:
          - username: ryan@example.com
            groups: [ a, b ]
            expects:
              username: oidc:ryan@example.com
              groups: [ oidc:a, oidc:b ]
EOF
  )"
fi

if [[ "$use_ldap_upstream" == "yes" ]]; then
  # Indenting the heredoc by 4 spaces to make it indented the correct amount in the FederationDomain below.
  fd_idps="${fd_idps}$(
    cat <<EOF

    - displayName: "My LDAP IDP"
      objectRef:
        apiGroup: idp.supervisor.pinniped.dev
        kind: LDAPIdentityProvider
        name: my-ldap-provider
      transforms: # these are contrived to exercise all the available features
        constants:
          - name: prefix
            type: string
            stringValue: "ldap:"
          - name: onlyIncludeGroupsWithThisPrefix
            type: string
            stringValue: "ball-" # pinny belongs to ball-game-players in openldap
          - name: mustBelongToOneOfThese
            type: stringList
            stringListValue: [ ball-admins, seals ] # pinny belongs to seals in openldap
          - name: additionalAdmins
            type: stringList
            stringListValue: [ pinny.ldap@example.com, ryan@example.com ] # pinny's email address in openldap
        expressions:
          - type: policy/v1
            expression: 'groups.exists(g, g in strListConst.mustBelongToOneOfThese)'
            message: "Only users in certain kube groups are allowed to authenticate"
          - type: groups/v1
            expression: 'username in strListConst.additionalAdmins ? groups + ["ball-admins"] : groups'
          - type: groups/v1
            expression: 'groups.filter(group, group.startsWith(strConst.onlyIncludeGroupsWithThisPrefix))'
          - type: username/v1
            expression: 'strConst.prefix + username'
          - type: groups/v1
            expression: 'groups.map(group, strConst.prefix + group)'
        examples:
          - username: ryan@example.com
            groups: [ ball-developers, seals, non-ball-group ] # allowed to auth because belongs to seals
            expects:
              username: ldap:ryan@example.com
              groups: [ ldap:ball-developers, ldap:ball-admins ] # gets ball-admins because of username, others dropped because they lack "ball-" prefix
          - username: someone_else@example.com
            groups: [ ball-developers, ball-admins, non-ball-group ] # allowed to auth because belongs to ball-admins
            expects:
              username: ldap:someone_else@example.com
              groups: [ ldap:ball-developers, ldap:ball-admins ] # seals dropped because it lacks prefix
          - username: paul@example.com
            groups: [ not-ball-admins-group, not-seals-group ] # reject because does not belong to any of the required groups
            expects:
              rejected: true
              message: "Only users in certain kube groups are allowed to authenticate"
EOF
  )"
fi

if [[ "$use_ad_upstream" == "yes" ]]; then
  # Indenting the heredoc by 4 spaces to make it indented the correct amount in the FederationDomain below.
  fd_idps="${fd_idps}$(
    cat <<EOF

    - displayName: "My AD IDP"
      objectRef:
        apiGroup: idp.supervisor.pinniped.dev
        kind: ActiveDirectoryIdentityProvider
        name: my-ad-provider
EOF
  )"
fi

# Make a FederationDomain using the TLS Secret and identity providers from above.
cat <<EOF | kubectl apply --namespace "$PINNIPED_TEST_SUPERVISOR_NAMESPACE" -f -
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: FederationDomain
metadata:
  name: my-federation-domain
spec:
  issuer: $issuer
  tls:
    secretName: my-federation-domain-tls
  identityProviders:${fd_idps}
EOF

echo "Waiting for FederationDomain to initialize or update..."
# Sleeping is a race, but that's probably good enough for the purposes of this script.
sleep 5

# Test that the federation domain is working before we proceed.
echo "Fetching FederationDomain discovery info via command: https_proxy=\"$PINNIPED_TEST_PROXY\" curl -fLsS --cacert \"$root_ca_crt_path\" \"$issuer/.well-known/openid-configuration\""
https_proxy="$PINNIPED_TEST_PROXY" curl -fLsS --cacert "$root_ca_crt_path" "$issuer/.well-known/openid-configuration" | jq .

if [[ "$OSTYPE" == "darwin"* ]]; then
  certificateAuthorityData=$(cat "$root_ca_crt_path" | base64)
else
  # Linux base64 requires an extra flag to keep the output on one line.
  certificateAuthorityData=$(cat "$root_ca_crt_path" | base64 -w 0)
fi

# Make a JWTAuthenticator which respects JWTs from the Supervisor's issuer.
# The issuer URL must be accessible from within the cluster for OIDC discovery.
cat <<EOF | kubectl apply -f -
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: JWTAuthenticator
metadata:
  name: my-jwt-authenticator
spec:
  issuer: $issuer
  audience: $audience
  tls:
    certificateAuthorityData: $certificateAuthorityData
EOF

echo "Waiting for JWTAuthenticator to initialize or update..."
# Sleeping is a race, but that's probably good enough for the purposes of this script.
sleep 5

# Compile the CLI.
go build ./cmd/pinniped

# In case Pinniped was just installed moments ago, wait for the CredentialIssuer to be ready.
while [[ -z "$(kubectl get credentialissuer pinniped-concierge-config -o=jsonpath='{.status.strategies[?(@.status == "Success")].type}')" ]]; do
  echo "Waiting for a successful strategy on CredentialIssuer"
  sleep 2
done

# Use the CLI to get the kubeconfig. Tell it that you don't want the browser to automatically open for browser-based
# flows so we can open our own browser with the proxy settings. Generate a kubeconfig for each IDP.
flow_arg=""
if [[ -n "$use_flow" ]]; then
  flow_arg="--upstream-identity-provider-flow $use_flow"
fi
if [[ "$use_oidc_upstream" == "yes" ]]; then
  https_proxy="$PINNIPED_TEST_PROXY" no_proxy="127.0.0.1" \
    ./pinniped get kubeconfig --oidc-skip-browser $flow_arg --upstream-identity-provider-type oidc >kubeconfig-oidc.yaml
fi
if [[ "$use_ldap_upstream" == "yes" ]]; then
  https_proxy="$PINNIPED_TEST_PROXY" no_proxy="127.0.0.1" \
    ./pinniped get kubeconfig --oidc-skip-browser $flow_arg --upstream-identity-provider-type ldap >kubeconfig-ldap.yaml
fi
if [[ "$use_ad_upstream" == "yes" ]]; then
  https_proxy="$PINNIPED_TEST_PROXY" no_proxy="127.0.0.1" \
    ./pinniped get kubeconfig --oidc-skip-browser $flow_arg --upstream-identity-provider-type activedirectory >kubeconfig-ad.yaml
fi

# Clear the local CLI cache to ensure that the kubectl command below will need to perform a fresh login.
rm -f "$HOME/.config/pinniped/sessions.yaml"
rm -f "$HOME/.config/pinniped/credentials.yaml"

echo
echo "Ready! 🚀"

if [[ "$use_oidc_upstream" == "yes" || "$use_flow" == "browser_authcode" ]]; then
  echo
  echo "To be able to access the Supervisor URL during login, start Chrome like this:"
  echo "    open -a \"Google Chrome\" --args --proxy-server=\"$PINNIPED_TEST_PROXY\""
  echo "Note that Chrome must be fully quit before being started with --proxy-server."
  echo "Then open the login URL shown below in that new Chrome window."
  echo
  echo "When prompted for username and password, use these values:"
  echo
fi

if [[ "$use_oidc_upstream" == "yes" ]]; then
  echo "    OIDC Username: $PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME"
  echo "    OIDC Password: $PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_PASSWORD"
  echo
fi

if [[ "$use_ldap_upstream" == "yes" ]]; then
  echo "    LDAP Username: $PINNIPED_TEST_LDAP_USER_CN"
  echo "    LDAP Password: $PINNIPED_TEST_LDAP_USER_PASSWORD"
  echo
fi

if [[ "$use_ad_upstream" == "yes" ]]; then
  echo "    AD Username: $PINNIPED_TEST_AD_USER_USER_PRINCIPAL_NAME"
  echo "    AD Password: $PINNIPED_TEST_AD_USER_PASSWORD"
  echo
fi

# Echo the commands that may be used to login and print the identity of the currently logged in user.
# Once the CLI has cached your tokens, it will automatically refresh your short-lived credentials whenever
# they expire, so you should not be prompted to log in again for the rest of the day.
if [[ "$use_oidc_upstream" == "yes" ]]; then
  echo "To log in using OIDC, run:"
  echo "PINNIPED_DEBUG=true https_proxy=\"$PINNIPED_TEST_PROXY\" no_proxy=\"127.0.0.1\" ./pinniped whoami --kubeconfig ./kubeconfig-oidc.yaml"
  echo
fi
if [[ "$use_ldap_upstream" == "yes" ]]; then
  echo "To log in using LDAP, run:"
  echo "PINNIPED_DEBUG=true https_proxy=\"$PINNIPED_TEST_PROXY\" no_proxy=\"127.0.0.1\" ./pinniped whoami --kubeconfig ./kubeconfig-ldap.yaml"
  echo
fi
if [[ "$use_ad_upstream" == "yes" ]]; then
  echo "To log in using AD, run:"
  echo "PINNIPED_DEBUG=true https_proxy=\"$PINNIPED_TEST_PROXY\" no_proxy=\"127.0.0.1\" ./pinniped whoami --kubeconfig ./kubeconfig-ad.yaml"
  echo
fi
