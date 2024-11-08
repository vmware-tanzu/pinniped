#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# This script is designed to be used in CI to deploy to kind, GKE, and TKGS clusters.
# It is also designed to be run on a development workstation (see hack/prepare-remote-cluster-for-integration-tests.sh).
#
# Goal:
#   To prepare the cluster for integration tests, and to write out the environment
#   variables needed for running integration tests against the cluster.
#
# Assumptions:
#   - The current working directory is the top of the source code repo.
#   - The kube config is already set up.
#   - The necessary tooling is installed.
#
# Inputs:
#  - $CONCIERGE_APP_NAME decides the app_name YTT template value of the Concierge app.
#    By default this is set to "concierge".
#  - $CONCIERGE_NAMESPACE decides in which namespace the Concierge app should be deployed.
#    By default this is set to "concierge".
#  - $SUPERVISOR_APP_NAME decides the app_name YTT template value of the Supervisor app.
#    By default this is set to "supervisor".
#  - $SUPERVISOR_NAMESPACE decides in which namespace the Supervisor app should be deployed.
#    By default this is set to "supervisor".
#  - $IMAGE_REPO, $IMAGE_TAG, and $IMAGE_DIGEST decide which app container to deploy.
#    - Note! The deployment templates prefer IMAGE_DIGEST, so:
#      - if both IMAGE_TAG and IMAGE_DIGEST are set, IMAGE_DIGEST is prefered;
#      - if IMAGE_TAG is set but IMAGE_DIGEST is not, then IMAGE_TAG is prefered;
#      - if IMAGE_TAG is not set but IMAGE_DIGEST is, then IMAGE_DIGEST is prefered.
#  - $TMC_API_TOKEN and $TMC_CLUSTER_NAME enables the cluster to be attached to TMC.
#  - $PINNIPED_DISCOVERY_URL decides the "discovery_url" ytt template value.
#    If the env var is not set, then we use "null" since that will indicate to
#    pinniped that we want to use the default discovery URL from the cluster.
#  - $PINNIPED_TEST_CLUSTER_CAPABILITY_FILE is the path to a yaml file which describes
#    the capabilities of the test cluster.
#  - $API_SERVING_CERT_DURATION and $API_SERVING_CERT_RENEW_BEFORE set the
#    corresponding values in the YTT template. They are optional.
#  - $DEPLOY_LOCAL_USER_AUTHENTICATOR, when set to "yes", will deploy and use the
#    local-user-authenticator instead of using the TMC webhook authenticator.
#  - $DEPLOY_TEST_TOOLS will deploy the squid proxy, Dex, and OpenLDAP into the cluster.
#    If the OKTA_* and JUMPCLOUD_* variables are not present, then Dex and OpenLDAP
#    will be configured for the integration tests.
#  - To use Okta instead of Dex, use the variables $OKTA_ISSUER, $OKTA_CLI_CLIENT_ID,
#    $OKTA_CLI_CALLBACK, $OKTA_ADDITIONAL_SCOPES, $OKTA_USERNAME_CLAIM, $OKTA_GROUPS_CLAIM,
#    $OKTA_SUPERVISOR_CLIENT_ID, $OKTA_SUPERVISOR_CLIENT_SECRET, $OKTA_SUPERVISOR_CALLBACK,
#    $OKTA_USERNAME, $OKTA_GROUPS, and $OKTA_PASSWORD to configure the Okta client.
#  - To use Jumpcloud instead of OpenLDAP, use the variables $JUMPCLOUD_LDAP_HOST,
#    $JUMPCLOUD_LDAP_STARTTLS_ONLY_HOST,
#    $JUMPCLOUD_LDAP_BIND_ACCOUNT_USERNAME, $JUMPCLOUD_LDAP_BIND_ACCOUNT_PASSWORD,
#    $JUMPCLOUD_LDAP_USERS_SEARCH_BASE, $JUMPCLOUD_LDAP_GROUPS_SEARCH_BASE,
#    $JUMPCLOUD_LDAP_USER_DN, $JUMPCLOUD_LDAP_USER_CN, $JUMPCLOUD_LDAP_USER_PASSWORD,
#    $JUMPCLOUD_LDAP_USER_UNIQUE_ID_ATTRIBUTE_NAME, $JUMPCLOUD_LDAP_USER_UNIQUE_ID_ATTRIBUTE_VALUE,
#    $JUMPCLOUD_LDAP_USER_EMAIL_ATTRIBUTE_NAME, $JUMPCLOUD_LDAP_USER_EMAIL_ATTRIBUTE_VALUE,
#    $JUMPCLOUD_LDAP_EXPECTED_DIRECT_GROUPS_DN, $JUMPCLOUD_LDAP_EXPECTED_DIRECT_POSIX_GROUPS_CN,
#    and $JUMPCLOUD_LDAP_EXPECTED_DIRECT_GROUPS_CN to configure the LDAP tests.
#  - $FIREWALL_IDPS, when set to "yes" will add NetworkPolicies to effectively firewall the Concierge
#    and Supervisor pods such that they need to use the Squid proxy server to reach several of the IDPs.
#    Note that NetworkPolicy is not supported on all flavors of Kube, but can be enabled on GKE by using
#    `--enable-network-policy` when creating the GKE cluster, abd is supported in recent versions of Kind.
#  - $TEST_ACTIVE_DIRECTORY determines whether to test against AWS Managed Active
#    Directory. Note that there's no "local" equivalent-- for OIDC we use Dex's internal
#    user store or Okta, for LDAP we deploy OpenLDAP or use Jumpcloud,
#    but for AD there is only the hosted version.
#    When set, the tests are configured with the variables
#    $AWS_AD_HOST, $AWS_AD_DOMAIN, $AWS_AD_BIND_ACCOUNT_USERNAME, $AWS_AD_BIND_ACCOUNT_PASSWORD,
#    AWS_AD_USER_USER_PRINCIPAL_NAME, $AWS_AD_USER_PASSWORD, $AWS_AD_USER_UNIQUE_ID_ATTRIBUTE_NAME,
#    $AWS_AD_USER_UNIQUE_ID_ATTRIBUTE_VALUE, $AWS_AD_USER_EXPECTED_GROUPS_DN,
#    $AWS_AD_USER_EXPECTED_GROUPS_CN, and $AWS_AD_LDAPS_CA_BUNDLE
#  - $USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR, when set to "yes", will create LoadBalancers for Dex and Supervisor.
#    This script will wait for those LoadBalancers to receive their IP addresses and then use those IP addresses:
#    - when configuring Dex with its own issuer URL
#    - when configuring Dex with allowed callbacks (for the Supervisor)
#    - when configuring the integration test variables for the Supervisor hostname amd Dex's callback URL for the Supervisor
#    This option cannot be used with $SUPERVISOR_LOAD_BALANCER==yes or $SUPERVISOR_INGRESS==yes.
#    This option must be used with $DEPLOY_TEST_TOOLS==yes.
#  - $SUPERVISOR_LOAD_BALANCER, when set to "yes", will deploy the Supervisor
#    with a LoadBalancer Service defined. When set to "yes" the following additional
#    variables are expected:
#    - $SUPERVISOR_LOAD_BALANCER_STATIC_IP: The IP for the load balancer service to
#      use. Optional.
#    - $SUPERVISOR_LOAD_BALANCER_DNS_NAME: The DNS name associated with the
#      load balancer IP address. Required when $SUPERVISOR_LOAD_BALANCER is "yes".
#    - If the $SUPERVISOR_LOAD_BALANCER_DNS_NAME is given without the
#      $SUPERVISOR_LOAD_BALANCER_STATIC_IP, then allow the load balancer service
#      to choose its own IP address, and dynamically register that address as the name
#      specified in $SUPERVISOR_LOAD_BALANCER_DNS_NAME using the Cloud DNS service.
#  - $SUPERVISOR_INGRESS, when set to "yes", will deploy the Supervisor with a
#    NodePort Service defined and create an Ingress connected to that Service.
#    When set to "yes" the following additional variables are expected:
#    - $SUPERVISOR_INGRESS_STATIC_IP_NAME: The name of the static IP resource from the
#      underlying cloud infrastructure platform. Optional.
#    - $SUPERVISOR_INGRESS_DNS_NAME: The DNS hostname name associated with the
#      ingress' IP address. Required when $SUPERVISOR_INGRESS is "yes".
#    - $SUPERVISOR_INGRESS_PATH_PATTERN: The path that will be set in the Ingress object
#      (e.g., "/", "/*"; this depends on what is supported by the underlying platform).
#      Required when $SUPERVISOR_INGRESS is "yes".
#    - If the $SUPERVISOR_INGRESS_DNS_NAME is given without the
#      $SUPERVISOR_INGRESS_STATIC_IP_NAME, then allow the ingress service
#      to choose its own IP address, and dynamically register that address as the name
#      specified in $SUPERVISOR_INGRESS_DNS_NAME using the Cloud DNS service.
#  - When neither $SUPERVISOR_LOAD_BALANCER nor $SUPERVISOR_INGRESS then we will use
#    nodeport services to make the supervisor available. In this case you may specify
#    $PINNIPED_SUPERVISOR_HTTP_NODEPORT and $PINNIPED_SUPERVISOR_HTTPS_NODEPORT if you
#    would like to override the default port numbers.
#  - $PINNIPED_API_GROUP_SUFFIX decides the "api_group_suffix" ytt value for both
#    the Concierge and Supervisor deployments. Optional. The default is to omit the
#    "api_group_suffix" option, thus accepting the default from the ytt templates.
#  - $SECONDARY_DEPLOY, when set to "yes", assumes that some other invocation of this
#    script (another deploy) is responsible for actually deploying the dex and the
#    local-user-authenticator. This current (second) invocation will skip deploying dex
#    and the local-user-authenticator, them but will still set the test env file flags
#    for them if they were requested as if it had deployed them, to allow the integration
#    tests to still use them. This is currently only intended to be used on kind clusters,
#    so it is not designed to interact with flags that we only use on the acceptance
#    cluster deploys like the TMC token and ingress/load balancer flags mentioned above.
#  - $SECONDARY_SUPERVISOR_APP_NAME - the app name of the Supervisor that will be used
#    in the secondary deploy; this will be used in the primary deploy and ignored in the
#    secondary deploy. This is optional, and if you do not set this variable then we expect
#    that you do not intend to follow up with a second deploy.
#  - $SECONDARY_SUPERVISOR_NAMESPACE - the namespace of the Supervisor that will be used
#    in the secondary deploy; this will be used in the primary deploy and ignored in the
#    secondary deploy. This is optional, and if you do not set this variable then we expect
#    that you do not intend to follow up with a second deploy.
#  - $PINNIPED_DEX_TEST_USER_PASSWORD - the password for "pinny" in dex. This only really
#    matters when you're deploying multiple pinnipeds, since the password needs to be
#    consistent between them. Otherwise one will be generated here.
#  - $PINNIPED_LDAP_TEST_USER_PASSWORD - the password for "pinny" in LDAP. This only really
#    matters when you're deploying multiple pinnipeds, since the password needs to be
#    consistent between them. Otherwise one will be generated here.
#  - $SUPERVISOR_AND_CONCIERGE_NO_CPU_REQUEST - when set to any value, causes the CPU requests
#    to be unset on the deployments, which helps us squeeze these deployments onto a small cluster.

# Require kubectl >= 1.18.x.
if [ "$(kubectl version --client=true -o=json | grep gitVersion | cut -d '.' -f 2)" -lt 18 ]; then
  echo "kubectl >= 1.18.x is required, you have $(kubectl version --client=true --short | cut -d ':' -f2)"
  exit 1
fi

# extract_env takes a JSON object representing an client.authentication.k8s.io/v1beta1
# exec credential config (as parameter $1) and pulls out the env var value for the
# provided name (as parameter $2).
function extract_env_value() {
  filter=".env[] | select(.name==\"$2\") | .value"
  echo "$1" | jq -r "$filter"
}

function print_or_redact_doc() {
  doc_kind=$(echo "$1" | awk '/^kind: / {print $2}')
  if [[ -z "$doc_kind" ]]; then
    echo "warning: <empty kind>"
  elif [[ $doc_kind == "Secret" || $doc_kind == "secret" ]]; then
    echo
    echo "---"
    echo "<SECRET REDACTED>"
  else
    printf "%s\n" "$1"
  fi
}

function print_redacted_manifest() {
  doc=""
  while IFS="" read -r line || [ -n "$line" ]; do
    if [[ $line == "---" ]]; then
      if [[ -n "$doc" ]]; then
        print_or_redact_doc "$doc"
      fi
      doc=""
    fi
    doc=$(printf "%s\n%s" "$doc" "$line")
  done <"$1"

  print_or_redact_doc "$doc"
}

function update_gcloud_dns_record() {
  if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
    echo "PINNIPED_GCP_PROJECT env var must be set when using update_gcloud_dns_record"
    exit 1
  fi

  local dns_name=$1
  local new_ip=$2
  local dns_record_name="${dns_name}."
  local dns_zone="pinniped-dev"
  local dns_project="$PINNIPED_GCP_PROJECT"

  # Login to gcloud CLI
  gcloud auth activate-service-account "$GKE_USERNAME" --key-file <(echo "$GKE_JSON_KEY") --project "$dns_project"

  # Get the current value of the DNS A record.
  # We assume that this record already exists because it was manually created.
  # We also assume in the transaction commands below that it was created with a TTL of 30 seconds.
  current_dns_record_ip=$(gcloud dns record-sets list --zone "$dns_zone" \
    --project "$dns_project" --name "$dns_record_name" --format json |
    jq -r ".[] | select(.name ==\"${dns_record_name}\") | .rrdatas[0]")

  if [[ "$current_dns_record_ip" == "$new_ip" ]]; then
    echo "No update needed: DNS record $dns_record_name was already set to $new_ip"
  else
    echo "Changing DNS record $dns_record_name from $current_dns_record_ip to $new_ip ..."

    # Updating a DNS record with gcloud must be done with a remove and an add wrapped in a transaction.
    gcloud dns record-sets transaction start --zone "$dns_zone" --project "$dns_project"
    gcloud dns record-sets transaction remove "$current_dns_record_ip" --name "$dns_name" \
      --ttl "30" --type "A" --zone "$dns_zone" --project "$dns_project"
    gcloud dns record-sets transaction add "$new_ip" --name "$dns_name" \
      --ttl "30" --type "A" --zone "$dns_zone" --project "$dns_project"
    change_id=$(gcloud dns record-sets transaction execute --zone "$dns_zone" --project "$dns_project" --format json | jq -r '.id')

    # Wait for that transaction to commit. This is usually quick.
    change_status="not-done"
    while [[ "$change_status" != "done" ]]; do
      sleep 3
      change_status=$(gcloud dns record-sets changes describe "$change_id" \
        --zone "$dns_zone" --project "$dns_project" --format json | jq -r '.status')
      echo "Waiting for change $change_id to have status 'done'. Current status: $change_status"
    done

    # Wait for DNS propagation. The TTL is 30 seconds, so this shouldn't take too long.
    echo "Waiting for new IP address $new_ip to appear in the result of a local DNS query. This may take a few minutes..."
    while true; do
      dig_result=$(dig +short "$dns_name")
      echo "dig result for $dns_name: $dig_result"
      if [[ "$dig_result" == "$new_ip" ]]; then
        echo "New IP address has finished DNS propagation. Done with DNS update!"
        break
      fi
      sleep 5
    done
  fi
}

if [[ "${TMC_API_TOKEN:-}" == "" && "${DEPLOY_LOCAL_USER_AUTHENTICATOR:-no}" != "yes" ]]; then
  echo "Must use either \$TMC_API_TOKEN or \$DEPLOY_LOCAL_USER_AUTHENTICATOR"
  exit 1
fi

if [[ "${TMC_API_TOKEN:-}" != "" ]]; then
  tmc_context_name="tanzu-user-authentication-stable"
  # I dunno what the valid values for "--management-cluster-name" and
  # "--provisioner-name" are, but I know "attached" is one of them.  I also
  # dunno what a "--provisioner-name" refers to...
  attached="attached"

  # This command uses the API token in $TMC_API_TOKEN and points the tmc CLI at the TMC staging env
  tmc system context create --stg-stable --name "$tmc_context_name" --no-configure

  echo "Checking if cluster is attached as '$TMC_CLUSTER_NAME'..."
  cluster_name="$(kubectl -n vmware-system-tmc get configmaps stack-config -o jsonpath=\{.data.cluster_name\} 2>/dev/null || echo 'no_cluster_name')"
  if [[ "$cluster_name" == "$TMC_CLUSTER_NAME" ]]; then
    echo "Cluster is already attached as '$TMC_CLUSTER_NAME'..."
  elif [[ "$cluster_name" == "no_cluster_name" ]]; then
    if ! tmc cluster list --name "$TMC_CLUSTER_NAME" --management-cluster-name "$attached" --provisioner-name "$attached" | grep -q "No clusters to list"; then
      echo "Detaching old '$TMC_CLUSTER_NAME'..."
      tmc cluster delete "$TMC_CLUSTER_NAME" --force --management-cluster-name "$attached" --provisioner-name "$attached"
      # unfortunately it seems like deleting the cluster takes time to propagate before it is safe to attach again
      sleep 3
    fi

    echo "Attaching cluster '$TMC_CLUSTER_NAME'..."
    manifest="$(mktemp)"
    tmc cluster attach --name "$TMC_CLUSTER_NAME" --management-cluster-name "$attached" --provisioner-name "$attached" --output "$manifest"
    kubectl apply -f "$manifest"
    rm "$manifest"
  else
    echo "Cluster is already attached as '$cluster_name'"
    echo "Please either:"
    echo "  1) detach the cluster with something like 'tmc cluster delete $TMC_CLUSTER_NAME --force'"
    echo "  2) create a new cluster with 'kind delete cluster && kind create cluster' (or analagous commands for other providers)"
    echo "I don't want to mess up your cluster, so I'm gonna bail out"
    exit 1
  fi

  # Generate token for testing.
  echo "Generating cluster token for testing..."
  exec_cred_config="$(tmc cluster auth userconfig get --cluster-name "$TMC_CLUSTER_NAME" --management-cluster-name "$attached" --provisioner-name "$attached" --output json | jq .status.user.exec)"
  cluster_uid="$(extract_env_value "$exec_cred_config" CLUSTER_UID)"
  cluster_rid="$(extract_env_value "$exec_cred_config" CLUSTER_RID)"
  cluster_rid_v2="$(extract_env_value "$exec_cred_config" CLUSTER_RID_V2)"
  tmc_environment="$(extract_env_value "$exec_cred_config" TMC_ENVIRONMENT)"
  tmc_endpoint="$(extract_env_value "$exec_cred_config" TMC_ENDPOINT)"

  tmc_token_exec_cred="$(CLUSTER_UID="$cluster_uid" \
    CLUSTER_RID="$cluster_rid" \
    CLUSTER_RID_V2="$cluster_rid_v2" \
    TMC_ENVIRONMENT="$tmc_environment" \
    TMC_ENDPOINT="$tmc_endpoint" \
    tmc cluster generate-token-v2)"
  tmc_cluster_token="$(echo "$tmc_token_exec_cred" | jq -r .status.token)"

  tmc_server_config="$(tmc cluster auth serverconfig get --cluster-name "$TMC_CLUSTER_NAME" --management-cluster-name "$attached" --provisioner-name "$attached" --output json)"
  webhook_url="$(echo "$tmc_server_config" | jq -r .status.authenticationWebhook.endpoint)"
  webhook_ca_bundle="$(echo "$tmc_server_config" | jq -r .status.authenticationWebhook.certificateAuthorityData)"
fi

# Print for debugging
kubectl config current-context
kubectl version
kubectl cluster-info

concierge_app_name="${CONCIERGE_APP_NAME:-concierge}"
concierge_namespace="${CONCIERGE_NAMESPACE:-concierge}"
concierge_custom_labels="{myConciergeCustomLabelName: myConciergeCustomLabelValue}"
supervisor_app_name="${SUPERVISOR_APP_NAME:-supervisor}"
supervisor_namespace="${SUPERVISOR_NAMESPACE:-supervisor}"
supervisor_custom_labels="{mySupervisorCustomLabelName: mySupervisorCustomLabelValue}"
discovery_url="${PINNIPED_DISCOVERY_URL:-null}"
manifest=/tmp/manifest.yaml

test_username="${concierge_app_name}-test-username"
test_groups="${concierge_app_name}-test-group-0,${concierge_app_name}-test-group-1"
test_password="$(openssl rand -hex 16)"
test_user_token="${test_username}:${test_password}"

dex_test_password="${PINNIPED_DEX_TEST_USER_PASSWORD:-$(openssl rand -hex 16)}"
ldap_test_password="${PINNIPED_LDAP_TEST_USER_PASSWORD:-$(openssl rand -hex 16)}"

# Check if the BackendConfig resource exists (i.e. if it is a GKE cluster).
cluster_has_gke_backend_config="no"
if kubectl api-resources --api-group cloud.google.com -o name | grep -q backendconfigs.cloud.google.com; then
  echo "Found backendconfigs.cloud.google.com API on this cluster."
  cluster_has_gke_backend_config="yes"
fi

# Save this file for possible later use. Sometimes we want to remove the CPU requests,
# which also means that we need to remove the limits or else Kubernetes will use the limit as
# an implicit request amount.
cat <<EOF >>/tmp/remove-cpu-request-overlay.yaml
#@ load("@ytt:overlay", "overlay")
#@overlay/match by=overlay.subset({"kind": "Deployment"}), expects=1
---
spec:
  template:
    spec:
      containers:
        - #@overlay/match by=overlay.all, expects=1
          resources:
            requests:
              cpu:
            limits:
              cpu:
EOF

# Save this file for possible later use. For our GKE Ingress, we need to apply these extra
# annotations every time. Losing these annotations from the Service for even just a few seconds during a
# redeploy causes the Ingress health checks to revert to defaults, which causes them to fail, which causes
# the Ingress to start returning 502's for a few minutes until it picks up these annotations again.
# To configure GKE Ingress health checks, we annotate the Service to tell it to use our BackendConfig.
# Also annotate the service so that GKE ingress knows to use HTTP2 for the backend connection.
cat <<EOF >>/tmp/add-annotations-for-gke-ingress-overlay.yaml
#@ load("@ytt:overlay", "overlay")
#@overlay/match by=overlay.subset({"kind": "Service", "metadata":{"name":"${supervisor_app_name}-nodeport"}}), expects=1
---
metadata:
  annotations:
    #@overlay/match missing_ok=True
    cloud.google.com/app-protocols: '{"https":"HTTP2"}'
    #@overlay/match missing_ok=True
    cloud.google.com/backend-config: '{"default":"healthcheck-backendconfig"}'
EOF

if [[ "${DEPLOY_LOCAL_USER_AUTHENTICATOR:-no}" == "yes" ]]; then
  #
  # Deploy local-user-authenticator
  #
  pushd deploy/local-user-authenticator >/dev/null

  # When SECONDARY_DEPLOY == "yes", act like we deployed local-user-authenticator, but don't really.
  if [[ "${SECONDARY_DEPLOY:-no}" != "yes" ]]; then

    echo "Deploying the local-user-authenticator app to the cluster..."
    ytt --file . \
      --data-value "image_repo=$IMAGE_REPO" \
      --data-value "image_digest=${IMAGE_DIGEST:-}" \
      --data-value "image_tag=${IMAGE_TAG:-}" >"$manifest"

    echo
    echo "Full local-user-authenticator app manifest with Secrets redacted..."
    echo "--------------------------------------------------------------------------------"
    print_redacted_manifest $manifest
    echo "--------------------------------------------------------------------------------"
    echo

    set -x
    kapp deploy --yes --app local-user-authenticator --diff-changes --file "$manifest"
    { set +x; } 2>/dev/null

  fi

  # Always create a secret, even if this is a secondary deploy.
  echo "Creating test user '$test_username'..."
  kubectl create secret generic "$test_username" \
    --namespace local-user-authenticator \
    --from-literal=groups="$test_groups" \
    --from-literal=passwordHash="$(htpasswd -nbBC 10 x "$test_password" | sed -e "s/^x://")" \
    --dry-run=client \
    --output yaml |
    kubectl apply -f -

  # Override the TMC webhook settings to use the local-user-authenticator instead
  webhook_url="https://local-user-authenticator.local-user-authenticator.svc.cluster.local/authenticate"

  # Sometimes the local-user-authenticator pod hasn't generated the serving certificate yet, so we poll until it has.
  set +o pipefail
  while ! kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator >/dev/null; do
    echo "Waiting for local-user-authenticator Secret to be created..."
    sleep 1
  done
  set -o pipefail

  webhook_ca_bundle="$(kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator -o 'jsonpath={.data.caCertificate}')"

  popd >/dev/null

else
  # Assume TMC when not using local-user-authenticator.
  # Use username and groups of our test user as expected values.
  test_username="tanzu-user-authentication@groups.vmware.com"

  test_groups_as_array=(
    "tmc:member"
    "csp:org_member"
    "Everyone@vmwareid"
    "Everyone@vmwareid@vmwareid"
    "OKTA_MASTERED_External@vmwareid"
    "Okta_Mastered_External_MFA@vmwareid"
    "OKTA_MASTERED_External@vmwareid@vmwareid"
    "Okta_Mastered_External_MFA@vmwareid@vmwareid"
    "csp-uid:vmwareid:01b58eb7-9a2c-4c02-9a2f-f79532702d14"
  )
  # join array elements with comma as delimiter
  test_groups=$(
    IFS=,
    echo "${test_groups_as_array[*]}"
  )

  test_user_token="${tmc_cluster_token}"
fi

# Do some input checking for USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR
if [[ "${USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR:-no}" == "yes" && "${DEPLOY_TEST_TOOLS:-no}" != "yes" ]]; then
  echo "You must set DEPLOY_TEST_TOOLS=yes when using USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR=yes"
  echo ""
  echo "It has no meaning to create a LoadBalancer for Dex when Dex will not exist"
  exit 1
fi

if [[ "${USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR:-no}" == "yes" && "${SUPERVISOR_LOAD_BALANCER:-no}" == "yes" ]]; then
  echo "Use no more than one of USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR=yes and SUPERVISOR_LOAD_BALANCER=yes"
  echo ""
  echo "USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR=yes tells this script to create a LoadBalancer for Dex and Supervisor with dynamic IP addresses"
  echo "and will configure the integration tests to use those IP addresses for direct communication with Dex and Supervisor"
  echo "SUPERVISOR_LOAD_BALANCER=yes tells this script to create a LoadBalancer for the Supervisor with an IP address and will update the DNS record for SUPERVISOR_LOAD_BALANCER_DNS_NAME".
  exit 1
fi

if [[ "${USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR:-no}" == "yes" && "${SUPERVISOR_INGRESS:-no}" == "yes" ]]; then
  echo "Use no more than one of USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR=yes and SUPERVISOR_INGRESS=yes"
  echo ""
  echo "USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR=yes tells this script to create a LoadBalancer for Dex and Supervisor with dynamic IP addresses"
  echo "and will configure the integration tests to use those IP addresses for direct communication with Dex and Supervisor"
  echo "SUPERVISOR_INGRESS=yes tells this script to create a NodePort service and an Ingress service for the Supervisor".
  exit 1
fi

if [[ "${USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR:-no}" == "yes" ]]; then
  supervisor_service_name="${supervisor_app_name}-loadbalancer"

  # Make a Supervisor LoadBalancer
  cat <<EOF | kubectl apply -f -
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${supervisor_namespace}
---
apiVersion: v1
kind: Service
metadata:
  name: ${supervisor_service_name}
  namespace: ${supervisor_namespace}
  labels:
    app: ${supervisor_app_name}
  annotations:
    kapp.k14s.io/disable-default-label-scoping-rules: ""
spec:
  type: LoadBalancer
  selector:
    deployment.pinniped.dev: supervisor
  ports:
  - name: https
    protocol: TCP
    port: 443
    targetPort: 8443
EOF

  # Make a Dex LoadBalancer
  cat <<EOF | kubectl apply -f -
---
apiVersion: v1
kind: Namespace
metadata:
  name: tools
---
apiVersion: v1
kind: Service
metadata:
  name: dex-loadbalancer
  namespace: tools
  labels:
    app: dex
  annotations:
    kapp.k14s.io/disable-default-label-scoping-rules: ""
spec:
  type: LoadBalancer
  selector:
    app: dex
  ports:
  - name: https
    protocol: TCP
    port: 443
    targetPort: 8443
EOF

  # Wait for BOTH LoadBalancers to receive their assigned IP addresses
  ingress_json='{}'
  while [[ "$ingress_json" == '{}' ]]; do
    echo "Checking for the Supervisor's LoadBalancer IP Address..."
    sleep 1
    ingress_json=$(kubectl get service "${supervisor_service_name}" -n "$supervisor_namespace" -o json |
      jq -r '.status.loadBalancer')
  done

  echo "Supervisor LoadBalancer reported ingress: $ingress_json"
  supervisor_loadbalancer_public_ip_or_hostname=$(echo "$ingress_json" | jq -r '.ingress[0].ip')
  if [[ -z "${supervisor_loadbalancer_public_ip_or_hostname}" || "${supervisor_loadbalancer_public_ip_or_hostname}" == "null" ]]; then
    echo "On EKS this will be a hostname instead of an IP address"
    supervisor_loadbalancer_public_ip_or_hostname=$(echo "$ingress_json" | jq -r '.ingress[0].hostname')
  fi
  echo "found supervisor_loadbalancer_public_ip_or_hostname=$supervisor_loadbalancer_public_ip_or_hostname"
  if [[ -z "${supervisor_loadbalancer_public_ip_or_hostname}" || "${supervisor_loadbalancer_public_ip_or_hostname}" == "null" ]]; then
    echo "Unable to determine supervisor_loadbalancer_public_ip_or_hostname"
    exit 1
  fi

  ingress_json='{}'
  while [[ "$ingress_json" == '{}' ]]; do
    echo "Checking for Dex's LoadBalancer IP Address..."
    sleep 1
    ingress_json=$(kubectl get service "dex-loadbalancer" -n "tools" -o json |
      jq -r '.status.loadBalancer')
  done

  echo "Dex LoadBalancer reported ingress: $ingress_json"
  dex_loadbalancer_public_ip_or_hostname=$(echo "$ingress_json" | jq -r '.ingress[0].ip')
  if [[ -z "${dex_loadbalancer_public_ip_or_hostname}" || "${dex_loadbalancer_public_ip_or_hostname}" == "null" ]]; then
    echo "On EKS this will be a hostname instead of an IP address"
    dex_loadbalancer_public_ip_or_hostname=$(echo "$ingress_json" | jq -r '.ingress[0].hostname')
  fi
  echo "found dex_loadbalancer_public_ip_or_hostname=$dex_loadbalancer_public_ip_or_hostname"
  if [[ -z "${dex_loadbalancer_public_ip_or_hostname}" || "${dex_loadbalancer_public_ip_or_hostname}" == "null" ]]; then
    echo "Unable to determine dex_loadbalancer_public_ip_or_hostname"
    exit 1
  fi
elif [[ "${SUPERVISOR_LOAD_BALANCER:-no}" == "yes" ]]; then
  supervisor_service_name="${supervisor_app_name}-loadbalancer"
else
  supervisor_service_name="${supervisor_app_name}-nodeport"
fi

if [[ "${DEPLOY_TEST_TOOLS:-no}" == "yes" ]]; then
  #
  # Deploy tools
  #
  pushd test/deploy/tools >/dev/null

  if [[ "${USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR:-no}" == "yes" ]]; then
    test_supervisor_upstream_oidc_callback_url="https://${supervisor_loadbalancer_public_ip_or_hostname}/some/path/callback"
  else
    test_supervisor_upstream_oidc_callback_url="https://${supervisor_app_name}-clusterip.${supervisor_namespace}.svc.cluster.local/some/path/callback"
  fi

  # When SECONDARY_DEPLOY == "yes", act like we deployed dex, but don't really.
  if [[ "${SECONDARY_DEPLOY:-no}" != "yes" ]]; then

    # If someone has told you about a secondary Supervisor app name, then add it
    # on to the list of Dex redirect URIs.
    if [[ -n "${SECONDARY_SUPERVISOR_APP_NAME:-}" ]]; then
      test_secondary_supervisor_upstream_oidc_callback_url="https://${SECONDARY_SUPERVISOR_APP_NAME}-clusterip.${SECONDARY_SUPERVISOR_NAMESPACE}.svc.cluster.local/some/path/callback"
      supervisor_redirect_uris="[
          ${test_supervisor_upstream_oidc_callback_url},
          ${test_secondary_supervisor_upstream_oidc_callback_url}
      ]"
    else
      supervisor_redirect_uris="[
          ${test_supervisor_upstream_oidc_callback_url}
      ]"
    fi

    dex_optional_ytt_values=()
    if [[ "${USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR:-no}" == "yes" ]]; then
      dex_optional_ytt_values+=("--data-value=dex_issuer_hostname=${dex_loadbalancer_public_ip_or_hostname}")
    fi

    echo "Deploying Tools to the cluster..."
    echo "Using ytt optional flags:" "${dex_optional_ytt_values[@]}"
    ytt --file . \
      --data-value-yaml "supervisor_redirect_uris=${supervisor_redirect_uris}" \
      --data-value "pinny_ldap_password=$ldap_test_password" \
      --data-value "pinny_bcrypt_passwd_hash=$(htpasswd -nbBC 10 x "$dex_test_password" | sed -e "s/^x://")" \
      ${dex_optional_ytt_values[@]+"${dex_optional_ytt_values[@]}"} \
      >"$manifest"

    echo
    echo "Full Tools manifest with Secrets redacted..."
    echo "--------------------------------------------------------------------------------"
    print_redacted_manifest $manifest
    echo "--------------------------------------------------------------------------------"
    echo

    set -x
    kapp deploy --yes --app tools --diff-changes --file "$manifest"
    { set +x; } 2>/dev/null
  fi

  dex_issuer_url="https://dex.tools.svc.cluster.local/dex"
  test_proxy="http://127.0.0.1:12346"
  if [[ "${USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR:-no}" == "yes" ]]; then
    dex_issuer_url="https://${dex_loadbalancer_public_ip_or_hostname}/dex"

    # The purpose of USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR is specifically to avoid using 'kubectl port-forward',
    # so set this to empty so that any integration tests that specifically need the squid proxy will know to not run.
    test_proxy=""
  fi

  dex_ca_bundle="$(kubectl get secrets -n tools certs -o go-template='{{index .data "ca.pem" | base64decode}}' | base64)"
  pinniped_test_tools_namespace="tools"
  test_cli_oidc_callback_url="http://127.0.0.1:48095/callback"
  test_cli_oidc_client_id="pinniped-cli"
  test_cli_oidc_issuer_ca_bundle="${dex_ca_bundle}"
  test_cli_oidc_issuer="${dex_issuer_url}"
  test_cli_oidc_password="${dex_test_password}"
  test_cli_oidc_username="pinny@example.com"
  # note that test_supervisor_upstream_oidc_callback_url was already set above
  test_supervisor_upstream_oidc_client_id="pinniped-supervisor"
  test_supervisor_upstream_oidc_client_secret="pinniped-supervisor-secret"
  test_supervisor_upstream_oidc_additional_scopes="offline_access,email"
  test_supervisor_upstream_oidc_username_claim="email"
  test_supervisor_upstream_oidc_groups_claim="groups"
  test_supervisor_upstream_oidc_issuer_ca_bundle="${dex_ca_bundle}"
  test_supervisor_upstream_oidc_issuer="${dex_issuer_url}"
  test_supervisor_upstream_oidc_password="${dex_test_password}"
  test_supervisor_upstream_oidc_username="pinny@example.com"
  test_supervisor_upstream_oidc_groups="" # Dex's local user store does not let us configure groups.
  pinniped_test_ldap_host="ldap.tools.svc.cluster.local"
  pinniped_test_ldap_starttls_only_host="ldapstarttls.tools.svc.cluster.local"
  pinniped_test_ldap_ldaps_ca_bundle="${dex_ca_bundle}"
  pinniped_test_ldap_bind_account_username="cn=admin,dc=pinniped,dc=dev"
  pinniped_test_ldap_bind_account_password=password
  pinniped_test_ldap_users_search_base="ou=users,dc=pinniped,dc=dev"
  pinniped_test_ldap_groups_search_base="ou=groups,dc=pinniped,dc=dev"
  pinniped_test_ldap_user_dn="cn=pinny,ou=users,dc=pinniped,dc=dev"
  pinniped_test_ldap_user_cn="pinny"
  pinniped_test_ldap_user_password=${ldap_test_password}
  pinniped_test_ldap_user_unique_id_attribute_name="uidNumber"
  pinniped_test_ldap_user_unique_id_attribute_value="1000"
  pinniped_test_ldap_user_email_attribute_name="mail"
  pinniped_test_ldap_user_email_attribute_value="pinny.ldap@example.com"
  pinniped_test_ldap_expected_direct_groups_dn="cn=ball-game-players,ou=beach-groups,ou=groups,dc=pinniped,dc=dev;cn=seals,ou=groups,dc=pinniped,dc=dev"
  pinniped_test_ldap_expected_indirect_groups_dn="cn=pinnipeds,ou=groups,dc=pinniped,dc=dev;cn=mammals,ou=groups,dc=pinniped,dc=dev"
  pinniped_test_ldap_expected_direct_groups_cn="ball-game-players;seals"
  pinniped_test_ldap_expected_direct_posix_groups_cn="ball-game-players-posix;seals-posix"
  pinniped_test_ldap_expected_indirect_groups_cn="pinnipeds;mammals"

  popd >/dev/null
else
  # Did not deploy the tools namespace.
  pinniped_test_tools_namespace="" # tools were not deployed, so leave empty
  # The squid proxy in the tools namespace was not deployed, so do not use a proxy.
  test_proxy=""
  # The tools namespace was not deployed, so do not use the .svc.cluster.local hostname.
  # Instead use the real hostname of the Supervisor.
  test_supervisor_upstream_oidc_callback_url="https://$SUPERVISOR_LOAD_BALANCER_DNS_NAME/test-issuer/callback"
fi

# Whether or not the tools namespace is deployed, we can configure the integration
# tests to use Okta instead of Dex as the OIDC provider.
if [[ "${OKTA_ISSUER:-no}" != "no" ]]; then
  test_cli_oidc_callback_url="$OKTA_CLI_CALLBACK"
  test_cli_oidc_client_id="$OKTA_CLI_CLIENT_ID"
  test_cli_oidc_issuer_ca_bundle=""
  test_cli_oidc_issuer="$OKTA_ISSUER"
  test_cli_oidc_password="$OKTA_PASSWORD"
  test_cli_oidc_username="$OKTA_USERNAME"
  # Note that we are not overwriting the test_supervisor_upstream_oidc_callback_url variable,
  # which was set by the if/else statement above. This is because the value of that variable
  # should be decided based on the hostname of the Supervisor, which could be a .svc.cluster.local
  # address or it could be a real DNS entry, depending on how the cluster was deployed.
  test_supervisor_upstream_oidc_client_id="$OKTA_SUPERVISOR_CLIENT_ID"
  test_supervisor_upstream_oidc_client_secret="$OKTA_SUPERVISOR_CLIENT_SECRET"
  test_supervisor_upstream_oidc_additional_scopes="$OKTA_ADDITIONAL_SCOPES"
  test_supervisor_upstream_oidc_username_claim="$OKTA_USERNAME_CLAIM"
  test_supervisor_upstream_oidc_groups_claim="$OKTA_GROUPS_CLAIM"
  test_supervisor_upstream_oidc_issuer_ca_bundle=""
  test_supervisor_upstream_oidc_issuer="$OKTA_ISSUER"
  test_supervisor_upstream_oidc_password="$OKTA_PASSWORD"
  test_supervisor_upstream_oidc_username="$OKTA_USERNAME"
  test_supervisor_upstream_oidc_groups="$OKTA_GROUPS"
fi

# Whether or not the tools namespace is deployed, we can configure the integration
# tests to use Jumpcloud instead of OpenLDAP as the LDAP provider.
if [[ "${JUMPCLOUD_LDAP_HOST:-no}" != "no" ]]; then
  pinniped_test_ldap_host="$JUMPCLOUD_LDAP_HOST"
  pinniped_test_ldap_starttls_only_host="$JUMPCLOUD_LDAP_STARTTLS_ONLY_HOST"
  pinniped_test_ldap_ldaps_ca_bundle=""
  pinniped_test_ldap_bind_account_username="$JUMPCLOUD_LDAP_BIND_ACCOUNT_USERNAME"
  pinniped_test_ldap_bind_account_password="$JUMPCLOUD_LDAP_BIND_ACCOUNT_PASSWORD"
  pinniped_test_ldap_users_search_base="$JUMPCLOUD_LDAP_USERS_SEARCH_BASE"
  pinniped_test_ldap_groups_search_base="$JUMPCLOUD_LDAP_GROUPS_SEARCH_BASE"
  pinniped_test_ldap_user_dn="$JUMPCLOUD_LDAP_USER_DN"
  pinniped_test_ldap_user_cn="$JUMPCLOUD_LDAP_USER_CN"
  pinniped_test_ldap_user_password="$JUMPCLOUD_LDAP_USER_PASSWORD"
  pinniped_test_ldap_user_unique_id_attribute_name="$JUMPCLOUD_LDAP_USER_UNIQUE_ID_ATTRIBUTE_NAME"
  pinniped_test_ldap_user_unique_id_attribute_value="$JUMPCLOUD_LDAP_USER_UNIQUE_ID_ATTRIBUTE_VALUE"
  pinniped_test_ldap_user_email_attribute_name="$JUMPCLOUD_LDAP_USER_EMAIL_ATTRIBUTE_NAME"
  pinniped_test_ldap_user_email_attribute_value="$JUMPCLOUD_LDAP_USER_EMAIL_ATTRIBUTE_VALUE"
  pinniped_test_ldap_expected_direct_groups_dn="$JUMPCLOUD_LDAP_EXPECTED_DIRECT_GROUPS_DN"
  pinniped_test_ldap_expected_indirect_groups_dn=""
  pinniped_test_ldap_expected_direct_groups_cn="$JUMPCLOUD_LDAP_EXPECTED_DIRECT_GROUPS_CN"
  pinniped_test_ldap_expected_direct_posix_groups_cn="$JUMPCLOUD_LDAP_EXPECTED_DIRECT_POSIX_GROUPS_CN"
  pinniped_test_ldap_expected_indirect_groups_cn=""
fi

if [[ "${TEST_ACTIVE_DIRECTORY:-no}" == "yes" ]]; then
  # there's no way to test active directory locally... it has to be aws managed ad or nothing.
  # this is a separate toggle from $DEPLOY_TEST_TOOLS so we can run against ad once in the pr pipeline
  # without doing so every time
  pinniped_test_ad_host="$AWS_AD_HOST"
  pinniped_test_ad_domain="$AWS_AD_DOMAIN"
  pinniped_test_ad_bind_account_username="$AWS_AD_BIND_ACCOUNT_USERNAME"
  pinniped_test_ad_bind_account_password="$AWS_AD_BIND_ACCOUNT_PASSWORD"
  pinniped_test_ad_user_password="$AWS_AD_USER_PASSWORD"
  pinniped_test_ad_user_unique_id_attribute_name="$AWS_AD_USER_UNIQUE_ID_ATTRIBUTE_NAME"
  pinniped_test_ad_user_unique_id_attribute_value="$AWS_AD_USER_UNIQUE_ID_ATTRIBUTE_VALUE"
  pinniped_test_ad_user_user_principal_name="$AWS_AD_USER_USER_PRINCIPAL_NAME"
  pinniped_test_ad_user_expected_groups_dn="$AWS_AD_USER_EXPECTED_GROUPS_DN"
  pinniped_test_ad_user_expected_groups_cn="$AWS_AD_USER_EXPECTED_GROUPS_CN"
  pinniped_test_ad_user_expected_indirect_groups_samaccountname="$AWS_AD_USER_EXPECTED_GROUPS_SAMACCOUNTNAME"
  pinniped_test_ad_user_expected_indirect_groups_samaccountname_domainnames="$AWS_AD_USER_EXPECTED_GROUPS_SAMACCOUNTNAME_DOMAINNAMES"
  pinniped_test_ad_ldaps_ca_bundle="$AWS_AD_LDAPS_CA_BUNDLE"
  pinniped_test_deactivated_ad_user_samaccountname="$AWS_AD_DEACTIVATED_USER_SAMACCOUNTNAME"
  pinniped_test_deactivated_ad_user_password="$AWS_AD_DEACTIVATED_USER_PASSWORD"
  pinniped_test_ad_user_email_attribute_name="mail"
  pinniped_test_ad_user_email_attribute_value="$AWS_AD_USER_EMAIL_ATTRIBUTE_VALUE"
  pinniped_test_ad_defaultnamingcontext_dn="$AWS_AD_DEFAULTNAMINGCONTEXT_DN"
  pinniped_test_ad_users_dn="$AWS_AD_USERS_DN"
else
  pinniped_test_ad_host=""
  pinniped_test_ad_domain=""
  pinniped_test_ad_bind_account_username=""
  pinniped_test_ad_bind_account_password=""
  pinniped_test_ad_user_password=""
  pinniped_test_ad_user_unique_id_attribute_name=""
  pinniped_test_ad_user_unique_id_attribute_value=""
  pinniped_test_ad_user_user_principal_name=""
  pinniped_test_ad_user_expected_groups_dn=""
  pinniped_test_ad_user_expected_groups_cn=""
  pinniped_test_ad_user_expected_indirect_groups_samaccountname=""
  pinniped_test_ad_user_expected_indirect_groups_samaccountname_domainnames=""
  pinniped_test_ad_ldaps_ca_bundle=""
  pinniped_test_deactivated_ad_user_samaccountname=""
  pinniped_test_deactivated_ad_user_password=""
  pinniped_test_ad_user_email_attribute_name=""
  pinniped_test_ad_user_email_attribute_value=""
  pinniped_test_ad_defaultnamingcontext_dn=""
  pinniped_test_ad_users_dn=""
fi

if [[ "${PINNIPED_TEST_GITHUB_APP_CLIENT_ID:-none}" != "none" ]]; then
  pinniped_test_github_app_client_id="$PINNIPED_TEST_GITHUB_APP_CLIENT_ID"
  pinniped_test_github_app_client_secret="$PINNIPED_TEST_GITHUB_APP_CLIENT_SECRET"
  pinniped_test_github_oauth_app_client_id="$PINNIPED_TEST_GITHUB_OAUTH_APP_CLIENT_ID"
  pinniped_test_github_oauth_app_client_secret="$PINNIPED_TEST_GITHUB_OAUTH_APP_CLIENT_SECRET"
  pinniped_test_github_oauth_app_allowed_callback_url="$PINNIPED_TEST_GITHUB_OAUTH_APP_ALLOWED_CALLBACK_URL"
  pinniped_test_github_user_username="$PINNIPED_TEST_GITHUB_USER_USERNAME"
  pinniped_test_github_user_password="$PINNIPED_TEST_GITHUB_USER_PASSWORD"
  pinniped_test_github_user_otp_secret="$PINNIPED_TEST_GITHUB_USER_OTP_SECRET"
  pinniped_test_github_userid="$PINNIPED_TEST_GITHUB_USERID"
  pinniped_test_github_org="$PINNIPED_TEST_GITHUB_ORG"
  pinniped_test_github_expected_team_names="$PINNIPED_TEST_GITHUB_EXPECTED_TEAM_NAMES"
  pinniped_test_github_expected_team_slugs="$PINNIPED_TEST_GITHUB_EXPECTED_TEAM_SLUGS"
else
  pinniped_test_github_app_client_id=""
  pinniped_test_github_app_client_secret=""
  pinniped_test_github_oauth_app_client_id=""
  pinniped_test_github_oauth_app_client_secret=""
  pinniped_test_github_oauth_app_allowed_callback_url=""
  pinniped_test_github_user_username=""
  pinniped_test_github_user_password=""
  pinniped_test_github_user_otp_secret=""
  pinniped_test_github_userid=""
  pinniped_test_github_org=""
  pinniped_test_github_expected_team_names=""
  pinniped_test_github_expected_team_slugs=""
fi

#
# Deploy Concierge
#
pushd deploy/concierge >/dev/null

# Prepare ytt flags that should be either added to set a custom value or omitted to accept the default from ytt.
concierge_optional_ytt_values=()
if [[ -n "${PINNIPED_API_GROUP_SUFFIX:-}" ]]; then
  concierge_optional_ytt_values+=("--data-value-yaml=api_group_suffix=${PINNIPED_API_GROUP_SUFFIX}")
fi
if [[ "${FIREWALL_IDPS:-no}" == "yes" ]]; then
  # Configure the web proxy on the Concierge pods. Note that .svc and .cluster.local are not included,
  # so requests for things like pinniped-supervisor-clusterip.supervisor.svc.cluster.local and
  # local-user-authenticator.local-user-authenticator.svc.cluster.local will go through the web proxy.
  concierge_optional_ytt_values+=("--data-value=https_proxy=http://proxy.tools.svc.cluster.local:3128")
  concierge_optional_ytt_values+=("--data-value=no_proxy=\$(KUBERNETES_SERVICE_HOST),169.254.169.254,127.0.0.1,localhost")
fi
if [[ -n "${SUPERVISOR_AND_CONCIERGE_NO_CPU_REQUEST:-}" ]]; then
  concierge_optional_ytt_values+=("--file=/tmp/remove-cpu-request-overlay.yaml")
fi

echo "Deploying the Concierge app to the cluster..."
echo "Using ytt optional flags:" "${concierge_optional_ytt_values[@]}"
ytt --file . \
  --data-value "app_name=$concierge_app_name" \
  --data-value "namespace=$concierge_namespace" \
  --data-value "image_repo=$IMAGE_REPO" \
  --data-value "image_digest=${IMAGE_DIGEST:-}" \
  --data-value "image_tag=${IMAGE_TAG:-}" \
  --data-value-yaml "image_pull_dockerconfigjson=${IMAGE_PULL_SECRET:-}" \
  --data-value "api_serving_certificate_duration_seconds=${API_SERVING_CERT_DURATION:-2592000}" \
  --data-value "api_serving_certificate_renew_before_seconds=${API_SERVING_CERT_RENEW_BEFORE:-2160000}" \
  --data-value "log_level=debug" \
  --data-value-yaml "custom_labels=$concierge_custom_labels" \
  --data-value "discovery_url=$discovery_url" \
  ${concierge_optional_ytt_values[@]+"${concierge_optional_ytt_values[@]}"} \
  >"$manifest"

echo
echo "Full Concierge app manifest with Secrets redacted..."
echo "--------------------------------------------------------------------------------"
print_redacted_manifest $manifest
echo "--------------------------------------------------------------------------------"
echo

set -x
kapp deploy --yes --app "$concierge_app_name" --diff-changes --file "$manifest"

if ! { (($(kubectl version --output json | jq -r .serverVersion.major) == 1)) && (($(kubectl version --output json | jq -r .serverVersion.minor) < 19)); }; then
  # Also perform a dry-run create with kubectl just to see if there are any validation errors.
  # Skip this on very old clusters, since we use some API fields (like seccompProfile) which did not exist back then.
  # Use can still install on these clusters by using kapp or by using kubectl --validate=false.
  kubectl create --dry-run=client -f "$manifest"
fi

{ set +x; } 2>/dev/null

popd >/dev/null

#
# Deploy Supervisor
#
pushd deploy/supervisor >/dev/null

supervisor_ytt_service_flags=()
if [[ "${USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR:-no}" != "yes" ]]; then
  if [[ "${SUPERVISOR_LOAD_BALANCER:-no}" == "yes" ]]; then
    supervisor_ytt_service_flags+=("--data-value-yaml=service_https_loadbalancer_port=443")
    if [[ "${SUPERVISOR_LOAD_BALANCER_STATIC_IP:-}" != "" ]]; then
      supervisor_ytt_service_flags+=("--data-value=service_loadbalancer_ip=$SUPERVISOR_LOAD_BALANCER_STATIC_IP")
    fi
  fi
  if [[ "${SUPERVISOR_INGRESS:-no}" == "yes" ]]; then
    # even when we have functioning ingress, we need a TCP connection to the supervisor https port to test its TLS config
    supervisor_ytt_service_flags+=("--data-value-yaml=service_https_nodeport_port=443")
  fi
  if [[ "${SUPERVISOR_LOAD_BALANCER:-no}" == "no" && "${SUPERVISOR_INGRESS:-no}" == "no" ]]; then
    # When no specific service was requested for the supervisor, we assume we are running on
    # kind, and therefore expect to talk to the supervisor via NodePort and ClusterIP services.
    # This nodePort is the same port number is hardcoded in the port forwarding of our kind configuration.
    supervisor_ytt_service_flags+=("--data-value-yaml=service_https_nodeport_port=443")
    supervisor_ytt_service_flags+=("--data-value-yaml=service_https_clusterip_port=443")
    supervisor_ytt_service_flags+=("--data-value-yaml=service_https_nodeport_nodeport=${PINNIPED_SUPERVISOR_HTTPS_NODEPORT:-31243}")
  fi
fi

# Prepare ytt flags that should be either added to set a custom value or omitted to accept the default from ytt.
supervisor_optional_ytt_values=()
if [[ -n "${PINNIPED_API_GROUP_SUFFIX:-}" ]]; then
  supervisor_optional_ytt_values+=("--data-value-yaml=api_group_suffix=${PINNIPED_API_GROUP_SUFFIX}")
fi
if [[ "${FIREWALL_IDPS:-no}" == "yes" ]]; then
  # Configure the web proxy on the Supervisor pods. Note that .svc and .cluster.local are not included,
  # so requests for things like dex.tools.svc.cluster.local will go through the web proxy.
  supervisor_optional_ytt_values+=("--data-value=https_proxy=http://proxy.tools.svc.cluster.local:3128")
  supervisor_optional_ytt_values+=("--data-value=no_proxy=\$(KUBERNETES_SERVICE_HOST),169.254.169.254,127.0.0.1,localhost")
fi
if [[ -n "${SUPERVISOR_AND_CONCIERGE_NO_CPU_REQUEST:-}" ]]; then
  supervisor_optional_ytt_values+=("--file=/tmp/remove-cpu-request-overlay.yaml")
fi
if [[ "${SUPERVISOR_INGRESS:-no}" == "yes" && "$cluster_has_gke_backend_config" == "yes" ]]; then
  supervisor_optional_ytt_values+=("--file=/tmp/add-annotations-for-gke-ingress-overlay.yaml")
fi

echo "Deploying the Supervisor app to the cluster..."
echo "Using ytt service flags:" "${supervisor_ytt_service_flags[@]}"
echo "Using ytt optional flags:" "${supervisor_optional_ytt_values[@]}"
ytt --file . \
  --data-value "app_name=$supervisor_app_name" \
  --data-value "namespace=$supervisor_namespace" \
  --data-value "image_repo=$IMAGE_REPO" \
  --data-value "image_digest=${IMAGE_DIGEST:-}" \
  --data-value "image_tag=${IMAGE_TAG:-}" \
  --data-value-yaml "image_pull_dockerconfigjson=${IMAGE_PULL_SECRET:-}" \
  --data-value "log_level=debug" \
  --data-value-yaml "custom_labels=$supervisor_custom_labels" \
  "${supervisor_ytt_service_flags[@]}" \
  ${supervisor_optional_ytt_values[@]+"${supervisor_optional_ytt_values[@]}"} \
  >"$manifest"

echo
echo "Full Supervisor app manifest with Secrets redacted..."
echo "--------------------------------------------------------------------------------"
print_redacted_manifest $manifest
echo "--------------------------------------------------------------------------------"
echo

set -x
kapp deploy --yes --app "$supervisor_app_name" --diff-changes --file "$manifest"

if ! { (($(kubectl version --output json | jq -r .serverVersion.major) == 1)) && (($(kubectl version --output json | jq -r .serverVersion.minor) < 23)); }; then
  # Also perform a dry-run create with kubectl just to see if there are any validation errors.
  # Skip this on very old clusters, since we use some API fields (like seccompProfile) which did not exist back then.
  # In the Supervisor CRDs we began to use CEL validations which were introduced in Kubernetes 1.23.
  # Use can still install on these clusters by using kapp or by using kubectl --validate=false.
  kubectl create --dry-run=client -f "$manifest"
fi

{ set +x; } 2>/dev/null

# Now that the everything is deployed, optionally firewall the Dex server, the local user authenticator server,
# and the GitHub API so that the Supervisor and Concierge cannot reach them directly. However, the Squid
# proxy server can reach them all, so the Supervisor and Concierge can reach them through the proxy.
if [[ "${FIREWALL_IDPS:-no}" == "yes" ]]; then
  echo "Setting up firewalls for the Supervisor and Concierge's outgoing TCP/UDP network traffic..."
  cat <<EOF | kubectl apply --wait -f -
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: supervisor-cannot-make-external-requests
  namespace: ${supervisor_namespace}
spec:
  # An empty podSelector matches all pods in this namespace.
  podSelector: {}
  policyTypes:
    - Egress
  # This is an allow list. Everything else disallowed.
  # Especially note that it cannot access Dex or the GitHub API directly.
  egress:
  - to:
    # Allowed to make requests to all pods in kube-system for DNS and Kube API.
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    # Allowed to make requests to the LDAP server in tools, because we cannot use
    # an HTTP proxy for the LDAP protocol, since LDAP is not over HTTP.
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: tools
      podSelector:
        matchLabels:
          app: ldap
    # Allowed to make requests to the Squid proxy server in the tools namespace.
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: tools
      podSelector:
        matchLabels:
          app: proxy
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: concierge-cannot-make-external-requests
  namespace: ${concierge_namespace}
spec:
  # An empty podSelector matches all pods in this namespace.
  podSelector: {}
  policyTypes:
    - Egress
  # This is an allow list. Everything else disallowed.
  # Especially note that it cannot access the local user authenticator or Supervisor directly.
  egress:
  - to:
    # Allowed to make requests to all pods in kube-system for DNS and Kube API.
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    # Allowed to make requests to the Squid proxy server in the tools namespace.
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: tools
      podSelector:
        matchLabels:
          app: proxy
EOF
fi

# When we test on kind, we use "kubectl port-forward" in the task script to expose these ports for the integration tests.
supervisor_https_address='https://localhost:12344'
supervisor_https_ingress_address=
supervisor_https_ingress_ca_bundle=

if [[ "${SUPERVISOR_LOAD_BALANCER:-no}" == "yes" ]]; then
  # Wait for the load balancer that was created during the supervisor deploy to publish the ingress address.
  ingress_json='{}'
  while [[ "$ingress_json" == '{}' ]]; do
    echo "Checking for load balancer ingress address..."
    sleep 1
    ingress_json=$(kubectl get service "${supervisor_service_name}" -n "$supervisor_namespace" -o json |
      jq -r '.status.loadBalancer')
  done

  echo "Load balancer reported ingress: $ingress_json"
  ingress_ip=$(echo "$ingress_json" | jq -r '.ingress[0].ip')

  if [[ "${SUPERVISOR_LOAD_BALANCER_STATIC_IP:-}" == "" ]]; then
    # No static IP was provided, so the load balancer was allowed to choose its own IP.
    # Update the DNS record associated with $SUPERVISOR_LOAD_BALANCER_DNS_NAME to make it match the new IP.
    update_gcloud_dns_record "$SUPERVISOR_LOAD_BALANCER_DNS_NAME" "$ingress_ip"
  fi

  # Use the published ingress address for the integration test env vars below.
  supervisor_https_address="https://${SUPERVISOR_LOAD_BALANCER_DNS_NAME}:443"
elif [[ "${USE_LOAD_BALANCERS_FOR_DEX_AND_SUPERVISOR:-no}" == "yes" ]]; then
  supervisor_https_address="https://${supervisor_loadbalancer_public_ip_or_hostname}:443"
fi

if [[ "${SUPERVISOR_INGRESS:-no}" == "yes" ]]; then
  # Create a secret for the ingress cert.
  #
  # Note! If someone were to change the ingress DNS name (SUPERVISOR_INGRESS_DNS_NAME),
  # then this script might reuse the existing secret that has the old DNS name in it. The
  # failure would show up when we run the integration tests looking something like "x509:
  # cannot validate certificate".
  ingress_tls_ca_secret="supervisor-ingress-tls-ca"
  ingress_tls_secret="supervisor-ingress-tls"
  ingress_tls_ca_cert_file="/tmp/ingress-tls-ca-cert.crt"
  ingress_tls_cert_file="/tmp/ingress-tls-cert.crt"
  if [[ "$(kubectl get -n "$supervisor_namespace" secret "$ingress_tls_secret" --ignore-not-found)" == "" ]]; then
    ca_cert_config_file="/tmp/ingress-tls-ca-cert.conf"
    cat <<EOF >"$ca_cert_config_file"
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Pinniped
OU = Pinniped Testing CA
[v3_req]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = keyCertSign, digitalSignature
EOF

    ca_key_file="/tmp/ingress-tls-ca-cert.key"
    openssl req \
      -new \
      -x509 \
      -config "$ca_cert_config_file" \
      -days 36500 \
      -sha256 \
      -out "$ingress_tls_ca_cert_file" \
      -newkey rsa:2048 \
      -keyout "$ca_key_file" \
      -nodes
    echo "Creating ingress tls CA secret: $ingress_tls_ca_secret"
    kubectl -n "$supervisor_namespace" create secret tls "$ingress_tls_ca_secret" \
      --cert="$ingress_tls_ca_cert_file" --key="$ca_key_file"

    cert_config_file="/tmp/ingress-tls-cert.conf"
    cat <<EOF >"$cert_config_file"
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = ${SUPERVISOR_INGRESS_DNS_NAME}
C = US
ST = California
L = San Fransisco
O = Pinniped
[v3_req]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
keyUsage = keyEncipherment, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SUPERVISOR_INGRESS_DNS_NAME}
EOF

    key_file="/tmp/ingress-tls-cert.key"
    csr_file="/tmp/ingress-tls-cert.csr"
    openssl req \
      -new \
      -config "$cert_config_file" \
      -sha256 \
      -out "$csr_file" \
      -newkey rsa:2048 \
      -keyout "$key_file" \
      -nodes
    openssl x509 \
      -req \
      -in "$csr_file" \
      -extfile "$cert_config_file" \
      -extensions 'v3_req' \
      -days 36500 \
      -sha256 \
      -out "$ingress_tls_cert_file" \
      -CA "$ingress_tls_ca_cert_file" \
      -CAkey "$ca_key_file" \
      -CAcreateserial

    echo "Creating ingress tls secret: $ingress_tls_secret"
    kubectl -n "$supervisor_namespace" create secret tls "$ingress_tls_secret" \
      --cert="$ingress_tls_cert_file" --key="$key_file"
  else
    # The Secret already exists, so just read the server's public key from it.
    kubectl get -n "$supervisor_namespace" secret "$ingress_tls_ca_secret" -o jsonpath=\{.data.'tls\.crt'\} | base64 -d >"$ingress_tls_ca_cert_file"
    kubectl get -n "$supervisor_namespace" secret "$ingress_tls_secret" -o jsonpath=\{.data.'tls\.crt'\} | base64 -d >"$ingress_tls_cert_file"
  fi

  # If a static IP name was provided then use it. Otherwise, don't include the annotation at all.
  static_ip_annotation=""
  if [[ "${SUPERVISOR_INGRESS_STATIC_IP_NAME:-}" != "" ]]; then
    static_ip_annotation="kubernetes.io/ingress.global-static-ip-name: ${SUPERVISOR_INGRESS_STATIC_IP_NAME}"
  fi

  if [[ "$cluster_has_gke_backend_config" == "yes" ]]; then
    # Get the nodePort port number that was dynamically assigned to the nodeport service.
    nodeport_service_port=$(kubectl get service -n "${supervisor_namespace}" "${supervisor_app_name}-nodeport" -o jsonpath='{.spec.ports[0].nodePort}')
    echo "${supervisor_app_name}-nodeport Service was assigned nodePort $nodeport_service_port"

    # Create or update a BackendConfig to configure the health checks that will be used by the Ingress for its backend Service.
    # The annotation already added to the Service by an overlay above tells the Service to use this BackendConfig.
    cat <<EOF | kubectl apply --wait -f -
apiVersion: cloud.google.com/v1
kind: BackendConfig
metadata:
  name: healthcheck-backendconfig
  namespace: ${supervisor_namespace}
spec:
  healthCheck:
    type: HTTPS
    requestPath: /healthz
    timeoutSec: 10
    checkIntervalSec: 30
    healthyThreshold: 1
    unhealthyThreshold: 10
    port: ${nodeport_service_port}
EOF
  fi

  # Create or update an Ingress to sit in front of our supervisor-nodeport service.
  cat <<EOF | kubectl apply --wait -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ${supervisor_app_name}
  namespace: ${supervisor_namespace}
  annotations:
    kubernetes.io/ingress.allow-http: "false"
    nginx.ingress.kubernetes.io/backend-protocol: HTTPS
    # TODO Re-enable backend TLS cert verification once the Supervisor's default TLS cert is generated by automation in this script.
    # Using tooling that was manually installed to manage the default TLS cert makes the cluster a snowflake that cannot be easily reproduced.
    #nginx.ingress.kubernetes.io/proxy-ssl-verify: "on"
    #nginx.ingress.kubernetes.io/proxy-ssl-secret: ${supervisor_namespace}/${supervisor_app_name}-default-tls-certificate
    nginx.ingress.kubernetes.io/proxy-ssl-verify: "off"
    ${static_ip_annotation}
spec:
  defaultBackend:
    service:
      name: ${supervisor_app_name}-nodeport
      port:
        number: 443
  tls:
    - secretName: ${ingress_tls_secret}
      hosts:
        - ${SUPERVISOR_INGRESS_DNS_NAME}
EOF

  # If no static IP was provided for the ingress, then register the dynamic IP of the ingress with the DNS provider.
  if [[ "${SUPERVISOR_INGRESS_STATIC_IP_NAME:-}" == "" ]]; then
    # Wait for the ingress to get an IP
    ingress_json='{}'
    while [[ "$ingress_json" == '{}' ]]; do
      echo "Checking for ingress address..."
      sleep 1
      ingress_json=$(kubectl get ingress "${supervisor_app_name}" -n "$supervisor_namespace" -o json |
        jq -r '.status.loadBalancer')
    done

    echo "Ingress reported address: $ingress_json"
    ingress_ip=$(echo "$ingress_json" | jq -r '.ingress[0].ip')

    # No static IP was provided, so the load balancer was allowed to choose its own IP.
    # Update the DNS record associated with $SUPERVISOR_INGRESS_DNS_NAME to make it match the new IP.
    update_gcloud_dns_record "$SUPERVISOR_INGRESS_DNS_NAME" "$ingress_ip"
  fi

  # Wait for the Ingress frontend to be up and running. Wait forever... until this Concourse task times out.
  healthz_via_ingress_url="https://${SUPERVISOR_INGRESS_DNS_NAME}/healthz"
  echo "The Ingress TLS CA bundle is:"
  cat "$ingress_tls_ca_cert_file"
  echo
  while ! curl -s -f --cacert "$ingress_tls_ca_cert_file" "$healthz_via_ingress_url"; do
    echo "Curling Supervisor via Ingress $healthz_via_ingress_url (this could take about 10 minutes for a new Ingress)..."
    sleep 10
  done

  supervisor_https_ingress_address="https://$SUPERVISOR_INGRESS_DNS_NAME"
  supervisor_https_ingress_ca_bundle="$(base64 <"$ingress_tls_ca_cert_file")"
  echo "Using ingress external address: $supervisor_https_ingress_address"
fi

popd >/dev/null

#
# Set up the integration test env vars
#
pinniped_cluster_capability_file_content=$(cat "$PINNIPED_TEST_CLUSTER_CAPABILITY_FILE")

cat <<EOF >/tmp/integration-test-env
export PINNIPED_TEST_TOOLS_NAMESPACE='${pinniped_test_tools_namespace}'
export PINNIPED_TEST_CONCIERGE_NAMESPACE='${concierge_namespace}'
export PINNIPED_TEST_CONCIERGE_APP_NAME='${concierge_app_name}'
export PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS='${concierge_custom_labels}'
export PINNIPED_TEST_USER_USERNAME='${test_username}'
export PINNIPED_TEST_USER_GROUPS='${test_groups}'
export PINNIPED_TEST_USER_TOKEN='${test_user_token}'
export PINNIPED_TEST_WEBHOOK_ENDPOINT='${webhook_url}'
export PINNIPED_TEST_WEBHOOK_CA_BUNDLE='${webhook_ca_bundle}'
export PINNIPED_TEST_SUPERVISOR_NAMESPACE='${supervisor_namespace}'
export PINNIPED_TEST_SUPERVISOR_APP_NAME='${supervisor_app_name}'
export PINNIPED_TEST_SUPERVISOR_SERVICE_NAME='${supervisor_service_name}'
export PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS='${supervisor_custom_labels}'
export PINNIPED_TEST_SUPERVISOR_HTTPS_ADDRESS='${supervisor_https_address}'
export PINNIPED_TEST_SUPERVISOR_HTTPS_INGRESS_ADDRESS='${supervisor_https_ingress_address}'
export PINNIPED_TEST_SUPERVISOR_HTTPS_INGRESS_CA_BUNDLE='${supervisor_https_ingress_ca_bundle}'
export PINNIPED_TEST_PROXY='${test_proxy}'
export PINNIPED_TEST_LDAP_HOST='${pinniped_test_ldap_host}'
export PINNIPED_TEST_LDAP_STARTTLS_ONLY_HOST='${pinniped_test_ldap_starttls_only_host}'
export PINNIPED_TEST_LDAP_LDAPS_CA_BUNDLE='${pinniped_test_ldap_ldaps_ca_bundle}'
export PINNIPED_TEST_LDAP_BIND_ACCOUNT_USERNAME='${pinniped_test_ldap_bind_account_username}'
export PINNIPED_TEST_LDAP_BIND_ACCOUNT_PASSWORD='${pinniped_test_ldap_bind_account_password}'
export PINNIPED_TEST_LDAP_USERS_SEARCH_BASE='${pinniped_test_ldap_users_search_base}'
export PINNIPED_TEST_LDAP_GROUPS_SEARCH_BASE='${pinniped_test_ldap_groups_search_base}'
export PINNIPED_TEST_LDAP_USER_DN='${pinniped_test_ldap_user_dn}'
export PINNIPED_TEST_LDAP_USER_CN='${pinniped_test_ldap_user_cn}'
export PINNIPED_TEST_LDAP_USER_PASSWORD='${pinniped_test_ldap_user_password}'
export PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_NAME='${pinniped_test_ldap_user_unique_id_attribute_name}'
export PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_VALUE='${pinniped_test_ldap_user_unique_id_attribute_value}'
export PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_NAME='${pinniped_test_ldap_user_email_attribute_name}'
export PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_VALUE='${pinniped_test_ldap_user_email_attribute_value}'
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_GROUPS_DN='${pinniped_test_ldap_expected_direct_groups_dn}'
export PINNIPED_TEST_LDAP_EXPECTED_INDIRECT_GROUPS_DN='${pinniped_test_ldap_expected_indirect_groups_dn}'
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_GROUPS_CN='${pinniped_test_ldap_expected_direct_groups_cn}'
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_POSIX_GROUPS_CN='${pinniped_test_ldap_expected_direct_posix_groups_cn}'
export PINNIPED_TEST_LDAP_EXPECTED_INDIRECT_GROUPS_CN='${pinniped_test_ldap_expected_indirect_groups_cn}'
export PINNIPED_TEST_CLI_OIDC_CALLBACK_URL='${test_cli_oidc_callback_url}'
export PINNIPED_TEST_CLI_OIDC_CLIENT_ID='${test_cli_oidc_client_id}'
export PINNIPED_TEST_CLI_OIDC_ISSUER_CA_BUNDLE='${test_cli_oidc_issuer_ca_bundle}'
export PINNIPED_TEST_CLI_OIDC_ISSUER='${test_cli_oidc_issuer}'
export PINNIPED_TEST_CLI_OIDC_PASSWORD='${test_cli_oidc_password}'
export PINNIPED_TEST_CLI_OIDC_USERNAME='${test_cli_oidc_username}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CALLBACK_URL='${test_supervisor_upstream_oidc_callback_url}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ADDITIONAL_SCOPES='${test_supervisor_upstream_oidc_additional_scopes}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME_CLAIM='${test_supervisor_upstream_oidc_username_claim}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_GROUPS_CLAIM='${test_supervisor_upstream_oidc_groups_claim}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_ID='${test_supervisor_upstream_oidc_client_id}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_SECRET='${test_supervisor_upstream_oidc_client_secret}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER_CA_BUNDLE='${test_supervisor_upstream_oidc_issuer_ca_bundle}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER='${test_supervisor_upstream_oidc_issuer}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_PASSWORD='${test_supervisor_upstream_oidc_password}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME='${test_supervisor_upstream_oidc_username}'
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_EXPECTED_GROUPS='${test_supervisor_upstream_oidc_groups}'
export PINNIPED_TEST_AD_HOST='${pinniped_test_ad_host}'
export PINNIPED_TEST_AD_DOMAIN='${pinniped_test_ad_domain}'
export PINNIPED_TEST_AD_BIND_ACCOUNT_USERNAME='${pinniped_test_ad_bind_account_username}'
export PINNIPED_TEST_AD_BIND_ACCOUNT_PASSWORD='${pinniped_test_ad_bind_account_password}'
export PINNIPED_TEST_AD_USER_UNIQUE_ID_ATTRIBUTE_NAME='${pinniped_test_ad_user_unique_id_attribute_name}'
export PINNIPED_TEST_AD_USER_UNIQUE_ID_ATTRIBUTE_VALUE='${pinniped_test_ad_user_unique_id_attribute_value}'
export PINNIPED_TEST_AD_USER_USER_PRINCIPAL_NAME='${pinniped_test_ad_user_user_principal_name}'
export PINNIPED_TEST_AD_USER_PASSWORD='${pinniped_test_ad_user_password}'
export PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_DN='${pinniped_test_ad_user_expected_groups_dn}'
export PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_CN='${pinniped_test_ad_user_expected_groups_cn}'
export PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_SAMACCOUNTNAME='${pinniped_test_ad_user_expected_indirect_groups_samaccountname}'
export PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_SAMACCOUNTNAME_DOMAINNAMES='${pinniped_test_ad_user_expected_indirect_groups_samaccountname_domainnames}'
export PINNIPED_TEST_AD_LDAPS_CA_BUNDLE='${pinniped_test_ad_ldaps_ca_bundle}'
export PINNIPED_TEST_DEACTIVATED_AD_USER_SAMACCOUNTNAME='${pinniped_test_deactivated_ad_user_samaccountname}'
export PINNIPED_TEST_DEACTIVATED_AD_USER_PASSWORD='${pinniped_test_deactivated_ad_user_password}'
export PINNIPED_TEST_AD_USER_EMAIL_ATTRIBUTE_NAME='${pinniped_test_ad_user_email_attribute_name}'
export PINNIPED_TEST_AD_USER_EMAIL_ATTRIBUTE_VALUE='${pinniped_test_ad_user_email_attribute_value}'
export PINNIPED_TEST_AD_DEFAULTNAMINGCONTEXT_DN='${pinniped_test_ad_defaultnamingcontext_dn}'
export PINNIPED_TEST_AD_USERS_DN='${pinniped_test_ad_users_dn}'
export PINNIPED_TEST_GITHUB_APP_CLIENT_ID='${pinniped_test_github_app_client_id}'
export PINNIPED_TEST_GITHUB_APP_CLIENT_SECRET='${pinniped_test_github_app_client_secret}'
export PINNIPED_TEST_GITHUB_OAUTH_APP_CLIENT_ID='${pinniped_test_github_oauth_app_client_id}'
export PINNIPED_TEST_GITHUB_OAUTH_APP_CLIENT_SECRET='${pinniped_test_github_oauth_app_client_secret}'
export PINNIPED_TEST_GITHUB_OAUTH_APP_ALLOWED_CALLBACK_URL='${pinniped_test_github_oauth_app_allowed_callback_url}'
export PINNIPED_TEST_GITHUB_USER_USERNAME='${pinniped_test_github_user_username}'
export PINNIPED_TEST_GITHUB_USER_PASSWORD='${pinniped_test_github_user_password}'
export PINNIPED_TEST_GITHUB_USER_OTP_SECRET='${pinniped_test_github_user_otp_secret}'
export PINNIPED_TEST_GITHUB_USERID='${pinniped_test_github_userid}'
export PINNIPED_TEST_GITHUB_ORG='${pinniped_test_github_org}'
export PINNIPED_TEST_GITHUB_EXPECTED_TEAM_NAMES='${pinniped_test_github_expected_team_names}'
export PINNIPED_TEST_GITHUB_EXPECTED_TEAM_SLUGS='${pinniped_test_github_expected_team_slugs}'
export PINNIPED_TEST_SHELL_CONTAINER_IMAGE="ghcr.io/pinniped-ci-bot/test-kubectl:latest"

read -r -d '' PINNIPED_TEST_CLUSTER_CAPABILITY_YAML << PINNIPED_TEST_CLUSTER_CAPABILITY_YAML_EOF || true
${pinniped_cluster_capability_file_content}
PINNIPED_TEST_CLUSTER_CAPABILITY_YAML_EOF

export PINNIPED_TEST_CLUSTER_CAPABILITY_YAML
EOF

if [[ -n "${PINNIPED_API_GROUP_SUFFIX:-}" ]]; then
  # Only when $PINNIPED_API_GROUP_SUFFIX was passed in, then also append the related flag in the test env,
  # because it has a good default value in the integration test helper library.
  cat <<EOF >>/tmp/integration-test-env

export PINNIPED_TEST_API_GROUP_SUFFIX='${PINNIPED_API_GROUP_SUFFIX}'
EOF
fi
