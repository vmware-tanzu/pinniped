#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script can be used to prepare a kind cluster and deploy the app.
# You can call this script again to redeploy the app.
# It will also output instructions on how to run the integration tests.
#
# When invoked with the PINNIPED_USE_LOCAL_KIND_REGISTRY environment variable set to a non-empty value, then
# this script will create a local registry and configure kind to use that registry. This is normally unnecessary.
# However, if an alternative build and deploy approach is used, such as via a Carvel packaging mechanism, then a local
# registry could be needed (e.g. the kbld tool requires a registry to resolve images to shas).
# For example, to alternatively build and deploy Pinniped as a Carvel package, use:
#   PINNIPED_USE_LOCAL_KIND_REGISTRY=1 ./hack/prepare-for-integration-tests.sh --clean --pre-install ./hack/lib/carvel_packages/build.sh --alternate-deploy ./hack/lib/carvel_packages/deploy.sh
#
# Set PINNIPED_USE_CONTOUR=1 when running this script to cause the kind cluster created by this script to be
# ready for using PINNIPED_USE_CONTOUR=1 with subsequent hack scripts, e.g. prepare-supervisor-on-kind.sh.
#
set -euo pipefail

pinniped_path="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$pinniped_path" || exit 1

source hack/lib/helpers.sh

#
# Handle argument parsing and help message
#
help=no
skip_build=no
clean_kind=no
api_group_suffix="pinniped.dev" # same default as in the values.yaml ytt file
dockerfile_path=""
get_active_directory_vars="" # specify a filename for a script to get AD related env variables
get_github_vars="" # specify a filename for a script to get GitHub related env variables
alternate_deploy="undefined"
pre_install="undefined"

while (("$#")); do
  case "$1" in
  -h | --help)
    help=yes
    shift
    ;;
  -s | --skip-build)
    skip_build=yes
    shift
    ;;
  -c | --clean)
    clean_kind=yes
    shift
    ;;
  -g | --api-group-suffix)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "-g|--api-group-suffix requires a group name to be specified"
      exit 1
    fi
    api_group_suffix=$1
    shift
    ;;
  -a | --get-active-directory-vars)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "--get-active-directory-vars requires a script name to be specified"
      exit 1
    fi
    get_active_directory_vars=$1
    shift
    ;;
  --get-github-vars)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "--get-github-vars requires a script name to be specified"
      exit 1
    fi
    get_github_vars=$1
    shift
    ;;
  --dockerfile-path)
    shift
    # If there are no more command line arguments, or there is another command line argument but it starts with a dash, then error
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "--dockerfile-path requires a script name to be specified"
      exit 1
    fi
    dockerfile_path=$1
    shift
    ;;
  --alternate-deploy)
    shift
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "--alternate-deploy requires a script path to be specified"
      exit 1
    fi
    alternate_deploy=$1
    shift
    ;;
  --pre-install)
    shift
    if [[ "$#" == "0" || "$1" == -* ]]; then
      log_error "--pre-install requires a script path to be specified"
      exit 1
    fi
    pre_install=$1
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
  log_note "   -h, --help:                      print this usage"
  log_note "   -c, --clean:                     destroy the current kind cluster and make a new one"
  log_note "   -g, --api-group-suffix:          deploy Pinniped with an alternate API group suffix"
  log_note "   -s, --skip-build:                reuse the most recently built image of the app instead of building"
  log_note "   -a, --get-active-directory-vars: specify a script that exports active directory environment variables"
  log_note "       --get-github-vars:           specify a script that exports GitHub environment variables"
  log_note "       --alternate-deploy:          specify an alternate deploy script to install all components of Pinniped"
  log_note "       --pre-install:               specify an pre-install script such as a build script"
  exit 1
fi

#
# Check for dependencies
#
check_dependency docker "Please install docker. See https://docs.docker.com/get-docker"
check_dependency kind "Please install kind. e.g. 'brew install kind' for MacOS"
check_dependency ytt "Please install ytt. e.g. 'brew tap vmware-tanzu/carvel && brew install ytt' for MacOS"
check_dependency kapp "Please install kapp. e.g. 'brew tap vmware-tanzu/carvel && brew install kapp' for MacOS"
check_dependency kubectl "Please install kubectl. e.g. 'brew install kubectl' for MacOS"
check_dependency htpasswd "Please install htpasswd. Should be pre-installed on MacOS. Usually found in 'apache2-utils' package for linux."
check_dependency openssl "Please install openssl. Should be pre-installed on MacOS."
check_dependency nmap "Please install nmap. e.g. 'brew install nmap' for MacOS"

# Require kubectl >= 1.21.x.
if [ "$(kubectl version --client=true -o=json | grep gitVersion | cut -d '.' -f 2)" -lt 21 ]; then
  log_error "kubectl >= 1.21.x is required, you have $(kubectl version --client=true --short | cut -d ':' -f2)"
  exit 1
fi

# Require nmap >= 7.92.x
if [ "$(nmap -V | grep 'Nmap version' | cut -d ' ' -f 3 | cut -d '.' -f 2)" -lt 92 ]; then
  log_error "nmap >= 7.92.x is required, you have $(nmap -V | grep 'Nmap version' | cut -d ' ' -f 3)"
  exit 1
fi

if [[ "$clean_kind" == "yes" ]]; then
  log_note "Deleting running kind cluster to prepare from a clean slate..."
  ./hack/kind-down.sh
fi

#
# Setup kind and build the app
#
log_note "Checking for running kind cluster..."
if ! kind get clusters | grep -q -e '^pinniped$'; then
  log_note "Creating a kind cluster..."
  # Our kind config exposes node port 31243 as 127.0.0.1:12344 and 31235 as 127.0.0.1:12346
  ./hack/kind-up.sh
else
  if ! kubectl cluster-info | grep -E '(master|control plane)' | grep -q 127.0.0.1; then
    log_error "Seems like your kubeconfig is not targeting a local cluster."
    log_error "Exiting to avoid accidentally running tests against a real cluster."
    exit 1
  fi
fi

registry="pinniped.local"
registry_with_port="$registry"
if [[ "${PINNIPED_USE_LOCAL_KIND_REGISTRY:-}" != "" ]]; then
  registry="kind-registry.local"
  registry_with_port="$registry:5000"
fi

repo="test/build"
registry_repo="$registry_with_port/$repo"
tag="0.0.0-$(uuidgen)" # always a new tag to force K8s to reload the image on redeploy

if [[ "${PINNIPED_USE_LOCAL_KIND_REGISTRY:-}" != "" ]]; then
  etc_hosts_local_registry_missing=no
  if ! grep -q "$registry" /etc/hosts; then
    etc_hosts_local_registry_missing=yes
  fi
  if [[ "$etc_hosts_local_registry_missing" == "yes" ]]; then
    echo
    log_error "In order to configure the kind cluster to use the local registry properly,"
    log_error "please run this command to edit /etc/hosts, and then run this script again with the same options."
    echo "sudo bash -c \"echo '127.0.0.1 $registry' >> /etc/hosts\""
    log_error "When you are finished with your Kind cluster, you can remove this line from /etc/hosts."
    exit 1
  fi
fi

if [[ "$skip_build" == "yes" ]]; then
  most_recent_tag=$(docker images "$registry_repo" --format "{{.Tag}}" | head -1)
  if [[ -n "$most_recent_tag" ]]; then
    tag="$most_recent_tag"
    do_build=no
  else
    # Oops, there was no previous build. Need to build anyway.
    do_build=yes
  fi
else
  do_build=yes
fi

registry_repo_tag="${registry_repo}:${tag}"

if [[ "$do_build" == "yes" ]]; then
  # Rebuild the code
  testing_version="${KUBE_GIT_VERSION:-}"
  if [[ "$dockerfile_path" != "" ]]; then
    log_note "Docker building the app with dockerfile $dockerfile_path and KUBE_GIT_VERSION='$testing_version'"
    DOCKER_BUILDKIT=1 docker build . --tag "$registry_repo_tag" --file "$dockerfile_path" --build-arg "KUBE_GIT_VERSION=$testing_version"
  else
    log_note "Docker building the app with KUBE_GIT_VERSION='$testing_version'"
    # DOCKER_BUILDKIT=1 is optional on MacOS but required on linux.
    DOCKER_BUILDKIT=1 docker build . --tag "$registry_repo_tag" --build-arg "KUBE_GIT_VERSION=$testing_version"
  fi
fi

if [[ "${PINNIPED_USE_LOCAL_KIND_REGISTRY:-}" != "" ]]; then
  # If registry used, push to the registry.
  log_note "Loading the app's container image into the local registry ($registry_with_port)..."
  docker push "$registry_repo_tag"
else
  # Otherwise, side-load directly.
  log_note "Loading the app's container image into the kind cluster..."
  kind load docker-image "$registry_repo_tag" --name pinniped
fi

if [ "$pre_install" != "undefined" ]; then
  log_note "Calling the pre-install script with args: $tag $registry_with_port $repo ..."
  $pre_install pre-install-script "$tag" $registry_with_port $repo
fi

#
# Deploy local-user-authenticator
#
manifest=/tmp/pinniped-local-user-authenticator.yaml
data_values_file=/tmp/local-user-authenticator-values.yml
cat <<EOF >"$data_values_file"
---
image_repo: $registry_repo
image_tag: $tag
EOF

if [ "$alternate_deploy" != "undefined" ]; then
  log_note "The local-user-authenticator will be deployed with $alternate_deploy local-user-authenticator $tag $registry_with_port $repo $data_values_file ..."
  $alternate_deploy local-user-authenticator "$tag" $registry_with_port $repo $data_values_file
else
  log_note "Deploying the local-user-authenticator app to the cluster using kapp..."
  pushd deploy/local-user-authenticator >/dev/null
  ytt --file . --data-values-file "$data_values_file" >"$manifest"
  kapp deploy --yes --app local-user-authenticator --diff-changes --file "$manifest"
  kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
  popd >/dev/null
fi

#
# Deploy Tools
#
manifest=/tmp/pinniped-tools.yaml
dex_test_password="$(openssl rand -hex 16)"
ldap_test_password="$(openssl rand -hex 16)"
pushd test/deploy/tools >/dev/null

log_note "Deploying Tools to the cluster..."
ytt --file . \
  --data-value-yaml "supervisor_redirect_uris=[https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/callback]" \
  --data-value "pinny_ldap_password=$ldap_test_password" \
  --data-value "pinny_bcrypt_passwd_hash=$(htpasswd -nbBC 10 x "$dex_test_password" | sed -e "s/^x://")" \
  >"$manifest"
kapp deploy --yes --app tools --diff-changes --file "$manifest"
kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
popd >/dev/null

#
# Deploy the Pinniped Supervisor
#
manifest=/tmp/pinniped-supervisor.yaml
data_values_file=/tmp/supervisor-values.yml
supervisor_app_name="pinniped-supervisor"
supervisor_namespace="supervisor"
supervisor_custom_labels="{mySupervisorCustomLabelName: mySupervisorCustomLabelValue}"
log_level="debug"
service_https_nodeport_port="443"
service_https_nodeport_nodeport="31243"
service_https_clusterip_port="443"
cat <<EOF >"$data_values_file"
---
app_name: $supervisor_app_name
namespace: $supervisor_namespace
api_group_suffix: $api_group_suffix
image_repo: $registry_repo
image_tag: $tag
log_level: $log_level
custom_labels: $supervisor_custom_labels
service_https_nodeport_port: $service_https_nodeport_port
service_https_nodeport_nodeport: $service_https_nodeport_nodeport
service_https_clusterip_port: $service_https_clusterip_port
EOF

if [ "$alternate_deploy" != "undefined" ]; then
  log_note "The Pinniped Supervisor will be deployed with $alternate_deploy pinniped-supervisor $tag $registry_with_port $repo $data_values_file ..."
  $alternate_deploy pinniped-supervisor "$tag" $registry_with_port $repo $data_values_file
else
  log_note "Deploying the Pinniped Supervisor app to the cluster using kapp..."
  pushd deploy/supervisor >/dev/null
  ytt --file . --data-values-file "$data_values_file" >"$manifest"
  kapp deploy --yes --app "$supervisor_app_name" --diff-changes --file "$manifest"
  kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
  popd >/dev/null
fi

#
# Deploy the Pinniped Concierge
#
manifest=/tmp/pinniped-concierge.yaml
data_values_file=/tmp/concierge-values.yml
concierge_app_name="pinniped-concierge"
concierge_namespace="concierge"
webhook_url="https://local-user-authenticator.local-user-authenticator.svc/authenticate"
discovery_url="$(TERM=dumb kubectl cluster-info | awk '/master|control plane/ {print $NF}')"
concierge_custom_labels="{myConciergeCustomLabelName: myConciergeCustomLabelValue}"
log_level="debug"
cat <<EOF >"$data_values_file"
---
app_name: $concierge_app_name
namespace: $concierge_namespace
api_group_suffix: $api_group_suffix
log_level: $log_level
custom_labels: $concierge_custom_labels
image_repo: $registry_repo
image_tag: $tag
discovery_url: $discovery_url
EOF

if [ "$alternate_deploy" != "undefined" ]; then
  log_note "The Pinniped Concierge will be deployed with $alternate_deploy pinniped-concierge $tag $registry_with_port $repo $data_values_file ..."
  $alternate_deploy pinniped-concierge "$tag" $registry_with_port $repo $data_values_file
else
  log_note "Deploying the Pinniped Concierge app to the cluster using kapp..."
  pushd deploy/concierge >/dev/null
  ytt --file . --data-values-file "$data_values_file" >"$manifest"
  kapp deploy --yes --app "$concierge_app_name" --diff-changes --file "$manifest"
  kubectl apply --dry-run=client -f "$manifest" # Validate manifest schema.
  popd >/dev/null
fi

#
# Create a test user in the local-user-authenticator and get its CA bundle.
#
log_note "Creating test user for local-user-authenticator..."
test_username="test-username"
test_groups="test-group-0,test-group-1"
test_password="$(openssl rand -hex 16)"

kubectl create secret generic "$test_username" \
  --namespace local-user-authenticator \
  --from-literal=groups="$test_groups" \
  --from-literal=passwordHash="$(htpasswd -nbBC 10 x "$test_password" | sed -e "s/^x://")" \
  --dry-run=client \
  --output yaml |
  kubectl apply -f -

webhook_ca_bundle="$(kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator -o 'jsonpath={.data.caCertificate}')"

#
# Download the test CA bundle that was generated in the Dex pod.
# Note that this returns a base64 encoded value.
#
test_ca_bundle_pem="$(kubectl get secrets -n tools certs -o go-template='{{index .data "ca.pem"}}')"

#
# Create the environment file.
#
# Note that all values should not contains newlines, except for PINNIPED_TEST_CLUSTER_CAPABILITY_YAML,
# so that the environment can also be used in tools like GoLand. Therefore, multi-line values,
# such as PEM-formatted certificates, should be base64 encoded.
#
kind_capabilities_file="$pinniped_path/test/cluster_capabilities/kind.yaml"
pinniped_cluster_capability_file_content=$(cat "$kind_capabilities_file")

cat <<EOF >/tmp/integration-test-env
# The following env vars should be set before running 'go test -v -count 1 -timeout 0 ./test/integration'
export PINNIPED_TEST_TOOLS_NAMESPACE="tools"
export PINNIPED_TEST_CONCIERGE_NAMESPACE=${concierge_namespace}
export PINNIPED_TEST_CONCIERGE_APP_NAME=${concierge_app_name}
export PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS='${concierge_custom_labels}'
export PINNIPED_TEST_USER_USERNAME=${test_username}
export PINNIPED_TEST_USER_GROUPS=${test_groups}
export PINNIPED_TEST_USER_TOKEN=${test_username}:${test_password}
export PINNIPED_TEST_WEBHOOK_ENDPOINT=${webhook_url}
export PINNIPED_TEST_WEBHOOK_CA_BUNDLE=${webhook_ca_bundle}
export PINNIPED_TEST_SUPERVISOR_NAMESPACE=${supervisor_namespace}
export PINNIPED_TEST_SUPERVISOR_APP_NAME=${supervisor_app_name}
export PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS='${supervisor_custom_labels}'
export PINNIPED_TEST_SUPERVISOR_HTTPS_ADDRESS="https://localhost:12344"
export PINNIPED_TEST_PROXY=http://127.0.0.1:12346
export PINNIPED_TEST_LDAP_HOST=ldap.tools.svc.cluster.local
export PINNIPED_TEST_LDAP_STARTTLS_ONLY_HOST=ldapstarttls.tools.svc.cluster.local
export PINNIPED_TEST_LDAP_LDAPS_CA_BUNDLE="${test_ca_bundle_pem}"
export PINNIPED_TEST_LDAP_BIND_ACCOUNT_USERNAME="cn=admin,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_BIND_ACCOUNT_PASSWORD=password
export PINNIPED_TEST_LDAP_USERS_SEARCH_BASE="ou=users,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_GROUPS_SEARCH_BASE="ou=groups,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_USER_DN="cn=pinny,ou=users,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_USER_CN="pinny"
export PINNIPED_TEST_LDAP_USER_PASSWORD=${ldap_test_password}
export PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_NAME="uidNumber"
export PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_VALUE="1000"
export PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_NAME="mail"
export PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_VALUE="pinny.ldap@example.com"
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_GROUPS_DN="cn=ball-game-players,ou=beach-groups,ou=groups,dc=pinniped,dc=dev;cn=seals,ou=groups,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_EXPECTED_INDIRECT_GROUPS_DN="cn=pinnipeds,ou=groups,dc=pinniped,dc=dev;cn=mammals,ou=groups,dc=pinniped,dc=dev"
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_GROUPS_CN="ball-game-players;seals"
export PINNIPED_TEST_LDAP_EXPECTED_DIRECT_POSIX_GROUPS_CN="ball-game-players-posix;seals-posix"
export PINNIPED_TEST_LDAP_EXPECTED_INDIRECT_GROUPS_CN="pinnipeds;mammals"
export PINNIPED_TEST_CLI_OIDC_ISSUER=https://dex.tools.svc.cluster.local/dex
export PINNIPED_TEST_CLI_OIDC_ISSUER_CA_BUNDLE="${test_ca_bundle_pem}"
export PINNIPED_TEST_CLI_OIDC_CLIENT_ID=pinniped-cli
export PINNIPED_TEST_CLI_OIDC_CALLBACK_URL=http://127.0.0.1:48095/callback
export PINNIPED_TEST_CLI_OIDC_USERNAME=pinny@example.com
export PINNIPED_TEST_CLI_OIDC_PASSWORD=${dex_test_password}
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER=https://dex.tools.svc.cluster.local/dex
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER_CA_BUNDLE="${test_ca_bundle_pem}"
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ADDITIONAL_SCOPES="offline_access,email"
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME_CLAIM=email
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_GROUPS_CLAIM=groups
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_ID=pinniped-supervisor
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_SECRET=pinniped-supervisor-secret
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CALLBACK_URL=https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/callback
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME=pinny@example.com
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_PASSWORD=${dex_test_password}
export PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_EXPECTED_GROUPS= # Dex's local user store does not let us configure groups.
export PINNIPED_TEST_API_GROUP_SUFFIX='${api_group_suffix}'
# PINNIPED_TEST_SHELL_CONTAINER_IMAGE should be a container which includes bash and sleep, used by some tests.
export PINNIPED_TEST_SHELL_CONTAINER_IMAGE="ghcr.io/pinniped-ci-bot/test-kubectl:latest"

# We can't set up an in-cluster active directory instance, but
# if you have an active directory instance that you wish to run the tests against,
# specify a script to set the ad-related environment variables.
# You will need to set the environment variables that start with "PINNIPED_TEST_AD_"
# found in pinniped/test/testlib/env.go.
if [[ "$get_active_directory_vars" != "" ]]; then
  source $get_active_directory_vars
fi

# We can't set up an in-cluster GitHub instance, but
# if you have a GitHub account that you wish to run the tests against,
# specify a script to set the GitHub environment variables.
# You will need to set the environment variables that start with "PINNIPED_TEST_GITHUB_"
# found in pinniped/test/testlib/env.go.
if [[ "$get_github_vars" != "" ]]; then
  source $get_github_vars
fi

read -r -d '' PINNIPED_TEST_CLUSTER_CAPABILITY_YAML << PINNIPED_TEST_CLUSTER_CAPABILITY_YAML_EOF || true
${pinniped_cluster_capability_file_content}
PINNIPED_TEST_CLUSTER_CAPABILITY_YAML_EOF

export PINNIPED_TEST_CLUSTER_CAPABILITY_YAML
EOF

#
# Print instructions for next steps.
#
log_note
log_note "🚀 Ready to run integration tests! For example..."
log_note "    cd $pinniped_path"
log_note "    ulimit -n 512"
log_note '    source /tmp/integration-test-env && go test -v -race -count 1 -timeout 0 ./test/integration'
log_note
log_note "Using GoLand? Paste the result of this command into GoLand's run configuration \"Environment\"."
log_note "    hack/integration-test-env-goland.sh | pbcopy"
log_note
log_note "You can rerun this script to redeploy local production code changes while you are working."
log_note
log_note "To delete the deployments, run:"
log_note "  kapp delete -a local-user-authenticator -y && kapp delete -a $concierge_app_name -y &&  kapp delete -a $supervisor_app_name -y"
if [[ "${PINNIPED_USE_LOCAL_KIND_REGISTRY:-}" != "" ]]; then
  log_note "When you're finished, use 'PINNIPED_USE_LOCAL_KIND_REGISTRY=1 ./hack/kind-down.sh' to tear down the cluster."
else
  log_note "When you're finished, use './hack/kind-down.sh' to tear down the cluster."
fi
