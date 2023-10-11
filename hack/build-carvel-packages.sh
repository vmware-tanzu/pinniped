#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script can be used to prepare a kind cluster and deploy the app.
# You can call this script again to redeploy the app.
# It will also output instructions on how to run the integration.
#

set -euo pipefail

#
# Helper functions
#
function log_note() {
  GREEN='\033[0;32m'
  NC='\033[0m'
  if [[ ${COLORTERM:-unknown} =~ ^(truecolor|24bit)$ ]]; then
    echo -e "${GREEN}$*${NC}"
  else
    echo "$*"
  fi
}

function log_error() {
  RED='\033[0;31m'
  NC='\033[0m'
  if [[ ${COLORTERM:-unknown} =~ ^(truecolor|24bit)$ ]]; then
    echo -e "🙁${RED} Error: $* ${NC}"
  else
    echo ":( Error: $*"
  fi
}

function check_dependency() {
  if ! command -v "$1" >/dev/null; then
    log_error "Missing dependency..."
    log_error "$2"
    exit 1
  fi
}


pinniped_path="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$pinniped_path" || exit 1

# arguments provided to scripts called by hack/prepare-for-integration-tests.sh
# - app: unimportant, but always first
# - tag: uuidgen in hack/prepare-for-integration-tests.sh
#        if this script is run standalone, then auto-fill with a unique value
app=${1:-"undefined"}
tag=${2:-$(uuidgen)}

# TODO: automate the version by release somehow.
# the tag is the version in our build scripts, but we will want real versions for releases
pinniped_package_version="${tag}" # ie, "0.25.0"

# core pinniped binaries (concierge, supervisor, local-user-authenticator)
registry="kind-registry.local:5000"
repo="test/build"
registry_repo="$registry/$repo"
registry_repo_tag="${registry_repo}:${tag}"

api_group_suffix="pinniped.dev"

# Package prefix for concierge, supervisor, local-user-authenticator
package_prefix="test/build-package" # + $resource_name + ":" + $tag
package_repo_prefix="${registry_repo}/${package_prefix}" # + $resource_name + ":" + $tag

# Pinniped Package repository
package_repository_repo="test/build-package-repository-pinniped"
package_repository_repo_tag="${registry_repo}/${package_repository_repo}:${tag}"

# carvel
log_note "Installing kapp-controller on cluster..."
KAPP_CONTROLLER_GLOBAL_NAMESPACE="kapp-controller-packaging-global"
kapp deploy --app kapp-controller --file "https://github.com/vmware-tanzu/carvel-kapp-controller/releases/latest/download/release.yml" -y
kubectl get customresourcedefinitions

# Generate the OpenAPI v3 Schema files, imgpkg images.yml files
declare -a arr=("local-user-authenticator" "concierge" "supervisor")
for resource_name in "${arr[@]}"
do
  resource_qualified_name="${resource_name}.${api_group_suffix}"
  package_repo_tag="${package_repo_prefix}-${resource_name}:${tag}"

  resource_dir="deploy_carvel/${resource_name}"
  resource_config_source_dir="deploy/${resource_name}"
  resource_destination_dir="deploy_carvel/${resource_name}"
  resource_config_destination_dir="${resource_destination_dir}/config"

  # these must be real files, not symlinks
  log_note "Vendir sync deploy directory for ${resource_name} to package bundle..."
  pushd "${resource_destination_dir}" > /dev/null
    vendir sync
  popd > /dev/null

  log_note "Generating OpenAPI v3 schema for ${resource_name}..."
  ytt \
    --file "${resource_config_destination_dir}" \
    --data-values-schema-inspect \
    --output openapi-v3 > \
    "${resource_dir}/schema-openapi.yaml"

  log_note "Generating .imgpkg/images.yml for ${resource_name}..."
  mkdir -p "${resource_dir}/.imgpkg"
  ytt \
    --file "${resource_config_destination_dir}" | \
    kbld -f- --imgpkg-lock-output "${resource_dir}/.imgpkg/images.yml"


  log_note "Pushing Pinniped ${resource_name} Package bundle..."
  imgpkg push --bundle "${package_repo_tag}" --file "${resource_dir}"
  # validation flag?
  log_note "Validating ${resource_name} Package bundle not empty (/tmp/${package_repo_tag})..."
  imgpkg pull --bundle "${package_repo_tag}" --output "/tmp/${package_repo_tag}"


  log_note "Generating PackageRepository Package entry for ${resource_name}"
  # publish package versions to package repository
  package_repository_dir="deploy_carvel/package_repository/packages/${resource_qualified_name}"
  rm -rf "${package_repository_dir}"
  mkdir "${package_repository_dir}"

  ytt \
    --file "${resource_dir}/package-template.yml" \
    --data-value-file openapi="${resource_dir}/schema-openapi.yml" \
    --data-value repo_host="${package_repo_prefix}-${resource_name}" \
    --data-value version="${pinniped_package_version}" > "${package_repository_dir}/${pinniped_package_version}.yml"
  cp "deploy_carvel/${resource_name}/metadata.yml" "${package_repository_dir}/metadata.yml"
done

log_note "Generating .imgpkg/images.yml for  Pinniped PackageRepository bundle..."
mkdir -p "deploy_carvel/package_repository/.imgpkg"
kbld --file "deploy_carvel/package_repository/packages/" --imgpkg-lock-output "deploy_carvel/package_repository/.imgpkg/images.yml"

log_note "Pushing Pinniped PackageRepository bundle.... "
imgpkg push --bundle "${package_repository_repo_tag}" --file "deploy_carvel/package_repository"

# validation flag?
log_note "Validating Pinniped PackageRepository bundle not empty /tmp/${package_repo_tag}..."
imgpkg pull --bundle "${package_repository_repo_tag}" --output "/tmp/${package_repository_repo_tag}"



## NOTE: could break apart here at a build and a deploy script.

log_note "cleaning deploy artifacts..."
rm -rf "deploy_carvel/deploy"
mkdir "deploy_carvel/deploy"

log_note "deploying PackageRepository..."
pinniped_package_repository_name="pinniped-package-repository"
pinniped_package_repository_file="deploy_carvel/deploy/packagerepository.${pinniped_package_version}.yml"
echo -n "" > "${pinniped_package_repository_file}"
cat <<EOT >> "${pinniped_package_repository_file}"
---
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageRepository
metadata:
  name: "${pinniped_package_repository_name}"
  namespace: "${KAPP_CONTROLLER_GLOBAL_NAMESPACE}"
spec:
  fetch:
    imgpkgBundle:
      image: "${package_repository_repo_tag}"
EOT

kapp deploy --app "${pinniped_package_repository_name}" --file "${pinniped_package_repository_file}" -y
kapp inspect --app "${pinniped_package_repository_name}" --tree


for resource_name in "${arr[@]}"
do
  log_note "creating PackageInstall and RBAC for ${resource_name}..."

  namespace="${resource_name}-install-ns"
  pinniped_package_rbac_prefix="pinniped-package-rbac-${resource_name}"
  pinniped_package_rbac_file="deploy_carvel/deploy/${pinniped_package_rbac_prefix}-${resource_name}-rbac.yml"
  echo -n "" > "${pinniped_package_rbac_file}"
cat <<EOF >> "${pinniped_package_rbac_file}"
---
apiVersion: v1
kind: Namespace
metadata:
  name: "${namespace}"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: "${pinniped_package_rbac_prefix}-sa-superadmin-dangerous"
  namespace: "${namespace}"
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: "${pinniped_package_rbac_prefix}-role-superadmin-dangerous"
  namespace: "${namespace}"
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: "${pinniped_package_rbac_prefix}-role-binding-superadmin-dangerous"
subjects:
- kind: ServiceAccount
  name: "${pinniped_package_rbac_prefix}-sa-superadmin-dangerous"
  namespace: "${namespace}"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: "${pinniped_package_rbac_prefix}-role-superadmin-dangerous"

EOF

  kapp deploy --app "${pinniped_package_rbac_prefix}" --file "${pinniped_package_rbac_file}" -y
done

# start local-user-authenticator
# local-user-authenticator
log_note "deploying local-user-authenticator PackageInstall resources..."
resource_name="local-user-authenticator"
NAMESPACE="${resource_name}-install-ns"
PINNIPED_PACKAGE_RBAC_PREFIX="pinniped-package-rbac-${resource_name}"
RESOURCE_PACKAGE_VERSION="${resource_name}.pinniped.dev"
PACKAGE_INSTALL_FILE_NAME="deploy_carvel/deploy/${resource_name}-pkginstall.yml"
SECRET_NAME="${resource_name}-package-install-secret"

cat > "${PACKAGE_INSTALL_FILE_NAME}" << EOF
---
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageInstall
metadata:
    # name, does not have to be versioned, versionSelection.constraints below will handle
    name: "${resource_name}-package-install"
    namespace: "${NAMESPACE}"
spec:
  serviceAccountName: "${PINNIPED_PACKAGE_RBAC_PREFIX}-sa-superadmin-dangerous"
  packageRef:
    refName: "${RESOURCE_PACKAGE_VERSION}"
    versionSelection:
      constraints: "${pinniped_package_version}"
  values:
  - secretRef:
      name: "${SECRET_NAME}"
---
apiVersion: v1
kind: Secret
metadata:
  name: "${SECRET_NAME}"
  namespace: "${NAMESPACE}"
stringData:
  values.yml: |
    ---
    image_repo: $registry_repo
    image_tag: $tag
EOF

KAPP_CONTROLLER_APP_NAME="${resource_name}-pkginstall"
log_note "deploying ${KAPP_CONTROLLER_APP_NAME}..."
kapp deploy --app "${KAPP_CONTROLLER_APP_NAME}" --file "${PACKAGE_INSTALL_FILE_NAME}" -y

test_username="test-username"
test_groups="test-group-0,test-group-1"
test_password="$(openssl rand -hex 16)"
log_note "Creating test user '$test_username'..."
kubectl create secret generic "$test_username" \
  --namespace local-user-authenticator \
  --from-literal=groups="$test_groups" \
  --from-literal=passwordHash="$(htpasswd -nbBC 10 x "$test_password" | sed -e "s/^x://")" \
  --dry-run=client \
  --output yaml |
  kubectl apply -f -
# end local-user-authenticator


# start concierge
log_note "deploying concierge PackageInstall resources..."
resource_name="concierge"
NAMESPACE="${resource_name}-install-ns"
PINNIPED_PACKAGE_RBAC_PREFIX="pinniped-package-rbac-${resource_name}"
RESOURCE_PACKAGE_VERSION="${resource_name}.pinniped.dev"
PACKAGE_INSTALL_FILE_NAME="deploy_carvel/${resource_name}-pkginstall.yml"
SECRET_NAME="${resource_name}-package-install-secret"

# from prepare-for-integration-tests.sh
concierge_app_name="pinniped-concierge"
concierge_namespace="concierge"
webhook_url="https://local-user-authenticator.local-user-authenticator.svc/authenticate"
discovery_url="$(TERM=dumb kubectl cluster-info | awk '/master|control plane/ {print $NF}')"
concierge_custom_labels="{myConciergeCustomLabelName: myConciergeCustomLabelValue}"
log_level="debug"
cat > "${PACKAGE_INSTALL_FILE_NAME}" << EOF
---
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageInstall
metadata:
    # name, does not have to be versioned, versionSelection.constraints below will handle
    name: "${resource_name}-package-install"
    namespace: "${NAMESPACE}"
spec:
  serviceAccountName: "${PINNIPED_PACKAGE_RBAC_PREFIX}-sa-superadmin-dangerous"
  packageRef:
    refName: "${RESOURCE_PACKAGE_VERSION}"
    versionSelection:
      constraints: "${pinniped_package_version}"
  values:
  - secretRef:
      name: "${SECRET_NAME}"
---
apiVersion: v1
kind: Secret
metadata:
  name: "${SECRET_NAME}"
  namespace: "${NAMESPACE}"
stringData:
  values.yml: |
    ---
    app_name: $concierge_app_name
    namespace: $concierge_namespace
    api_group_suffix: $api_group_suffix
    log_level: $log_level

    image_repo: $registry_repo
    image_tag: $tag
EOF

KAPP_CONTROLLER_APP_NAME="${resource_name}-pkginstall"
log_note "deploying ${KAPP_CONTROLLER_APP_NAME}..."
kapp deploy --app "${KAPP_CONTROLLER_APP_NAME}" --file "${PACKAGE_INSTALL_FILE_NAME}" -y
# end concierge


# start supervisor
log_note "deploying supervisor PackageInstall resources..."
resource_name="supervisor"
NAMESPACE="${resource_name}-install-ns"
PINNIPED_PACKAGE_RBAC_PREFIX="pinniped-package-rbac-${resource_name}"
RESOURCE_PACKAGE_VERSION="${resource_name}.pinniped.dev"
PACKAGE_INSTALL_FILE_NAME="deploy_carvel/${resource_name}-pkginstall.yml"
SECRET_NAME="${resource_name}-package-install-secret"

# from prepare-for-integration-test.sh
supervisor_app_name="pinniped-supervisor"
supervisor_namespace="supervisor"
supervisor_custom_labels="{mySupervisorCustomLabelName: mySupervisorCustomLabelValue}"
log_level="debug"
service_https_nodeport_port="443"
service_https_nodeport_nodeport="31243"
service_https_clusterip_port="443"
cat > "${PACKAGE_INSTALL_FILE_NAME}" << EOF
---
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageInstall
metadata:
    # name, does not have to be versioned, versionSelection.constraints below will handle
    name: "${resource_name}-package-install"
    namespace: "${NAMESPACE}"
spec:
  serviceAccountName: "${PINNIPED_PACKAGE_RBAC_PREFIX}-sa-superadmin-dangerous"
  packageRef:
    refName: "${RESOURCE_PACKAGE_VERSION}"
    versionSelection:
      constraints: "${pinniped_package_version}"
  values:
  - secretRef:
      name: "${SECRET_NAME}"
---
apiVersion: v1
kind: Secret
metadata:
  name: "${SECRET_NAME}"
  namespace: "${NAMESPACE}"
stringData:
  values.yml: |
    ---
    app_name: $supervisor_app_name
    namespace: $supervisor_namespace
    api_group_suffix: $api_group_suffix
    image_repo: $registry_repo
    image_tag: $tag
    log_level: $log_level

    service_https_nodeport_port: $service_https_nodeport_port
    service_https_nodeport_nodeport: $service_https_nodeport_nodeport
    service_https_clusterip_port: $service_https_clusterip_port
EOF

KAPP_CONTROLLER_APP_NAME="${resource_name}-pkginstall"
log_note "deploying ${KAPP_CONTROLLER_APP_NAME}..."
kapp deploy --app "${KAPP_CONTROLLER_APP_NAME}" --file "${PACKAGE_INSTALL_FILE_NAME}" -y
# end supervisor


log_note "appending environment variables to /tmp/integration-test-env"
echo "PINNIPED_TEST_USER_USERNAME=${test_username}"
echo "PINNIPED_TEST_USER_GROUPS=${test_groups}"
echo "PINNIPED_TEST_USER_TOKEN=${test_username}:${test_password}"
# To be "finished" the scripts need to work for both the ytt deploy and the carvel package,
# regardless of which branch the user takes.
integration_env_file="/tmp/integration-test-env"
integration_env_file_text=$(cat "${integration_env_file}")

cat <<EOT >"${integration_env_file}"
export PINNIPED_TEST_USER_USERNAME=${test_username}
export PINNIPED_TEST_USER_GROUPS=${test_groups}
export PINNIPED_TEST_USER_TOKEN=${test_username}:${test_password}
EOT
echo "${integration_env_file_text}" >> "${integration_env_file}"

log_note "verifying PackageInstall resources..."
kubectl get PackageInstall -A | grep pinniped
kubectl get secret -A | grep pinniped

log_note "listing all package resources (PackageRepository, Package, PackageInstall)..."
kubectl get pkgi && kubectl get pkgr && kubectl get pkg

log_note "listing all kapp cli apps..."
kapp ls --all-namespaces

log_note "listing all kapp-controller apps..."
kubectl get app --all-namespaces
