#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script can be used to prepare a kind cluster and deploy the app.
# You can call this script again to redeploy the app.
# It will also output instructions on how to run the integration.
#

set -e # immediately exit
set -u # error if variables undefined
set -o pipefail # prevent masking errors in a pipeline
# set -x # print all executed commands to terminal

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
# Deploy the PackageRepository and Package resources
# Requires a running kind cluster
# Does not configure Pinniped
#
app="${1:-undefined}"
tag="${2:-undefined}"
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
log_note "log-args.sh >>> script dir: ${SCRIPT_DIR} 🦄 🦄 🦄 🦄 🦄 🦄 🦄 🦄"
log_note "log-args.sh >>> app: ${app} tag: ${tag}   🦄 🦄 🦄 🦄 🦄 🦄 🦄 🦄"




log_note "Deploying kapp-controller on kind cluster..."
kapp deploy --app kapp-controller --file https://github.com/vmware-tanzu/carvel-kapp-controller/releases/latest/download/release.yml -y
kubectl get customresourcedefinitions
# Global kapp-controller-namespace:
#   -packaging-global-namespace=kapp-controller-packaging-global
# kapp-controller resources like PackageRepository and Package are namepaced.
# However, this namespace, provided via flag to kapp-controller in the yaml above,
# defines a "global" namespace.  That is, resources installed in this namespace
# can be installed in every namespace as kapp will always pay attention to its
# pseudo-global namespace.
KAPP_CONTROLLER_GLOBAL_NAMESPACE="kapp-controller-packaging-global"


# deploy the Carvel packages for Pinniped & Supervisor.
# - Deploy the PackageRepository
# - Create PackageInstalls for Supervisor, Concierge
#   - deploy these
# - then after, run hack/prepare-supervisor-on-kind.sh
#   - ideally this configures the Supervisor


# need a directory for our yamls for deployment
log_note "Clean previous PackageInstalls in order to create new ones..."
PACKAGE_INSTALL_DIR="temp_actual_deploy_resources"
rm -rf "${SCRIPT_DIR}/${PACKAGE_INSTALL_DIR}"
mkdir "${SCRIPT_DIR}/${PACKAGE_INSTALL_DIR}"


# this is built via the build.sh script
# build.sh must be run first.
# TODO: since the ytt values.yaml takes in a version="x.y.z"
# for Pinniped, our packages are currently not meaningfully versioned.
# this is one of the questions we must answer, do we deviate in the
# "./deploy_carvel" directory by hard-coding this version in the packages?
log_note "Deploying Pinniped PackageRepository on kind cluster..."
PINNIPED_PACKAGE_VERSION="0.25.0"
PINNIPED_PACKGE_REPOSITORY_NAME="pinniped-package-repository"
PINNIPED_PACKGE_REPOSITORY_FILE_NAME="packagerepository.${PINNIPED_PACKAGE_VERSION}.yml"
PINNIPED_PACKGE_REPOSITORY_FILE_PATH="${SCRIPT_DIR}/${PINNIPED_PACKGE_REPOSITORY_FILE_NAME}"
# Now, gotta make this work.  It'll be interesting if we can...
kapp deploy \
  --namespace "${KAPP_CONTROLLER_GLOBAL_NAMESPACE}" \
  --app "${PINNIPED_PACKGE_REPOSITORY_NAME}" \
  --file "${PINNIPED_PACKGE_REPOSITORY_FILE_PATH}" -y
kapp inspect \
  --namespace "${KAPP_CONTROLLER_GLOBAL_NAMESPACE}" \
  --app "${PINNIPED_PACKGE_REPOSITORY_NAME}" \
  --tree




log_note "Generating RBAC for use with pinniped PackageInstall..."

# TODO: obviously a mega-role that can do everything is not good. we need to scope this down to appropriate things.
declare -a arr=("supervisor" "concierge")
for resource_name in "${arr[@]}"
do
  # we want the install-ns to not be "default"
  # it should be a unique namespace
  # but it should also not be in kapp-controllers global namespace
  # nor should it be in any Pinniped resource namespace
  # - PackageRepository,Package = global kapp-controller namespace
  # - PackageInstall,RBAC = *-install namespace
  # - App = (supervisor, concierge) generated via ytt namespace
  INSTALL_NAMESPACE="${resource_name}-install-ns"
  PINNIPED_PACKAGE_RBAC_PREFIX="pinniped-package-rbac-${resource_name}"
  PINNIPED_PACKAGE_RBAC_FILE_NAME="${PINNIPED_PACKAGE_RBAC_PREFIX}-${resource_name}-rbac.yml"
  PINNIPED_PACKAGE_RBAC_FILE_PATH="${SCRIPT_DIR}/${PACKAGE_INSTALL_DIR}/${PINNIPED_PACKAGE_RBAC_FILE_NAME}"

  # empty and regenerate
  echo -n "" > "${PINNIPED_PACKAGE_RBAC_FILE_PATH}"
  cat <<EOF >> "${PINNIPED_PACKAGE_RBAC_FILE_PATH}"
---
apiVersion: v1
kind: Namespace
metadata:
  name: "${INSTALL_NAMESPACE}"
---
# ServiceAccount details from the file linked above
apiVersion: v1
kind: ServiceAccount
metadata:
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-sa-superadmin-dangerous"
  namespace: "${INSTALL_NAMESPACE}"
  # namespace: default # --> sticking to default for everything for now.
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-role-superadmin-dangerous"
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-role-binding-superadmin-dangerous"
subjects:
- kind: ServiceAccount
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-sa-superadmin-dangerous"
  namespace: "${INSTALL_NAMESPACE}"
  # namespace: default # --> sticking to default for everything for now.
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-role-superadmin-dangerous"

EOF

  kapp deploy --app "${PINNIPED_PACKAGE_RBAC_PREFIX}" --file "${PINNIPED_PACKAGE_RBAC_FILE_PATH}" -y
done



log_note "Deploying PackageInstall resources for pinniped supervisor and concierge packages..."
for resource_name in "${arr[@]}"
do
  RESOURCE_NAMESPACE="${resource_name}" # to match the hack/prepare-for-integration-tests.sh file
  INSTALL_NAME="${resource_name}-install"
  INSTALL_NAMESPACE="${INSTALL_NAME}-ns"
  PINNIPED_PACKAGE_RBAC_PREFIX="pinniped-package-rbac-${resource_name}"
  RESOURCE_PACKGE_VERSION="${resource_name}.pinniped.dev"
  PACKAGE_INSTALL_FILE_NAME="./${PACKAGE_INSTALL_DIR}/${resource_name}-pkginstall.yml"
  PACKAGE_INSTALL_FILE_PATH="${SCRIPT_DIR}/${PACKAGE_INSTALL_FILE_NAME}"
  SECRET_NAME="${resource_name}-package-install-secret"
  cat > "${PACKAGE_INSTALL_FILE_PATH}" << EOF
---
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageInstall
metadata:
    # name, does not have to be versioned, versionSelection.constraints below will handle
    name: ${INSTALL_NAME}
    namespace: ${INSTALL_NAMESPACE}
spec:
  serviceAccountName: "${PINNIPED_PACKAGE_RBAC_PREFIX}-sa-superadmin-dangerous"
  packageRef:
    refName: "${RESOURCE_PACKGE_VERSION}"
    versionSelection:
      constraints: "${PINNIPED_PACKAGE_VERSION}"
  values:
  - secretRef:
      name: "${SECRET_NAME}"
---
apiVersion: v1
kind: Secret
metadata:
  name: "${SECRET_NAME}"
  namespace: ${INSTALL_NAMESPACE}
stringData:
  values.yml: |
    ---
    namespace: "${RESOURCE_NAMESPACE}"
    app_name: "${resource_name}-app-installed-via-package"
    replicas: 3
EOF

  KAPP_CONTROLLER_APP_NAME="${resource_name}-pkginstall"
  log_note "deploying ${KAPP_CONTROLLER_APP_NAME}..."
  kapp deploy --app "${KAPP_CONTROLLER_APP_NAME}" --file "${PACKAGE_INSTALL_FILE_PATH}" -y

done


log_note "Available Packages:"
kubectl get pkgr -A && kubectl get pkg -A && kubectl get pkgi -A

log_note "Pinniped Supervisor Package Deployed"
log_note "Pinniped Concierge Package Deployed"
kubectl get namespace -A | grep pinniped
kubectl get deploy -n supervisor
kubectl get deploy -n concierge


# TODO:
# - change the namespace to whatever it is in ./hack/prepare-for-integration-tests.sh
# - make a script that can work for $alternate-deploy
# - then run ./hack/prepare-supervisor-on-kind.sh and make sure it works



#
#
#log_note "verifying PackageInstall resources..."
#kubectl get PackageInstall -A | grep pinniped
#kubectl get secret -A | grep pinniped
#
#log_note "listing all package resources (PackageRepository, Package, PackageInstall)..."
#kubectl get pkgi && kubectl get pkgr && kubectl get pkg
#
#log_note "listing all kapp cli apps..."
## list again what is installed so we can ensure we have everything
#kapp ls --all-namespaces
#
## these are fundamentally different than what kapp cli understands, unfortunately.
## the term "app" is overloaded in Carvel and can mean two different things, based on
## the use of kapp cli and kapp-controller on cluster
#log_note "listing all kapp-controller apps..."
#kubectl get app --all-namespaces
#
## TODO:
## update the deployment.yaml and remove the deployment-HACKED.yaml files
## both are probably hacked a bit, so delete them and just get fresh from the ./deploy directory
## then make sure REAL PINNIPED actually deploys.
#
#
## In the end we should have:
## docker pull benjaminapetersen/pinniped-package-repo:latest
## docker pull benjaminapetersen/pinniped-package-repo-package-supervisor:0.25.0
## docker pull benjaminapetersen/pinniped-package-repo-package-concierge:0.25.0
#
## log_note "verifying RBAC resources created (namespace, serviceaccount, clusterrole, clusterrolebinding)..."
## kubectl get ns -A | grep pinniped
## kubectl get sa -A | grep pinniped
## kubectl get ClusterRole -A | grep pinniped
## kubectl get clusterrolebinding -A | grep pinniped
#
#
## stuff
#kubectl get PackageRepository -A
#kubectl get Package -A
#kubectl get PackageInstall -A
