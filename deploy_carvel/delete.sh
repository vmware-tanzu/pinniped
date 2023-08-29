#!/usr/bin/env bash

# https://gist.github.com/mohanpedala/1e2ff5661761d3abd0385e8223e16425
set -e # immediately exit
set -u # error if variables undefined
set -o pipefail # prevent masking errors in a pipeline
# set -x # print all executed commands to terminal


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
DEFAULT='\033[0m'

echo_yellow() {
    echo -e "${YELLOW}>> $@${DEFAULT}\n"
    # printf "${GREEN}$@${DEFAULT}"
}

echo_green() {
    echo -e "${GREEN}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}
echo_red() {
    echo -e "${RED}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}
echo_blue() {
    echo -e "${BLUE}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}

echo_yellow "creating fresh kind cluster - my-pinniped-package-repo-cluster"
kind delete cluster --name my-pinniped-package-repo-cluster
kind create cluster --name my-pinniped-package-repo-cluster

#
#
#echo_yellow "check before install..."
#echo_yellow "kubectl get pkgr -A && kubectl get pkg -A && kubectl get pkgi -A"
#kubectl get pkgr -A && kubectl get pkg -A && kubectl get pkgi -A
##  NAMESPACE   NAME                          AGE   DESCRIPTION
##  default     pinniped-package-repository   18h   Reconcile succeeded
##  NAMESPACE   NAME                             PACKAGEMETADATA NAME      VERSION   AGE
##  default     concierge.pinniped.dev.0.25.0    concierge.pinniped.dev    0.25.0    18h16m28s
##  default     supervisor.pinniped.dev.0.25.0   supervisor.pinniped.dev   0.25.0    18h16m28s
##  NAMESPACE       NAME                         PACKAGE NAME              PACKAGE VERSION   DESCRIPTION                                                         AGE
##  default         supervisor-package-install   supervisor.pinniped.dev   0.25.0            Delete failed: Error (see .status.usefulErrorMessage for details)   92m
##  supervisor-ns   supervisor-package-install   supervisor.pinniped.dev                     Reconcile failed: Package supervisor.pinniped.dev not found         18h
#
#
#kubectl delete pkgr pinniped-package-repository
## should be automatic
## kubectl delete pkg concierge.pinniped.dev.0.25.0
## kubectl delete pkg supervisor.pinniped.dev.0.25.0
#kubectl delete pkgi supervisor-package-install
#kubectl delete pkgi concierge-package-install
#
#echo_yellow "check after install..."
#echo_yellow "kubectl get pkgr -A && kubectl get pkg -A && kubectl get pkgi -A"
#kubectl get pkgr -A && kubectl get pkg -A && kubectl get pkgi -A
