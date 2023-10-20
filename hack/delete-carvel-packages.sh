#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script can be used to prepare a kind cluster and deploy the app.
# You can call this script again to redeploy the app.
# It will also output instructions on how to run the integration.
#

set -euo pipefail

# whats all installed
kubectl get pkgr -A && kubectl get pkg -A && kubectl get pkgi -A

# delete the package installs
kubectl delete pkgi concierge-package-install -n concierge-install-ns
kubectl delete pkgi supervisor-package-install -n supervisor-install-ns
kubectl delete pkgi local-user-authenticator-package-install -n local-user-authenticator-install-ns

# TODO: clean up the rest also
