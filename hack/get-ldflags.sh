#!/usr/bin/env bash

# Copyright 2020 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

KUBE_ROOT="${ROOT}" # required by `hack/lib/version.sh`
source "${ROOT}/hack/lib/version.sh"

kube::version::ldflags
