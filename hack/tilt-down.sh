#!/usr/bin/env bash

# Copyright 2020 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "${ROOT}"
exec tilt down -f ./hack/lib/tilt/Tiltfile
