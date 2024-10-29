#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

openssl rand -hex 16 > pinniped-password/pinniped-dex-password
openssl rand -hex 16 > pinniped-password/pinniped-ldap-password
