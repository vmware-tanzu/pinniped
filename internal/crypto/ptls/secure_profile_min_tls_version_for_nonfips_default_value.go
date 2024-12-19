// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !secure_profile_min_tls_for_nonfips_12

package ptls

import "crypto/tls"

const SecureProfileMinTLSVersionForNonFIPS = tls.VersionTLS13
