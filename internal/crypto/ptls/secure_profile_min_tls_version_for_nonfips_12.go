// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build nonfips_enable_tls12_min_for_secure_profile

package ptls

import "crypto/tls"

const SecureProfileMinTLSVersionForNonFIPS = tls.VersionTLS12
