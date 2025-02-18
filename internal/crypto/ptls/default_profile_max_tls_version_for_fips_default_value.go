// Copyright 2024-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !fips_enable_tls13_max_for_default_profile

package ptls

import "crypto/tls"

const DefaultProfileMaxTLSVersionForFIPS = tls.VersionTLS13 // Starting in Go 1.24, boringcrypto supports TLS 1.3 by default, so this build tag is no longer needed
