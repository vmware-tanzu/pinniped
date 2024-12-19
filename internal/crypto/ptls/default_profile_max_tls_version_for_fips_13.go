// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build default_profile_max_tls_for_fips_13

package ptls

import "crypto/tls"

const DefaultProfileMaxTLSVersionForFIPS = tls.VersionTLS13
