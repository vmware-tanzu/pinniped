// Copyright 2022-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build boringcrypto
// +build boringcrypto

package testlib

// Because of a bug in nmap, the cipher suite preference is
// incorrectly shown as 'client' in some cases.
// in fips-only mode, it correctly shows the cipher preference
// as 'server', while in non-fips mode it shows as 'client'.
const cipherSuitePreference = "server"
