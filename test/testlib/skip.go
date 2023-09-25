// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import "testing"

// SkipUnlessIntegration skips the current test if `-short` has been passed to `go test`.
func SkipUnlessIntegration(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test because of '-short' flag")
	}
}

func SkipTestWhenLDAPIsUnavailable(t *testing.T, env *TestEnv) {
	t.Helper()

	if len(env.ToolsNamespace) == 0 && !env.HasCapability(CanReachInternetLDAPPorts) {
		t.Skip("LDAP integration test requires connectivity to an LDAP server")
	}
}

func SkipTestWhenActiveDirectoryIsUnavailable(t *testing.T, env *TestEnv) {
	t.Helper()

	if !env.HasCapability(CanReachInternetLDAPPorts) {
		t.Skip("Active Directory integration test requires network connectivity to an AD server")
	}

	if IntegrationEnv(t).SupervisorUpstreamActiveDirectory.Host == "" {
		t.Skip("Active Directory hostname not specified")
	}
}
