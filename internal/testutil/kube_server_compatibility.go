// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/client-go/discovery"
)

func KubeServerSupportsCertificatesV1API(t *testing.T, discoveryClient discovery.DiscoveryInterface) bool {
	t.Helper()
	groupList, err := discoveryClient.ServerGroups()
	require.NoError(t, err)
	for _, group := range groupList.Groups {
		if group.Name == certificatesv1.GroupName {
			for _, version := range group.Versions {
				if version.Version == "v1" {
					// Note: v1 should exist in Kubernetes 1.19 and above
					return true
				}
			}
		}
		continue
	}
	return false
}

func KubeServerMinorVersionAtLeastInclusive(t *testing.T, discoveryClient discovery.DiscoveryInterface, min int) bool {
	return !KubeServerMinorVersionInBetweenInclusive(t, discoveryClient, 0, min-1)
}

func KubeServerMinorVersionInBetweenInclusive(t *testing.T, discoveryClient discovery.DiscoveryInterface, min, max int) bool {
	t.Helper()

	version, err := discoveryClient.ServerVersion()
	require.NoError(t, err)

	require.Equal(t, "1", version.Major)

	minor, err := strconv.Atoi(strings.TrimSuffix(version.Minor, "+"))
	require.NoError(t, err)

	return minor >= min && minor <= max
}
