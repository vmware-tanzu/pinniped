// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
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
