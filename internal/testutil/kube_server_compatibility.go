// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
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

func PrintKubeServerVersion(t *testing.T, discoveryClient discovery.DiscoveryInterface) {
	t.Helper()

	version, err := discoveryClient.ServerVersion()
	require.NoError(t, err)

	t.Logf("K8s server version: %s\n%+v", version, version)
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

func convertMap[K1, K2 comparable, V1, V2 any](m1 map[K1]V1, fT func(K1) K2, fU func(V1) V2) map[K2]V2 {
	m2 := make(map[K2]V2)
	for k, v := range m1 {
		m2[fT(k)] = fU(v)
	}
	return m2
}

func identity[T any](t T) T {
	return t
}

func CheckServiceAccountExtraFieldsAccountingForChangesInK8s1_30[M ~map[string]V, V ~[]string](
	t *testing.T,
	discoveryClient discovery.DiscoveryInterface,
	actualExtras M,
	expectedPodValues *corev1.Pod,
) {
	t.Helper()

	extra := convertMap(
		actualExtras,
		identity[string],
		func(v V) []string {
			return v
		},
	)

	require.Equal(t, extra["authentication.kubernetes.io/pod-name"], []string{expectedPodValues.Name})
	require.Equal(t, extra["authentication.kubernetes.io/pod-uid"], []string{string(expectedPodValues.UID)})

	if KubeServerMinorVersionAtLeastInclusive(t, discoveryClient, 30) {
		// Starting in K8s 1.30, three additional `Extra` fields were added with unpredictable values.
		// This is because the following three feature gates were enabled by default in 1.30.
		// https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/
		// - ServiceAccountTokenJTI
		// - ServiceAccountTokenNodeBindingValidation
		// - ServiceAccountTokenPodNodeInfo
		// These were added in source code in 1.29 but not enabled by default until 1.30.
		// <1.29: https://pkg.go.dev/k8s.io/apiserver@v0.28.7/pkg/authentication/serviceaccount
		// 1.29+: https://pkg.go.dev/k8s.io/apiserver@v0.29.0/pkg/authentication/serviceaccount

		require.Equal(t, 5, len(extra))
		require.NotEmpty(t, extra["authentication.kubernetes.io/credential-id"])
		require.NotEmpty(t, extra["authentication.kubernetes.io/node-name"])
		require.NotEmpty(t, extra["authentication.kubernetes.io/node-uid"])
	} else {
		require.Equal(t, 2, len(extra))
	}
}
