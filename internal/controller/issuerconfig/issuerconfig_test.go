// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuerconfig

import (
	"math/rand"
	"sort"
	"testing"
	"testing/quick"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
)

func TestMergeStrategy(t *testing.T) {
	t1 := metav1.Now()
	t2 := metav1.NewTime(metav1.Now().Add(-1 * time.Hour))

	tests := []struct {
		name           string
		configToUpdate conciergeconfigv1alpha1.CredentialIssuerStatus
		strategy       conciergeconfigv1alpha1.CredentialIssuerStrategy
		expected       conciergeconfigv1alpha1.CredentialIssuerStatus
	}{
		{
			name: "new entry",
			configToUpdate: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: nil,
			},
			strategy: conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           "Type1",
				Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
				Reason:         "some reason",
				Message:        "some message",
				LastUpdateTime: t1,
			},
			expected: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type1",
						Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
						Reason:         "some reason",
						Message:        "some message",
						LastUpdateTime: t1,
					},
				},
			},
		},
		{
			name: "new entry updating deprecated kubeConfigInfo",
			configToUpdate: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: nil,
			},
			strategy: conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           "Type1",
				Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
				Reason:         "some reason",
				Message:        "some message",
				LastUpdateTime: t1,
				Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
					Type: "TokenCredentialRequestAPI",
					TokenCredentialRequestAPIInfo: &conciergeconfigv1alpha1.TokenCredentialRequestAPIInfo{
						Server:                   "https://test-server",
						CertificateAuthorityData: "test-ca-bundle",
					},
				},
			},
			expected: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type1",
						Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
						Reason:         "some reason",
						Message:        "some message",
						LastUpdateTime: t1,
						Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
							Type: "TokenCredentialRequestAPI",
							TokenCredentialRequestAPIInfo: &conciergeconfigv1alpha1.TokenCredentialRequestAPIInfo{
								Server:                   "https://test-server",
								CertificateAuthorityData: "test-ca-bundle",
							},
						},
					},
				},
			},
		},
		{
			name: "existing entry to update",
			configToUpdate: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type1",
						Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason",
						Message:        "some starting message",
						LastUpdateTime: t2,
					},
				},
			},
			strategy: conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           "Type1",
				Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
				Reason:         "some reason",
				Message:        "some message",
				LastUpdateTime: t1,
			},
			expected: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type1",
						Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
						Reason:         "some reason",
						Message:        "some message",
						LastUpdateTime: t1,
					},
				},
			},
		},
		{
			name: "existing entry matches except for LastUpdated time",
			configToUpdate: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type1",
						Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason",
						Message:        "some starting message",
						LastUpdateTime: t1,
					},
				},
			},
			strategy: conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           "Type1",
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         "some starting reason",
				Message:        "some starting message",
				LastUpdateTime: t2,
			},
			expected: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type1",
						Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason",
						Message:        "some starting message",
						LastUpdateTime: t1,
					},
				},
			},
		},
		{
			name: "new entry among others",
			configToUpdate: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type0",
						Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason 0",
						Message:        "some starting message 0",
						LastUpdateTime: t2,
					},
					{
						Type:           "Type2",
						Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason 0",
						Message:        "some starting message 0",
						LastUpdateTime: t2,
					},
				},
			},
			strategy: conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           "Type1",
				Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
				Reason:         "some reason",
				Message:        "some message",
				LastUpdateTime: t1,
			},
			expected: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type0",
						Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason 0",
						Message:        "some starting message 0",
						LastUpdateTime: t2,
					},
					// Expect the Type1 entry to be sorted alphanumerically between the existing entries.
					{
						Type:           "Type1",
						Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
						Reason:         "some reason",
						Message:        "some message",
						LastUpdateTime: t1,
					},
					{
						Type:           "Type2",
						Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason 0",
						Message:        "some starting message 0",
						LastUpdateTime: t2,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated := tt.configToUpdate.DeepCopy()
			mergeStrategy(updated, tt.strategy)
			require.Equal(t, tt.expected.DeepCopy(), updated)
		})
	}
}

func TestStrategySorting(t *testing.T) {
	expected := []conciergeconfigv1alpha1.CredentialIssuerStrategy{
		{Type: conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType},
		{Type: conciergeconfigv1alpha1.ImpersonationProxyStrategyType},
		{Type: "Type1"},
		{Type: "Type2"},
		{Type: "Type3"},
	}
	require.NoError(t, quick.Check(func(seed int64) bool {
		// Create a randomly shuffled copy of the expected output.
		//nolint:gosec // this is not meant to be a secure random, just a seeded RNG for shuffling deterministically
		rng := rand.New(rand.NewSource(seed))
		output := make([]conciergeconfigv1alpha1.CredentialIssuerStrategy, len(expected))
		copy(output, expected)
		rng.Shuffle(
			len(output),
			func(i, j int) { output[i], output[j] = output[j], output[i] },
		)

		// Sort it using the code under test.
		sort.Stable(sortableStrategies(output))

		// Assert that it's sorted back to the expected output order.
		return assert.Equal(t, expected, output)
	}, nil))
}
