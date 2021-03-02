// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuerconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
)

func TestMergeStrategy(t *testing.T) {
	t1 := metav1.Now()
	t2 := metav1.NewTime(metav1.Now().Add(-1 * time.Hour))

	tests := []struct {
		name           string
		configToUpdate v1alpha1.CredentialIssuerStatus
		strategy       v1alpha1.CredentialIssuerStrategy
		expected       v1alpha1.CredentialIssuerStatus
	}{
		{
			name: "new entry",
			configToUpdate: v1alpha1.CredentialIssuerStatus{
				Strategies: nil,
			},
			strategy: v1alpha1.CredentialIssuerStrategy{
				Type:           "Type1",
				Status:         v1alpha1.SuccessStrategyStatus,
				Reason:         "some reason",
				Message:        "some message",
				LastUpdateTime: t1,
			},
			expected: v1alpha1.CredentialIssuerStatus{
				Strategies: []v1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type1",
						Status:         v1alpha1.SuccessStrategyStatus,
						Reason:         "some reason",
						Message:        "some message",
						LastUpdateTime: t1,
					},
				},
			},
		},
		{
			name: "new entry updating deprecated kubeConfigInfo",
			configToUpdate: v1alpha1.CredentialIssuerStatus{
				Strategies: nil,
			},
			strategy: v1alpha1.CredentialIssuerStrategy{
				Type:           "Type1",
				Status:         v1alpha1.SuccessStrategyStatus,
				Reason:         "some reason",
				Message:        "some message",
				LastUpdateTime: t1,
				Frontend: &v1alpha1.CredentialIssuerFrontend{
					Type: "TokenCredentialRequestAPI",
					TokenCredentialRequestAPIInfo: &v1alpha1.TokenCredentialRequestAPIInfo{
						Server:                   "https://test-server",
						CertificateAuthorityData: "test-ca-bundle",
					},
				},
			},
			expected: v1alpha1.CredentialIssuerStatus{
				Strategies: []v1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type1",
						Status:         v1alpha1.SuccessStrategyStatus,
						Reason:         "some reason",
						Message:        "some message",
						LastUpdateTime: t1,
						Frontend: &v1alpha1.CredentialIssuerFrontend{
							Type: "TokenCredentialRequestAPI",
							TokenCredentialRequestAPIInfo: &v1alpha1.TokenCredentialRequestAPIInfo{
								Server:                   "https://test-server",
								CertificateAuthorityData: "test-ca-bundle",
							},
						},
					},
				},
				KubeConfigInfo: &v1alpha1.CredentialIssuerKubeConfigInfo{
					Server:                   "https://test-server",
					CertificateAuthorityData: "test-ca-bundle",
				},
			},
		},
		{
			name: "existing entry to update",
			configToUpdate: v1alpha1.CredentialIssuerStatus{
				Strategies: []v1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type1",
						Status:         v1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason",
						Message:        "some starting message",
						LastUpdateTime: t2,
					},
				},
			},
			strategy: v1alpha1.CredentialIssuerStrategy{
				Type:           "Type1",
				Status:         v1alpha1.SuccessStrategyStatus,
				Reason:         "some reason",
				Message:        "some message",
				LastUpdateTime: t1,
			},
			expected: v1alpha1.CredentialIssuerStatus{
				Strategies: []v1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type1",
						Status:         v1alpha1.SuccessStrategyStatus,
						Reason:         "some reason",
						Message:        "some message",
						LastUpdateTime: t1,
					},
				},
			},
		},
		{
			name: "new entry among others",
			configToUpdate: v1alpha1.CredentialIssuerStatus{
				Strategies: []v1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type0",
						Status:         v1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason 0",
						Message:        "some starting message 0",
						LastUpdateTime: t2,
					},
					{
						Type:           "Type2",
						Status:         v1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason 0",
						Message:        "some starting message 0",
						LastUpdateTime: t2,
					},
				},
			},
			strategy: v1alpha1.CredentialIssuerStrategy{
				Type:           "Type1",
				Status:         v1alpha1.SuccessStrategyStatus,
				Reason:         "some reason",
				Message:        "some message",
				LastUpdateTime: t1,
			},
			expected: v1alpha1.CredentialIssuerStatus{
				Strategies: []v1alpha1.CredentialIssuerStrategy{
					{
						Type:           "Type0",
						Status:         v1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason 0",
						Message:        "some starting message 0",
						LastUpdateTime: t2,
					},
					// Expect the Type1 entry to be sorted alphanumerically between the existing entries.
					{
						Type:           "Type1",
						Status:         v1alpha1.SuccessStrategyStatus,
						Reason:         "some reason",
						Message:        "some message",
						LastUpdateTime: t1,
					},
					{
						Type:           "Type2",
						Status:         v1alpha1.ErrorStrategyStatus,
						Reason:         "some starting reason 0",
						Message:        "some starting message 0",
						LastUpdateTime: t2,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			updated := tt.configToUpdate.DeepCopy()
			mergeStrategy(updated, tt.strategy)
			require.Equal(t, &tt.expected, updated)
		})
	}
}
