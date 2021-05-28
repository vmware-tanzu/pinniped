// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package issuerconfig contains helpers for updating CredentialIssuer status entries.
package issuerconfig

import (
	"context"
	"fmt"
	"sort"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	"go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
)

// Update a strategy on an existing CredentialIssuer, merging into any existing strategy entries.
func Update(ctx context.Context, client versioned.Interface, issuer *v1alpha1.CredentialIssuer, strategy v1alpha1.CredentialIssuerStrategy) error {
	// Update the existing object to merge in the new strategy.
	updated := issuer.DeepCopy()
	mergeStrategy(&updated.Status, strategy)

	// If the status has not changed, we're done.
	if apiequality.Semantic.DeepEqual(issuer.Status, updated.Status) {
		return nil
	}

	if _, err := client.ConfigV1alpha1().CredentialIssuers().UpdateStatus(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update CredentialIssuer status: %w", err)
	}
	return nil
}

func mergeStrategy(configToUpdate *v1alpha1.CredentialIssuerStatus, strategy v1alpha1.CredentialIssuerStrategy) {
	var existing *v1alpha1.CredentialIssuerStrategy
	for i := range configToUpdate.Strategies {
		if configToUpdate.Strategies[i].Type == strategy.Type {
			existing = &configToUpdate.Strategies[i]
			break
		}
	}
	if existing != nil {
		if !equalExceptLastUpdated(existing, &strategy) {
			strategy.DeepCopyInto(existing)
		}
	} else {
		configToUpdate.Strategies = append(configToUpdate.Strategies, strategy)
	}
	sort.Stable(sortableStrategies(configToUpdate.Strategies))

	// Special case: the "TokenCredentialRequestAPI" data is mirrored into the deprecated status.kubeConfigInfo field.
	if strategy.Frontend != nil && strategy.Frontend.Type == v1alpha1.TokenCredentialRequestAPIFrontendType {
		configToUpdate.KubeConfigInfo = &v1alpha1.CredentialIssuerKubeConfigInfo{
			Server:                   strategy.Frontend.TokenCredentialRequestAPIInfo.Server,
			CertificateAuthorityData: strategy.Frontend.TokenCredentialRequestAPIInfo.CertificateAuthorityData,
		}
	}
}

// weights are a set of priorities for each strategy type.
//nolint: gochecknoglobals
var weights = map[v1alpha1.StrategyType]int{
	v1alpha1.KubeClusterSigningCertificateStrategyType: 2, // most preferred strategy
	v1alpha1.ImpersonationProxyStrategyType:            1,
	// unknown strategy types will have weight 0 by default
}

type sortableStrategies []v1alpha1.CredentialIssuerStrategy

func (s sortableStrategies) Len() int { return len(s) }
func (s sortableStrategies) Less(i, j int) bool {
	if wi, wj := weights[s[i].Type], weights[s[j].Type]; wi != wj {
		return wi > wj
	}
	return s[i].Type < s[j].Type
}
func (s sortableStrategies) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func equalExceptLastUpdated(s1, s2 *v1alpha1.CredentialIssuerStrategy) bool {
	s1 = s1.DeepCopy()
	s2 = s2.DeepCopy()
	s1.LastUpdateTime = metav1.Time{}
	s2.LastUpdateTime = metav1.Time{}
	return apiequality.Semantic.DeepEqual(s1, s2)
}
