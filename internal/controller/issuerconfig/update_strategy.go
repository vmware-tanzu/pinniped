// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuerconfig

import (
	"context"
	"sort"

	"go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	"go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
)

// UpdateStrategy creates or updates the desired strategy in the CredentialIssuer status.strategies field.
// The CredentialIssuer will be created if it does not already exist.
func UpdateStrategy(ctx context.Context,
	name string,
	credentialIssuerLabels map[string]string,
	pinnipedAPIClient versioned.Interface,
	strategy v1alpha1.CredentialIssuerStrategy,
) error {
	return CreateOrUpdateCredentialIssuerStatus(
		ctx,
		name,
		credentialIssuerLabels,
		pinnipedAPIClient,
		func(configToUpdate *v1alpha1.CredentialIssuerStatus) { mergeStrategy(configToUpdate, strategy) },
	)
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
		strategy.DeepCopyInto(existing)
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

// TODO: sort strategies by server preference rather than alphanumerically by type.
type sortableStrategies []v1alpha1.CredentialIssuerStrategy

func (s sortableStrategies) Len() int           { return len(s) }
func (s sortableStrategies) Less(i, j int) bool { return s[i].Type < s[j].Type }
func (s sortableStrategies) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
