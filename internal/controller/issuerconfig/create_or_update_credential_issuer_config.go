// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuerconfig

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
)

func CreateOrUpdateCredentialIssuerConfig(
	ctx context.Context,
	credentialIssuerConfigNamespace string,
	credentialIssuerConfigResourceName string,
	pinnipedClient pinnipedclientset.Interface,
	applyUpdatesToCredentialIssuerConfigFunc func(configToUpdate *configv1alpha1.CredentialIssuerConfig),
) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existingCredentialIssuerConfig, err := pinnipedClient.
			ConfigV1alpha1().
			CredentialIssuerConfigs(credentialIssuerConfigNamespace).
			Get(ctx, credentialIssuerConfigResourceName, metav1.GetOptions{})

		notFound := k8serrors.IsNotFound(err)
		if err != nil && !notFound {
			return fmt.Errorf("get failed: %w", err)
		}

		credentialIssuerConfigsClient := pinnipedClient.ConfigV1alpha1().CredentialIssuerConfigs(credentialIssuerConfigNamespace)

		if notFound {
			// Create it
			credentialIssuerConfig := minimalValidCredentialIssuerConfig(credentialIssuerConfigResourceName, credentialIssuerConfigNamespace)
			applyUpdatesToCredentialIssuerConfigFunc(credentialIssuerConfig)

			if _, err := credentialIssuerConfigsClient.Create(ctx, credentialIssuerConfig, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("create failed: %w", err)
			}
		} else {
			// Already exists, so check to see if we need to update it
			credentialIssuerConfig := existingCredentialIssuerConfig.DeepCopy()
			applyUpdatesToCredentialIssuerConfigFunc(credentialIssuerConfig)

			if equality.Semantic.DeepEqual(existingCredentialIssuerConfig, credentialIssuerConfig) {
				// Nothing interesting would change as a result of this update, so skip it
				return nil
			}

			if _, err := credentialIssuerConfigsClient.Update(ctx, credentialIssuerConfig, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("could not create or update credentialissuerconfig: %w", err)
	}
	return nil
}

func minimalValidCredentialIssuerConfig(
	credentialIssuerConfigName string,
	credentialIssuerConfigNamespace string,
) *configv1alpha1.CredentialIssuerConfig {
	return &configv1alpha1.CredentialIssuerConfig{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      credentialIssuerConfigName,
			Namespace: credentialIssuerConfigNamespace,
		},
		Status: configv1alpha1.CredentialIssuerConfigStatus{
			Strategies:     []configv1alpha1.CredentialIssuerConfigStrategy{},
			KubeConfigInfo: nil,
		},
	}
}
