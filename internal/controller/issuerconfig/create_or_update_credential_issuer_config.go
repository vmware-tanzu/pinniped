// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuerconfig

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	configv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned"
)

func CreateOrUpdateCredentialIssuer(
	ctx context.Context,
	credentialIssuerNamespace string,
	credentialIssuerResourceName string,
	credentialIssuerLabels map[string]string,
	pinnipedClient pinnipedclientset.Interface,
	applyUpdatesToCredentialIssuerFunc func(configToUpdate *configv1alpha1.CredentialIssuer),
) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existingCredentialIssuer, err := pinnipedClient.
			ConfigV1alpha1().
			CredentialIssuers(credentialIssuerNamespace).
			Get(ctx, credentialIssuerResourceName, metav1.GetOptions{})

		notFound := k8serrors.IsNotFound(err)
		if err != nil && !notFound {
			return fmt.Errorf("get failed: %w", err)
		}

		credentialIssuersClient := pinnipedClient.ConfigV1alpha1().CredentialIssuers(credentialIssuerNamespace)

		if notFound {
			// Create it
			credentialIssuer := minimalValidCredentialIssuer(
				credentialIssuerResourceName, credentialIssuerNamespace, credentialIssuerLabels,
			)
			applyUpdatesToCredentialIssuerFunc(credentialIssuer)

			if _, err := credentialIssuersClient.Create(ctx, credentialIssuer, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("create failed: %w", err)
			}
		} else {
			// Already exists, so check to see if we need to update it
			credentialIssuer := existingCredentialIssuer.DeepCopy()
			applyUpdatesToCredentialIssuerFunc(credentialIssuer)

			if equality.Semantic.DeepEqual(existingCredentialIssuer, credentialIssuer) {
				// Nothing interesting would change as a result of this update, so skip it
				return nil
			}

			if _, err := credentialIssuersClient.Update(ctx, credentialIssuer, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("could not create or update credentialissuer: %w", err)
	}
	return nil
}

func minimalValidCredentialIssuer(
	credentialIssuerName string,
	credentialIssuerNamespace string,
	credentialIssuerLabels map[string]string,
) *configv1alpha1.CredentialIssuer {
	return &configv1alpha1.CredentialIssuer{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      credentialIssuerName,
			Namespace: credentialIssuerNamespace,
			Labels:    credentialIssuerLabels,
		},
		Status: configv1alpha1.CredentialIssuerStatus{
			Strategies:     []configv1alpha1.CredentialIssuerStrategy{},
			KubeConfigInfo: nil,
		},
	}
}
