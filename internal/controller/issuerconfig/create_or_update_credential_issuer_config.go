/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package issuerconfig

import (
	"context"
	"fmt"
	"reflect"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdpinnipedv1alpha1 "github.com/suzerain-io/pinniped/generated/1.19/apis/crdpinniped/v1alpha1"
	pinnipedclientset "github.com/suzerain-io/pinniped/generated/1.19/client/clientset/versioned"
)

func CreateOrUpdateCredentialIssuerConfig(
	ctx context.Context,
	credentialIssuerConfigNamespace string,
	pinnipedClient pinnipedclientset.Interface,
	applyUpdatesToCredentialIssuerConfigFunc func(configToUpdate *crdpinnipedv1alpha1.CredentialIssuerConfig),
) error {
	credentialIssuerConfigName := configName

	existingCredentialIssuerConfig, err := pinnipedClient.
		CrdV1alpha1().
		CredentialIssuerConfigs(credentialIssuerConfigNamespace).
		Get(ctx, credentialIssuerConfigName, metav1.GetOptions{})

	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("could not get credentialissuerconfig: %w", err)
	}

	return createOrUpdateCredentialIssuerConfig(
		ctx,
		existingCredentialIssuerConfig,
		notFound,
		credentialIssuerConfigName,
		credentialIssuerConfigNamespace,
		pinnipedClient,
		applyUpdatesToCredentialIssuerConfigFunc)
}

func createOrUpdateCredentialIssuerConfig(
	ctx context.Context,
	existingCredentialIssuerConfig *crdpinnipedv1alpha1.CredentialIssuerConfig,
	notFound bool,
	credentialIssuerConfigName string,
	credentialIssuerConfigNamespace string,
	pinnipedClient pinnipedclientset.Interface,
	applyUpdatesToCredentialIssuerConfigFunc func(configToUpdate *crdpinnipedv1alpha1.CredentialIssuerConfig),
) error {
	credentialIssuerConfigsClient := pinnipedClient.CrdV1alpha1().CredentialIssuerConfigs(credentialIssuerConfigNamespace)

	if notFound {
		// Create it
		credentialIssuerConfig := minimalValidCredentialIssuerConfig(credentialIssuerConfigName, credentialIssuerConfigNamespace)
		applyUpdatesToCredentialIssuerConfigFunc(credentialIssuerConfig)

		if _, err := credentialIssuerConfigsClient.Create(ctx, credentialIssuerConfig, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("could not create credentialissuerconfig: %w", err)
		}
	} else {
		// Already exists, so check to see if we need to update it
		credentialIssuerConfig := existingCredentialIssuerConfig.DeepCopy()
		applyUpdatesToCredentialIssuerConfigFunc(credentialIssuerConfig)

		if reflect.DeepEqual(existingCredentialIssuerConfig.Status, credentialIssuerConfig.Status) {
			// Nothing interesting would change as a result of this update, so skip it
			return nil
		}

		if _, err := credentialIssuerConfigsClient.Update(ctx, credentialIssuerConfig, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("could not update credentialissuerconfig: %w", err)
		}
	}

	return nil
}

func minimalValidCredentialIssuerConfig(
	credentialIssuerConfigName string,
	credentialIssuerConfigNamespace string,
) *crdpinnipedv1alpha1.CredentialIssuerConfig {
	return &crdpinnipedv1alpha1.CredentialIssuerConfig{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      credentialIssuerConfigName,
			Namespace: credentialIssuerConfigNamespace,
		},
		Status: crdpinnipedv1alpha1.CredentialIssuerConfigStatus{
			Strategies:     []crdpinnipedv1alpha1.CredentialIssuerConfigStrategy{},
			KubeConfigInfo: nil,
		},
	}
}
