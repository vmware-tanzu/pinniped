/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package apicerts

import (
	"bytes"
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	pinnipedv1alpha1 "github.com/suzerain-io/pinniped/generated/1.19/apis/pinniped/v1alpha1"
)

// UpdateAPIService updates the APIService's CA bundle.
func UpdateAPIService(ctx context.Context, aggregatorClient aggregatorclient.Interface, aggregatedAPIServerCA []byte) error {
	apiServices := aggregatorClient.ApiregistrationV1().APIServices()
	apiServiceName := pinnipedv1alpha1.SchemeGroupVersion.Version + "." + pinnipedv1alpha1.GroupName

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Retrieve the latest version of the Service.
		fetchedAPIService, err := apiServices.Get(ctx, apiServiceName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("could not get existing version of API service: %w", err)
		}

		if bytes.Equal(fetchedAPIService.Spec.CABundle, aggregatedAPIServerCA) {
			// Already has the same value, perhaps because another process already updated the object, so no need to update.
			return nil
		}

		// Update just the field we care about.
		fetchedAPIService.Spec.CABundle = aggregatedAPIServerCA

		_, updateErr := apiServices.Update(ctx, fetchedAPIService, metav1.UpdateOptions{})
		return updateErr
	}); err != nil {
		return fmt.Errorf("could not update API service: %w", err)
	}
	return nil
}
