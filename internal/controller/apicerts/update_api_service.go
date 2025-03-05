// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"bytes"
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

// UpdateAPIService updates the APIService's CA bundle.
func UpdateAPIService(
	ctx context.Context,
	aggregatorClient aggregatorclient.Interface,
	apiServiceName, serviceNamespace string,
	aggregatedAPIServerCA []byte,
) error {
	apiServices := aggregatorClient.ApiregistrationV1().APIServices()

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Retrieve the latest version of the Service.
		fetchedAPIService, err := apiServices.Get(ctx, apiServiceName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("could not get existing version of API service: %w", err)
		}

		if serviceRef := fetchedAPIService.Spec.Service; serviceRef != nil {
			if serviceRef.Namespace != serviceNamespace {
				// we do not own this API service so do not attempt to mutate it
				return nil
			}
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
