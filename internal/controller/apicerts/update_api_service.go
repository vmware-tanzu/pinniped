/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package apicerts

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	pinnipedv1alpha1 "github.com/suzerain-io/pinniped/kubernetes/1.19/api/apis/pinniped/v1alpha1"
)

// UpdateAPIService updates the APIService's CA bundle.
func UpdateAPIService(ctx context.Context, aggregatorClient aggregatorclient.Interface, aggregatedAPIServerCA []byte) error {
	apiServices := aggregatorClient.ApiregistrationV1().APIServices()
	apiServiceName := pinnipedv1alpha1.SchemeGroupVersion.Version + "." + pinnipedv1alpha1.GroupName

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Retrieve the latest version of the Service before attempting update.
		// RetryOnConflict uses exponential backoff to avoid exhausting the API server.
		fetchedAPIService, err := apiServices.Get(ctx, apiServiceName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("could not get existing version of API service: %w", err)
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
