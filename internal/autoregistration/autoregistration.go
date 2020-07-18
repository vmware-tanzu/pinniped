/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package autoregistration registers a Kubernetes APIService pointing at the current pod.
package autoregistration

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatationv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

// ErrInvalidServiceTemplate is returned by Setup when the provided ServiceTemplate is not valid.
var ErrInvalidServiceTemplate = errors.New("invalid service template")

// SetupOptions specifies the inputs for Setup().
type SetupOptions struct {
	CoreV1             corev1client.CoreV1Interface
	AggregationV1      aggregatationv1client.Interface
	Namespace          string
	ServiceTemplate    corev1.Service
	APIServiceTemplate apiregistrationv1.APIService
}

// Setup registers a Kubernetes Service, and an aggregation APIService which points to it.
func Setup(ctx context.Context, options SetupOptions) error {
	// Get the namespace so we can use its UID set owner references on other objects.
	ns, err := options.CoreV1.Namespaces().Get(ctx, options.Namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("could not get namespace: %w", err)
	}

	// Make a copy of the Service template.
	svc := options.ServiceTemplate.DeepCopy()
	svc.Namespace = ns.Name

	// Validate that the Service meets our expectations.
	if len(svc.Spec.Ports) != 1 {
		return fmt.Errorf("%w: must have 1 port (found %d)", ErrInvalidServiceTemplate, len(svc.Spec.Ports))
	}
	if port := svc.Spec.Ports[0]; port.Protocol != corev1.ProtocolTCP || port.Port != 443 {
		return fmt.Errorf("%w: must expose TCP/443 (found %s/%d)", ErrInvalidServiceTemplate, port.Protocol, port.Port)
	}

	// Create or update the Service.
	if err := createOrUpdateService(ctx, options.CoreV1, svc); err != nil {
		return err
	}

	apiSvc := options.APIServiceTemplate.DeepCopy()
	apiSvc.Spec.Service = &apiregistrationv1.ServiceReference{
		Namespace: ns.Name,
		Name:      svc.Name,
		Port:      &svc.Spec.Ports[0].Port,
	}
	apiSvc.ObjectMeta.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "v1",        // TODO why did we need to hardcode this to avoid errors? was ns.APIVersion
		Kind:       "Namespace", // TODO why did we need to hardcode this to avoid errors? was ns.Kind
		UID:        ns.UID,
		Name:       ns.Name,
	}}
	if err := createOrUpdateAPIService(ctx, options.AggregationV1, apiSvc); err != nil {
		return err
	}
	return nil
}

func createOrUpdateService(ctx context.Context, client corev1client.CoreV1Interface, svc *corev1.Service) error {
	services := client.Services(svc.Namespace)

	_, err := services.Create(ctx, svc, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("could not create service: %w", err)
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Retrieve the latest version of the Service before attempting update
		// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
		result, err := services.Get(ctx, svc.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("could not get existing version of service: %w", err)
		}

		// Update just the fields we care about.
		result.Spec.Ports = svc.Spec.Ports
		result.Spec.Selector = svc.Spec.Selector

		_, updateErr := services.Update(ctx, result, metav1.UpdateOptions{})
		return updateErr
	}); err != nil {
		return fmt.Errorf("could not update service: %w", err)
	}
	return nil
}

func createOrUpdateAPIService(ctx context.Context, client aggregatationv1client.Interface, apiSvc *apiregistrationv1.APIService) error {
	apiServices := client.ApiregistrationV1().APIServices()

	_, err := apiServices.Create(ctx, apiSvc, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("could not create API service: %w", err)
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Retrieve the latest version of the Service before attempting update
		// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
		result, err := apiServices.Get(ctx, apiSvc.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("could not get existing version of API service: %w", err)
		}

		// Update just the fields we care about.
		apiSvc.Spec.DeepCopyInto(&result.Spec)
		apiSvc.OwnerReferences = result.OwnerReferences

		_, updateErr := apiServices.Update(ctx, result, metav1.UpdateOptions{})
		return updateErr
	}); err != nil {
		return fmt.Errorf("could not update API service: %w", err)
	}
	return nil
}
