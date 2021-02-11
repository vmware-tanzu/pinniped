// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apiserviceref

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/ownerref"
)

func New(apiServiceName string, opts ...kubeclient.Option) (kubeclient.Option, error) {
	tempClient, err := kubeclient.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("cannot create temp client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	apiService, err := tempClient.Aggregation.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("cannot get api service %s: %w", apiServiceName, err)
	}

	// work around stupid behavior of WithoutVersionDecoder.Decode
	apiService.APIVersion, apiService.Kind = apiregistrationv1.SchemeGroupVersion.WithKind("APIService").ToAPIVersionAndKind()

	return kubeclient.WithMiddleware(ownerref.New(apiService)), nil
}
