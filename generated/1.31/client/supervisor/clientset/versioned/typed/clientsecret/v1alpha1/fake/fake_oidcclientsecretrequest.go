// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "go.pinniped.dev/generated/1.31/apis/supervisor/clientsecret/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testing "k8s.io/client-go/testing"
)

// FakeOIDCClientSecretRequests implements OIDCClientSecretRequestInterface
type FakeOIDCClientSecretRequests struct {
	Fake *FakeClientsecretV1alpha1
	ns   string
}

var oidcclientsecretrequestsResource = v1alpha1.SchemeGroupVersion.WithResource("oidcclientsecretrequests")

var oidcclientsecretrequestsKind = v1alpha1.SchemeGroupVersion.WithKind("OIDCClientSecretRequest")

// Create takes the representation of a oIDCClientSecretRequest and creates it.  Returns the server's representation of the oIDCClientSecretRequest, and an error, if there is any.
func (c *FakeOIDCClientSecretRequests) Create(ctx context.Context, oIDCClientSecretRequest *v1alpha1.OIDCClientSecretRequest, opts v1.CreateOptions) (result *v1alpha1.OIDCClientSecretRequest, err error) {
	emptyResult := &v1alpha1.OIDCClientSecretRequest{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(oidcclientsecretrequestsResource, c.ns, oIDCClientSecretRequest, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.OIDCClientSecretRequest), err
}
