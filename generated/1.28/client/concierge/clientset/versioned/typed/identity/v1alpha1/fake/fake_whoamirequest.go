// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "go.pinniped.dev/generated/1.28/apis/concierge/identity/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testing "k8s.io/client-go/testing"
)

// FakeWhoAmIRequests implements WhoAmIRequestInterface
type FakeWhoAmIRequests struct {
	Fake *FakeIdentityV1alpha1
}

var whoamirequestsResource = v1alpha1.SchemeGroupVersion.WithResource("whoamirequests")

var whoamirequestsKind = v1alpha1.SchemeGroupVersion.WithKind("WhoAmIRequest")

// Create takes the representation of a whoAmIRequest and creates it.  Returns the server's representation of the whoAmIRequest, and an error, if there is any.
func (c *FakeWhoAmIRequests) Create(ctx context.Context, whoAmIRequest *v1alpha1.WhoAmIRequest, opts v1.CreateOptions) (result *v1alpha1.WhoAmIRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(whoamirequestsResource, whoAmIRequest), &v1alpha1.WhoAmIRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.WhoAmIRequest), err
}
