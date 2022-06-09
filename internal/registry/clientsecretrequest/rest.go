// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package clientsecretrequest provides REST functionality for the CredentialRequest resource.
package clientsecretrequest

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/utils/trace"

	oauthapi "go.pinniped.dev/generated/latest/apis/supervisor/virtual/oauth"
)

func NewREST() *REST {
	return &REST{}
}

type REST struct {
}

// Assert that our *REST implements all the optional interfaces that we expect it to implement.
var _ interface {
	rest.Creater
	rest.NamespaceScopedStrategy
	rest.Scoper
	rest.Storage
} = (*REST)(nil)

func (*REST) New() runtime.Object {
	return &oauthapi.OIDCClientSecretRequest{}
}

func (*REST) NamespaceScoped() bool {
	return true
}

func (*REST) Categories() []string {
	// because we haven't implemented lister, adding it to categories breaks things.
	return []string{}
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	t := trace.FromContext(ctx).Nest("create", trace.Field{
		Key:   "kind",
		Value: "OIDCClientSecretRequest",
	})
	defer t.Log()

	_, err := validateRequest(obj, t)
	if err != nil {
		return nil, err
	}

	return &oauthapi.OIDCClientSecretRequest{
		Status: oauthapi.OIDCClientSecretRequestStatus{
			GeneratedSecret:    "not-a-real-secret",
			TotalClientSecrets: 20,
		},
	}, nil
}

func validateRequest(obj runtime.Object, t *trace.Trace) (*oauthapi.OIDCClientSecretRequest, error) {
	clientSecretRequest, ok := obj.(*oauthapi.OIDCClientSecretRequest)
	if !ok {
		traceValidationFailure(t, "not an OIDCClientSecretRequest")
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not an OIDCClientSecretRequest: %#v", obj))
	}

	return clientSecretRequest, nil
}

func traceValidationFailure(t *trace.Trace, msg string) {
	t.Step("failure",
		trace.Field{Key: "failureType", Value: "request validation"},
		trace.Field{Key: "msg", Value: msg},
	)
}
