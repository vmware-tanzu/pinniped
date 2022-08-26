// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package clientsecretrequest provides REST functionality for the CredentialRequest resource.
package clientsecretrequest

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/utils/trace"

	clientsecretapi "go.pinniped.dev/generated/latest/apis/supervisor/clientsecret"
)

func NewREST(resource schema.GroupResource) *REST {
	return &REST{
		tableConvertor: rest.NewDefaultTableConvertor(resource),
	}
}

type REST struct {
	tableConvertor rest.TableConvertor
}

// Assert that our *REST implements all the optional interfaces that we expect it to implement.
var _ interface {
	rest.Creater
	rest.NamespaceScopedStrategy
	rest.Scoper
	rest.Storage
	rest.CategoriesProvider
	rest.Lister
	rest.TableConvertor
} = (*REST)(nil)

func (*REST) New() runtime.Object {
	return &clientsecretapi.OIDCClientSecretRequest{}
}

func (*REST) Destroy() {}

func (*REST) NewList() runtime.Object {
	return &clientsecretapi.OIDCClientSecretRequestList{}
}

func (*REST) List(_ context.Context, _ *metainternalversion.ListOptions) (runtime.Object, error) {
	return &clientsecretapi.OIDCClientSecretRequestList{
		ListMeta: metav1.ListMeta{
			ResourceVersion: "0", // this resource version means "from the API server cache"
		},
		Items: []clientsecretapi.OIDCClientSecretRequest{}, // avoid sending nil items list
	}, nil
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return r.tableConvertor.ConvertToTable(ctx, obj, tableOptions)
}

func (*REST) NamespaceScoped() bool {
	return true
}

func (*REST) Categories() []string {
	return []string{"pinniped"}
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

	return &clientsecretapi.OIDCClientSecretRequest{
		Status: clientsecretapi.OIDCClientSecretRequestStatus{
			GeneratedSecret:    "not-a-real-secret",
			TotalClientSecrets: 20,
		},
	}, nil
}

func validateRequest(obj runtime.Object, t *trace.Trace) (*clientsecretapi.OIDCClientSecretRequest, error) {
	clientSecretRequest, ok := obj.(*clientsecretapi.OIDCClientSecretRequest)
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
