// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package whoamirequest

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	identityapi "go.pinniped.dev/generated/latest/apis/concierge/identity"
	identityapivalidation "go.pinniped.dev/generated/latest/apis/concierge/identity/validation"
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
} = (*REST)(nil)

func (*REST) New() runtime.Object {
	return &identityapi.WhoAmIRequest{}
}

func (*REST) NewList() runtime.Object {
	return &identityapi.WhoAmIRequestList{}
}

func (*REST) List(_ context.Context, _ *metainternalversion.ListOptions) (runtime.Object, error) {
	return &identityapi.WhoAmIRequestList{
		ListMeta: metav1.ListMeta{
			ResourceVersion: "0", // this resource version means "from the API server cache"
		},
		Items: []identityapi.WhoAmIRequest{}, // avoid sending nil items list
	}, nil
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return r.tableConvertor.ConvertToTable(ctx, obj, tableOptions)
}

func (*REST) NamespaceScoped() bool {
	return false
}

func (*REST) Categories() []string {
	return []string{"pinniped"}
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	whoAmIRequest, ok := obj.(*identityapi.WhoAmIRequest)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a WhoAmIRequest: %#v", obj))
	}

	if errs := identityapivalidation.ValidateWhoAmIRequest(whoAmIRequest); len(errs) > 0 {
		return nil, apierrors.NewInvalid(identityapi.Kind(whoAmIRequest.Kind), whoAmIRequest.Name, errs)
	}

	// just a sanity check, not sure how to honor a dry run on a virtual API
	if options != nil {
		if len(options.DryRun) != 0 {
			errs := field.ErrorList{field.NotSupported(field.NewPath("dryRun"), options.DryRun, nil)}
			return nil, apierrors.NewInvalid(identityapi.Kind(whoAmIRequest.Kind), whoAmIRequest.Name, errs)
		}
	}

	if namespace := genericapirequest.NamespaceValue(ctx); len(namespace) != 0 {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("namespace is not allowed on WhoAmIRequest: %v", namespace))
	}

	if createValidation != nil {
		if err := createValidation(ctx, obj.DeepCopyObject()); err != nil {
			return nil, err
		}
	}

	userInfo, ok := genericapirequest.UserFrom(ctx)
	if !ok {
		return nil, apierrors.NewInternalError(fmt.Errorf("no user info on request"))
	}

	auds, _ := authenticator.AudiencesFrom(ctx)

	out := &identityapi.WhoAmIRequest{
		Status: identityapi.WhoAmIRequestStatus{
			KubernetesUserInfo: identityapi.KubernetesUserInfo{
				User: identityapi.UserInfo{
					Username: userInfo.GetName(),
					UID:      userInfo.GetUID(),
					Groups:   userInfo.GetGroups(),
				},
				Audiences: auds,
			},
		},
	}
	for k, v := range userInfo.GetExtra() {
		if out.Status.KubernetesUserInfo.User.Extra == nil {
			out.Status.KubernetesUserInfo.User.Extra = map[string]identityapi.ExtraValue{}
		}

		// this assumes no one is putting secret data in the extra field
		// I think this is a safe assumption since it would leak into audit logs
		out.Status.KubernetesUserInfo.User.Extra[k] = v
	}

	return out, nil
}
