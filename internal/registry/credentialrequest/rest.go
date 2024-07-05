// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package credentialrequest provides REST functionality for the CredentialRequest resource.
package credentialrequest

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/utils/trace"

	loginapi "go.pinniped.dev/generated/latest/apis/concierge/login"
	"go.pinniped.dev/internal/clientcertissuer"
	"go.pinniped.dev/internal/plog"
)

// clientCertificateTTL is the TTL for short-lived client certificates returned by this API.
const clientCertificateTTL = 5 * time.Minute

type TokenCredentialRequestAuthenticator interface {
	AuthenticateTokenCredentialRequest(ctx context.Context, req *loginapi.TokenCredentialRequest) (user.Info, error)
}

func NewREST(
	authenticator TokenCredentialRequestAuthenticator,
	issuer clientcertissuer.ClientCertIssuer,
	resource schema.GroupResource,
	auditLogger plog.AuditLogger,
) *REST {
	return &REST{
		authenticator:  authenticator,
		issuer:         issuer,
		tableConvertor: rest.NewDefaultTableConvertor(resource),
		auditLogger:    auditLogger,
	}
}

type REST struct {
	authenticator  TokenCredentialRequestAuthenticator
	issuer         clientcertissuer.ClientCertIssuer
	tableConvertor rest.TableConvertor
	auditLogger    plog.AuditLogger
}

// Assert that our *REST implements all the optional interfaces that we expect it to implement.
var _ interface {
	rest.Creater //nolint:misspell // this name comes from a dependency
	rest.NamespaceScopedStrategy
	rest.Scoper
	rest.Storage
	rest.CategoriesProvider
	rest.SingularNameProvider
	rest.Lister
} = (*REST)(nil)

func (*REST) New() runtime.Object {
	return &loginapi.TokenCredentialRequest{}
}

func (*REST) Destroy() {}

func (*REST) NewList() runtime.Object {
	return &loginapi.TokenCredentialRequestList{}
}

func (*REST) List(_ context.Context, _ *metainternalversion.ListOptions) (runtime.Object, error) {
	return &loginapi.TokenCredentialRequestList{
		ListMeta: metav1.ListMeta{
			ResourceVersion: "0", // this resource version means "from the API server cache"
		},
		Items: []loginapi.TokenCredentialRequest{}, // avoid sending nil items list
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

func (*REST) GetSingularName() string {
	return "tokencredentialrequest"
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	t := trace.FromContext(ctx).Nest("create", trace.Field{
		Key:   "kind",
		Value: "TokenCredentialRequest",
	})
	defer t.Log()

	credentialRequest, err := validateRequest(ctx, obj, createValidation, options, t)
	if err != nil {
		return nil, err
	}

	userInfo, err := r.authenticator.AuthenticateTokenCredentialRequest(ctx, credentialRequest)
	if err != nil {
		traceFailureWithError(t, "token authentication", err)
		return failureResponse(), nil
	}
	if ok := isUserInfoValid(userInfo); !ok {
		traceSuccess(t, userInfo, false)
		return failureResponse(), nil
	}

	// this timestamp should be returned from IssueClientCertPEM but this is a safe approximation
	expires := metav1.NewTime(time.Now().UTC().Add(clientCertificateTTL))
	certPEM, keyPEM, err := r.issuer.IssueClientCertPEM(userInfo.GetName(), userInfo.GetGroups(), clientCertificateTTL)
	if err != nil {
		traceFailureWithError(t, "cert issuer", err)
		return failureResponse(), nil
	}

	traceSuccess(t, userInfo, true)

	r.auditLogger.Audit(plog.AuditEventTokenCredentialRequest, ctx, nil,
		"username", userInfo.GetName(),
		"groups", userInfo.GetGroups(),
		"authenticated", true,
		"expires", expires.Format(time.RFC3339))

	return &loginapi.TokenCredentialRequest{
		Status: loginapi.TokenCredentialRequestStatus{
			Credential: &loginapi.ClusterCredential{
				ExpirationTimestamp:   expires,
				ClientCertificateData: string(certPEM),
				ClientKeyData:         string(keyPEM),
			},
		},
	}, nil
}

func validateRequest(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions, t *trace.Trace) (*loginapi.TokenCredentialRequest, error) {
	credentialRequest, ok := obj.(*loginapi.TokenCredentialRequest)
	if !ok {
		traceValidationFailure(t, "not a TokenCredentialRequest")
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a TokenCredentialRequest: %#v", obj))
	}

	if len(credentialRequest.Spec.Token) == 0 {
		traceValidationFailure(t, "token must be supplied")
		errs := field.ErrorList{field.Required(field.NewPath("spec", "token", "value"), "token must be supplied")}
		return nil, apierrors.NewInvalid(loginapi.Kind(credentialRequest.Kind), credentialRequest.Name, errs)
	}

	// just a sanity check, not sure how to honor a dry run on a virtual API
	if options != nil {
		if len(options.DryRun) != 0 {
			traceValidationFailure(t, "dryRun not supported")
			errs := field.ErrorList{field.NotSupported(field.NewPath("dryRun"), options.DryRun, []string(nil))}
			return nil, apierrors.NewInvalid(loginapi.Kind(credentialRequest.Kind), credentialRequest.Name, errs)
		}
	}

	if namespace := genericapirequest.NamespaceValue(ctx); len(namespace) != 0 {
		traceValidationFailure(t, "namespace is not allowed")
		return nil, apierrors.NewBadRequest(fmt.Sprintf("namespace is not allowed on TokenCredentialRequest: %v", namespace))
	}

	// let dynamic admission webhooks have a chance to validate (but not mutate) as well
	//  TODO Since we are an aggregated API, we should investigate to see if the kube API server is already invoking admission hooks for us.
	//   Even if it is, its okay to call it again here. However, if the kube API server is already calling the webhooks and passing
	//   the token, then there is probably no reason for us to avoid passing the token when we call the webhooks here, since
	//   they already got the token.
	if createValidation != nil {
		requestForValidation := obj.DeepCopyObject()
		requestForValidation.(*loginapi.TokenCredentialRequest).Spec.Token = ""
		if err := createValidation(ctx, requestForValidation); err != nil {
			traceFailureWithError(t, "validation webhook", err)
			return nil, err
		}
	}

	return credentialRequest, nil
}

func isUserInfoValid(userInfo user.Info) bool {
	switch {
	case userInfo == nil, // must be non-nil
		len(userInfo.GetName()) == 0,  // must have a username, groups are optional
		len(userInfo.GetUID()) != 0,   // certs cannot assert UID
		len(userInfo.GetExtra()) != 0: // certs cannot assert extra
		return false

	default:
		return true
	}
}

func traceSuccess(t *trace.Trace, userInfo user.Info, authenticated bool) {
	userID := "<none>"
	hasExtra := false
	if userInfo != nil {
		userID = userInfo.GetUID()
		hasExtra = len(userInfo.GetExtra()) > 0
	}
	t.Step("success",
		trace.Field{Key: "userID", Value: userID},
		trace.Field{Key: "hasExtra", Value: hasExtra},
		trace.Field{Key: "authenticated", Value: authenticated},
	)
}

func traceValidationFailure(t *trace.Trace, msg string) {
	t.Step("failure",
		trace.Field{Key: "failureType", Value: "request validation"},
		trace.Field{Key: "msg", Value: msg},
	)
}

func traceFailureWithError(t *trace.Trace, failureType string, err error) {
	t.Step("failure",
		trace.Field{Key: "failureType", Value: failureType},
		trace.Field{Key: "msg", Value: err.Error()},
	)
}

func failureResponse() *loginapi.TokenCredentialRequest {
	m := "authentication failed"
	return &loginapi.TokenCredentialRequest{
		Status: loginapi.TokenCredentialRequestStatus{
			Credential: nil,
			Message:    &m,
		},
	}
}
