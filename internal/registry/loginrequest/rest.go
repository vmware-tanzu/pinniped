/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package loginrequest provides REST functionality for the LoginRequest resource.
package loginrequest

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/utils/trace"

	placeholderapi "github.com/suzerain-io/placeholder-name/kubernetes/1.19/api/apis/placeholder"
)

// clientCertificateTTL is the TTL for short-lived client certificates returned by this API.
const clientCertificateTTL = 1 * time.Hour

var (
	_ rest.Creater                 = &REST{}
	_ rest.NamespaceScopedStrategy = &REST{}
	_ rest.Scoper                  = &REST{}
	_ rest.Storage                 = &REST{}
)

type CertIssuer interface {
	IssuePEM(subject pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, []byte, error)
}

func NewREST(webhook authenticator.Token, issuer CertIssuer) *REST {
	return &REST{
		webhook: webhook,
		issuer:  issuer,
	}
}

type REST struct {
	webhook authenticator.Token
	issuer  CertIssuer
}

func (r *REST) New() runtime.Object {
	return &placeholderapi.LoginRequest{}
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	t := trace.FromContext(ctx).Nest("create LoginRequest")
	defer t.Log()

	loginRequest, err := validateRequest(ctx, obj, createValidation, options, t)
	if err != nil {
		return nil, err
	}

	// The incoming context could have an audience. Since we do not want to handle audiences right now, do not pass it
	// through directly to the authentication webhook. Instead only propagate cancellation of the parent context.
	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-cancelCtx.Done():
		}
	}()

	authResponse, authenticated, err := r.webhook.AuthenticateToken(cancelCtx, loginRequest.Spec.Token.Value)
	if err != nil {
		traceFailureWithError(t, "webhook authentication", err)
		return failureResponse(), nil
	}
	if !authenticated || authResponse.User == nil || authResponse.User.GetName() == "" {
		traceSuccess(t, authResponse.User, authenticated, false)
		return failureResponse(), nil
	}

	username := authResponse.User.GetName()
	groups := authResponse.User.GetGroups()

	certPEM, keyPEM, err := r.issuer.IssuePEM(
		pkix.Name{
			CommonName:   username,
			Organization: groups,
		},
		[]string{},
		clientCertificateTTL,
	)
	if err != nil {
		traceFailureWithError(t, "cert issuer", err)
		return failureResponse(), nil
	}

	traceSuccess(t, authResponse.User, authenticated, true)

	return &placeholderapi.LoginRequest{
		Status: placeholderapi.LoginRequestStatus{
			Credential: &placeholderapi.LoginRequestCredential{
				ExpirationTimestamp:   metav1.NewTime(time.Now().UTC().Add(clientCertificateTTL)),
				ClientCertificateData: string(certPEM),
				ClientKeyData:         string(keyPEM),
			},
			User: &placeholderapi.User{
				Name:   username,
				Groups: groups,
			},
		},
	}, nil
}

func validateRequest(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions, t *trace.Trace) (*placeholderapi.LoginRequest, error) {
	loginRequest, ok := obj.(*placeholderapi.LoginRequest)
	if !ok {
		traceValidationFailure(t, "not a LoginRequest")
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a LoginRequest: %#v", obj))
	}

	if len(loginRequest.Spec.Type) == 0 {
		traceValidationFailure(t, "type must be supplied")
		errs := field.ErrorList{field.Required(field.NewPath("spec", "type"), "type must be supplied")}
		return nil, apierrors.NewInvalid(placeholderapi.Kind(loginRequest.Kind), loginRequest.Name, errs)
	}

	if loginRequest.Spec.Type != placeholderapi.TokenLoginCredentialType {
		traceValidationFailure(t, "unrecognized type")
		errs := field.ErrorList{field.Invalid(field.NewPath("spec", "type"), loginRequest.Spec.Type, "unrecognized type")}
		return nil, apierrors.NewInvalid(placeholderapi.Kind(loginRequest.Kind), loginRequest.Name, errs)
	}

	token := loginRequest.Spec.Token
	if token == nil || len(token.Value) == 0 {
		traceValidationFailure(t, "token must be supplied")
		errs := field.ErrorList{field.Required(field.NewPath("spec", "token", "value"), "token must be supplied")}
		return nil, apierrors.NewInvalid(placeholderapi.Kind(loginRequest.Kind), loginRequest.Name, errs)
	}

	// just a sanity check, not sure how to honor a dry run on a virtual API
	if options != nil {
		if len(options.DryRun) != 0 {
			traceValidationFailure(t, "dryRun not supported")
			errs := field.ErrorList{field.NotSupported(field.NewPath("dryRun"), options.DryRun, nil)}
			return nil, apierrors.NewInvalid(placeholderapi.Kind(loginRequest.Kind), loginRequest.Name, errs)
		}
	}

	// let dynamic admission webhooks have a chance to validate (but not mutate) as well
	//  TODO Since we are an aggregated API, we should investigate to see if the kube API server is already invoking admission hooks for us.
	//   Even if it is, its okay to call it again here. However, if the kube API server is already calling the webhooks and passing
	//   the token, then there is probably no reason for us to avoid passing the token when we call the webhooks here, since
	//   they already got the token.
	if createValidation != nil {
		requestForValidation := obj.DeepCopyObject()
		loginRequestCopy, _ := requestForValidation.(*placeholderapi.LoginRequest)
		loginRequestCopy.Spec.Token.Value = ""
		if err := createValidation(ctx, requestForValidation); err != nil {
			traceFailureWithError(t, "validation webhook", err)
			return nil, err
		}
	}

	return loginRequest, nil
}

func traceSuccess(t *trace.Trace, user user.Info, webhookAuthenticated bool, placeholderNameAuthenticated bool) {
	userID := "<none>"
	if user != nil {
		userID = user.GetUID()
	}
	t.Step("success",
		trace.Field{Key: "userID", Value: userID},
		trace.Field{Key: "idpAuthenticated", Value: webhookAuthenticated},
		trace.Field{Key: "placeholderNameAuthenticated", Value: placeholderNameAuthenticated},
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

func failureResponse() *placeholderapi.LoginRequest {
	return &placeholderapi.LoginRequest{
		Status: placeholderapi.LoginRequestStatus{
			Credential: nil,
			Message:    "authentication failed",
		},
	}
}
