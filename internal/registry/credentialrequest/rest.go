// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package credentialrequest provides REST functionality for the CredentialRequest resource.
package credentialrequest

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
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/utils/trace"

	loginapi "github.com/vmware-tanzu/pinniped/generated/1.19/apis/login"
	pinnipedapi "github.com/vmware-tanzu/pinniped/generated/1.19/apis/pinniped"
)

// clientCertificateTTL is the TTL for short-lived client certificates returned by this API.
const clientCertificateTTL = 1 * time.Hour

type Storage interface {
	rest.Creater
	rest.NamespaceScopedStrategy
	rest.Scoper
	rest.Storage
}

type CertIssuer interface {
	IssuePEM(subject pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, []byte, error)
}

func NewREST(tokenAuthenticator authenticator.Token, issuer CertIssuer) *REST {
	return &REST{
		tokenAuthenticator: tokenAuthenticator,
		issuer:             issuer,
	}
}

type REST struct {
	tokenAuthenticator authenticator.Token
	issuer             CertIssuer
}

// PinnipedV1alpha1Storage returns a wrapper of the REST which serves the pinniped.dev/v1alpha1 API.
func (r *REST) PinnipedV1alpha1Storage() Storage { return &oldAPIREST{r} }

type oldAPIREST struct{ *REST }

func (*oldAPIREST) New() runtime.Object { return &pinnipedapi.CredentialRequest{} }

func (*oldAPIREST) NamespaceScoped() bool { return false }

// LoginV1alpha1Storage returns a wrapper of the REST which serves the login.pinniped.dev/v1alpha1 API.
func (r *REST) LoginV1alpha1Storage() Storage { return &newAPIREST{r} }

type newAPIREST struct{ *REST }

func (*newAPIREST) New() runtime.Object { return &loginapi.TokenCredentialRequest{} }

func (*newAPIREST) NamespaceScoped() bool { return true }

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	t := trace.FromContext(ctx).Nest("create", trace.Field{
		Key:   "kind",
		Value: obj.GetObjectKind().GroupVersionKind().Kind,
	})
	defer t.Log()

	// If the incoming request is from the newer version of the API, convert it into the older API and map the result back later.
	convertResponse := func(in *pinnipedapi.CredentialRequest) runtime.Object { return in }
	if req, ok := obj.(*loginapi.TokenCredentialRequest); ok {
		obj = convertFromLoginAPI(req)
		convertResponse = func(in *pinnipedapi.CredentialRequest) runtime.Object { return convertToLoginAPI(in) }
	}

	credentialRequest, err := validateRequest(ctx, obj, createValidation, options, t)
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

	authResponse, authenticated, err := r.tokenAuthenticator.AuthenticateToken(cancelCtx, credentialRequest.Spec.Token.Value)
	if err != nil {
		traceFailureWithError(t, "webhook authentication", err)
		return convertResponse(failureResponse()), nil
	}
	if !authenticated || authResponse == nil || authResponse.User == nil || authResponse.User.GetName() == "" {
		traceSuccess(t, authResponse, authenticated, false)
		return convertResponse(failureResponse()), nil
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

	traceSuccess(t, authResponse, authenticated, true)

	return convertResponse(&pinnipedapi.CredentialRequest{
		Status: pinnipedapi.CredentialRequestStatus{
			Credential: &pinnipedapi.CredentialRequestCredential{
				ExpirationTimestamp:   metav1.NewTime(time.Now().UTC().Add(clientCertificateTTL)),
				ClientCertificateData: string(certPEM),
				ClientKeyData:         string(keyPEM),
			},
		},
	}), nil
}

func validateRequest(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions, t *trace.Trace) (*pinnipedapi.CredentialRequest, error) {
	credentialRequest, ok := obj.(*pinnipedapi.CredentialRequest)
	if !ok {
		traceValidationFailure(t, "not a CredentialRequest")
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a CredentialRequest: %#v", obj))
	}

	if len(credentialRequest.Spec.Type) == 0 {
		traceValidationFailure(t, "type must be supplied")
		errs := field.ErrorList{field.Required(field.NewPath("spec", "type"), "type must be supplied")}
		return nil, apierrors.NewInvalid(pinnipedapi.Kind(credentialRequest.Kind), credentialRequest.Name, errs)
	}

	if credentialRequest.Spec.Type != pinnipedapi.TokenCredentialType {
		traceValidationFailure(t, "unrecognized type")
		errs := field.ErrorList{field.Invalid(field.NewPath("spec", "type"), credentialRequest.Spec.Type, "unrecognized type")}
		return nil, apierrors.NewInvalid(pinnipedapi.Kind(credentialRequest.Kind), credentialRequest.Name, errs)
	}

	token := credentialRequest.Spec.Token
	if token == nil || len(token.Value) == 0 {
		traceValidationFailure(t, "token must be supplied")
		errs := field.ErrorList{field.Required(field.NewPath("spec", "token", "value"), "token must be supplied")}
		return nil, apierrors.NewInvalid(pinnipedapi.Kind(credentialRequest.Kind), credentialRequest.Name, errs)
	}

	// just a sanity check, not sure how to honor a dry run on a virtual API
	if options != nil {
		if len(options.DryRun) != 0 {
			traceValidationFailure(t, "dryRun not supported")
			errs := field.ErrorList{field.NotSupported(field.NewPath("dryRun"), options.DryRun, nil)}
			return nil, apierrors.NewInvalid(pinnipedapi.Kind(credentialRequest.Kind), credentialRequest.Name, errs)
		}
	}

	// let dynamic admission webhooks have a chance to validate (but not mutate) as well
	//  TODO Since we are an aggregated API, we should investigate to see if the kube API server is already invoking admission hooks for us.
	//   Even if it is, its okay to call it again here. However, if the kube API server is already calling the webhooks and passing
	//   the token, then there is probably no reason for us to avoid passing the token when we call the webhooks here, since
	//   they already got the token.
	if createValidation != nil {
		requestForValidation := obj.DeepCopyObject()
		credentialRequestCopy, _ := requestForValidation.(*pinnipedapi.CredentialRequest)
		credentialRequestCopy.Spec.Token.Value = ""
		if err := createValidation(ctx, requestForValidation); err != nil {
			traceFailureWithError(t, "validation webhook", err)
			return nil, err
		}
	}

	return credentialRequest, nil
}

func traceSuccess(t *trace.Trace, response *authenticator.Response, webhookAuthenticated bool, pinnipedAuthenticated bool) {
	userID := "<none>"
	if response != nil && response.User != nil {
		userID = response.User.GetUID()
	}
	t.Step("success",
		trace.Field{Key: "userID", Value: userID},
		trace.Field{Key: "idpAuthenticated", Value: webhookAuthenticated},
		trace.Field{Key: "pinnipedAuthenticated", Value: pinnipedAuthenticated},
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

func failureResponse() *pinnipedapi.CredentialRequest {
	m := "authentication failed"
	return &pinnipedapi.CredentialRequest{
		Status: pinnipedapi.CredentialRequestStatus{
			Credential: nil,
			Message:    &m,
		},
	}
}
