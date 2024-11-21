// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package credentialrequest provides REST functionality for the CredentialRequest resource.
package credentialrequest

import (
	"context"
	"crypto/sha256"
	"errors"
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
	"k8s.io/utils/clock"

	loginapi "go.pinniped.dev/generated/latest/apis/concierge/login"
	"go.pinniped.dev/internal/auditevent"
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
	clock clock.Clock,
) *REST {
	return &REST{
		authenticator:  authenticator,
		issuer:         issuer,
		tableConvertor: rest.NewDefaultTableConvertor(resource),
		auditLogger:    auditLogger,
		clock:          clock,
	}
}

type REST struct {
	authenticator  TokenCredentialRequestAuthenticator
	issuer         clientcertissuer.ClientCertIssuer
	tableConvertor rest.TableConvertor
	auditLogger    plog.AuditLogger
	clock          clock.Clock
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
	credentialRequest, err := validateRequest(ctx, obj, createValidation, options)
	if err != nil {
		// Bad requests are not audit logged because the Kubernetes audit log will show the response's status error code.
		plog.DebugErr("TokenCredentialRequest request object validation error", err)
		return nil, err
	}

	// Allow cross-referencing the token with the Supervisor's audit logs.
	r.auditLogger.Audit(auditevent.TokenCredentialRequestTokenReceived, &plog.AuditParams{
		ReqCtx: ctx,
		KeysAndValues: []any{
			"tokenID", fmt.Sprintf("%x", sha256.Sum256([]byte(credentialRequest.Spec.Token))),
		},
	})

	userInfo, err := r.authenticator.AuthenticateTokenCredentialRequest(ctx, credentialRequest)
	if err != nil {
		r.auditLogger.Audit(auditevent.TokenCredentialRequestUnexpectedError, &plog.AuditParams{
			ReqCtx: ctx,
			KeysAndValues: []any{
				"reason", "authenticator returned an error",
				"err", err.Error(),
				"authenticator", credentialRequest.Spec.Authenticator,
			},
		})
		return authenticationFailedResponse(), nil
	}

	if userInfo == nil {
		r.auditLogger.Audit(auditevent.TokenCredentialRequestAuthenticationFailed, &plog.AuditParams{
			ReqCtx: ctx,
			KeysAndValues: []any{
				"reason", "auth rejected by authenticator",
				"authenticator", credentialRequest.Spec.Authenticator,
			},
		})
		return authenticationFailedResponse(), nil
	}

	if err = validateUserInfo(userInfo); err != nil {
		r.auditLogger.Audit(auditevent.TokenCredentialRequestUnsupportedUserInfo, &plog.AuditParams{
			ReqCtx: ctx,
			PIIKeysAndValues: []any{
				"userInfoName", userInfo.GetName(),
				"userInfoUID", userInfo.GetUID(),
			},
			KeysAndValues: []any{
				"userInfoExtrasCount", len(userInfo.GetExtra()),
				"reason", "unsupported value in userInfo returned by authenticator",
				"err", err.Error(),
				"authenticator", credentialRequest.Spec.Authenticator,
			},
		})
		return authenticationFailedResponse(), nil
	}

	// this timestamp should be returned from IssueClientCertPEM but this is a safe approximation
	expires := metav1.NewTime(r.clock.Now().UTC().Add(clientCertificateTTL))
	certPEM, keyPEM, err := r.issuer.IssueClientCertPEM(userInfo.GetName(), userInfo.GetGroups(), clientCertificateTTL)
	if err != nil {
		r.auditLogger.Audit(auditevent.TokenCredentialRequestUnexpectedError, &plog.AuditParams{
			ReqCtx: ctx,
			KeysAndValues: []any{
				"reason", "cert issuer returned an error",
				"err", err.Error(),
				"authenticator", credentialRequest.Spec.Authenticator,
			},
		})
		return authenticationFailedResponse(), nil
	}

	r.auditLogger.Audit(auditevent.TokenCredentialRequestAuthenticatedUser, &plog.AuditParams{
		ReqCtx: ctx,
		PIIKeysAndValues: []any{
			"username", userInfo.GetName(),
			"groups", userInfo.GetGroups(),
		},
		KeysAndValues: []any{
			"issuedClientCertExpires", expires.Format(time.RFC3339),
			"authenticator", credentialRequest.Spec.Authenticator,
		},
	})

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

func validateRequest(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (*loginapi.TokenCredentialRequest, error) {
	credentialRequest, ok := obj.(*loginapi.TokenCredentialRequest)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a TokenCredentialRequest: %#v", obj))
	}

	if len(credentialRequest.Spec.Token) == 0 {
		errs := field.ErrorList{field.Required(field.NewPath("spec", "token", "value"), "token must be supplied")}
		return nil, apierrors.NewInvalid(loginapi.Kind(credentialRequest.Kind), credentialRequest.Name, errs)
	}

	// just a sanity check, not sure how to honor a dry run on a virtual API
	if options != nil {
		if len(options.DryRun) != 0 {
			errs := field.ErrorList{field.NotSupported(field.NewPath("dryRun"), options.DryRun, []string(nil))}
			return nil, apierrors.NewInvalid(loginapi.Kind(credentialRequest.Kind), credentialRequest.Name, errs)
		}
	}

	if namespace := genericapirequest.NamespaceValue(ctx); len(namespace) != 0 {
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
			return nil, err
		}
	}

	return credentialRequest, nil
}

func validateUserInfo(userInfo user.Info) error {
	switch {
	case len(userInfo.GetName()) == 0:
		return errors.New("empty username is not allowed")
	case len(userInfo.GetUID()) != 0:
		return errors.New("UIDs are not supported") // certs cannot assert UID
	case len(userInfo.GetExtra()) != 0:
		return errors.New("extras are not supported") // certs cannot assert extra
	default:
		return nil
	}
}

func authenticationFailedResponse() *loginapi.TokenCredentialRequest {
	m := "authentication failed"
	return &loginapi.TokenCredentialRequest{
		Status: loginapi.TokenCredentialRequestStatus{
			Credential: nil,
			Message:    &m,
		},
	}
}
