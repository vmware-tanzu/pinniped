// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
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

	pem, err := r.issuer.IssueClientCertPEM(userInfo.GetName(), userInfo.GetGroups(), clientCertificateTTL)
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

	notBefore := metav1.NewTime(pem.NotBefore)
	notAfter := metav1.NewTime(pem.NotAfter)

	r.auditLogger.Audit(auditevent.TokenCredentialRequestAuthenticatedUser, &plog.AuditParams{
		ReqCtx: ctx,
		PIIKeysAndValues: []any{
			"username", userInfo.GetName(),
			"groups", userInfo.GetGroups(),
		},
		KeysAndValues: []any{
			"issuedClientCert", map[string]string{
				"notBefore": notBefore.Format(time.RFC3339),
				"notAfter":  notAfter.Format(time.RFC3339),
			},
			"authenticator", credentialRequest.Spec.Authenticator,
		},
	})

	return &loginapi.TokenCredentialRequest{
		Status: loginapi.TokenCredentialRequestStatus{
			Credential: &loginapi.ClusterCredential{
				ExpirationTimestamp:   notAfter,
				ClientCertificateData: string(pem.CertPEM),
				ClientKeyData:         string(pem.KeyPEM),
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
	if len(userInfo.GetName()) == 0 {
		return errors.New("empty username is not allowed")
	}

	// certs cannot assert UID
	if len(userInfo.GetUID()) != 0 {
		return errors.New("UIDs are not supported")
	}

	// certs cannot assert extras, but starting in K8s 1.32 the authenticator will always provide this information
	if len(userInfo.GetExtra()) == 0 { // it's ok for this to be empty...
		return nil
	}

	// ... but if it's not empty, should have only exactly this one key.
	if len(userInfo.GetExtra()) > 1 {
		return errors.New("extra may have only one key 'authentication.kubernetes.io/credential-id'")
	}

	_, ok := userInfo.GetExtra()["authentication.kubernetes.io/credential-id"]
	if !ok {
		return errors.New("extra may have only one key 'authentication.kubernetes.io/credential-id'")
	}
	return nil
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
