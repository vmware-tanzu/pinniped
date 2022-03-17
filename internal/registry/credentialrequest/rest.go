// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package credentialrequest provides REST functionality for the CredentialRequest resource.
package credentialrequest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate/csr"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/utils/trace"

	loginapi "go.pinniped.dev/generated/latest/apis/concierge/login"
	"go.pinniped.dev/internal/issuer"
)

// clientCertificateTTL is the TTL for short-lived client certificates returned by this API.
const clientCertificateTTL = 5 * time.Minute

type TokenCredentialRequestAuthenticator interface {
	AuthenticateTokenCredentialRequest(ctx context.Context, req *loginapi.TokenCredentialRequest) (user.Info, error)
}

func NewREST(authenticator TokenCredentialRequestAuthenticator, issuer issuer.ClientCertIssuer, kubeClientWithoutLeaderElection kubernetes.Interface, resource schema.GroupResource) *REST {
	return &REST{
		authenticator:                   authenticator,
		issuer:                          issuer,
		tableConvertor:                  rest.NewDefaultTableConvertor(resource),
		kubeClientWithoutLeaderElection: kubeClientWithoutLeaderElection,
	}
}

type REST struct {
	authenticator                   TokenCredentialRequestAuthenticator
	issuer                          issuer.ClientCertIssuer
	tableConvertor                  rest.TableConvertor
	kubeClientWithoutLeaderElection kubernetes.Interface
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
	return &loginapi.TokenCredentialRequest{}
}

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

	// By commenting out this code for the spike, we prevent the usual kube cert agent and impersonation proxy
	// strategies from getting involved in creating client certs. Instead, we will use the Kube CSR APIs below.
	//// this timestamp should be returned from IssueClientCertPEM but this is a safe approximation
	//expires := metav1.NewTime(time.Now().UTC().Add(clientCertificateTTL))
	//certPEM, keyPEM, err := r.issuer.IssueClientCertPEM(userInfo.GetName(), userInfo.GetGroups(), clientCertificateTTL)
	//if err != nil {
	//	traceFailureWithError(t, "cert issuer", err)
	//	return failureResponse(), nil
	//}

	expires, certPEM, keyPEM, err := getCertFromCSR(ctx, r.kubeClientWithoutLeaderElection, userInfo)
	if err != nil {
		return nil, apierrors.NewInternalError(err) // TODO better error handling, but this is good enough for a spike
	}

	traceSuccess(t, userInfo, true)

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

func getCertFromCSR(
	ctx context.Context,
	kubeClient kubernetes.Interface,
	userInfo user.Info,
) (expires metav1.Time, certPEM []byte, keyPEM []byte, err error) {
	// Make a private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return metav1.Time{}, nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return metav1.Time{}, nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: keyutil.ECPrivateKeyBlockType, Bytes: der})

	// Make a CSR.
	csrPEM, err := cert.MakeCSR(privateKey, &pkix.Name{
		CommonName:   userInfo.GetName(),
		Organization: userInfo.GetGroups(),
	}, nil, nil)
	if err != nil {
		return metav1.Time{}, nil, nil, err
	}

	// Docs say that 600 seconds is the smallest allowed duration.
	// This should result in a cert which is valid from 5 minutes ago
	// until 10 minutes in the future.
	minimumAllowedDuration := time.Second * 600

	// Use the CSR API to request a client cert for the API server.
	csrName, csrUID, err := csr.RequestCertificate(
		kubeClient,
		csrPEM,
		"", // empty means auto-generate a random name
		certificatesv1.KubeAPIServerClientSignerName,
		&minimumAllowedDuration,
		[]certificatesv1.KeyUsage{certificatesv1.UsageClientAuth},
		privateKey,
	)
	if err != nil {
		return metav1.Time{}, nil, nil, err
	}

	// These CSRs are not auto-approved, so approve our own request.
	_, err = kubeClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csrName, &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
		},
		Status: certificatesv1.CertificateSigningRequestStatus{
			Conditions: []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
					Reason: "TokenCredentialRequest",
				},
			},
		},
	}, metav1.UpdateOptions{})
	if err != nil {
		return metav1.Time{}, nil, nil, err
	}

	// Wait for the cert to be issued by the signer, or error after a reasonably long timeout.
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 90*time.Second)
	defer cancelFunc()
	certPEM, err = csr.WaitForCertificate(timeoutCtx, kubeClient, csrName, csrUID)
	if err != nil {
		return metav1.Time{}, nil, nil, err
	}

	// This feels awkward to need to decode the cert to find out when it expires,
	// but the CSR API only returns the encoded cert. It might be nice if it also
	// returned the cert's expiration time as a separate field?
	decodedCertPEMBlock, _ := pem.Decode(certPEM)
	parsedCertPEM, err := x509.ParseCertificate(decodedCertPEMBlock.Bytes)
	if err != nil {
		return metav1.Time{}, nil, nil, err
	}
	// TODO maybe return an error unless the signer honored our 600 second duration request
	expires = metav1.NewTime(parsedCertPEM.NotAfter)

	return expires, certPEM, keyPEM, nil
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
			errs := field.ErrorList{field.NotSupported(field.NewPath("dryRun"), options.DryRun, nil)}
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
