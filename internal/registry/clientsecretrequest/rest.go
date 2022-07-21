// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package clientsecretrequest provides REST functionality for the CredentialRequest resource.
package clientsecretrequest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/trace"

	clientsecretapi "go.pinniped.dev/generated/latest/apis/supervisor/clientsecret"
	configv1alpha1clientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/config/v1alpha1"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
)

// cost is a good bcrypt cost for 2022, should take about 250 ms to validate
// this value is expected to be increased over time to match CPU improvements
// thus it must be kept private because validation of client secrets cannot rely
// on a cost that changes without some form client secret storage migration
// TODO write a unit test that fails in 2023 to ask this to be updated to latest recommendation
const cost = 12

func NewREST(resource schema.GroupResource, secrets corev1client.SecretInterface, clients configv1alpha1clientset.OIDCClientInterface, namespace string) *REST {
	return &REST{
		tableConvertor: rest.NewDefaultTableConvertor(resource),
		secretStorage:  oidcclientsecretstorage.New(secrets),
		clients:        clients,
		namespace:      namespace,
		rand:           rand.Reader,
	}
}

type REST struct {
	tableConvertor rest.TableConvertor
	secretStorage  *oidcclientsecretstorage.OIDCClientSecretStorage
	clients        configv1alpha1clientset.OIDCClientInterface
	namespace      string
	rand           io.Reader
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

func (*REST) NewList() runtime.Object {
	return &clientsecretapi.OIDCClientSecretRequestList{}
}

// support `kubectl get pinniped`
// to make sure all resources are in the pinniped category and
// avoid kubectl errors when kubectl lists you must support the list verb
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

	req, err := r.validateRequest(ctx, obj, createValidation, options, t)
	if err != nil {
		return nil, err
	}
	t.Step("validateRequest")

	oidcClient, err := r.clients.Get(ctx, req.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err // TODO obfuscate
	}
	t.Step("clients.Get")

	rv, hashes, err := r.secretStorage.Get(ctx, oidcClient.UID)
	if err != nil {
		return nil, err // TODO obfuscate
	}
	t.Step("secretStorage.Get")

	var secret string
	if req.Spec.GenerateNewSecret {
		secret, err = generateSecret(r.rand)
		if err != nil {
			return nil, err // TODO obfuscate
		}
		t.Step("generateSecret")

		hash, err := bcrypt.GenerateFromPassword([]byte(secret), cost)
		if err != nil {
			return nil, err // TODO obfuscate
		}
		t.Step("bcrypt.GenerateFromPassword")

		hashes = append([]string{string(hash)}, hashes...)
	}

	needsRevoke := req.Spec.RevokeOldSecrets && len(hashes) > 0
	if needsRevoke {
		hashes = []string{hashes[0]}
	}

	if req.Spec.GenerateNewSecret || needsRevoke {
		// each bcrypt comparison is expensive and we do not want a large list to cause wasted CPU
		if len(hashes) > 5 {
			return nil, apierrors.NewRequestEntityTooLargeError(fmt.Sprintf("OIDCClient %s has too many secrets, spec.revokeOldSecrets must be true", oidcClient.Name))
		}

		if err := r.secretStorage.Set(ctx, rv, oidcClient.Name, oidcClient.UID, hashes); err != nil {
			return nil, err // TODO obfuscate, also return good errors for cases like when the secret now exists but previously did not
		}
		t.Step("secretStorage.Set")
	}

	return &clientsecretapi.OIDCClientSecretRequest{
		Status: clientsecretapi.OIDCClientSecretRequestStatus{
			GeneratedSecret:    secret,
			TotalClientSecrets: len(hashes),
		},
	}, nil
}

func (r *REST) validateRequest(
	ctx context.Context,
	obj runtime.Object,
	createValidation rest.ValidateObjectFunc,
	options *metav1.CreateOptions,
	t *trace.Trace,
) (*clientsecretapi.OIDCClientSecretRequest, error) {
	clientSecretRequest, ok := obj.(*clientsecretapi.OIDCClientSecretRequest)
	if !ok {
		traceValidationFailure(t, "not an OIDCClientSecretRequest")
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not an OIDCClientSecretRequest: %#v", obj))
	}

	// just a sanity check, not sure how to honor a dry run on a virtual API
	if options != nil {
		if len(options.DryRun) != 0 {
			traceValidationFailure(t, "dryRun not supported")
			errs := field.ErrorList{field.NotSupported(field.NewPath("dryRun"), options.DryRun, nil)}
			return nil, apierrors.NewInvalid(clientsecretapi.Kind(clientSecretRequest.Kind), clientSecretRequest.Name, errs)
		}
	}

	if namespace := genericapirequest.NamespaceValue(ctx); namespace != r.namespace {
		msg := fmt.Sprintf("namespace must be %s on OIDCClientSecretRequest, was %s", r.namespace, namespace)
		traceValidationFailure(t, msg)
		return nil, apierrors.NewBadRequest(msg)
	}

	if createValidation != nil {
		if err := createValidation(ctx, obj.DeepCopyObject()); err != nil {
			traceFailureWithError(t, "validation webhook", err)
			return nil, err
		}
	}

	return clientSecretRequest, nil
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

func generateSecret(rand io.Reader) (string, error) {
	var buf [32]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return "", fmt.Errorf("could not generate client secret: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}
