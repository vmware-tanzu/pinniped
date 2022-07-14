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
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/utils/trace"

	clientsecretapi "go.pinniped.dev/generated/latest/apis/supervisor/clientsecret"
	configv1alpha1clientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/config/v1alpha1"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
)

const cost = 15 // a good bcrypt cost for 2022, should take about a second to validate

func NewREST(resource schema.GroupResource, client *kubeclient.Client, namespace string) *REST {
	return &REST{
		tableConvertor: rest.NewDefaultTableConvertor(resource),
		secretStorage:  oidcclientsecretstorage.New(client.Kubernetes.CoreV1().Secrets(namespace)),
		clients:        client.PinnipedSupervisor.ConfigV1alpha1().OIDCClients(namespace),
		rand:           rand.Reader,
	}
}

type REST struct {
	tableConvertor rest.TableConvertor
	secretStorage  *oidcclientsecretstorage.OIDCClientSecretStorage
	clients        configv1alpha1clientset.OIDCClientInterface
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

	req, err := validateRequest(obj, t)
	if err != nil {
		return nil, err
	}

	oidcClient, err := r.clients.Get(ctx, req.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err // TODO obfuscate
	}

	hashes, err := r.secretStorage.Get(ctx, oidcClient.UID)
	if err != nil {
		return nil, err // TODO obfuscate
	}

	var secret string
	if req.Spec.GenerateNewSecret {
		secret, err = generateSecret(r.rand)
		if err != nil {
			return nil, err // TODO obfuscate
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(secret), cost)
		if err != nil {
			return nil, err // TODO obfuscate
		}

		hashes = append([]string{string(hash)}, hashes...)

		err = r.secretStorage.Set(ctx, oidcClient.Name, oidcClient.UID, hashes)
		if err != nil {
			return nil, err // TODO obfuscate
		}
	}

	if req.Spec.RevokeOldSecrets && len(hashes) > 0 {
		hashes = []string{hashes[0]}
	}

	// do not let them have more than 100? secrets

	return &clientsecretapi.OIDCClientSecretRequest{
		Status: clientsecretapi.OIDCClientSecretRequestStatus{
			GeneratedSecret:    secret,
			TotalClientSecrets: len(hashes), // TODO what about validation of hashes??
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

func generateSecret(rand io.Reader) (string, error) {
	var buf [32]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return "", fmt.Errorf("could not generate client secret: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}
