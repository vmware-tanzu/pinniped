// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package clientsecretrequest provides REST functionality for the CredentialRequest resource.
package clientsecretrequest

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	genericvalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/api/validation/path"
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

// Cost is a good bcrypt cost for 2022, should take about 250 ms to validate.
// This value is expected to be increased over time to match CPU improvements.
const Cost = 12

type byteHasher func(password []byte, cost int) ([]byte, error)
type timeNowFunc func() metav1.Time

func NewREST(
	resource schema.GroupResource,
	secretsClient corev1client.SecretInterface,
	oidcClientsClient configv1alpha1clientset.OIDCClientInterface,
	namespace string,
	cost int,
	randByteGenerator io.Reader,
	byteHasher byteHasher,
	timeNowFunc timeNowFunc,
) *REST {
	return &REST{
		secretStorage:     oidcclientsecretstorage.New(secretsClient),
		oidcClientsClient: oidcClientsClient,
		namespace:         namespace,
		cost:              cost,
		randByteGenerator: randByteGenerator,
		byteHasher:        byteHasher,
		tableConvertor:    rest.NewDefaultTableConvertor(resource),
		timeNowFunc:       timeNowFunc,
	}
}

type REST struct {
	secretStorage     *oidcclientsecretstorage.OIDCClientSecretStorage
	oidcClientsClient configv1alpha1clientset.OIDCClientInterface
	namespace         string
	randByteGenerator io.Reader
	cost              int
	byteHasher        byteHasher
	tableConvertor    rest.TableConvertor
	timeNowFunc       timeNowFunc
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
	rest.TableConvertor
} = (*REST)(nil)

func (*REST) New() runtime.Object {
	return &clientsecretapi.OIDCClientSecretRequest{}
}

func (*REST) Destroy() {}

func (*REST) NewList() runtime.Object {
	return &clientsecretapi.OIDCClientSecretRequestList{}
}

// List implements the list verb. Support the list verb to support `kubectl get pinniped`, to make sure all resources
// are in the pinniped category, and avoid kubectl errors when kubectl lists.
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

func (*REST) GetSingularName() string {
	return "oidcclientsecretrequest"
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	t := trace.FromContext(ctx).Nest("create",
		trace.Field{Key: "kind", Value: "OIDCClientSecretRequest"},
		trace.Field{Key: "metadata.name", Value: name(obj)},
	)
	defer t.Log()

	// Validate the create request before honoring it.
	// This function is provided from kube kube-api server calling validating admission webhooks if there are any registered.
	req, err := r.validateRequest(ctx, obj, createValidation, options, t)
	if err != nil {
		return nil, err
	}
	t.Step("validateRequest")

	// Find the specified OIDCClient.
	oidcClient, err := r.oidcClientsClient.Get(ctx, req.Name, metav1.GetOptions{})
	if err != nil {
		traceFailureWithError(t, "oidcClientsClient.Get", err)
		if apierrors.IsNotFound(err) {
			errs := field.ErrorList{field.NotFound(field.NewPath("metadata", "name"), req.Name)}
			return nil, apierrors.NewInvalid(kindFromContext(ctx), req.Name, errs)
		}
		return nil, apierrors.NewInternalError(fmt.Errorf("getting client %q failed", req.Name))
	}
	t.Step("oidcClientsClient.Get")

	// Using the OIDCClient's UID, check to see if the storage Secret for its client secrets already exists.
	// Note that when it does not exist, this Get() function will not return an error, and will return nil rv and hashes.
	rv, hashes, err := r.secretStorage.Get(ctx, oidcClient.UID)
	if err != nil {
		traceFailureWithError(t, "secretStorage.Get", err)
		return nil, apierrors.NewInternalError(fmt.Errorf("getting secret for client %q failed", req.Name))
	}
	t.Step("secretStorage.Get")

	// If requested, generate a new client secret and add it to the list.
	var secret string
	if req.Spec.GenerateNewSecret {
		secret, err = generateSecret(r.randByteGenerator)
		if err != nil {
			traceFailureWithError(t, "generateSecret", err)
			return nil, apierrors.NewInternalError(fmt.Errorf("client secret generation failed"))
		}
		t.Step("generateSecret")

		hash, err := r.byteHasher([]byte(secret), r.cost)
		if err != nil {
			traceFailureWithError(t, "bcrypt.GenerateFromPassword", err)
			return nil, apierrors.NewInternalError(fmt.Errorf("hash generation failed"))
		}
		t.Step("bcrypt.GenerateFromPassword")

		hashes = slices.Concat([]string{string(hash)}, hashes)
	}

	// If requested, remove all client secrets except for the most recent one.
	needsRevoke := req.Spec.RevokeOldSecrets && len(hashes) > 0
	if needsRevoke {
		hashes = []string{hashes[0]}
	}

	// If anything was requested to change...
	if req.Spec.GenerateNewSecret || needsRevoke {
		// Each bcrypt comparison is expensive, and we do not want a large list to cause wasted CPU.
		if len(hashes) > 5 {
			msg := fmt.Sprintf("OIDCClient %s has too many secrets, spec.revokeOldSecrets must be true", oidcClient.Name)
			traceFailure(t, "secretStorage.Set", msg)
			return nil, apierrors.NewBadRequest(msg)
		}

		// Create or update the storage Secret for client secrets.
		if err := r.secretStorage.Set(ctx, rv, oidcClient.Name, oidcClient.UID, hashes); err != nil {
			if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
				traceFailureWithError(t, "secretStorage.Set", err)
				return nil, apierrors.NewConflict(qualifiedResourceFromContext(ctx), req.Name,
					fmt.Errorf("multiple concurrent secret generation requests for same client"))
			}

			traceFailureWithError(t, "secretStorage.Set", err)
			return nil, apierrors.NewInternalError(fmt.Errorf("setting client secret failed"))
		}
		t.Step("secretStorage.Set")
	}

	// Return the new secret in plaintext, if one was generated, along with the total number of secrets.
	return &clientsecretapi.OIDCClientSecretRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              req.Name,
			Namespace:         req.Namespace,
			CreationTimestamp: r.timeNowFunc(),
		},
		Spec: clientsecretapi.OIDCClientSecretRequestSpec{
			GenerateNewSecret: req.Spec.GenerateNewSecret,
			RevokeOldSecrets:  req.Spec.RevokeOldSecrets,
		},
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
	tracer *trace.Trace,
) (*clientsecretapi.OIDCClientSecretRequest, error) {
	clientSecretRequest, ok := obj.(*clientsecretapi.OIDCClientSecretRequest)
	if !ok {
		traceValidationFailure(tracer, "not an OIDCClientSecretRequest")
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not an OIDCClientSecretRequest: %#v", obj))
	}

	// Ensure namespace on the object is correct, or error if a conflicting namespace was set in the object.
	requestNamespace, ok := genericapirequest.NamespaceFrom(ctx)
	if !ok {
		const errorMsg = "no namespace information found in request context"
		traceValidationFailure(tracer, errorMsg)
		return nil, apierrors.NewInternalError(errors.New(errorMsg))
	}
	if err := rest.EnsureObjectNamespaceMatchesRequestNamespace(requestNamespace, clientSecretRequest); err != nil {
		traceValidationFailure(tracer, err.Error())
		return nil, err
	}
	// Making client secrets outside the supervisor's namespace does not make sense.
	if requestNamespace != r.namespace {
		msg := fmt.Sprintf("namespace must be %s on OIDCClientSecretRequest, was %s", r.namespace, requestNamespace)
		traceValidationFailure(tracer, msg)
		return nil, apierrors.NewBadRequest(msg)
	}

	if errs := genericvalidation.ValidateObjectMetaAccessor(
		clientSecretRequest,
		true,
		func(name string, prefix bool) []string {
			if prefix {
				return []string{"generateName is not supported"}
			}
			var errs []string
			if name == "client.oauth.pinniped.dev-" {
				errs = append(errs, `must not equal 'client.oauth.pinniped.dev-'`)
			}
			if !strings.HasPrefix(name, "client.oauth.pinniped.dev-") {
				errs = append(errs, `must start with 'client.oauth.pinniped.dev-'`)
			}
			return slices.Concat(errs, path.IsValidPathSegmentName(name))
		},
		field.NewPath("metadata"),
	); len(errs) > 0 {
		traceValidationFailure(tracer, errs.ToAggregate().Error())
		return nil, apierrors.NewInvalid(kindFromContext(ctx), clientSecretRequest.Name, errs)
	}

	// just a sanity check, not sure how to honor a dry run on a virtual API
	if options != nil {
		if len(options.DryRun) != 0 {
			traceValidationFailure(tracer, "dryRun not supported")
			errs := field.ErrorList{field.NotSupported(field.NewPath("dryRun"), options.DryRun, []string(nil))}
			return nil, apierrors.NewInvalid(kindFromContext(ctx), clientSecretRequest.Name, errs)
		}
	}

	if createValidation != nil {
		if err := createValidation(ctx, obj.DeepCopyObject()); err != nil {
			traceFailureWithError(tracer, "validation webhook", err)
			return nil, err
		}
	}

	return clientSecretRequest, nil
}

func traceFailure(t *trace.Trace, failureType string, msg string) {
	t.Step("failure",
		trace.Field{Key: "failureType", Value: failureType},
		trace.Field{Key: "msg", Value: msg},
	)
}

func traceValidationFailure(t *trace.Trace, msg string) {
	traceFailure(t, "request validation", msg)
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

func name(obj runtime.Object) string {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return "<unknown>"
	}
	return accessor.GetName()
}

func qualifiedResourceFromContext(ctx context.Context) schema.GroupResource {
	if info, ok := genericapirequest.RequestInfoFrom(ctx); ok {
		return schema.GroupResource{Group: info.APIGroup, Resource: info.Resource}
	}
	// this should never happen in practice
	return clientsecretapi.Resource("oidcclientsecretrequests")
}

func kindFromContext(ctx context.Context) schema.GroupKind {
	if info, ok := genericapirequest.RequestInfoFrom(ctx); ok {
		return schema.GroupKind{Group: info.APIGroup, Kind: "OIDCClientSecretRequest"}
	}
	// this should never happen in practice
	return clientsecretapi.Kind("OIDCClientSecretRequest")
}
