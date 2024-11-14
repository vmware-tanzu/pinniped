// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clientsecretrequest

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/audit"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	kubefake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/klog/v2"

	clientsecretapi "go.pinniped.dev/generated/latest/apis/supervisor/clientsecret"
	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
)

func TestNew(t *testing.T) {
	r := NewREST(
		schema.GroupResource{Group: "bears", Resource: "panda"},
		nil,
		nil,
		"foobar",
		4,
		nil,
		nil,
		nil,
		nil,
	)

	require.NotNil(t, r)
	require.True(t, r.NamespaceScoped())
	require.Equal(t, []string{"pinniped"}, r.Categories())
	require.Equal(t, "oidcclientsecretrequest", r.GetSingularName())

	require.IsType(t, &clientsecretapi.OIDCClientSecretRequest{}, r.New())
	require.IsType(t, &clientsecretapi.OIDCClientSecretRequestList{}, r.NewList())

	ctx := context.Background()

	// check the simple invariants of our no-op list
	list, err := r.List(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, list)
	require.IsType(t, &clientsecretapi.OIDCClientSecretRequestList{}, list)
	require.Equal(t, "0", list.(*clientsecretapi.OIDCClientSecretRequestList).ResourceVersion)
	require.NotNil(t, list.(*clientsecretapi.OIDCClientSecretRequestList).Items)
	require.Len(t, list.(*clientsecretapi.OIDCClientSecretRequestList).Items, 0)

	// make sure we can turn lists into tables if needed
	table, err := r.ConvertToTable(ctx, list, nil)
	require.NoError(t, err)
	require.NotNil(t, table)
	require.Equal(t, "0", table.ResourceVersion)
	require.Nil(t, table.Rows)

	// exercise group resource - force error by passing a runtime.Object that does not have an embedded object meta
	_, err = r.ConvertToTable(ctx, &metav1.APIGroup{}, nil)
	require.Error(t, err, "the resource panda.bears does not support being converted to a Table")
}

func TestCreate(t *testing.T) {
	type wantHashes struct {
		UID    string
		hashes []string
	}
	type args struct {
		ctx              context.Context
		obj              runtime.Object
		createValidation rest.ValidateObjectFunc
		options          *metav1.CreateOptions
	}
	namespace := "some-namespace"
	namespacedContext := genericapirequest.WithNamespace(
		genericapirequest.WithRequestInfo(
			genericapirequest.NewContext(),
			&genericapirequest.RequestInfo{
				APIGroup:   "clientsecret.supervisor.pinniped.dev",
				APIVersion: "v1alpha1",
				Resource:   "oidcclientsecretrequests",
			},
		),
		namespace,
	)

	fakeRandomBytes := "0123456789abcdefghijklmnopqrstuv"
	fakeHexEncodedRandomBytes := hex.EncodeToString([]byte(fakeRandomBytes))
	fakeBcryptRandomBytes := fakeHexEncodedRandomBytes + ":4-fake-hash"

	fakeNow := metav1.Now()
	fakeTimeNowFunc := func() metav1.Time { return fakeNow }

	tests := []struct {
		name                  string
		args                  args
		seedOIDCClients       []*supervisorconfigv1alpha1.OIDCClient
		seedHashes            func(storage *oidcclientsecretstorage.OIDCClientSecretStorage)
		addReactors           func(*kubefake.Clientset, *supervisorfake.Clientset)
		fakeByteGenerator     io.Reader
		fakeHasher            byteHasher
		want                  runtime.Object
		wantErrStatus         *metav1.Status
		wantHashes            *wantHashes
		wantLogStepSubstrings []string
		wantAuditLog          []testutil.WantedAuditLog
	}{
		{
			name: "wrong type of request object provided",
			args: args{
				ctx: namespacedContext,
				obj: &metav1.Status{},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status: metav1.StatusFailure,
				Message: `not an OIDCClientSecretRequest: &v1.Status{TypeMeta:v1.TypeMeta{Kind:"", APIVersion:""}, ` +
					`ListMeta:v1.ListMeta{SelfLink:"", ResourceVersion:"", Continue:"", RemainingItemCount:(*int64)(nil)},` +
					` Status:"", Message:"", Reason:"", Details:(*v1.StatusDetails)(nil), Code:0}`,
				Reason: metav1.StatusReasonBadRequest,
				Code:   http.StatusBadRequest,
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:request validation,msg:not an OIDCClientSecretRequest`,
				`END`,
			},
		},
		{
			name: "bad options for dry run",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client-name",
					},
				},
				options: &metav1.CreateOptions{DryRun: []string{"stuff"}},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status: metav1.StatusFailure,
				Message: `OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev "client.oauth.pinniped.dev-some-client-name" ` +
					`is invalid: dryRun: Unsupported value: []string{"stuff"}`,
				Reason: metav1.StatusReasonInvalid,
				Code:   http.StatusUnprocessableEntity,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "OIDCClientSecretRequest",
					Name:  "client.oauth.pinniped.dev-some-client-name",
					Causes: []metav1.StatusCause{{
						Type:    "FieldValueNotSupported",
						Message: "Unsupported value: []string{\"stuff\"}",
						Field:   "dryRun",
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:request validation,msg:dryRun not supported`,
				`END`,
			},
		},
		{
			name: "incorrect namespace on request context",
			args: args{
				ctx: genericapirequest.WithNamespace(genericapirequest.NewContext(), "wrong-namespace"),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client-name",
					},
				},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: `namespace must be some-namespace on OIDCClientSecretRequest, was wrong-namespace`,
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:request validation,msg:namespace must be some-namespace on OIDCClientSecretRequest, was wrong-namespace`,
				`END`,
			},
		},
		{
			name: "create validation: failure from kube api-server rest.ValidateObjectFunc",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client-name",
					},
				},
				createValidation: func(ctx context.Context, obj runtime.Object) error {
					return apierrors.NewInternalError(errors.New("some-error-here"))
				},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: "Internal error occurred: some-error-here",
				Reason:  metav1.StatusReasonInternalError,
				Code:    http.StatusInternalServerError,
				Details: &metav1.StatusDetails{
					Causes: []metav1.StatusCause{{
						Message: "some-error-here",
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:validation webhook,msg:Internal error occurred: some-error-here`,
				`END`,
			},
		},
		{
			name: "create validation: no namespace on the request context",
			args: args{
				ctx: genericapirequest.NewContext(),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client-name",
					},
				},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: "Internal error occurred: no namespace information found in request context",
				Reason:  metav1.StatusReasonInternalError,
				Code:    http.StatusInternalServerError,
				Details: &metav1.StatusDetails{
					Causes: []metav1.StatusCause{{
						Message: "no namespace information found in request context",
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:request validation,msg:no namespace information found in request context`,
				`END`,
			},
		},
		{
			name: "create validation: namespace on object does not match namespace on request",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "client.oauth.pinniped.dev-some-client-name",
						Namespace: "not-a-matching-namespace",
					},
				},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: "the namespace of the provided object does not match the namespace sent on the request",
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:request validation,msg:the namespace of the provided object does not match the namespace sent on the request`,
				`END`,
			},
		},
		{
			name: "create validation: generateName is unsupported",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName: "foo",
					},
				},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status: metav1.StatusFailure,
				Message: `OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev "" is invalid: [metadata.generateName: ` +
					`Invalid value: "foo": generateName is not supported, metadata.name: Required value: name or generateName is required]`,
				Reason: metav1.StatusReasonInvalid,
				Code:   http.StatusUnprocessableEntity,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "OIDCClientSecretRequest",
					Name:  "",
					Causes: []metav1.StatusCause{{
						Type:    metav1.CauseTypeFieldValueInvalid,
						Message: `Invalid value: "foo": generateName is not supported`,
						Field:   "metadata.generateName",
					}, {
						Type:    metav1.CauseTypeFieldValueRequired,
						Message: "Required value: name or generateName is required",
						Field:   "metadata.name",
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:request validation,msg:[metadata.generateName: Invalid value: "foo": generateName is not supported, metadata.name: Required value: name or generateName is required]`,
				`END`,
			},
		},
		{
			name: "create validation: name cannot exactly match client.oauth.pinniped.dev-",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-",
					},
				},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status: metav1.StatusFailure,
				Message: `OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev "client.oauth.pinniped.dev-" is invalid: ` +
					`metadata.name: Invalid value: "client.oauth.pinniped.dev-": must not equal 'client.oauth.pinniped.dev-'`,
				Reason: metav1.StatusReasonInvalid,
				Code:   http.StatusUnprocessableEntity,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "OIDCClientSecretRequest",
					Name:  "client.oauth.pinniped.dev-",
					Causes: []metav1.StatusCause{{
						Type:    metav1.CauseTypeFieldValueInvalid,
						Message: `Invalid value: "client.oauth.pinniped.dev-": must not equal 'client.oauth.pinniped.dev-'`,
						Field:   "metadata.name",
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:request validation,msg:metadata.name: Invalid value: "client.oauth.pinniped.dev-": must not equal 'client.oauth.pinniped.dev-'`,
				`END`,
			},
		},
		{
			name: "create validation: name must contain prefix client.oauth.pinniped.dev-",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "does-not-contain-the-prefix",
					},
				},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status: metav1.StatusFailure,
				Message: `OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev "does-not-contain-the-prefix" is invalid: ` +
					`metadata.name: Invalid value: "does-not-contain-the-prefix": must start with 'client.oauth.pinniped.dev-'`,
				Reason: metav1.StatusReasonInvalid,
				Code:   http.StatusUnprocessableEntity,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "OIDCClientSecretRequest",
					Name:  "does-not-contain-the-prefix",
					Causes: []metav1.StatusCause{{
						Type:    metav1.CauseTypeFieldValueInvalid,
						Message: `Invalid value: "does-not-contain-the-prefix": must start with 'client.oauth.pinniped.dev-'`,
						Field:   "metadata.name",
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:request validation,msg:metadata.name: Invalid value: "does-not-contain-the-prefix": must start with 'client.oauth.pinniped.dev-'`,
				`END`,
			},
		},
		{
			name: "create validation: name with invalid characters should error",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-contains/invalid/characters",
					},
				},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status: metav1.StatusFailure,
				Message: `OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev "client.oauth.pinniped.dev-contains/invalid/characters" ` +
					`is invalid: metadata.name: Invalid value: "client.oauth.pinniped.dev-contains/invalid/characters": may not contain '/'`,
				Reason: metav1.StatusReasonInvalid,
				Code:   http.StatusUnprocessableEntity,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "OIDCClientSecretRequest",
					Name:  "client.oauth.pinniped.dev-contains/invalid/characters",
					Causes: []metav1.StatusCause{{
						Type:    metav1.CauseTypeFieldValueInvalid,
						Message: `Invalid value: "client.oauth.pinniped.dev-contains/invalid/characters": may not contain '/'`,
						Field:   "metadata.name",
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:request validation,msg:metadata.name: Invalid value: "client.oauth.pinniped.dev-contains/invalid/characters": may not contain '/'`,
				`END`,
			},
		},
		{
			name: "create validation: name validation may return multiple errors",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:         "multiple/errors/aggregated",
						GenerateName: "no-generate-allowed",
					},
				},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status: metav1.StatusFailure,
				Message: `OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev "multiple/errors/aggregated" is invalid: [metadata.generateName: ` +
					`Invalid value: "no-generate-allowed": generateName is not supported, metadata.name: ` +
					`Invalid value: "multiple/errors/aggregated": must start with 'client.oauth.pinniped.dev-', metadata.name: ` +
					`Invalid value: "multiple/errors/aggregated": may not contain '/']`,
				Reason: metav1.StatusReasonInvalid,
				Code:   http.StatusUnprocessableEntity,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "OIDCClientSecretRequest",
					Name:  "multiple/errors/aggregated",
					Causes: []metav1.StatusCause{{
						Type:    metav1.CauseTypeFieldValueInvalid,
						Message: `Invalid value: "no-generate-allowed": generateName is not supported`,
						Field:   "metadata.generateName",
					}, {
						Type:    metav1.CauseTypeFieldValueInvalid,
						Message: `Invalid value: "multiple/errors/aggregated": must start with 'client.oauth.pinniped.dev-'`,
						Field:   "metadata.name",
					}, {
						Type:    metav1.CauseTypeFieldValueInvalid,
						Message: `Invalid value: "multiple/errors/aggregated": may not contain '/'`,
						Field:   "metadata.name",
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`failureType:request validation,msg:[metadata.generateName: Invalid value: "no-generate-allowed": generateName is not supported, metadata.name: Invalid value: "multiple/errors/aggregated": must start with 'client.oauth.pinniped.dev-', metadata.name: Invalid value: "multiple/errors/aggregated": may not contain '/']`,
				`END`,
			},
		},
		{
			name: "oidcClient does not exist 404",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-oidc-client-does-not-exist-404",
					},
				},
			},
			want: nil,
			wantErrStatus: &metav1.Status{
				Status: metav1.StatusFailure,
				Message: `OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev "client.oauth.pinniped.dev-oidc-client-does-not-exist-404" ` +
					`is invalid: metadata.name: Not found: "client.oauth.pinniped.dev-oidc-client-does-not-exist-404"`,
				Reason: metav1.StatusReasonInvalid,
				Code:   http.StatusUnprocessableEntity,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "OIDCClientSecretRequest",
					Name:  "client.oauth.pinniped.dev-oidc-client-does-not-exist-404",
					Causes: []metav1.StatusCause{{
						Type:    metav1.CauseTypeFieldValueNotFound,
						Message: `Not found: "client.oauth.pinniped.dev-oidc-client-does-not-exist-404"`,
						Field:   "metadata.name",
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`failureType:oidcClientsClient.Get,msg:oidcclients.config.supervisor.pinniped.dev "client.oauth.pinniped.dev-oidc-client-does-not-exist-404" not found`,
				`END`,
			},
		},
		{
			name: "unexpected error getting oidcClient 500",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-internal-error-could-not-get-client",
					},
				},
			},
			addReactors: func(kubeClient *kubefake.Clientset, supervisorClient *supervisorfake.Clientset) {
				supervisorClient.PrependReactor("get", "oidcclients", func(action coretesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("unexpected error darn")
				})
			},
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Code:    http.StatusInternalServerError,
				Reason:  metav1.StatusReasonInternalError,
				Message: `Internal error occurred: getting client "client.oauth.pinniped.dev-internal-error-could-not-get-client" failed`,
				Details: &metav1.StatusDetails{
					Causes: []metav1.StatusCause{{
						Message: `getting client "client.oauth.pinniped.dev-internal-error-could-not-get-client" failed`,
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`failureType:oidcClientsClient.Get,msg:unexpected error darn`,
				`END`,
			},
		},
		{
			name: "failed to get kube secret for oidcClient",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-no-secret-for-oidcclient",
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-no-secret-for-oidcclient",
					Namespace: namespace,
				},
			}},
			addReactors: func(kubeClient *kubefake.Clientset, supervisorClient *supervisorfake.Clientset) {
				kubeClient.PrependReactor("get", "secrets", func(action coretesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("sadly no secrets")
				})
			},
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Code:    http.StatusInternalServerError,
				Reason:  metav1.StatusReasonInternalError,
				Message: `Internal error occurred: getting secret for client "client.oauth.pinniped.dev-no-secret-for-oidcclient" failed`,
				Details: &metav1.StatusDetails{
					Causes: []metav1.StatusCause{{
						Message: `getting secret for client "client.oauth.pinniped.dev-no-secret-for-oidcclient" failed`,
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`failureType:secretStorage.Get,msg:failed to get client secret for uid : failed to get oidc-client-secret for signature : sadly no secrets`,
				`END`,
			},
		},
		{
			name: "failed to generate new client secret for oidcClient",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-fail-to-generate-secret",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  false,
					},
				},
			},
			fakeByteGenerator: readerAlwaysErrors{},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-fail-to-generate-secret",
					Namespace: namespace,
				},
			}},
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Code:    http.StatusInternalServerError,
				Reason:  metav1.StatusReasonInternalError,
				Message: `Internal error occurred: client secret generation failed`,
				Details: &metav1.StatusDetails{
					Causes: []metav1.StatusCause{{
						Message: `client secret generation failed`,
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`failureType:generateSecret,msg:could not generate client secret: always errors`,
				`END`,
			},
		},
		{
			name: "failed to generate hash for new client secret for oidcClient",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-fail-to-hash-secret",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  false,
					},
				},
			},
			fakeHasher: func(password []byte, cost int) ([]byte, error) {
				return nil, errors.New("can't hash stuff")
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-fail-to-hash-secret",
					Namespace: namespace,
				},
			}},
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Code:    http.StatusInternalServerError,
				Reason:  metav1.StatusReasonInternalError,
				Message: `Internal error occurred: hash generation failed`,
				Details: &metav1.StatusDetails{
					Causes: []metav1.StatusCause{{
						Message: `hash generation failed`,
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`failureType:bcrypt.GenerateFromPassword,msg:can't hash stuff`,
				`END`,
			},
		},
		{
			name: "happy path: no secrets exist, create secret and hash for found oidcclient",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-happy-new-secret",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  false,
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-happy-new-secret",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			want: &clientsecretapi.OIDCClientSecretRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "client.oauth.pinniped.dev-happy-new-secret",
					Namespace:         namespace,
					CreationTimestamp: fakeNow,
				},
				Spec: clientsecretapi.OIDCClientSecretRequestSpec{
					GenerateNewSecret: true,
					RevokeOldSecrets:  false,
				},
				Status: clientsecretapi.OIDCClientSecretRequestStatus{
					GeneratedSecret:    fakeHexEncodedRandomBytes,
					TotalClientSecrets: 1,
				},
			},
			wantErrStatus: nil,
			wantHashes: &wantHashes{
				UID: "12345",
				hashes: []string{
					fakeBcryptRandomBytes,
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`secretStorage.Set`,
				`END`,
			},
			wantAuditLog: []testutil.WantedAuditLog{
				testutil.WantAuditLog("OIDCClientSecretRequest Updated Secrets", map[string]any{
					"auditID":         "fake-audit-id",
					"clientID":        "client.oauth.pinniped.dev-happy-new-secret",
					"generatedSecret": true,
					"revokedSecrets":  float64(0),
					"totalSecrets":    float64(1),
				}),
			},
		},
		{
			name: "happy path: secret exists, prepend new secret hash to secret to the list of hashes for found oidcclient",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-append-new-secret-hash",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  false,
					},
				},
			},
			seedHashes: func(storage *oidcclientsecretstorage.OIDCClientSecretStorage) {
				require.NoError(t,
					storage.Set(
						context.Background(),
						"",
						"client.oauth.pinniped.dev-append-new-secret-hash",
						"12345",
						[]string{
							"hashed-password-1",
							"hashed-password-2",
						},
					),
				)
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-append-new-secret-hash",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			wantHashes: &wantHashes{
				UID: "12345",
				hashes: []string{
					fakeBcryptRandomBytes,
					"hashed-password-1",
					"hashed-password-2",
				},
			},
			want: &clientsecretapi.OIDCClientSecretRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "client.oauth.pinniped.dev-append-new-secret-hash",
					Namespace:         namespace,
					CreationTimestamp: fakeNow,
				},
				Spec: clientsecretapi.OIDCClientSecretRequestSpec{
					GenerateNewSecret: true,
					RevokeOldSecrets:  false,
				},
				Status: clientsecretapi.OIDCClientSecretRequestStatus{
					GeneratedSecret:    fakeHexEncodedRandomBytes,
					TotalClientSecrets: 3,
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`secretStorage.Set`,
				`END`,
			},
			wantAuditLog: []testutil.WantedAuditLog{
				testutil.WantAuditLog("OIDCClientSecretRequest Updated Secrets", map[string]any{
					"auditID":         "fake-audit-id",
					"clientID":        "client.oauth.pinniped.dev-append-new-secret-hash",
					"generatedSecret": true,
					"revokedSecrets":  float64(0),
					"totalSecrets":    float64(3),
				}),
			},
		},
		{
			name: "happy path: secret exists, append new secret hash to secret and revoke old for found oidcclient",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-append-new-secret-hash",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  true,
					},
				},
			},
			seedHashes: func(storage *oidcclientsecretstorage.OIDCClientSecretStorage) {
				require.NoError(t,
					storage.Set(
						context.Background(),
						"",
						"client.oauth.pinniped.dev-append-new-secret-hash",
						"12345",
						[]string{
							"hashed-password-1",
							"hashed-password-2",
						},
					))
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-append-new-secret-hash",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			wantHashes: &wantHashes{
				UID: "12345",
				hashes: []string{
					fakeBcryptRandomBytes,
				},
			},
			want: &clientsecretapi.OIDCClientSecretRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "client.oauth.pinniped.dev-append-new-secret-hash",
					Namespace:         namespace,
					CreationTimestamp: fakeNow,
				},
				Spec: clientsecretapi.OIDCClientSecretRequestSpec{
					GenerateNewSecret: true,
					RevokeOldSecrets:  true,
				},
				Status: clientsecretapi.OIDCClientSecretRequestStatus{
					GeneratedSecret:    fakeHexEncodedRandomBytes,
					TotalClientSecrets: 1,
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`secretStorage.Set`,
				`END`,
			},
			wantAuditLog: []testutil.WantedAuditLog{
				testutil.WantAuditLog("OIDCClientSecretRequest Updated Secrets", map[string]any{
					"auditID":         "fake-audit-id",
					"clientID":        "client.oauth.pinniped.dev-append-new-secret-hash",
					"generatedSecret": true,
					"revokedSecrets":  float64(2),
					"totalSecrets":    float64(1),
				}),
			},
		},
		{
			name: "happy path: secret exists, revoke oldest secrets but retain latest old secret for found oidcclient",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: false,
						RevokeOldSecrets:  true,
					},
				},
			},
			seedHashes: func(storage *oidcclientsecretstorage.OIDCClientSecretStorage) {
				require.NoError(t,
					storage.Set(
						context.Background(),
						"",
						"client.oauth.pinniped.dev-some-client",
						"12345",
						[]string{
							"hashed-password-1",
							"hashed-password-2",
							"hashed-password-3",
						},
					))
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			wantHashes: &wantHashes{
				UID: "12345",
				hashes: []string{
					"hashed-password-1",
				},
			},
			want: &clientsecretapi.OIDCClientSecretRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "client.oauth.pinniped.dev-some-client",
					Namespace:         namespace,
					CreationTimestamp: fakeNow,
				},
				Spec: clientsecretapi.OIDCClientSecretRequestSpec{
					GenerateNewSecret: false,
					RevokeOldSecrets:  true,
				},
				Status: clientsecretapi.OIDCClientSecretRequestStatus{
					GeneratedSecret:    "",
					TotalClientSecrets: 1,
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`secretStorage.Set`,
				`END`,
			},
			wantAuditLog: []testutil.WantedAuditLog{
				testutil.WantAuditLog("OIDCClientSecretRequest Updated Secrets", map[string]any{
					"auditID":         "fake-audit-id",
					"clientID":        "client.oauth.pinniped.dev-some-client",
					"generatedSecret": false,
					"revokedSecrets":  float64(2),
					"totalSecrets":    float64(1),
				}),
			},
		},
		{
			name: "secret exists but oidcclient secret has too many hashes, fails to create when RevokeOldSecrets:false (max 5), secret is not updated",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  false,
					},
				},
			},
			seedHashes: func(storage *oidcclientsecretstorage.OIDCClientSecretStorage) {
				require.NoError(t,
					storage.Set(
						context.Background(),
						"",
						"client.oauth.pinniped.dev-some-client",
						"12345",
						[]string{
							"hashed-password-1",
							"hashed-password-2",
							"hashed-password-3",
							"hashed-password-4",
							"hashed-password-5",
						},
					))
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			wantHashes: &wantHashes{
				UID: "12345",
				hashes: []string{
					"hashed-password-1",
					"hashed-password-2",
					"hashed-password-3",
					"hashed-password-4",
					"hashed-password-5",
				},
			},
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: `OIDCClient client.oauth.pinniped.dev-some-client has too many secrets, spec.revokeOldSecrets must be true`,
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`failureType:secretStorage.Set,msg:OIDCClient client.oauth.pinniped.dev-some-client has too many secrets, spec.revokeOldSecrets must be true`,
				`END`,
			},
			want: nil,
		},
		{
			name: "secret exists but oidcclient secret has too many hashes, fails to create when RevokeOldSecrets:false (greater than 5), secret is not updated",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  false,
					},
				},
			},
			seedHashes: func(storage *oidcclientsecretstorage.OIDCClientSecretStorage) {
				require.NoError(t,
					storage.Set(
						context.Background(),
						"",
						"client.oauth.pinniped.dev-some-client",
						"12345",
						[]string{
							"hashed-password-1",
							"hashed-password-2",
							"hashed-password-3",
							"hashed-password-4",
							"hashed-password-5",
							"hashed-password-6",
						},
					))
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			wantHashes: &wantHashes{
				UID: "12345",
				hashes: []string{
					"hashed-password-1",
					"hashed-password-2",
					"hashed-password-3",
					"hashed-password-4",
					"hashed-password-5",
					"hashed-password-6",
				},
			},
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: `OIDCClient client.oauth.pinniped.dev-some-client has too many secrets, spec.revokeOldSecrets must be true`,
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`failureType:secretStorage.Set,msg:OIDCClient client.oauth.pinniped.dev-some-client has too many secrets, spec.revokeOldSecrets must be true`,
				`END`,
			},
		},
		{
			name: "attempted to create storage secret because it did not initially exist but was created by someone else while generating new client secret & hash",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  false,
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			addReactors: func(kubeClient *kubefake.Clientset, supervisorClient *supervisorfake.Clientset) {
				kubeClient.PrependReactor("create", "secrets", func(action coretesting.Action) (bool, runtime.Object, error) {
					secret := action.(coretesting.UpdateAction).GetObject().(*corev1.Secret)
					return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Group: "", Resource: "secrets"}, secret.Name)
				})
			},
			wantErrStatus: &metav1.Status{
				Status: metav1.StatusFailure,
				Message: `Operation cannot be fulfilled on oidcclientsecretrequests.clientsecret.supervisor.pinniped.dev ` +
					`"client.oauth.pinniped.dev-some-client": multiple concurrent secret generation requests for same client`,
				Reason: metav1.StatusReasonConflict,
				Code:   http.StatusConflict,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "oidcclientsecretrequests",
					Name:  "client.oauth.pinniped.dev-some-client",
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`failureType:secretStorage.Set,msg:failed to create client secret for uid 12345: failed to create oidc-client-secret for signature MTIzNDU: secrets "pinniped-storage-oidc-client-secret-gezdgnbv" already exists`,
				`END`,
			},
		},
		{
			name: "attempted to create storage secret because it did not initially exist but received a conflict error",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  false,
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			addReactors: func(kubeClient *kubefake.Clientset, supervisorClient *supervisorfake.Clientset) {
				kubeClient.PrependReactor("create", "secrets", func(action coretesting.Action) (bool, runtime.Object, error) {
					secret := action.(coretesting.UpdateAction).GetObject().(*corev1.Secret)
					return true, nil, apierrors.NewConflict(
						schema.GroupResource{Group: "", Resource: "secrets"},
						secret.Name,
						errors.New("something deeply conflicted"),
					)
				})
			},
			wantErrStatus: &metav1.Status{
				Status: metav1.StatusFailure,
				Message: `Operation cannot be fulfilled on oidcclientsecretrequests.clientsecret.supervisor.pinniped.dev ` +
					`"client.oauth.pinniped.dev-some-client": multiple concurrent secret generation requests for same client`,
				Reason: metav1.StatusReasonConflict,
				Code:   http.StatusConflict,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "oidcclientsecretrequests",
					Name:  "client.oauth.pinniped.dev-some-client",
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`failureType:secretStorage.Set,msg:failed to create client secret for uid 12345: failed to create oidc-client-secret for signature MTIzNDU: Operation cannot be fulfilled on secrets "pinniped-storage-oidc-client-secret-gezdgnbv": something deeply conflicted`,
				`END`,
			},
		},
		{
			name: "attempted to create storage secret but received an unknown error",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  false,
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			addReactors: func(kubeClient *kubefake.Clientset, supervisorClient *supervisorfake.Clientset) {
				kubeClient.PrependReactor("create", "secrets", func(action coretesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some random error")
				})
			},
			wantErrStatus: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: `Internal error occurred: setting client secret failed`,
				Reason:  metav1.StatusReasonInternalError,
				Code:    http.StatusInternalServerError,
				Details: &metav1.StatusDetails{
					Causes: []metav1.StatusCause{{
						Message: "setting client secret failed",
					}},
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`failureType:secretStorage.Set,msg:failed to create client secret for uid 12345: failed to create oidc-client-secret for signature MTIzNDU: some random error`,
				`END`,
			},
		},
		{
			name: "happy path noop: do not create a new secret, do not revoke old secrets, but there is no existing storage secret",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-happy-new-secret",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: false,
						RevokeOldSecrets:  true,
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-happy-new-secret",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			want: &clientsecretapi.OIDCClientSecretRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "client.oauth.pinniped.dev-happy-new-secret",
					Namespace:         namespace,
					CreationTimestamp: fakeNow,
				},
				Spec: clientsecretapi.OIDCClientSecretRequestSpec{
					GenerateNewSecret: false,
					RevokeOldSecrets:  true,
				},
				Status: clientsecretapi.OIDCClientSecretRequestStatus{
					GeneratedSecret:    "",
					TotalClientSecrets: 0,
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`END`,
			},
		},
		{
			name: "happy path noop: do not create a new secret, revoke old secrets, but there is no existing storage secret",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: false,
						RevokeOldSecrets:  false,
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			want: &clientsecretapi.OIDCClientSecretRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "client.oauth.pinniped.dev-some-client",
					Namespace:         namespace,
					CreationTimestamp: fakeNow,
				},
				Spec: clientsecretapi.OIDCClientSecretRequestSpec{
					GenerateNewSecret: false,
					RevokeOldSecrets:  false,
				},
				Status: clientsecretapi.OIDCClientSecretRequestStatus{
					GeneratedSecret:    "",
					TotalClientSecrets: 0,
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`END`,
			},
		},
		{
			name: "happy path noop: do not create a new secret, revoke old secrets, and there is an existing storage secret",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: false,
						RevokeOldSecrets:  false,
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			seedHashes: func(storage *oidcclientsecretstorage.OIDCClientSecretStorage) {
				require.NoError(t,
					storage.Set(
						context.Background(),
						"",
						"client.oauth.pinniped.dev-some-client",
						"12345",
						[]string{
							"hashed-password-1",
							"hashed-password-2",
						},
					))
			},
			wantHashes: &wantHashes{
				UID: "12345",
				hashes: []string{
					"hashed-password-1",
					"hashed-password-2",
				},
			},
			want: &clientsecretapi.OIDCClientSecretRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "client.oauth.pinniped.dev-some-client",
					Namespace:         namespace,
					CreationTimestamp: fakeNow,
				},
				Spec: clientsecretapi.OIDCClientSecretRequestSpec{
					GenerateNewSecret: false,
					RevokeOldSecrets:  false,
				},
				Status: clientsecretapi.OIDCClientSecretRequestStatus{
					GeneratedSecret:    "",
					TotalClientSecrets: 2,
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`END`,
			},
		},
		{
			name: "happy path: generate new secret and revoking old secret when there was a single secret hash to start with",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  true,
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			seedHashes: func(storage *oidcclientsecretstorage.OIDCClientSecretStorage) {
				require.NoError(t,
					storage.Set(
						context.Background(),
						"",
						"client.oauth.pinniped.dev-some-client",
						"12345",
						[]string{
							"hashed-password-1",
						},
					))
			},
			wantHashes: &wantHashes{
				UID: "12345",
				hashes: []string{
					fakeBcryptRandomBytes,
				},
			},
			want: &clientsecretapi.OIDCClientSecretRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "client.oauth.pinniped.dev-some-client",
					Namespace:         namespace,
					CreationTimestamp: fakeNow,
				},
				Spec: clientsecretapi.OIDCClientSecretRequestSpec{
					GenerateNewSecret: true,
					RevokeOldSecrets:  true,
				},
				Status: clientsecretapi.OIDCClientSecretRequestStatus{
					GeneratedSecret:    fakeHexEncodedRandomBytes,
					TotalClientSecrets: 1,
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`secretStorage.Set`,
				`END`,
			},
			wantAuditLog: []testutil.WantedAuditLog{
				testutil.WantAuditLog("OIDCClientSecretRequest Updated Secrets", map[string]any{
					"auditID":         "fake-audit-id",
					"clientID":        "client.oauth.pinniped.dev-some-client",
					"generatedSecret": true,
					"revokedSecrets":  float64(1),
					"totalSecrets":    float64(1),
				}),
			},
		},
		{
			name: "happy path: generate new secret when existing secrets is max (5)",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  true,
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			seedHashes: func(storage *oidcclientsecretstorage.OIDCClientSecretStorage) {
				require.NoError(t,
					storage.Set(
						context.Background(),
						"",
						"client.oauth.pinniped.dev-some-client",
						"12345",
						[]string{
							"hashed-password-1",
							"hashed-password-2",
							"hashed-password-3",
							"hashed-password-4",
							"hashed-password-5",
						},
					))
			},
			wantHashes: &wantHashes{
				UID: "12345",
				hashes: []string{
					fakeBcryptRandomBytes,
				},
			},
			want: &clientsecretapi.OIDCClientSecretRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "client.oauth.pinniped.dev-some-client",
					Namespace:         namespace,
					CreationTimestamp: fakeNow,
				},
				Spec: clientsecretapi.OIDCClientSecretRequestSpec{
					GenerateNewSecret: true,
					RevokeOldSecrets:  true,
				},
				Status: clientsecretapi.OIDCClientSecretRequestStatus{
					GeneratedSecret:    fakeHexEncodedRandomBytes,
					TotalClientSecrets: 1,
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`secretStorage.Set`,
				`END`,
			},
			wantAuditLog: []testutil.WantedAuditLog{
				testutil.WantAuditLog("OIDCClientSecretRequest Updated Secrets", map[string]any{
					"auditID":         "fake-audit-id",
					"clientID":        "client.oauth.pinniped.dev-some-client",
					"generatedSecret": true,
					"revokedSecrets":  float64(5),
					"totalSecrets":    float64(1),
				}),
			},
		},
		{
			name: "happy path: generate new secret when existing secrets exceeds maximum (5)",
			args: args{
				ctx: namespacedContext,
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client",
					},
					Spec: clientsecretapi.OIDCClientSecretRequestSpec{
						GenerateNewSecret: true,
						RevokeOldSecrets:  true,
					},
				},
			},
			seedOIDCClients: []*supervisorconfigv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client.oauth.pinniped.dev-some-client",
					Namespace: namespace,
					UID:       "12345",
				},
			}},
			seedHashes: func(storage *oidcclientsecretstorage.OIDCClientSecretStorage) {
				require.NoError(t,
					storage.Set(
						context.Background(),
						"",
						"client.oauth.pinniped.dev-some-client",
						"12345",
						[]string{
							"hashed-password-1",
							"hashed-password-2",
							"hashed-password-3",
							"hashed-password-4",
							"hashed-password-5",
							"hashed-password-6",
						},
					))
			},
			wantHashes: &wantHashes{
				UID: "12345",
				hashes: []string{
					fakeBcryptRandomBytes,
				},
			},
			want: &clientsecretapi.OIDCClientSecretRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "client.oauth.pinniped.dev-some-client",
					Namespace:         namespace,
					CreationTimestamp: fakeNow,
				},
				Spec: clientsecretapi.OIDCClientSecretRequestSpec{
					GenerateNewSecret: true,
					RevokeOldSecrets:  true,
				},
				Status: clientsecretapi.OIDCClientSecretRequestStatus{
					GeneratedSecret:    fakeHexEncodedRandomBytes,
					TotalClientSecrets: 1,
				},
			},
			wantLogStepSubstrings: []string{
				`"create"`,
				`"validateRequest"`,
				`oidcClientsClient.Get`,
				`secretStorage.Get`,
				`generateSecret`,
				`bcrypt.GenerateFromPassword`,
				`secretStorage.Set`,
				`END`,
			},
			wantAuditLog: []testutil.WantedAuditLog{
				testutil.WantAuditLog("OIDCClientSecretRequest Updated Secrets", map[string]any{
					"auditID":         "fake-audit-id",
					"clientID":        "client.oauth.pinniped.dev-some-client",
					"generatedSecret": true,
					"revokedSecrets":  float64(6),
					"totalSecrets":    float64(1),
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel() should not be used because we are mutating the global logger.
			logger := testutil.NewTranscriptLogger(t) //nolint:staticcheck  // old test with lots of log statements
			klog.SetLogger(logr.New(logger))
			originalKLogLevel := testutil.GetGlobalKlogLevel()
			// trace.Log() utility will only log at level 2 or above, so set that for this test.
			testutil.SetGlobalKlogLevel(t, 2) //nolint:staticcheck // old test of code using trace.Log()
			t.Cleanup(func() {
				klog.ClearLogger()
				testutil.SetGlobalKlogLevel(t, originalKLogLevel) //nolint:staticcheck // old test of code using trace.Log()
			})

			kubeClient := kubefake.NewSimpleClientset()
			secretsClient := kubeClient.CoreV1().Secrets(namespace)
			// Production code depends on secrets having a resource version.
			// Our seedHashes mechanism with the fake client unfortunately does not cause a resourceVersion to be set on the secret.
			// Therefore, we need to add this reactor before we seed hashes so our secrets have RVs.
			kubeClient.PrependReactor("create", "secrets", func(action coretesting.Action) (bool, runtime.Object, error) {
				secret := action.(coretesting.UpdateAction).GetObject().(*corev1.Secret)
				secret.ResourceVersion = "1"
				return false, nil, nil
			})

			oidcClientSecretStore := oidcclientsecretstorage.New(secretsClient)
			if tt.seedHashes != nil {
				tt.seedHashes(oidcClientSecretStore)
			}

			supervisorClient := supervisorfake.NewSimpleClientset()
			if tt.seedOIDCClients != nil {
				for _, client := range tt.seedOIDCClients {
					require.NoError(t, supervisorClient.Tracker().Add(client))
				}
			}
			oidcClientClient := supervisorClient.ConfigV1alpha1().OIDCClients(namespace)

			if tt.addReactors != nil {
				tt.addReactors(kubeClient, supervisorClient)
			}

			fakeHasher := tt.fakeHasher
			if tt.fakeHasher == nil {
				fakeHasher = func(password []byte, cost int) ([]byte, error) {
					return []byte(fmt.Sprintf("%s:%d-fake-hash", password, cost)), nil
				}
			}
			fakeByteGenerator := tt.fakeByteGenerator
			if tt.fakeByteGenerator == nil {
				fakeByteGenerator = strings.NewReader(fakeRandomBytes + "these extra bytes should be ignored since we only read 32 bytes")
			}

			auditLogger, actualAuditLog := plog.TestAuditLogger(t)
			ctx := audit.WithAuditContext(tt.args.ctx)
			audit.WithAuditID(ctx, "fake-audit-id")

			r := NewREST(
				schema.GroupResource{Group: "bears", Resource: "panda"},
				secretsClient,
				oidcClientClient,
				namespace,
				4,
				fakeByteGenerator,
				fakeHasher,
				fakeTimeNowFunc,
				auditLogger,
			)

			got, err := r.Create(ctx, tt.args.obj, tt.args.createValidation, tt.args.options)

			require.Equal(t, tt.want, got)
			if tt.wantErrStatus != nil {
				require.Equal(t, &apierrors.StatusError{ErrStatus: *tt.wantErrStatus}, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantHashes != nil {
				secretStoreName := oidcClientSecretStore.GetName(types.UID(tt.wantHashes.UID))
				secretGVR := schema.GroupVersionResource{
					Group:    corev1.SchemeGroupVersion.Group,
					Version:  corev1.SchemeGroupVersion.Version,
					Resource: "secrets",
				}
				storeSecret, err := kubeClient.Tracker().Get(secretGVR, namespace, secretStoreName)
				require.NoError(t, err)
				require.IsType(t, &corev1.Secret{}, storeSecret)
				secretHashes, err := oidcclientsecretstorage.ReadFromSecret(storeSecret.(*corev1.Secret))
				require.NoError(t, err)
				require.Equal(t, tt.wantHashes.hashes, secretHashes)
			} else {
				secrets, err := secretsClient.List(context.Background(), metav1.ListOptions{})
				require.NoError(t, err)
				require.Empty(t, secrets.Items)
			}

			requireExactlyOneLogLineWithMultipleSteps(t, logger, tt.wantLogStepSubstrings)

			testutil.CompareAuditLogs(t, tt.wantAuditLog, actualAuditLog.String())
		})
	}
}

type readerAlwaysErrors struct{}

func (r readerAlwaysErrors) Read(_ []byte) (n int, err error) {
	return 0, errors.New("always errors")
}

func requireExactlyOneLogLineWithMultipleSteps(t *testing.T, logger *testutil.TranscriptLogger, wantLines []string) {
	transcript := logger.Transcript()
	require.Len(t, transcript, 1)
	lines := strings.Split(strings.TrimSpace(transcript[0].Message), "\n")

	require.Lenf(t, lines, len(wantLines), "actual log lines length should match expected length, actual lines:\n\n%s", strings.Join(lines, "\n"))
	for i := range wantLines {
		require.Containsf(t, lines[i], wantLines[i], "log line at index %d should have contained expected output", i)
	}
}
