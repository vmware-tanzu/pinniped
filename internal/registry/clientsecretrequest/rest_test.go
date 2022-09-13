// NOTES:
// Take a look at the unit tests from the sibling files as we already have some there.
// whoamirequest is super simple, zero side effects...
// - add bits similar to what we did for crud.go to seed kube with secrets & prove your updates
// - perhaps look at oidcclientsecretstorage.go also for the seeding code we wrote
//   - the things we are seeding here IS the storage of client secrets + hashes
//     - this is the specific secret formats that we need
//     - but instead of hello world hashes we will want to put real BCrypt hashes in the seeds
//     - there is a test helper with some real BCrypt hashes we can use in oidcclient.go -- HashedPassword1AtGoMinCost - 04 for unit tests for speed
//       - look for a test using HashedPassword1AtGoMinCost to see how we step around the min value of 11 tho production code must do that
// 			- NewKubeStorage, bcrypt.MinCost will show this
// 			// Use lower minimum required bcrypt cost than we would use in production to keep unit the tests fast.
// 			oauthStore := oidc.NewKubeStorage(secrets, oidcClientsClient, timeoutsConfiguration, bcrypt.MinCost)
// credentialrequest also has no side effects...
//
//
// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package clientsecretrequest

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	clientsecretapi "go.pinniped.dev/generated/latest/apis/supervisor/clientsecret"
)

func TestNew(t *testing.T) {

	r := NewREST(schema.GroupResource{Group: "bears", Resource: "panda"}, nil, nil, "foobar", 4)

	require.NotNil(t, r)
	require.True(t, r.NamespaceScoped())
	require.Equal(t, []string{"pinniped"}, r.Categories())

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
	type args struct {
		ctx              context.Context
		obj              runtime.Object
		createValidation rest.ValidateObjectFunc
		options          *metav1.CreateOptions
	}
	namespace := "some-namespace"

	tests := []struct {
		name          string
		args          args
		want          runtime.Object
		wantErrStatus metav1.Status
	}{
		{
			name: "wrong type",
			args: args{
				ctx:              genericapirequest.NewContext(),
				obj:              &metav1.Status{},
				createValidation: nil,
				options:          nil,
			},
			want: nil,
			wantErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Message: `not an OIDCClientSecretRequest: &v1.Status{TypeMeta:v1.TypeMeta{Kind:"", APIVersion:""}, ListMeta:v1.ListMeta{SelfLink:"", ResourceVersion:"", Continue:"", RemainingItemCount:(*int64)(nil)}, Status:"", Message:"", Reason:"", Details:(*v1.StatusDetails)(nil), Code:0}`,
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			},
		},
		{
			name: "bad options for dry run",
			args: args{
				ctx: genericapirequest.WithNamespace(genericapirequest.NewContext(), namespace),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client-name",
					},
				},
				createValidation: nil,
				options:          &metav1.CreateOptions{DryRun: []string{"stuff"}},
			},
			want: nil,
			wantErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Message: `OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev "client.oauth.pinniped.dev-some-client-name" is invalid: dryRun: Unsupported value: []string{"stuff"}`,
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusUnprocessableEntity,
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
		},
		{
			name: "incorrect namespace",
			args: args{
				ctx: genericapirequest.WithNamespace(genericapirequest.NewContext(), "wrong-namespace"),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client-name",
					},
				},
				createValidation: nil,
				options:          nil,
			},
			want: nil,
			wantErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Message: `namespace must be some-namespace on OIDCClientSecretRequest, was wrong-namespace`,
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			},
		},
		{
			name: "create validation: failure from kube api-server rest.ValidateObjectFunc",
			args: args{
				ctx: genericapirequest.WithNamespace(genericapirequest.NewContext(), namespace),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-some-client-name",
					},
				},
				createValidation: func(ctx context.Context, obj runtime.Object) error {
					return apierrors.NewInternalError(errors.New("some-error-here"))
				},
				options: nil,
			},
			want: nil,
			wantErrStatus: metav1.Status{
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
				options: nil,
			},
			want: nil,
			wantErrStatus: metav1.Status{
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
		},
		{
			name: "create validation: namespace on object does not match namespace on request",
			args: args{
				ctx: genericapirequest.WithNamespace(genericapirequest.NewContext(), namespace),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "client.oauth.pinniped.dev-some-client-name",
						Namespace: "not-a-matching-namespace",
					},
				},
				options: nil,
			},
			want: nil,
			wantErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Message: "the namespace of the provided object does not match the namespace sent on the request",
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			},
		},
		{
			name: "create validation: generateName is unsupported",
			args: args{
				ctx: genericapirequest.WithNamespace(genericapirequest.NewContext(), namespace),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName: "foo",
					},
				},
				options: nil,
			},
			want: nil,
			wantErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Message: "OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev \"\" is invalid: [metadata.generateName: Invalid value: \"foo\": generateName is not supported, metadata.name: Required value: name or generateName is required]",
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusUnprocessableEntity,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "OIDCClientSecretRequest",
					Name:  "",
					Causes: []metav1.StatusCause{{
						Type:    metav1.CauseTypeFieldValueInvalid,
						Message: "Invalid value: \"foo\": generateName is not supported",
						Field:   "metadata.generateName",
					}, {
						Type:    metav1.CauseTypeFieldValueRequired,
						Message: "Required value: name or generateName is required",
						Field:   "metadata.name",
					}},
				},
			},
		},
		{
			name: "create validation: name cannot exactly match client.oauth.pinniped.dev-",
			args: args{
				ctx: genericapirequest.WithNamespace(genericapirequest.NewContext(), namespace),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-",
					},
				},
				options: nil,
			},
			want: nil,
			wantErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Message: "OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev \"client.oauth.pinniped.dev-\" is invalid: metadata.name: Invalid value: \"client.oauth.pinniped.dev-\": must not equal 'client.oauth.pinniped.dev-'",
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusUnprocessableEntity,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "OIDCClientSecretRequest",
					Name:  "client.oauth.pinniped.dev-",
					Causes: []metav1.StatusCause{{
						Type:    metav1.CauseTypeFieldValueInvalid,
						Message: "Invalid value: \"client.oauth.pinniped.dev-\": must not equal 'client.oauth.pinniped.dev-'",
						Field:   "metadata.name",
					}},
				},
			},
		},
		{
			name: "create validation: name must contain prefix client.oauth.pinniped.dev-",
			args: args{
				ctx: genericapirequest.WithNamespace(genericapirequest.NewContext(), namespace),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "does-not-contain-the-prefix",
					},
				},
				options: nil,
			},
			want: nil,
			wantErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Message: "OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev \"does-not-contain-the-prefix\" is invalid: metadata.name: Invalid value: \"does-not-contain-the-prefix\": must start with 'client.oauth.pinniped.dev-'",
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusUnprocessableEntity,
				Details: &metav1.StatusDetails{
					Group: "clientsecret.supervisor.pinniped.dev",
					Kind:  "OIDCClientSecretRequest",
					Name:  "does-not-contain-the-prefix",
					Causes: []metav1.StatusCause{{
						Type:    metav1.CauseTypeFieldValueInvalid,
						Message: "Invalid value: \"does-not-contain-the-prefix\": must start with 'client.oauth.pinniped.dev-'",
						Field:   "metadata.name",
					}},
				},
			},
		},
		{
			name: "create validation: name with invalid characters should error",
			args: args{
				ctx: genericapirequest.WithNamespace(genericapirequest.NewContext(), namespace),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name: "client.oauth.pinniped.dev-contains/invalid/characters",
					},
				},
				options: nil,
			},
			want: nil,
			wantErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Message: `OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev "client.oauth.pinniped.dev-contains/invalid/characters" is invalid: metadata.name: Invalid value: "client.oauth.pinniped.dev-contains/invalid/characters": may not contain '/'`,
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusUnprocessableEntity,
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
		},
		{
			name: "create validation: name validation may return multiple errors",
			args: args{
				ctx: genericapirequest.WithNamespace(genericapirequest.NewContext(), namespace),
				obj: &clientsecretapi.OIDCClientSecretRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:         "multiple/errors/aggregated",
						GenerateName: "no-generate-allowed",
					},
				},
				options: nil,
			},
			want: nil,
			wantErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Message: `OIDCClientSecretRequest.clientsecret.supervisor.pinniped.dev "multiple/errors/aggregated" is invalid: [metadata.generateName: Invalid value: "no-generate-allowed": generateName is not supported, metadata.name: Invalid value: "multiple/errors/aggregated": must start with 'client.oauth.pinniped.dev-', metadata.name: Invalid value: "multiple/errors/aggregated": may not contain '/']`,
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusUnprocessableEntity,
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
		},
		// {name: ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// TODO: update and fill these in with actual values, not nil!
			r := NewREST(schema.GroupResource{Group: "bears", Resource: "panda"}, nil, nil, namespace, 4)
			got, err := r.Create(tt.args.ctx, tt.args.obj, tt.args.createValidation, tt.args.options)
			require.Equal(t, &apierrors.StatusError{
				ErrStatus: tt.wantErrStatus,
			}, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
