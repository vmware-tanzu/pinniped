// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package whoamirequest

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	identityapi "go.pinniped.dev/generated/latest/apis/concierge/identity"
)

func TestNew(t *testing.T) {
	r := NewREST(schema.GroupResource{Group: "bears", Resource: "panda"})
	require.NotNil(t, r)
	require.False(t, r.NamespaceScoped())
	require.Equal(t, []string{"pinniped"}, r.Categories())
	require.IsType(t, &identityapi.WhoAmIRequest{}, r.New())
	require.IsType(t, &identityapi.WhoAmIRequestList{}, r.NewList())

	ctx := context.Background()

	// check the simple invariants of our no-op list
	list, err := r.List(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, list)
	require.IsType(t, &identityapi.WhoAmIRequestList{}, list)
	require.Equal(t, "0", list.(*identityapi.WhoAmIRequestList).ResourceVersion)
	require.NotNil(t, list.(*identityapi.WhoAmIRequestList).Items)
	require.Len(t, list.(*identityapi.WhoAmIRequestList).Items, 0)

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
	tests := []struct {
		name    string
		args    args
		want    runtime.Object
		wantErr string
	}{
		{
			name: "wrong type",
			args: args{
				ctx:              genericapirequest.NewContext(),
				obj:              &metav1.Status{},
				createValidation: nil,
				options:          nil,
			},
			want:    nil,
			wantErr: `not a WhoAmIRequest: &v1.Status{TypeMeta:v1.TypeMeta{Kind:"", APIVersion:""}, ListMeta:v1.ListMeta{SelfLink:"", ResourceVersion:"", Continue:"", RemainingItemCount:(*int64)(nil)}, Status:"", Message:"", Reason:"", Details:(*v1.StatusDetails)(nil), Code:0}`,
		},
		{
			name: "bad options",
			args: args{
				ctx: genericapirequest.NewContext(),
				obj: &identityapi.WhoAmIRequest{
					TypeMeta: metav1.TypeMeta{
						Kind: "SomeKind",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "some-name",
					},
				},
				createValidation: nil,
				options:          &metav1.CreateOptions{DryRun: []string{"stuff"}},
			},
			want:    nil,
			wantErr: `SomeKind.identity.concierge.pinniped.dev "some-name" is invalid: dryRun: Unsupported value: []string{"stuff"}`,
		},
		{
			name: "bad namespace",
			args: args{
				ctx:              genericapirequest.WithNamespace(genericapirequest.NewContext(), "some-ns"),
				obj:              &identityapi.WhoAmIRequest{},
				createValidation: nil,
				options:          nil,
			},
			want:    nil,
			wantErr: `namespace is not allowed on WhoAmIRequest: some-ns`,
		},
		{
			// if we add fields to spec, we need additional tests to:
			// - make sure admission cannot mutate it
			// - the input spec fields are validated correctly
			name: "create validation failure",
			args: args{
				ctx: genericapirequest.NewContext(),
				obj: &identityapi.WhoAmIRequest{},
				createValidation: func(ctx context.Context, obj runtime.Object) error {
					return errors.New("some-error-here")
				},
				options: nil,
			},
			want:    nil,
			wantErr: `some-error-here`,
		},
		{
			name: "no user info",
			args: args{
				ctx:              genericapirequest.NewContext(),
				obj:              &identityapi.WhoAmIRequest{},
				createValidation: nil,
				options:          nil,
			},
			want:    nil,
			wantErr: `Internal error occurred: no user info on request`,
		},
		{
			name: "with user info, no auds",
			args: args{
				ctx: genericapirequest.WithUser(genericapirequest.NewContext(), &user.DefaultInfo{
					Name:   "bond",
					UID:    "007",
					Groups: []string{"agents", "ops"},
					Extra: map[string][]string{
						"fan-of": {"pandas", "twizzlers"},
						"needs":  {"sleep"},
					},
				}),
				obj:              &identityapi.WhoAmIRequest{},
				createValidation: nil,
				options:          nil,
			},
			want: &identityapi.WhoAmIRequest{
				Status: identityapi.WhoAmIRequestStatus{
					KubernetesUserInfo: identityapi.KubernetesUserInfo{
						User: identityapi.UserInfo{
							Username: "bond",
							UID:      "007",
							Groups:   []string{"agents", "ops"},
							Extra: map[string]identityapi.ExtraValue{
								"fan-of": {"pandas", "twizzlers"},
								"needs":  {"sleep"},
							},
						},
						Audiences: nil,
					},
				},
			},
			wantErr: ``,
		},
		{
			name: "with user info and auds",
			args: args{
				ctx: authenticator.WithAudiences(
					genericapirequest.WithUser(genericapirequest.NewContext(), &user.DefaultInfo{
						Name: "panda",
					}),
					authenticator.Audiences{"gitlab", "aws"},
				),
				obj:              &identityapi.WhoAmIRequest{},
				createValidation: nil,
				options:          nil,
			},
			want: &identityapi.WhoAmIRequest{
				Status: identityapi.WhoAmIRequestStatus{
					KubernetesUserInfo: identityapi.KubernetesUserInfo{
						User: identityapi.UserInfo{
							Username: "panda",
						},
						Audiences: []string{"gitlab", "aws"},
					},
				},
			},
			wantErr: ``,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			r := &REST{}
			got, err := r.Create(tt.args.ctx, tt.args.obj, tt.args.createValidation, tt.args.options)
			require.Equal(t, tt.wantErr, errString(err))
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
