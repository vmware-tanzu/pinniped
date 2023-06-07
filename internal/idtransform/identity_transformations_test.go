// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package idtransform

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type FakeNoopTransformer struct{}

func (a FakeNoopTransformer) Evaluate(ctx context.Context, username string, groups []string) (*TransformationResult, error) {
	return &TransformationResult{
		Username:                      username,
		Groups:                        groups,
		AuthenticationAllowed:         true,
		RejectedAuthenticationMessage: "none",
	}, nil
}

type FakeNilGroupTransformer struct{}

func (a FakeNilGroupTransformer) Evaluate(ctx context.Context, username string, groups []string) (*TransformationResult, error) {
	return &TransformationResult{
		Username:                      username,
		Groups:                        nil,
		AuthenticationAllowed:         true,
		RejectedAuthenticationMessage: "none",
	}, nil
}

type FakeAppendStringTransformer struct{}

func (a FakeAppendStringTransformer) Evaluate(ctx context.Context, username string, groups []string) (*TransformationResult, error) {
	newGroups := []string{}
	for _, group := range groups {
		newGroups = append(newGroups, group+":transformed")
	}
	return &TransformationResult{
		Username:                      username + ":transformed",
		Groups:                        newGroups,
		AuthenticationAllowed:         true,
		RejectedAuthenticationMessage: "none",
	}, nil
}

type FakeDeleteUsernameAndGroupsTransformer struct{}

func (d FakeDeleteUsernameAndGroupsTransformer) Evaluate(ctx context.Context, username string, groups []string) (*TransformationResult, error) {
	return &TransformationResult{
		Username:                      "",
		Groups:                        []string{},
		AuthenticationAllowed:         true,
		RejectedAuthenticationMessage: "none",
	}, nil
}

type FakeAuthenticationDisallowedTransformer struct{}

func (d FakeAuthenticationDisallowedTransformer) Evaluate(ctx context.Context, username string, groups []string) (*TransformationResult, error) {
	newGroups := []string{}
	for _, group := range groups {
		newGroups = append(newGroups, group+":disallowed")
	}
	return &TransformationResult{
		Username:                      username + ":disallowed",
		Groups:                        newGroups,
		AuthenticationAllowed:         false,
		RejectedAuthenticationMessage: "no authentication is allowed",
	}, nil
}

type FakeErrorTransformer struct{}

func (d FakeErrorTransformer) Evaluate(ctx context.Context, username string, groups []string) (*TransformationResult, error) {
	return &TransformationResult{}, errors.New("unexpected catastrophic error")
}

func TestTransformationPipeline(t *testing.T) {
	tests := []struct {
		name                               string
		username                           string
		groups                             []string
		transforms                         []IdentityTransformation
		wantUsername                       string
		wantGroups                         []string
		wantAuthenticationAllowed          bool
		wantRejectionAuthenticationMessage string
		wantError                          string
	}{
		{
			name: "single transformation applied successfully",
			transforms: []IdentityTransformation{
				FakeAppendStringTransformer{},
			},
			username: "foo",
			groups: []string{
				"foobar",
				"foobaz",
			},
			wantUsername: "foo:transformed",
			wantGroups: []string{
				"foobar:transformed",
				"foobaz:transformed",
			},
			wantAuthenticationAllowed:          true,
			wantRejectionAuthenticationMessage: "none",
		},
		{
			name:     "multiple transformations applied successfully",
			username: "foo",
			groups: []string{
				"foobar",
				"foobaz",
			},
			transforms: []IdentityTransformation{
				FakeAppendStringTransformer{},
				FakeAppendStringTransformer{},
			},
			wantUsername: "foo:transformed:transformed",
			wantGroups: []string{
				"foobar:transformed:transformed",
				"foobaz:transformed:transformed",
			},
			wantAuthenticationAllowed:          true,
			wantRejectionAuthenticationMessage: "none",
		},
		{
			name:     "single transformation results in AuthenticationAllowed:false",
			username: "foo",
			groups: []string{
				"foobar",
			},
			transforms: []IdentityTransformation{
				FakeAuthenticationDisallowedTransformer{},
			},
			wantUsername:                       "foo:disallowed",
			wantGroups:                         []string{"foobar:disallowed"},
			wantAuthenticationAllowed:          false,
			wantRejectionAuthenticationMessage: "no authentication is allowed",
		},
		{
			name:     "multiple transformations results in AuthenticationAllowed:false but earlier transforms are successful",
			username: "foo",
			groups: []string{
				"foobar",
			},
			transforms: []IdentityTransformation{
				FakeAppendStringTransformer{},
				FakeAuthenticationDisallowedTransformer{},
				// this transformation will not be run because the previous exits the pipeline
				FakeAppendStringTransformer{},
			},
			wantUsername:                       "foo:transformed:disallowed",
			wantGroups:                         []string{"foobar:transformed:disallowed"},
			wantAuthenticationAllowed:          false,
			wantRejectionAuthenticationMessage: "no authentication is allowed",
		},
		{
			name:     "unexpected error at index",
			username: "foo",
			groups:   []string{"foobar"},
			transforms: []IdentityTransformation{
				FakeAppendStringTransformer{},
				FakeErrorTransformer{},
				FakeAppendStringTransformer{},
			},
			wantError: "identity transformation at index 1: unexpected catastrophic error",
		},
		{
			name:     "empty username not allowed",
			username: "foo",
			transforms: []IdentityTransformation{
				FakeDeleteUsernameAndGroupsTransformer{},
			},
			wantError: "identity transformation returned an empty username, which is not allowed",
		},
		{
			name:     "whitespace username not allowed",
			username: "    \t\n\r   ",
			transforms: []IdentityTransformation{
				FakeNoopTransformer{},
			},
			wantError: "identity transformation returned an empty username, which is not allowed",
		},
		{
			name:     "identity transformation which returns an empty list of groups is allowed",
			username: "foo",
			groups:   []string{},
			transforms: []IdentityTransformation{
				FakeAppendStringTransformer{},
			},
			wantUsername:                       "foo:transformed",
			wantGroups:                         []string{},
			wantAuthenticationAllowed:          true,
			wantRejectionAuthenticationMessage: "none",
		},
		{
			name:     "nil passed in for groups will be automatically converted to an empty list",
			username: "foo",
			groups:   nil,
			transforms: []IdentityTransformation{
				FakeNoopTransformer{},
			},
			wantUsername:                       "foo",
			wantGroups:                         []string{},
			wantAuthenticationAllowed:          true,
			wantRejectionAuthenticationMessage: "none",
		},
		{
			name:     "any transformation returning nil for the list of groups will cause an error",
			username: "foo",
			groups:   []string{"these.will.be.converted.to.nil"},
			transforms: []IdentityTransformation{
				FakeNilGroupTransformer{},
			},
			wantError: "identity transformation returned a null list of groups, which is not allowed",
		},
		{
			name:                      "no transformations is allowed",
			username:                  "foo",
			groups:                    []string{"bar", "baz"},
			transforms:                []IdentityTransformation{},
			wantUsername:              "foo",
			wantGroups:                []string{"bar", "baz"},
			wantAuthenticationAllowed: true,
			// since no transformations run, this will be empty string
			wantRejectionAuthenticationMessage: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pipeline := NewTransformationPipeline()

			for _, transform := range tt.transforms {
				pipeline.AppendTransformation(transform)
			}

			result, err := pipeline.Evaluate(context.Background(), tt.username, tt.groups)

			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
				require.Nil(t, result)
				return
			}

			require.NoError(t, err, "got an unexpected evaluation error")
			require.Equal(t, tt.wantUsername, result.Username)
			require.Equal(t, tt.wantGroups, result.Groups)
			require.Equal(t, tt.wantAuthenticationAllowed, result.AuthenticationAllowed)
			require.Equal(t, tt.wantRejectionAuthenticationMessage, result.RejectedAuthenticationMessage)
		})
	}
}
