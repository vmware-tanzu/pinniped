// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package idtransform

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeNoopTransformer struct{}

func (a fakeNoopTransformer) Evaluate(_ctx context.Context, username string, groups []string) (*TransformationResult, error) {
	return &TransformationResult{
		Username:                      username,
		Groups:                        groups,
		AuthenticationAllowed:         true,
		RejectedAuthenticationMessage: "none",
	}, nil
}

func (a fakeNoopTransformer) Source() any {
	return nil // not needed for this test
}

type fakeNilGroupTransformer struct{}

func (a fakeNilGroupTransformer) Evaluate(_ctx context.Context, username string, _groups []string) (*TransformationResult, error) {
	return &TransformationResult{
		Username:                      username,
		Groups:                        nil,
		AuthenticationAllowed:         true,
		RejectedAuthenticationMessage: "none",
	}, nil
}

func (a fakeNilGroupTransformer) Source() any {
	return nil // not needed for this test
}

type fakeAppendStringTransformer struct{}

func (a fakeAppendStringTransformer) Evaluate(_ctx context.Context, username string, groups []string) (*TransformationResult, error) {
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

func (a fakeAppendStringTransformer) Source() any {
	return nil // not needed for this test
}

type fakeDeleteUsernameAndGroupsTransformer struct{}

func (a fakeDeleteUsernameAndGroupsTransformer) Evaluate(_ctx context.Context, _username string, _groups []string) (*TransformationResult, error) {
	return &TransformationResult{
		Username:                      "",
		Groups:                        []string{},
		AuthenticationAllowed:         true,
		RejectedAuthenticationMessage: "none",
	}, nil
}

func (a fakeDeleteUsernameAndGroupsTransformer) Source() any {
	return nil // not needed for this test
}

type fakeAuthenticationDisallowedTransformer struct{}

func (a fakeAuthenticationDisallowedTransformer) Evaluate(_ctx context.Context, username string, groups []string) (*TransformationResult, error) {
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

func (a fakeAuthenticationDisallowedTransformer) Source() any {
	return nil // not needed for this test
}

type fakeErrorTransformer struct{}

func (a fakeErrorTransformer) Evaluate(_ctx context.Context, _username string, _groups []string) (*TransformationResult, error) {
	return &TransformationResult{}, errors.New("unexpected catastrophic error")
}

func (a fakeErrorTransformer) Source() any {
	return nil // not needed for this test
}

type fakeTransformerWithSource struct {
	source string
}

func (a fakeTransformerWithSource) Evaluate(_ctx context.Context, _username string, _groups []string) (*TransformationResult, error) {
	return nil, nil // not needed for this test
}

func (a fakeTransformerWithSource) Source() any {
	return a.source
}

func TestTransformationPipelineEvaluation(t *testing.T) {
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
				fakeAppendStringTransformer{},
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
			name: "group results are sorted and made unique",
			transforms: []IdentityTransformation{
				fakeAppendStringTransformer{},
			},
			username: "foo",
			groups: []string{
				"b",
				"a",
				"b",
				"a",
				"c",
				"b",
			},
			wantUsername: "foo:transformed",
			wantGroups: []string{
				"a:transformed",
				"b:transformed",
				"c:transformed",
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
				fakeAppendStringTransformer{},
				fakeAppendStringTransformer{},
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
				fakeAuthenticationDisallowedTransformer{},
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
				fakeAppendStringTransformer{},
				fakeAuthenticationDisallowedTransformer{},
				// this transformation will not be run because the previous exits the pipeline
				fakeAppendStringTransformer{},
			},
			wantUsername:                       "foo:transformed:disallowed",
			wantGroups:                         []string{"foobar:transformed:disallowed"},
			wantAuthenticationAllowed:          false,
			wantRejectionAuthenticationMessage: "no authentication is allowed",
		},
		{
			name:     "unexpected error at index",
			username: "foo",
			groups: []string{
				"foobar",
			},
			transforms: []IdentityTransformation{
				fakeAppendStringTransformer{},
				fakeErrorTransformer{},
				fakeAppendStringTransformer{},
			},
			wantError: "identity transformation at index 1: unexpected catastrophic error",
		},
		{
			name:     "empty username not allowed",
			username: "foo",
			transforms: []IdentityTransformation{
				fakeDeleteUsernameAndGroupsTransformer{},
			},
			wantError: "identity transformation returned an empty username, which is not allowed",
		},
		{
			name:     "whitespace username not allowed",
			username: "    \t\n\r   ",
			transforms: []IdentityTransformation{
				fakeNoopTransformer{},
			},
			wantError: "identity transformation returned an empty username, which is not allowed",
		},
		{
			name:     "identity transformation which returns an empty list of groups is allowed",
			username: "foo",
			groups:   []string{},
			transforms: []IdentityTransformation{
				fakeAppendStringTransformer{},
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
				fakeNoopTransformer{},
			},
			wantUsername:                       "foo",
			wantGroups:                         []string{},
			wantAuthenticationAllowed:          true,
			wantRejectionAuthenticationMessage: "none",
		},
		{
			name:     "any transformation returning nil for the list of groups will cause an error",
			username: "foo",
			groups: []string{
				"these.will.be.converted.to.nil",
			},
			transforms: []IdentityTransformation{
				fakeNilGroupTransformer{},
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

func TestTransformationSource(t *testing.T) {
	pipeline := NewTransformationPipeline()

	for _, transform := range []IdentityTransformation{
		&fakeTransformerWithSource{source: "foo"},
		&fakeTransformerWithSource{source: "bar"},
		&fakeTransformerWithSource{source: "baz"},
	} {
		pipeline.AppendTransformation(transform)
	}

	require.Equal(t, []any{"foo", "bar", "baz"}, pipeline.Source())
	require.NotEqual(t, []any{"foo", "something-else", "baz"}, pipeline.Source())
}
