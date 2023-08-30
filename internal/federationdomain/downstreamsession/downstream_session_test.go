// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package downstreamsession

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/celtransformer"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/testutil/oidctestutil"
)

func TestMapAdditionalClaimsFromUpstreamIDToken(t *testing.T) {
	tests := []struct {
		name                    string
		additionalClaimMappings map[string]string
		upstreamClaims          map[string]interface{}
		wantClaims              map[string]interface{}
	}{
		{
			name: "happy path",
			additionalClaimMappings: map[string]string{
				"email": "notification_email",
			},
			upstreamClaims: map[string]interface{}{
				"notification_email": "test@example.com",
			},
			wantClaims: map[string]interface{}{
				"email": "test@example.com",
			},
		},
		{
			name: "missing",
			additionalClaimMappings: map[string]string{
				"email": "email",
			},
			upstreamClaims: map[string]interface{}{},
			wantClaims:     map[string]interface{}{},
		},
		{
			name: "complex",
			additionalClaimMappings: map[string]string{
				"complex": "complex",
			},
			upstreamClaims: map[string]interface{}{
				"complex": map[string]string{
					"subClaim": "subValue",
				},
			},
			wantClaims: map[string]interface{}{
				"complex": map[string]string{
					"subClaim": "subValue",
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			idp := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
				WithAdditionalClaimMappings(test.additionalClaimMappings).
				Build()
			actual := MapAdditionalClaimsFromUpstreamIDToken(idp, test.upstreamClaims)

			require.Equal(t, test.wantClaims, actual)
		})
	}
}

func TestApplyIdentityTransformations(t *testing.T) {
	tests := []struct {
		name         string
		transforms   []celtransformer.CELTransformation
		username     string
		groups       []string
		wantUsername string
		wantGroups   []string
		wantErr      string
	}{
		{
			name: "unexpected errors",
			transforms: []celtransformer.CELTransformation{
				&celtransformer.UsernameTransformation{Expression: `""`},
			},
			username: "ryan",
			groups:   []string{"a", "b"},
			wantErr:  "configured identity transformation or policy resulted in unexpected error",
		},
		{
			name: "auth disallowed by policy with implicit rejection message",
			transforms: []celtransformer.CELTransformation{
				&celtransformer.AllowAuthenticationPolicy{Expression: `false`},
			},
			username: "ryan",
			groups:   []string{"a", "b"},
			wantErr:  "configured identity policy rejected this authentication: authentication was rejected by a configured policy",
		},
		{
			name: "auth disallowed by policy with explicit rejection message",
			transforms: []celtransformer.CELTransformation{
				&celtransformer.AllowAuthenticationPolicy{
					Expression:                    `false`,
					RejectedAuthenticationMessage: "this is the stated reason",
				},
			},
			username: "ryan",
			groups:   []string{"a", "b"},
			wantErr:  "configured identity policy rejected this authentication: this is the stated reason",
		},
		{
			name: "successful auth",
			transforms: []celtransformer.CELTransformation{
				&celtransformer.UsernameTransformation{Expression: `"pre:" + username`},
				&celtransformer.GroupsTransformation{Expression: `groups.map(g, "pre:" + g)`},
			},
			username:     "ryan",
			groups:       []string{"a", "b"},
			wantUsername: "pre:ryan",
			wantGroups:   []string{"pre:a", "pre:b"},
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transformer, err := celtransformer.NewCELTransformer(5 * time.Second)
			require.NoError(t, err)

			pipeline := idtransform.NewTransformationPipeline()
			for _, transform := range tt.transforms {
				compiledTransform, err := transformer.CompileTransformation(transform, nil)
				require.NoError(t, err)
				pipeline.AppendTransformation(compiledTransform)
			}

			gotUsername, gotGroups, err := ApplyIdentityTransformations(context.Background(), pipeline, tt.username, tt.groups)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Empty(t, gotUsername)
				require.Nil(t, gotGroups)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantUsername, gotUsername)
				require.Equal(t, tt.wantGroups, gotGroups)
			}
		})
	}
}

func TestDownstreamLDAPSubject(t *testing.T) {
	tests := []struct {
		name           string
		uid            string
		ldapURL        string
		idpDisplayName string
		wantSubject    string
	}{
		{
			name:           "simple display name",
			uid:            "some uid",
			ldapURL:        "ldaps://server.example.com:1234",
			idpDisplayName: "simpleName",
			wantSubject:    "ldaps://server.example.com:1234?idpName=simpleName&sub=some+uid",
		},
		{
			name:           "interesting display name",
			uid:            "some uid",
			ldapURL:        "ldaps://server.example.com:1234",
			idpDisplayName: "this is a 👍 display name that 🦭 can handle",
			wantSubject:    "ldaps://server.example.com:1234?idpName=this+is+a+%F0%9F%91%8D+display+name+that+%F0%9F%A6%AD+can+handle&sub=some+uid",
		},
		{
			name:           "url already has query",
			uid:            "some uid",
			ldapURL:        "ldaps://server.example.com:1234?a=1&b=%F0%9F%A6%AD",
			idpDisplayName: "some name",
			wantSubject:    "ldaps://server.example.com:1234?a=1&b=%F0%9F%A6%AD&idpName=some+name&sub=some+uid",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			url, err := url.Parse(test.ldapURL)
			require.NoError(t, err)

			actual := DownstreamLDAPSubject(test.uid, *url, test.idpDisplayName)

			require.Equal(t, test.wantSubject, actual)
		})
	}
}

func TestDownstreamSubjectFromUpstreamOIDC(t *testing.T) {
	tests := []struct {
		name                   string
		upstreamIssuerAsString string
		upstreamSubject        string
		idpDisplayName         string
		wantSubject            string
	}{
		{
			name:                   "simple display name",
			upstreamIssuerAsString: "https://server.example.com:1234/path",
			upstreamSubject:        "some subject",
			idpDisplayName:         "simpleName",
			wantSubject:            "https://server.example.com:1234/path?idpName=simpleName&sub=some+subject",
		},
		{
			name:                   "interesting display name",
			upstreamIssuerAsString: "https://server.example.com:1234/path",
			upstreamSubject:        "some subject",
			idpDisplayName:         "this is a 👍 display name that 🦭 can handle",
			wantSubject:            "https://server.example.com:1234/path?idpName=this+is+a+%F0%9F%91%8D+display+name+that+%F0%9F%A6%AD+can+handle&sub=some+subject",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual := downstreamSubjectFromUpstreamOIDC(test.upstreamIssuerAsString, test.upstreamSubject, test.idpDisplayName)

			require.Equal(t, test.wantSubject, actual)
		})
	}
}

func TestDownstreamUsernameFromUpstreamOIDCSubject(t *testing.T) {
	tests := []struct {
		name                   string
		upstreamIssuerAsString string
		upstreamSubject        string
		wantSubject            string
	}{
		{
			name:                   "simple upstreamSubject",
			upstreamIssuerAsString: "https://server.example.com:1234/path",
			upstreamSubject:        "some subject",
			wantSubject:            "https://server.example.com:1234/path?sub=some+subject",
		},
		{
			name:                   "interesting upstreamSubject",
			upstreamIssuerAsString: "https://server.example.com:1234/path",
			upstreamSubject:        "this is a 👍 subject that 🦭 can handle",
			wantSubject:            "https://server.example.com:1234/path?sub=this+is+a+%F0%9F%91%8D+subject+that+%F0%9F%A6%AD+can+handle",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual := downstreamUsernameFromUpstreamOIDCSubject(test.upstreamIssuerAsString, test.upstreamSubject)

			require.Equal(t, test.wantSubject, actual)
		})
	}
}
