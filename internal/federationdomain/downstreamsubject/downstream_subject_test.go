// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package downstreamsubject

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLDAP(t *testing.T) {
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
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			u, err := url.Parse(test.ldapURL)
			require.NoError(t, err)

			actual := LDAP(test.uid, *u, test.idpDisplayName)

			require.Equal(t, test.wantSubject, actual)
		})
	}
}

func TestOIDC(t *testing.T) {
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
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual := OIDC(test.upstreamIssuerAsString, test.upstreamSubject, test.idpDisplayName)

			require.Equal(t, test.wantSubject, actual)
		})
	}
}

func TestGitHub(t *testing.T) {
	tests := []struct {
		name           string
		apiBaseURL     string
		idpDisplayName string
		login          string
		id             string
		wantSubject    string
	}{
		{
			name:           "simple display name",
			apiBaseURL:     "https://github.com",
			idpDisplayName: "simpleName",
			login:          "some login",
			id:             "some id",
			wantSubject:    "https://github.com?idpName=simpleName&login=some+login&id=some+id",
		},
		{
			name:           "interesting display name",
			apiBaseURL:     "https://server.example.com:1234/path",
			idpDisplayName: "this is a 👍 display name that 🦭 can handle",
			login:          "some other login",
			id:             "some other id",
			wantSubject:    "https://server.example.com:1234/path?idpName=this+is+a+%F0%9F%91%8D+display+name+that+%F0%9F%A6%AD+can+handle&login=some+other+login&id=some+other+id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual := GitHub(test.apiBaseURL, test.idpDisplayName, test.login, test.id)

			require.Equal(t, test.wantSubject, actual)
		})
	}
}
