// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuer

import (
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"go.pinniped.dev/internal/mocks/issuermocks"
)

func TestName(t *testing.T) {
	ctrl := gomock.NewController(t)

	tests := []struct {
		name             string
		buildIssuerMocks func() ClientCertIssuers
		want             string
	}{
		{
			name:             "empty issuers",
			buildIssuerMocks: func() ClientCertIssuers { return ClientCertIssuers{} },
			want:             "empty-client-cert-issuers",
		},
		{
			name: "foo issuer",
			buildIssuerMocks: func() ClientCertIssuers {
				fooClientCertIssuer := issuermocks.NewMockClientCertIssuer(ctrl)
				fooClientCertIssuer.EXPECT().Name().Return("foo")

				return ClientCertIssuers{fooClientCertIssuer}
			},
			want: "foo",
		},
		{
			name: "foo and bar issuers",
			buildIssuerMocks: func() ClientCertIssuers {
				fooClientCertIssuer := issuermocks.NewMockClientCertIssuer(ctrl)
				fooClientCertIssuer.EXPECT().Name().Return("foo")

				barClientCertIssuer := issuermocks.NewMockClientCertIssuer(ctrl)
				barClientCertIssuer.EXPECT().Name().Return("bar")

				return ClientCertIssuers{fooClientCertIssuer, barClientCertIssuer}
			},
			want: "foo,bar",
		},
	}

	for _, tTemp := range tests {
		testcase := tTemp
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()

			name := testcase.buildIssuerMocks().Name()
			require.Equal(t, testcase.want, name)
		})
	}
}

func TestIssueClientCertPEM(t *testing.T) {
	ctrl := gomock.NewController(t)

	tests := []struct {
		name             string
		buildIssuerMocks func() ClientCertIssuers
		wantErrorMessage string
		wantCert         []byte
		wantKey          []byte
	}{
		{
			name:             "empty issuers",
			buildIssuerMocks: func() ClientCertIssuers { return ClientCertIssuers{} },
			wantErrorMessage: "failed to issue cert",
		},
		{
			name: "issuers with error",
			buildIssuerMocks: func() ClientCertIssuers {
				errClientCertIssuer := issuermocks.NewMockClientCertIssuer(ctrl)
				errClientCertIssuer.EXPECT().Name().Return("error cert issuer")
				errClientCertIssuer.EXPECT().
					IssueClientCertPEM("username", []string{"group1", "group2"}, 32*time.Second).
					Return(nil, nil, errors.New("error from wrapped cert issuer"))
				return ClientCertIssuers{errClientCertIssuer}
			},
			wantErrorMessage: "error cert issuer failed to issue client cert: error from wrapped cert issuer",
		},
		{
			name: "valid issuer",
			buildIssuerMocks: func() ClientCertIssuers {
				validClientCertIssuer := issuermocks.NewMockClientCertIssuer(ctrl)
				validClientCertIssuer.EXPECT().
					IssueClientCertPEM("username", []string{"group1", "group2"}, 32*time.Second).
					Return([]byte("cert"), []byte("key"), nil)
				return ClientCertIssuers{validClientCertIssuer}
			},
			wantCert: []byte("cert"),
			wantKey:  []byte("key"),
		},
		{
			name: "fallthrough issuer",
			buildIssuerMocks: func() ClientCertIssuers {
				errClientCertIssuer := issuermocks.NewMockClientCertIssuer(ctrl)
				errClientCertIssuer.EXPECT().Name().Return("error cert issuer")
				errClientCertIssuer.EXPECT().
					IssueClientCertPEM("username", []string{"group1", "group2"}, 32*time.Second).
					Return(nil, nil, errors.New("error from wrapped cert issuer"))

				validClientCertIssuer := issuermocks.NewMockClientCertIssuer(ctrl)
				validClientCertIssuer.EXPECT().
					IssueClientCertPEM("username", []string{"group1", "group2"}, 32*time.Second).
					Return([]byte("cert"), []byte("key"), nil)
				return ClientCertIssuers{
					errClientCertIssuer,
					validClientCertIssuer,
				}
			},
			wantCert: []byte("cert"),
			wantKey:  []byte("key"),
		},
		{
			name: "multiple error issuers",
			buildIssuerMocks: func() ClientCertIssuers {
				err1ClientCertIssuer := issuermocks.NewMockClientCertIssuer(ctrl)
				err1ClientCertIssuer.EXPECT().Name().Return("error1 cert issuer")
				err1ClientCertIssuer.EXPECT().
					IssueClientCertPEM("username", []string{"group1", "group2"}, 32*time.Second).
					Return(nil, nil, errors.New("error1 from wrapped cert issuer"))

				err2ClientCertIssuer := issuermocks.NewMockClientCertIssuer(ctrl)
				err2ClientCertIssuer.EXPECT().Name().Return("error2 cert issuer")
				err2ClientCertIssuer.EXPECT().
					IssueClientCertPEM("username", []string{"group1", "group2"}, 32*time.Second).
					Return(nil, nil, errors.New("error2 from wrapped cert issuer"))

				return ClientCertIssuers{
					err1ClientCertIssuer,
					err2ClientCertIssuer,
				}
			},
			wantErrorMessage: "[error1 cert issuer failed to issue client cert: error1 from wrapped cert issuer, error2 cert issuer failed to issue client cert: error2 from wrapped cert issuer]",
		},
	}

	for _, tTemp := range tests {
		testcase := tTemp
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()

			certPEM, keyPEM, err := testcase.buildIssuerMocks().
				IssueClientCertPEM("username", []string{"group1", "group2"}, 32*time.Second)

			if testcase.wantErrorMessage != "" {
				require.ErrorContains(t, err, testcase.wantErrorMessage)
				require.Empty(t, certPEM)
				require.Empty(t, keyPEM)
			} else {
				require.NoError(t, err)
				require.Equal(t, testcase.wantCert, certPEM)
				require.Equal(t, testcase.wantKey, keyPEM)
			}
		})
	}
}
