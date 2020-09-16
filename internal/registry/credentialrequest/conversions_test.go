// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package credentialrequest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	loginapi "github.com/suzerain-io/pinniped/generated/1.19/apis/login"
	pinnipedapi "github.com/suzerain-io/pinniped/generated/1.19/apis/pinniped"
)

func TestConversions(t *testing.T) {
	now := time.Now()
	errMsg := "some error message"

	tests := []struct {
		name string
		new  *loginapi.TokenCredentialRequest
		old  *pinnipedapi.CredentialRequest
	}{
		{
			name: "nil input",
		},
		{
			name: "usual request",
			new: &loginapi.TokenCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-object",
				},
				Spec: loginapi.TokenCredentialRequestSpec{Token: "test-token"},
			},
			old: &pinnipedapi.CredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-object",
				},
				Spec: pinnipedapi.CredentialRequestSpec{
					Type:  pinnipedapi.TokenCredentialType,
					Token: &pinnipedapi.CredentialRequestTokenCredential{Value: "test-token"},
				},
			},
		},
		{
			name: "usual response",
			new: &loginapi.TokenCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-object",
				},
				Status: loginapi.TokenCredentialRequestStatus{
					Credential: &loginapi.ClusterCredential{
						ExpirationTimestamp:   metav1.NewTime(now),
						Token:                 "test-cluster-token",
						ClientCertificateData: "test-cluster-cert",
						ClientKeyData:         "test-cluster-key",
					},
				},
			},
			old: &pinnipedapi.CredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-object",
				},
				Status: pinnipedapi.CredentialRequestStatus{
					Credential: &pinnipedapi.CredentialRequestCredential{
						ExpirationTimestamp:   metav1.NewTime(now),
						Token:                 "test-cluster-token",
						ClientCertificateData: "test-cluster-cert",
						ClientKeyData:         "test-cluster-key",
					},
				},
			},
		},
		{
			name: "error response",
			new: &loginapi.TokenCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-object",
				},
				Status: loginapi.TokenCredentialRequestStatus{
					Message: &errMsg,
				},
			},
			old: &pinnipedapi.CredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-object",
				},
				Status: pinnipedapi.CredentialRequestStatus{
					Message: &errMsg,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Run("upgrade", func(t *testing.T) {
				require.Equal(t, tt.new, convertToLoginAPI(tt.old))
			})
			t.Run("downgrade", func(t *testing.T) {
				require.Equal(t, tt.old, convertFromLoginAPI(tt.new))
			})
			t.Run("roundtrip", func(t *testing.T) {
				require.Equal(t, tt.old, convertFromLoginAPI(convertToLoginAPI(tt.old)))
				require.Equal(t, tt.new, convertToLoginAPI(convertFromLoginAPI(tt.new)))
			})
		})
	}
}
