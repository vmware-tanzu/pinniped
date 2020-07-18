/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/test/library"
)

func makeRequest(t *testing.T, spec v1alpha1.LoginRequestSpec) (*v1alpha1.LoginRequest, error) {
	t.Helper()

	client := library.NewPlaceholderNameClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return client.PlaceholderV1alpha1().LoginRequests().Create(ctx, &v1alpha1.LoginRequest{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{},
		Spec:       spec,
	}, metav1.CreateOptions{})
}

func TestSuccessfulLoginRequest(t *testing.T) {
	response, err := makeRequest(t, v1alpha1.LoginRequestSpec{
		Token: &v1alpha1.LoginRequestTokenCredential{Value: "token-value"},
	})

	require.NoError(t, err)

	require.Empty(t, response.Spec)
	require.Equal(t, "snorlax", response.Status.Token)
	require.Empty(t, response.Status.ClientCertificateData)
	require.Empty(t, response.Status.ClientKeyData)
	require.Nil(t, response.Status.ExpirationTimestamp)
}

func TestLoginRequest_ShouldFailWhenRequestDoesNotIncludeToken(t *testing.T) {
	_, err := makeRequest(t, v1alpha1.LoginRequestSpec{})

	require.Error(t, err)
	statusError, isStatus := err.(*errors.StatusError)
	require.True(t, isStatus)

	require.Equal(t, 1, len(statusError.ErrStatus.Details.Causes))
	cause := statusError.ErrStatus.Details.Causes[0]
	require.Equal(t, metav1.CauseType("FieldValueRequired"), cause.Type)
	require.Equal(t, "Required value: token must be supplied", cause.Message)
	require.Equal(t, "spec.token.value", cause.Field)
}

// TODO test that a dry run request fails with our error message
