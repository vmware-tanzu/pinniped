/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"encoding/json"
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

func TestGetDiscovery(t *testing.T) {
	client := library.NewPlaceholderNameClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.Discovery().RESTClient().Get().Do(ctx).Raw()
	require.NoError(t, err)

	var parsedResult map[string]interface{}
	err = json.Unmarshal(result, &parsedResult)
	require.NoError(t, err)
	require.Contains(t, parsedResult["paths"], "/apis/placeholder.suzerain-io.github.io")
	require.Contains(t, parsedResult["paths"], "/apis/placeholder.suzerain-io.github.io/v1alpha1")
}

func TestGetApiResourceList(t *testing.T) {
	var expectedAPIResourceList = `{
	  "kind": "APIResourceList",
	  "apiVersion": "v1",
	  "groupVersion": "placeholder.suzerain-io.github.io/v1alpha1",
	  "resources": [
		{
		  "name": "loginrequests",
		  "singularName": "",
		  "namespaced": false,
		  "kind": "LoginRequest",
		  "verbs": [
			"create"
		  ]
		}
	  ]
	}`

	client := library.NewPlaceholderNameClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.PlaceholderV1alpha1().RESTClient().Get().Do(ctx).Raw()
	require.NoError(t, err)
	require.JSONEq(t, expectedAPIResourceList, string(result))
}
