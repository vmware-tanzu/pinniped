// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/test/library"
)

func TestAuthorizeCodeStorage(t *testing.T) {
	env := library.IntegrationEnv(t)
	client := library.NewKubernetesClientset(t)

	const (
		// randomly generated HMAC authorization code (see below)
		code = "TQ72B8YjdEOZyxridYbTLE-pzoK4hpdkZxym5j4EmSc.TKRTgQG41IBQ16FDKTthRdhXfLlNaErcMd9Fy47uXAw"
		// name of the secret that will be created in Kube
		name = "pinniped-storage-authcode-jssfhaibxdkiaugxufbsso3bixmfo7fzjvuevxbr35c4xdxolqga"
	)

	hmac := compose.NewOAuth2HMACStrategy(&compose.Config{}, []byte("super-secret-32-byte-for-testing"), nil)
	// test data generation via:
	// code, signature, err := hmac.GenerateAuthorizeCode(ctx, nil)
	signature := hmac.AuthorizeCodeSignature(code)

	secrets := client.CoreV1().Secrets(env.SupervisorNamespace)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := secrets.Delete(ctx, name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// get a session with most of the data filled out
	session := authorizationcode.NewValidEmptyAuthorizeCodeSession()
	err := json.Unmarshal([]byte(authorizationcode.ExpectedAuthorizeCodeSessionJSONFromFuzzing), session)
	require.NoError(t, err)

	sessionStorageLifetime := 5 * time.Minute
	storage := authorizationcode.New(secrets, time.Now, sessionStorageLifetime)

	// the session for this signature should not exist yet
	notFoundRequest, err := storage.GetAuthorizeCodeSession(ctx, signature, nil)
	require.Error(t, err)
	require.True(t, stderrors.Is(err, fosite.ErrNotFound))
	require.Nil(t, notFoundRequest)

	err = storage.CreateAuthorizeCodeSession(ctx, signature, session.Request)
	require.NoError(t, err)

	// trying to create the session again fails because it already exists
	err = storage.CreateAuthorizeCodeSession(ctx, signature, session.Request)
	require.Error(t, err)
	require.True(t, errors.IsAlreadyExists(err))

	// check that the data stored in Kube matches what we put in
	initialSecret, err := secrets.Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	require.JSONEq(t, authorizationcode.ExpectedAuthorizeCodeSessionJSONFromFuzzing, string(initialSecret.Data["pinniped-storage-data"]))

	// check that the Secret got the expected annotations
	actualGCAfterValue := initialSecret.Annotations["storage.pinniped.dev/garbage-collect-after"]
	require.NotEmpty(t, actualGCAfterValue)
	parsedActualGCAfterValue, err := time.Parse(time.RFC3339, actualGCAfterValue)
	require.NoError(t, err)
	testutil.RequireTimeInDelta(t, time.Now().Add(sessionStorageLifetime), parsedActualGCAfterValue, 30*time.Second)

	// check that the Secret got the right labels
	require.Equal(t, map[string]string{"storage.pinniped.dev/type": "authcode"}, initialSecret.Labels)

	// check that the Secret got the right type
	require.Equal(t, v1.SecretType("storage.pinniped.dev/authcode"), initialSecret.Type)

	// we should be able to get the session now and the request should be the same as what we put in
	request, err := storage.GetAuthorizeCodeSession(ctx, signature, nil)
	require.NoError(t, err)
	require.Equal(t, session.Request, request)

	// simulate the authorization code being exchanged
	err = storage.InvalidateAuthorizeCodeSession(ctx, signature)
	require.NoError(t, err)

	// trying to use the code session more than once should fail
	// getting an invalidated session should return an error and the request
	invalidatedRequest, err := storage.GetAuthorizeCodeSession(ctx, signature, nil)
	require.Error(t, err)
	require.True(t, stderrors.Is(err, fosite.ErrInvalidatedAuthorizeCode))
	require.Equal(t, session.Request, invalidatedRequest)

	// trying to use the code session more than once should fail
	err = storage.InvalidateAuthorizeCodeSession(ctx, signature)
	require.Error(t, err)
	require.True(t, stderrors.Is(err, fosite.ErrInvalidatedAuthorizeCode))

	// the data stored in Kube should be exactly the same but it should be marked as used
	invalidatedSecret, err := secrets.Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	expectedInvalidatedJSON := strings.Replace(authorizationcode.ExpectedAuthorizeCodeSessionJSONFromFuzzing,
		`"active": true,`, `"active": false,`, 1)
	require.JSONEq(t, expectedInvalidatedJSON, string(invalidatedSecret.Data["pinniped-storage-data"]))
}
