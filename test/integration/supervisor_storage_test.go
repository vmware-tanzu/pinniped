// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/federationdomain/clientregistry"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/test/testlib"
)

func TestAuthorizeCodeStorage(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	client := testlib.NewKubernetesClientset(t)

	const (
		// randomly generated HMAC authorization code (see below)
		code = "TQ72B8YjdEOZyxridYbTLE-pzoK4hpdkZxym5j4EmSc.TKRTgQG41IBQ16FDKTthRdhXfLlNaErcMd9Fy47uXAw"
		// name of the secret that will be created in Kube
		name = "pinniped-storage-authcode-jssfhaibxdkiaugxufbsso3bixmfo7fzjvuevxbr35c4xdxolqga"
	)

	hmac := compose.NewOAuth2HMACStrategy(&fosite.Config{GlobalSecret: []byte("super-secret-32-byte-for-testing")})
	// test data generation via:
	// code, signature, err := hmac.GenerateAuthorizeCode(ctx, nil)
	signature := hmac.AuthorizeCodeSignature(context.Background(), code)

	secrets := client.CoreV1().Secrets(env.SupervisorNamespace)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := secrets.Delete(ctx, name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	sessionStorageLifetime := 5 * time.Minute
	storage := authorizationcode.New(secrets, time.Now, sessionStorageLifetime)

	// the session for this signature should not exist yet
	notFoundRequest, err := storage.GetAuthorizeCodeSession(ctx, signature, nil)
	require.Error(t, err)
	require.True(t, stderrors.Is(err, fosite.ErrNotFound))
	require.Nil(t, notFoundRequest)

	// Create a fake session to store below. Fill in a few fields to make sure we can get them back.
	session := authorizationcode.NewValidEmptyAuthorizeCodeSession()
	session.Request = &fosite.Request{
		ID:          "abcd-1",
		RequestedAt: time.Time{},
		Client: &clientregistry.Client{
			DefaultOpenIDConnectClient: fosite.DefaultOpenIDConnectClient{
				DefaultClient: &fosite.DefaultClient{
					ID: "pinny",
				},
				JSONWebKeysURI:          "where",
				TokenEndpointAuthMethod: "something",
			},
		},
		Session: testutil.NewFakePinnipedSession(),
	}

	err = storage.CreateAuthorizeCodeSession(ctx, signature, session.Request)
	require.NoError(t, err)

	// trying to create the session again fails because it already exists
	err = storage.CreateAuthorizeCodeSession(ctx, signature, session.Request)
	require.Error(t, err)
	require.True(t, errors.IsAlreadyExists(err))

	// check that the data stored in Kube matches what we put in
	initialSecret, err := secrets.Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	// Note that CreateAuthorizeCodeSession() sets Active to true and also sets the Version before storing the session,
	// so expect those here.
	session.Active = true
	session.Version = "6" // this is the value of the authorizationcode.authorizeCodeStorageVersion constant
	expectedSessionStorageJSON, err := json.Marshal(session)
	require.NoError(t, err)
	require.JSONEq(t, string(expectedSessionStorageJSON), string(initialSecret.Data["pinniped-storage-data"]))

	// check that the Secret got the expected annotations
	actualGCAfterValue := initialSecret.Annotations["storage.pinniped.dev/garbage-collect-after"]
	require.NotEmpty(t, actualGCAfterValue)
	parsedActualGCAfterValue, err := time.Parse(time.RFC3339, actualGCAfterValue)
	require.NoError(t, err)
	testutil.RequireTimeInDelta(t, time.Now().Add(sessionStorageLifetime), parsedActualGCAfterValue, 30*time.Second)

	// check that the Secret got the right labels
	require.Equal(t, map[string]string{"storage.pinniped.dev/type": "authcode"}, initialSecret.Labels)

	// check that the Secret got the right type
	require.Equal(t, corev1.SecretType("storage.pinniped.dev/authcode"), initialSecret.Type)

	// we should be able to get the session now and the request should be the same as what we put in
	request, err := storage.GetAuthorizeCodeSession(ctx, signature, nil)
	require.NoError(t, err)
	require.Equal(t, session.Request, request)

	// simulate the authorization code being exchanged
	err = storage.InvalidateAuthorizeCodeSession(ctx, signature)
	require.NoError(t, err)

	// trying to get the authcode session after it was invalidated should fail
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
	// InvalidateAuthorizeCodeSession() sets Active to false, so update the expected value accordingly.
	session.Active = false
	expectedInvalidatedJSON, err := json.Marshal(session)
	require.NoError(t, err)
	require.JSONEq(t, string(expectedInvalidatedJSON), string(invalidatedSecret.Data["pinniped-storage-data"]))
}
