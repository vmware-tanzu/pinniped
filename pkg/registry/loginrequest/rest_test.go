/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package loginrequest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	placeholderapi "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder"
)

type contextKey struct{}

type FakeToken struct {
	calledWithToken                       string
	calledWithContext                     context.Context
	timeout                               time.Duration
	reachedTimeout                        bool
	cancelled                             bool
	webhookStartedRunningNotificationChan chan bool
	returnResponse                        *authenticator.Response
	returnUnauthenticated                 bool
	returnErr                             error
}

func (f *FakeToken) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	f.calledWithToken = token
	f.calledWithContext = ctx
	if f.webhookStartedRunningNotificationChan != nil {
		f.webhookStartedRunningNotificationChan <- true
	}
	afterCh := time.After(f.timeout)
	select {
	case <-afterCh:
		f.reachedTimeout = true
	case <-ctx.Done():
		f.cancelled = true
	}
	return f.returnResponse, !f.returnUnauthenticated, f.returnErr
}

func callCreate(ctx context.Context, storage *REST, loginRequest *placeholderapi.LoginRequest) (runtime.Object, error) {
	return storage.Create(
		ctx,
		loginRequest,
		rest.ValidateAllObjectFunc,
		&metav1.CreateOptions{
			DryRun: []string{},
		})
}

func validLoginRequest() *placeholderapi.LoginRequest {
	return validLoginRequestWithToken("a token")
}

func validLoginRequestWithToken(token string) *placeholderapi.LoginRequest {
	return loginRequest(placeholderapi.LoginRequestSpec{
		Type:  placeholderapi.TokenLoginCredentialType,
		Token: &placeholderapi.LoginRequestTokenCredential{Value: token},
	})
}

func loginRequest(spec placeholderapi.LoginRequestSpec) *placeholderapi.LoginRequest {
	return &placeholderapi.LoginRequest{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: "request name",
		},
		Spec: spec,
	}
}

func requireAPIError(t *testing.T, response runtime.Object, err error, expectedErrorTypeChecker func(err error) bool, expectedErrorMessage string) {
	t.Helper()
	require.Nil(t, response)
	require.True(t, expectedErrorTypeChecker(err))
	var status apierrors.APIStatus
	errors.As(err, &status)
	require.Contains(t, status.Status().Message, expectedErrorMessage)
}

func emptyWebhookSuccessResponse() *authenticator.Response {
	return &authenticator.Response{User: &user.DefaultInfo{}}
}

func TestCreateSucceedsWhenGivenATokenAndTheWebhookAuthenticatesTheToken(t *testing.T) {
	webhook := FakeToken{
		returnResponse: &authenticator.Response{
			User: &user.DefaultInfo{
				Name:   "test-user",
				Groups: []string{"test-group-1", "test-group-2"},
			},
		},
		returnUnauthenticated: false,
	}
	storage := NewREST(&webhook)
	requestToken := "a token"

	response, err := callCreate(context.Background(), storage, validLoginRequestWithToken(requestToken))

	require.NoError(t, err)
	require.Equal(t, response, &placeholderapi.LoginRequest{
		Status: placeholderapi.LoginRequestStatus{
			User: &placeholderapi.User{
				Name:   "test-user",
				Groups: []string{"test-group-1", "test-group-2"},
			},
			Credential: &placeholderapi.LoginRequestCredential{
				ExpirationTimestamp:   nil,
				Token:                 "snorlax",
				ClientCertificateData: "",
				ClientKeyData:         "",
			},
			Message: "",
		},
	})
	require.Equal(t, requestToken, webhook.calledWithToken)
}

func TestCreateSucceedsWithAnUnauthenticatedStatusWhenGivenATokenAndTheWebhookDoesNotAuthenticateTheToken(t *testing.T) {
	webhook := FakeToken{
		returnUnauthenticated: true,
	}
	storage := NewREST(&webhook)
	requestToken := "a token"

	response, err := callCreate(context.Background(), storage, validLoginRequestWithToken(requestToken))

	require.NoError(t, err)
	require.Equal(t, response, &placeholderapi.LoginRequest{
		Status: placeholderapi.LoginRequestStatus{
			Credential: nil,
			Message:    "authentication failed",
		},
	})
	require.Equal(t, requestToken, webhook.calledWithToken)
}

func TestCreateSucceedsWithAnUnauthenticatedStatusWhenWebhookFails(t *testing.T) {
	webhook := FakeToken{
		returnErr: errors.New("some webhook error"),
	}
	storage := NewREST(&webhook)

	response, err := callCreate(context.Background(), storage, validLoginRequest())

	require.NoError(t, err)
	require.Equal(t, response, &placeholderapi.LoginRequest{
		Status: placeholderapi.LoginRequestStatus{
			Credential: nil,
			Message:    "authentication failed",
		},
	})
}

func TestCreateDoesNotPassAdditionalContextInfoToTheWebhook(t *testing.T) {
	webhook := FakeToken{
		returnResponse: emptyWebhookSuccessResponse(),
	}
	storage := NewREST(&webhook)
	ctx := context.WithValue(context.Background(), contextKey{}, "context-value")

	_, err := callCreate(ctx, storage, validLoginRequest())

	require.NoError(t, err)
	require.Nil(t, webhook.calledWithContext.Value("context-key"))
}

func TestCreateFailsWhenGivenTheWrongInputType(t *testing.T) {
	notALoginRequest := runtime.Unknown{}
	response, err := NewREST(&FakeToken{}).Create(
		genericapirequest.NewContext(),
		&notALoginRequest,
		rest.ValidateAllObjectFunc,
		&metav1.CreateOptions{})

	requireAPIError(t, response, err, apierrors.IsBadRequest, "not a LoginRequest")
}

func TestCreateFailsWhenTokenIsNilInRequest(t *testing.T) {
	storage := NewREST(&FakeToken{})
	response, err := callCreate(context.Background(), storage, loginRequest(placeholderapi.LoginRequestSpec{
		Type:  placeholderapi.TokenLoginCredentialType,
		Token: nil,
	}))

	requireAPIError(t, response, err, apierrors.IsInvalid,
		`.placeholder.suzerain-io.github.io "request name" is invalid: spec.token.value: Required value: token must be supplied`)
}

func TestCreateFailsWhenTypeInRequestIsMissing(t *testing.T) {
	storage := NewREST(&FakeToken{})
	response, err := callCreate(context.Background(), storage, loginRequest(placeholderapi.LoginRequestSpec{
		Type:  "",
		Token: &placeholderapi.LoginRequestTokenCredential{Value: "a token"},
	}))

	requireAPIError(t, response, err, apierrors.IsInvalid,
		`.placeholder.suzerain-io.github.io "request name" is invalid: spec.type: Required value: type must be supplied`)
}

func TestCreateFailsWhenTypeInRequestIsNotLegal(t *testing.T) {
	storage := NewREST(&FakeToken{})
	response, err := callCreate(context.Background(), storage, loginRequest(placeholderapi.LoginRequestSpec{
		Type:  "this in an invalid type",
		Token: &placeholderapi.LoginRequestTokenCredential{Value: "a token"},
	}))

	requireAPIError(t, response, err, apierrors.IsInvalid,
		`.placeholder.suzerain-io.github.io "request name" is invalid: spec.type: Invalid value: "this in an invalid type": unrecognized type`)
}

func TestCreateFailsWhenTokenValueIsEmptyInRequest(t *testing.T) {
	storage := NewREST(&FakeToken{})
	response, err := callCreate(context.Background(), storage, loginRequest(placeholderapi.LoginRequestSpec{
		Type:  placeholderapi.TokenLoginCredentialType,
		Token: &placeholderapi.LoginRequestTokenCredential{Value: ""},
	}))

	requireAPIError(t, response, err, apierrors.IsInvalid,
		`.placeholder.suzerain-io.github.io "request name" is invalid: spec.token.value: Required value: token must be supplied`)
}

func TestCreateFailsWhenRequestOptionsDryRunIsNotEmpty(t *testing.T) {
	response, err := NewREST(&FakeToken{}).Create(
		genericapirequest.NewContext(),
		validLoginRequest(),
		rest.ValidateAllObjectFunc,
		&metav1.CreateOptions{
			DryRun: []string{"some dry run flag"},
		})

	requireAPIError(t, response, err, apierrors.IsInvalid,
		`.placeholder.suzerain-io.github.io "request name" is invalid: dryRun: Unsupported value: []string{"some dry run flag"}`)
}

func TestCreateCancelsTheWebhookInvocationWhenTheCallToCreateIsCancelledItself(t *testing.T) {
	webhookStartedRunningNotificationChan := make(chan bool)
	webhook := FakeToken{
		timeout:                               time.Second * 2,
		webhookStartedRunningNotificationChan: webhookStartedRunningNotificationChan,
		returnResponse:                        emptyWebhookSuccessResponse(),
	}
	storage := NewREST(&webhook)
	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan bool)
	go func() {
		_, err := callCreate(ctx, storage, validLoginRequest())
		c <- true
		require.NoError(t, err)
	}()

	require.False(t, webhook.cancelled)
	require.False(t, webhook.reachedTimeout)
	<-webhookStartedRunningNotificationChan // wait long enough to make sure that the webhook has started
	cancel()                                // cancel the context that was passed to storage.Create() above
	<-c                                     // wait for the above call to storage.Create() to be finished
	require.True(t, webhook.cancelled)
	require.False(t, webhook.reachedTimeout)
	require.Equal(t, context.Canceled, webhook.calledWithContext.Err()) // the inner context is cancelled
}

func TestCreateAllowsTheWebhookInvocationToFinishWhenTheCallToCreateIsNotCancelledItself(t *testing.T) {
	webhookStartedRunningNotificationChan := make(chan bool)
	webhook := FakeToken{
		timeout:                               0,
		webhookStartedRunningNotificationChan: webhookStartedRunningNotificationChan,
		returnResponse:                        emptyWebhookSuccessResponse(),
	}
	storage := NewREST(&webhook)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan bool)
	go func() {
		_, err := callCreate(ctx, storage, validLoginRequest())
		c <- true
		require.NoError(t, err)
	}()

	require.False(t, webhook.cancelled)
	require.False(t, webhook.reachedTimeout)
	<-webhookStartedRunningNotificationChan // wait long enough to make sure that the webhook has started
	<-c                                     // wait for the above call to storage.Create() to be finished
	require.False(t, webhook.cancelled)
	require.True(t, webhook.reachedTimeout)
	require.Equal(t, context.Canceled, webhook.calledWithContext.Err()) // the inner context is cancelled (in this case by the "defer")
}
