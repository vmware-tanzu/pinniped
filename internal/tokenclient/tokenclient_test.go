// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokenclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	"go.pinniped.dev/internal/plog"
)

//nolint:gochecknoglobals // just some test helper stuff here
var (
	verb     = "create"
	resource = "serviceaccounts/token"
)

func TestNew(t *testing.T) {
	mockWhatToDoWithTokenFunc := *new(WhatToDoWithTokenFunc)
	mockClient := fake.NewSimpleClientset().CoreV1().ServiceAccounts("")
	mockTime := time.Now()
	mockClock := clocktesting.NewFakeClock(mockTime)
	var log bytes.Buffer
	testLogger := plog.TestLogger(t, &log)

	type args struct {
		serviceAccountName   string
		serviceAccountClient corev1client.ServiceAccountInterface
		whatToDoWithToken    WhatToDoWithTokenFunc
		logger               plog.Logger
		opts                 []Opt
	}

	tests := []struct {
		name     string
		args     args
		expected *TokenClient
	}{
		{
			name: "defaults",
			args: args{
				serviceAccountName:   "serviceAccountName",
				serviceAccountClient: mockClient,
				whatToDoWithToken:    mockWhatToDoWithTokenFunc,
				logger:               testLogger,
			},
			expected: &TokenClient{
				serviceAccountName:   "serviceAccountName",
				serviceAccountClient: mockClient,
				whatToDoWithToken:    mockWhatToDoWithTokenFunc,
				expirationSeconds:    600,
				clock:                clock.RealClock{},
				logger:               testLogger,
			},
		},
		{
			name: "with all opts",
			args: args{
				serviceAccountName:   "custom-serviceAccountName",
				serviceAccountClient: mockClient,
				whatToDoWithToken:    mockWhatToDoWithTokenFunc,
				logger:               testLogger,
				opts: []Opt{
					WithExpirationSeconds(777),
					withClock(mockClock),
				},
			},
			expected: &TokenClient{
				serviceAccountName:   "custom-serviceAccountName",
				serviceAccountClient: mockClient,
				whatToDoWithToken:    mockWhatToDoWithTokenFunc,
				expirationSeconds:    777,
				clock:                mockClock,
				logger:               testLogger,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			actual := New(
				tt.args.serviceAccountName,
				tt.args.serviceAccountClient,
				tt.args.whatToDoWithToken,
				tt.args.logger,
				tt.args.opts...,
			)

			require.Equal(t, tt.expected, actual)
		})
	}
}

// withClock should only be used for testing.
func withClock(clock clock.Clock) Opt {
	return func(client *TokenClient) {
		client.clock = clock
	}
}

func TestFetchToken(t *testing.T) {
	mockTime := metav1.Now()

	type expected struct {
		token      string
		ttl        time.Duration
		errMessage string
	}

	tests := []struct {
		name               string
		expirationSeconds  int64
		serviceAccountName string
		tokenResponseValue *authenticationv1.TokenRequest
		tokenResponseError error
		expected           expected
	}{
		{
			name:               "happy path",
			expirationSeconds:  555,
			serviceAccountName: "happy-path-service-account-name",
			tokenResponseValue: &authenticationv1.TokenRequest{
				Status: authenticationv1.TokenRequestStatus{
					Token:               "token value",
					ExpirationTimestamp: metav1.NewTime(mockTime.Add(25 * time.Minute)),
				},
			},
			expected: expected{
				token: "token value",
				ttl:   25 * time.Minute,
			},
		},
		{
			name:               "returns errors from howToFetchTokenFromAPIServer",
			expirationSeconds:  444,
			serviceAccountName: "service-account-name",
			tokenResponseError: errors.New("has an error"),
			expected: expected{
				errMessage: "error creating token: has an error",
			},
		},
		{
			name:               "errors when howToFetchTokenFromAPIServer returns nil",
			expirationSeconds:  333,
			serviceAccountName: "service-account-name",
			expected: expected{
				errMessage: "tokenRequest is nil after request",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			mockClock := clocktesting.NewFakeClock(mockTime.Time)
			var log bytes.Buffer

			require.NotEmpty(t, tt.serviceAccountName)

			mockClient := fake.NewSimpleClientset()
			tokenClient := New(
				tt.serviceAccountName,
				mockClient.CoreV1().ServiceAccounts("any-namespace-works"),
				nil,
				plog.TestLogger(t, &log),
				WithExpirationSeconds(tt.expirationSeconds),
			)
			tokenClient.clock = mockClock

			mockClient.PrependReactor(verb, resource, func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
				require.Equal(t, tt.serviceAccountName, action.(coretesting.CreateActionImpl).Name)

				tokenRequest := action.(coretesting.CreateAction).GetObject().(*authenticationv1.TokenRequest)
				require.NotNil(t, tokenRequest)
				require.Equal(t, tt.expirationSeconds, *tokenRequest.Spec.ExpirationSeconds)
				require.Empty(t, tokenRequest.Spec.Audiences)
				require.Empty(t, tokenRequest.Spec.BoundObjectRef)

				return true, tt.tokenResponseValue, tt.tokenResponseError
			})

			token, ttl, err := tokenClient.fetchToken(context.Background())

			if tt.expected.errMessage != "" {
				require.ErrorContains(t, err, tt.expected.errMessage)
			} else {
				require.Equal(t, tt.expected.token, token)
				require.Equal(t, tt.expected.ttl, ttl)
			}
		})
	}
}

func TestStart_HappyPath(t *testing.T) {
	mockClient := fake.NewSimpleClientset()
	now := time.Now()
	var log bytes.Buffer

	type receivedToken struct {
		token string
		ttl   time.Duration
	}

	var receivedTokens []receivedToken

	tokenClient := New(
		"service-account-name",
		mockClient.CoreV1().ServiceAccounts("any-namespace-works"),
		func(token string, ttl time.Duration) {
			t.Logf("received token %q with ttl %q", token, ttl)
			receivedTokens = append(receivedTokens, receivedToken{
				token: token,
				ttl:   ttl,
			})
		},
		plog.TestLogger(t, &log),
	)

	type reactionResponse struct {
		status authenticationv1.TokenRequestStatus
		err    error
	}

	var reactionResponses []reactionResponse

	for i := int64(0); i < 1000; i++ {
		ttl := time.Duration((1 + i) * 50 * int64(time.Millisecond))
		reactionResponses = append(reactionResponses, reactionResponse{
			status: authenticationv1.TokenRequestStatus{
				Token:               fmt.Sprintf("token-%d-ttl-%s", i, ttl),
				ExpirationTimestamp: metav1.Time{Time: now.Add(ttl)},
			},
		})
	}

	callCount := 0
	mockClient.PrependReactor(verb, resource, func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
		i := callCount
		callCount++
		response := &authenticationv1.TokenRequest{
			Status: reactionResponses[i].status,
		}
		return true, response, reactionResponses[i].err
	})

	defer func() {
		expected := int((10 * time.Second) / (50 * time.Millisecond))
		require.GreaterOrEqual(t, len(receivedTokens), expected*9/10)
		require.LessOrEqual(t, len(receivedTokens), expected*11/10)
		//require.Equal(t, "some expected logs", log.String())
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Second, cancel)
	go tokenClient.Start(ctx)

	<-ctx.Done()
}
