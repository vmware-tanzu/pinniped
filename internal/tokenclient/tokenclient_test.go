// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokenclient

import (
	"context"
	"errors"
	"sync"
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

const (
	verb     = "create"
	resource = "serviceaccounts/token"
)

func TestNew(t *testing.T) {
	mockWhatToDoWithTokenFunc := *new(WhatToDoWithTokenFunc)
	mockClient := fake.NewSimpleClientset().CoreV1().ServiceAccounts("")
	mockTime := time.Now()
	mockClock := clocktesting.NewFakeClock(mockTime)
	logger, _ := plog.TestLogger(t)

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
				logger:               logger,
			},
			expected: &TokenClient{
				serviceAccountName:   "serviceAccountName",
				serviceAccountClient: mockClient,
				whatToDoWithToken:    mockWhatToDoWithTokenFunc,
				expirationSeconds:    600,
				clock:                clock.RealClock{},
				logger:               logger,
			},
		},
		{
			name: "with all opts",
			args: args{
				serviceAccountName:   "custom-serviceAccountName",
				serviceAccountClient: mockClient,
				whatToDoWithToken:    mockWhatToDoWithTokenFunc,
				logger:               logger,
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
				logger:               logger,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

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
				errMessage: "got nil CreateToken response",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockClock := clocktesting.NewFakeClock(mockTime.Time)
			logger, _ := plog.TestLogger(t)

			require.NotEmpty(t, tt.serviceAccountName)

			mockClient := fake.NewSimpleClientset()
			tokenClient := New(
				tt.serviceAccountName,
				mockClient.CoreV1().ServiceAccounts("any-namespace-works"),
				nil,
				logger,
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

func TestStart(t *testing.T) {
	type apiResponse struct {
		token string
		ttl   time.Duration // how much in the future from the time of token response to set the expiration date
		err   error
	}

	type receivedToken struct {
		token string
		ttl   time.Duration // expected ttl, within a fudge factor
	}

	type wanted struct {
		receivedTokens                   []receivedToken
		timeFudgeFactor                  time.Duration
		approxTimesBetweenAPIInvocations []time.Duration
	}

	tests := []struct {
		name         string
		apiResponses []apiResponse
		want         *wanted
	}{
		{
			name: "several successful token requests",
			apiResponses: []apiResponse{
				{token: "t1", ttl: 200 * time.Millisecond},
				{token: "t2", ttl: 400 * time.Millisecond},
				{token: "t3", ttl: 300 * time.Millisecond},
				{token: "t4", ttl: time.Hour},
			},
			want: &wanted{
				timeFudgeFactor: 80 * time.Millisecond, // sadly, lots of fudge needed for busy CI workers
				receivedTokens: []receivedToken{
					{token: "t1", ttl: 200 * time.Millisecond},
					{token: "t2", ttl: 400 * time.Millisecond},
					{token: "t3", ttl: 300 * time.Millisecond},
					{token: "t4", ttl: time.Hour},
				},
				approxTimesBetweenAPIInvocations: []time.Duration{
					160 * time.Millisecond, // time between getting t1 and t2 (80% of t1's ttl)
					320 * time.Millisecond, // time between getting t2 and t3 (80% of t2's ttl)
					240 * time.Millisecond, // time between getting t4 and t4 (80% of t3's ttl)
				},
			},
		},
		{
			name: "some errors in the middle",
			apiResponses: []apiResponse{
				{token: "t1", ttl: 100 * time.Millisecond},
				{token: "t2", ttl: 200 * time.Millisecond},
				{err: errors.New("err1")},
				{err: errors.New("err2")},
				{err: errors.New("err3")},
				{err: errors.New("err4")},
				{err: errors.New("err5")},
				{err: errors.New("err6")},
				{err: errors.New("err7")},
				{token: "t3", ttl: 100 * time.Millisecond},
				{token: "t4", ttl: time.Hour},
			},
			want: &wanted{
				timeFudgeFactor: 80 * time.Millisecond, // sadly, lots of fudge needed for busy CI workers
				receivedTokens: []receivedToken{
					{token: "t1", ttl: 100 * time.Millisecond},
					{token: "t2", ttl: 200 * time.Millisecond},
					{token: "t3", ttl: 100 * time.Millisecond},
					{token: "t4", ttl: time.Hour},
				},
				approxTimesBetweenAPIInvocations: []time.Duration{
					80 * time.Millisecond,  // time between getting t1 and t2 (80% of t1's ttl)
					160 * time.Millisecond, // time between getting t2 and err1 (80% of t2's ttl)
					10 * time.Millisecond,  // time between getting err1 and err2 (1st step of exponential backoff)
					20 * time.Millisecond,  // time between getting err2 and err3 (2nd step of exponential backoff)
					40 * time.Millisecond,  // time between getting err3 and err4 (3rd step of exponential backoff)
					80 * time.Millisecond,  // time between getting err4 and err5 (4th step of exponential backoff)
					160 * time.Millisecond, // time between getting err5 and err6 (5th step of exponential backoff)
					320 * time.Millisecond, // time between getting err6 and err7 (6th step of exponential backoff)
					640 * time.Millisecond, // time between getting err7 and t3 (7th step of exponential backoff)
					80 * time.Millisecond,  // time between getting t3 and t4 (80% of t3's ttl)
				},
			},
		},
		{
			name: "getting errors before successfully fetching the first token",
			apiResponses: []apiResponse{
				{err: errors.New("err1")},
				{err: errors.New("err2")},
				{err: errors.New("err3")},
				{err: errors.New("err4")},
				{token: "t1", ttl: 100 * time.Millisecond},
				{token: "t2", ttl: 200 * time.Millisecond},
				{token: "t3", ttl: time.Hour},
			},
			want: &wanted{
				timeFudgeFactor: 80 * time.Millisecond, // sadly, lots of fudge needed for busy CI workers
				receivedTokens: []receivedToken{
					{token: "t1", ttl: 100 * time.Millisecond},
					{token: "t2", ttl: 200 * time.Millisecond},
					{token: "t3", ttl: time.Hour},
				},
				approxTimesBetweenAPIInvocations: []time.Duration{
					10 * time.Millisecond,  // time between getting err1 and err2 (1st step of exponential backoff)
					20 * time.Millisecond,  // time between getting err2 and err3 (2nd step of exponential backoff)
					40 * time.Millisecond,  // time between getting err3 and err4 (3rd step of exponential backoff)
					80 * time.Millisecond,  // time between getting err4 and t1 (4th step of exponential backoff)
					80 * time.Millisecond,  // time between getting t1 and t2 (80% of t1's ttl)
					160 * time.Millisecond, // time between getting t2 and t3 (80% of t2's ttl)
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockClient := fake.NewSimpleClientset()
			logger, _ := plog.TestLogger(t)

			var mutex sync.Mutex
			// These variables are accessed by the reactor and by the callback function in the goroutine which is
			// running Start() below. But they are also accessed by this test's main goroutine to make assertions later.
			// Protect them with a mutex to make the data race detector happy.
			var receivedTokens []receivedToken
			var reactorCallTimestamps []time.Time
			reactorCallCount := 0

			subject := New(
				"service-account-name",
				mockClient.CoreV1().ServiceAccounts("any-namespace-works"),
				func(token string, ttl time.Duration) {
					mutex.Lock()
					defer mutex.Unlock()
					t.Logf("received token %q with ttl %q", token, ttl)
					receivedTokens = append(receivedTokens, receivedToken{token: token, ttl: ttl})
				},
				logger,
			)

			mockClient.PrependReactor(verb, resource, func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
				mutex.Lock()
				defer mutex.Unlock()
				require.Less(t, reactorCallCount, len(tt.apiResponses),
					"more TokenRequests were made than fake reactor responses were prepared in the test setup")
				response := &authenticationv1.TokenRequest{Status: authenticationv1.TokenRequestStatus{
					Token:               tt.apiResponses[reactorCallCount].token,
					ExpirationTimestamp: metav1.NewTime(time.Now().Add(tt.apiResponses[reactorCallCount].ttl)),
				}}
				responseErr := tt.apiResponses[reactorCallCount].err
				reactorCallCount++
				reactorCallTimestamps = append(reactorCallTimestamps, time.Now())
				t.Logf("fake CreateToken API returning response %q at time %s", response.Status, time.Now())
				return true, response, responseErr
			})

			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(4*time.Second, cancel) // cancel the context after a few seconds
			go subject.Start(ctx)                 // Start() should only return after the context is cancelled
			<-ctx.Done()
			mutex.Lock()
			defer mutex.Unlock()

			// Should have used up all the reactor responses from the test table.
			require.Equal(t, reactorCallCount, len(tt.apiResponses))

			// Should have got the expected callbacks for new tokens.
			require.Equal(t, len(tt.want.receivedTokens), len(receivedTokens))
			for i := range tt.want.receivedTokens {
				require.Equal(t, tt.want.receivedTokens[i].token, receivedTokens[i].token)
				require.InDelta(t,
					float64(tt.want.receivedTokens[i].ttl), float64(receivedTokens[i].ttl),
					float64(tt.want.timeFudgeFactor),
				)
			}

			// Should have observed the appropriate amount of elapsed time in between each call to the CreateToken API.
			require.Equal(t, reactorCallCount-1, len(tt.want.approxTimesBetweenAPIInvocations), "wrong number of expected time deltas in test setup")
			for i := range reactorCallTimestamps {
				if i == 0 {
					continue
				}
				actualDelta := reactorCallTimestamps[i].Sub(reactorCallTimestamps[i-1])
				require.InDeltaf(t,
					tt.want.approxTimesBetweenAPIInvocations[i-1], actualDelta,
					float64(tt.want.timeFudgeFactor),
					"for API invocation %d", i,
				)
			}
		})
	}
}
