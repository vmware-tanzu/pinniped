// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokenclient

import (
	"context"
	"time"

	"github.com/pkg/errors"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/clock"

	"go.pinniped.dev/internal/backoff"
	"go.pinniped.dev/internal/plog"
)

type WhatToDoWithTokenFunc func(token string, ttl time.Duration)

type TokenClient struct {
	serviceAccountName   string
	serviceAccountClient corev1client.ServiceAccountInterface
	whatToDoWithToken    WhatToDoWithTokenFunc
	expirationSeconds    int64
	clock                clock.Clock
	logger               plog.Logger
}

type Opt func(client *TokenClient)

func WithExpirationSeconds(expirationSeconds int64) Opt {
	return func(client *TokenClient) {
		client.expirationSeconds = expirationSeconds
	}
}

func New(
	serviceAccountName string,
	serviceAccountClient corev1client.ServiceAccountInterface,
	whatToDoWithToken WhatToDoWithTokenFunc,
	logger plog.Logger,
	opts ...Opt,
) *TokenClient {
	client := &TokenClient{
		serviceAccountName:   serviceAccountName,
		serviceAccountClient: serviceAccountClient,
		whatToDoWithToken:    whatToDoWithToken,
		expirationSeconds:    600,
		clock:                clock.RealClock{},
		logger:               logger,
	}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

func (tc TokenClient) Start(ctx context.Context) {
	sleeper := make(chan time.Time, 1)

	// Make sure that the <-sleeper below gets run once immediately.
	sleeper <- time.Now()

	for {
		select {
		case <-ctx.Done():
			tc.logger.Info("TokenClient was cancelled and is stopping")
			return
		case <-sleeper:
			var tokenTTL time.Duration

			err := backoff.WithContext(ctx, &backoff.InfiniteBackoff{
				Duration:    10 * time.Millisecond,
				MaxDuration: 10 * time.Second,
				Factor:      2.0,
			}, func(ctx context.Context) (bool, error) {
				var (
					err   error
					token string
				)

				token, tokenTTL, err = tc.fetchToken(ctx)
				if err != nil {
					// We got an error. Log it, swallow it, and ask for retry by returning false.
					tc.logger.Error("TokenClient could not fetch short-lived service account token (will retry)", err,
						"serviceAccountName", tc.serviceAccountName)
					return false, nil
				}

				// We got a new token, so invoke the callback.
				tc.whatToDoWithToken(token, tokenTTL)
				// Stop backing off.
				return true, nil
			})

			if err != nil {
				// We were cancelled during our WithContext. We know it was not due to some other
				// error because our last argument to WithContext above never returns any errors.
				return
			}

			// Schedule ourselves to wake up in the future.
			time.AfterFunc(tokenTTL*4/5, func() {
				sleeper <- time.Now()
			})
		}
	}
}

func (tc TokenClient) fetchToken(ctx context.Context) (token string, ttl time.Duration, _ error) {
	tc.logger.Debug("TokenClient calling CreateToken to fetch a short-lived service account token")
	tokenResponse, err := tc.serviceAccountClient.CreateToken(ctx,
		tc.serviceAccountName,
		&authenticationv1.TokenRequest{
			Spec: authenticationv1.TokenRequestSpec{
				ExpirationSeconds: &tc.expirationSeconds,
			},
		},
		metav1.CreateOptions{},
	)

	if err != nil {
		return "", 0, errors.Wrap(err, "error creating token")
	}

	if tokenResponse == nil {
		return "", 0, errors.New("got nil CreateToken response")
	}

	return tokenResponse.Status.Token,
		tokenResponse.Status.ExpirationTimestamp.Sub(tc.clock.Now()),
		nil
}
