// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokenclient

import (
	"context"
	"fmt"
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

func (tokenClient TokenClient) Start(ctx context.Context) {
	sleeper := make(chan time.Time, 1)
	// Make sure that the <-sleeper below gets run once immediately.
	sleeper <- time.Now()
	for {
		select {
		case <-ctx.Done():
			tokenClient.logger.Info("TokenClient was cancelled and is stopping")
			return
		case <-sleeper:
			var tokenTTL time.Duration
			err := backoff.WithContext(ctx, &backoff.InfiniteBackoff{
				Duration:    10 * time.Millisecond,
				MaxDuration: 5 * time.Second,
				Factor:      2.0,
			}, func(ctx context.Context) (bool, error) {
				var (
					err   error
					token string
				)
				token, tokenTTL, err = tokenClient.fetchToken(ctx)

				if err != nil {
					tokenClient.logger.Warning(fmt.Sprintf("Could not fetch token: %s\n", err))
					// We got an error. Swallow it and ask for retry.
					return false, nil
				}

				tokenClient.whatToDoWithToken(token, tokenTTL)
				// We got a token. Stop backing off.
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

func (tokenClient TokenClient) fetchToken(ctx context.Context) (token string, ttl time.Duration, _ error) {
	tokenClient.logger.Debug(fmt.Sprintf("refreshing cache at time=%s\n", tokenClient.clock.Now().Format(time.RFC3339)))

	tokenRequestInput := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &tokenClient.expirationSeconds,
		},
	}

	tokenResponse, err := tokenClient.serviceAccountClient.CreateToken(
		ctx,
		tokenClient.serviceAccountName,
		tokenRequestInput,
		metav1.CreateOptions{},
	)

	if err != nil {
		return "", 0, errors.Wrap(err, "error creating token")
	}

	if tokenResponse == nil {
		return "", 0, errors.New("tokenRequest is nil after request")
	}

	return tokenResponse.Status.Token,
		tokenResponse.Status.ExpirationTimestamp.Sub(tokenClient.clock.Now()),
		nil
}
