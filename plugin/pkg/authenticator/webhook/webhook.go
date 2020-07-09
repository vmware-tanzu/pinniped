/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package webhook uses the Kubernetes TokenReview API to authenticate a user.
package webhook

import (
	"context"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/suzerain-io/placeholder-name/pkg/authentication"
)

// Webhook is a webhook client that authenticates users via the Kubernetes
// TokenReview API.
type Webhook struct {
	clientset kubernetes.Interface
}

// New returns a new Webhook client that uses the provided clientset.
func New(clientset kubernetes.Interface) *Webhook {
	return &Webhook{
		clientset: clientset,
	}
}

func (w *Webhook) Authenticate(
	ctx context.Context,
	cred authentication.Credential,
) (*authentication.Status, bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tokenReviewsClient := w.clientset.AuthenticationV1().TokenReviews()
	tokenReview, err := tokenReviewsClient.Create(
		ctx,
		&authenticationv1.TokenReview{},
		metav1.CreateOptions{},
	)
	if err != nil {
		return nil, false, fmt.Errorf("create token review: %w", err)
	}

	if tokenReview.Status.Error != "" {
		return nil, false, tokenReviewError{tokenReview.Status.Error}
	}

	if !tokenReview.Status.Authenticated {
		return nil, false, tokenReviewUnauthenticatedError{}
	}

	return &authentication.Status{
		Audiences: tokenReview.Status.Audiences,
		User: &authentication.DefaultUser{
			Name:   tokenReview.Status.User.Username,
			UID:    tokenReview.Status.User.UID,
			Groups: tokenReview.Status.User.Groups,
			Extra:  convertExtra(tokenReview.Status.User.Extra),
		},
	}, true, nil
}

func convertExtra(extraValue map[string]authenticationv1.ExtraValue) map[string][]string {
	m := make(map[string][]string)
	for k, v := range extraValue {
		m[k] = []string(v)
	}
	return m
}
