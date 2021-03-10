// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"context"
	"testing"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
)

func CreateTokenCredentialRequest(ctx context.Context, t *testing.T, spec v1alpha1.TokenCredentialRequestSpec) (*v1alpha1.TokenCredentialRequest, error) {
	t.Helper()

	client := NewAnonymousConciergeClientset(t)

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	return client.LoginV1alpha1().TokenCredentialRequests().Create(ctx,
		&v1alpha1.TokenCredentialRequest{Spec: spec}, v1.CreateOptions{},
	)
}
