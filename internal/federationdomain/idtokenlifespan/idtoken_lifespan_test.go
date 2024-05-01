// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package idtokenlifespan

import (
	"context"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

func TestOverrideIDTokenLifespanInContext(t *testing.T) {
	tests := []struct {
		name             string
		defaultLifespan  time.Duration
		overrideLifespan func(ctx context.Context) context.Context
		wantLifespan     time.Duration
	}{
		{
			name:            "does not override the context's default timeout",
			defaultLifespan: 10 * time.Second,
			overrideLifespan: func(baseCtx context.Context) context.Context {
				return baseCtx // no-op on the context
			},
			wantLifespan: 10 * time.Second,
		},
		{
			name:            "overrides the context's default to be 42 seconds",
			defaultLifespan: 10 * time.Second,
			overrideLifespan: func(baseCtx context.Context) context.Context {
				return OverrideIDTokenLifespanInContext(baseCtx, 42*time.Second)
			},
			wantLifespan: 42 * time.Second,
		},
		{
			name:            "overrides the context's default to be 42 minutes",
			defaultLifespan: 10 * time.Second,
			overrideLifespan: func(baseCtx context.Context) context.Context {
				return OverrideIDTokenLifespanInContext(baseCtx, 42*time.Minute)
			},
			wantLifespan: 42 * time.Minute,
		},
		{
			name:            "somehow accidentally overrides the context's default timeout to be the wrong type",
			defaultLifespan: 10 * time.Second,
			overrideLifespan: func(baseCtx context.Context) context.Context {
				return context.WithValue(baseCtx, idTokenLifetimeOverrideKey, "this should be a duration but is a string")
			},
			wantLifespan: 10 * time.Second, // should ignore the illegal value and just return the default
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			baseConfig := fosite.Config{
				IDTokenLifespan: tt.defaultLifespan,
			}

			contextAwareProvider := &contextAwareIDTokenLifespanProvider{
				DelegateConfig: &baseConfig,
			}

			// Possibly override the default lifespan on the context.
			updatedCtx := tt.overrideLifespan(context.Background())

			// Read the lifespan from the context.
			gotLifespan := contextAwareProvider.GetIDTokenLifespan(updatedCtx)
			require.Equal(t, tt.wantLifespan, gotLifespan)
		})
	}
}
