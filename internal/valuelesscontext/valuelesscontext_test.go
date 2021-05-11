// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package valuelesscontext

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

func TestNew(t *testing.T) {
	t.Parallel()

	type contextKey int

	tests := []struct {
		name                       string
		f                          func(*testing.T, context.Context) context.Context
		wantReg, wantNew, wantBoth func(*testing.T, context.Context)
	}{
		{
			name: "empty context",
			f: func(t *testing.T, ctx context.Context) context.Context {
				return ctx
			},
			wantReg: func(t *testing.T, ctx context.Context) {},
			wantNew: func(t *testing.T, ctx context.Context) {},
			wantBoth: func(t *testing.T, ctx context.Context) {
				auds, ok := authenticator.AudiencesFrom(ctx)
				require.False(t, ok)
				require.Nil(t, auds)

				val, ok := ctx.Value(contextKey(0xDEADBEEF)).(string)
				require.False(t, ok)
				require.Zero(t, val)

				deadline, ok := ctx.Deadline()
				require.False(t, ok)
				require.Zero(t, deadline)

				require.Nil(t, ctx.Done())

				require.NoError(t, ctx.Err())
			},
		},
		{
			name: "context with audience",
			f: func(t *testing.T, ctx context.Context) context.Context {
				return authenticator.WithAudiences(ctx, authenticator.Audiences{"1", "2"})
			},
			wantReg: func(t *testing.T, ctx context.Context) {
				auds, ok := authenticator.AudiencesFrom(ctx)
				require.True(t, ok)
				require.Equal(t, authenticator.Audiences{"1", "2"}, auds)
			},
			wantNew: func(t *testing.T, ctx context.Context) {
				auds, ok := authenticator.AudiencesFrom(ctx)
				require.False(t, ok)
				require.Nil(t, auds)
			},
			wantBoth: func(t *testing.T, ctx context.Context) {
				val, ok := ctx.Value(contextKey(0xDEADBEEF)).(string)
				require.False(t, ok)
				require.Zero(t, val)

				deadline, ok := ctx.Deadline()
				require.False(t, ok)
				require.Zero(t, deadline)

				require.Nil(t, ctx.Done())

				require.NoError(t, ctx.Err())
			},
		},
		{
			name: "context with audience and past deadline",
			f: func(t *testing.T, ctx context.Context) context.Context {
				ctx = authenticator.WithAudiences(ctx, authenticator.Audiences{"3", "4"})
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Hour))
				t.Cleanup(cancel)
				return ctx
			},
			wantReg: func(t *testing.T, ctx context.Context) {
				auds, ok := authenticator.AudiencesFrom(ctx)
				require.True(t, ok)
				require.Equal(t, authenticator.Audiences{"3", "4"}, auds)
			},
			wantNew: func(t *testing.T, ctx context.Context) {
				auds, ok := authenticator.AudiencesFrom(ctx)
				require.False(t, ok)
				require.Nil(t, auds)
			},
			wantBoth: func(t *testing.T, ctx context.Context) {
				val, ok := ctx.Value(contextKey(0xDEADBEEF)).(string)
				require.False(t, ok)
				require.Zero(t, val)

				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.NotZero(t, deadline)
				require.True(t, deadline.Before(time.Now()))

				ch := ctx.Done()
				require.NotNil(t, ch)
				select {
				case <-ch:
				case <-time.After(10 * time.Second):
					t.Error("expected closed done channel")
				}

				require.Equal(t, context.DeadlineExceeded, ctx.Err())
			},
		},
		{
			name: "context with audience and custom value and past deadline",
			f: func(t *testing.T, ctx context.Context) context.Context {
				ctx = authenticator.WithAudiences(ctx, authenticator.Audiences{"3", "4"})
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Hour))
				t.Cleanup(cancel)
				ctx = context.WithValue(ctx, contextKey(0xDEADBEEF), "mooo")
				return ctx
			},
			wantReg: func(t *testing.T, ctx context.Context) {
				auds, ok := authenticator.AudiencesFrom(ctx)
				require.True(t, ok)
				require.Equal(t, authenticator.Audiences{"3", "4"}, auds)

				val, ok := ctx.Value(contextKey(0xDEADBEEF)).(string)
				require.True(t, ok)
				require.Equal(t, "mooo", val)
			},
			wantNew: func(t *testing.T, ctx context.Context) {
				auds, ok := authenticator.AudiencesFrom(ctx)
				require.False(t, ok)
				require.Nil(t, auds)

				val, ok := ctx.Value(contextKey(0xDEADBEEF)).(string)
				require.False(t, ok)
				require.Zero(t, val)
			},
			wantBoth: func(t *testing.T, ctx context.Context) {
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.NotZero(t, deadline)
				require.True(t, deadline.Before(time.Now()))

				ch := ctx.Done()
				require.NotNil(t, ch)
				select {
				case <-ch:
				case <-time.After(10 * time.Second):
					t.Error("expected closed done channel")
				}

				require.Equal(t, context.DeadlineExceeded, ctx.Err())
			},
		},
		{
			name: "context with audience and custom value and future deadline",
			f: func(t *testing.T, ctx context.Context) context.Context {
				ctx = authenticator.WithAudiences(ctx, authenticator.Audiences{"3", "4"})
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(time.Hour))
				t.Cleanup(cancel)
				ctx = context.WithValue(ctx, contextKey(0xDEADBEEF), "mooo")
				return ctx
			},
			wantReg: func(t *testing.T, ctx context.Context) {
				auds, ok := authenticator.AudiencesFrom(ctx)
				require.True(t, ok)
				require.Equal(t, authenticator.Audiences{"3", "4"}, auds)

				val, ok := ctx.Value(contextKey(0xDEADBEEF)).(string)
				require.True(t, ok)
				require.Equal(t, "mooo", val)
			},
			wantNew: func(t *testing.T, ctx context.Context) {
				auds, ok := authenticator.AudiencesFrom(ctx)
				require.False(t, ok)
				require.Nil(t, auds)

				val, ok := ctx.Value(contextKey(0xDEADBEEF)).(string)
				require.False(t, ok)
				require.Zero(t, val)
			},
			wantBoth: func(t *testing.T, ctx context.Context) {
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.NotZero(t, deadline)
				require.True(t, deadline.After(time.Now()))

				ch := ctx.Done()
				require.NotNil(t, ch)
				select {
				case <-ch:
					t.Error("expected not closed done channel")
				case <-time.After(3 * time.Second):
				}

				require.NoError(t, ctx.Err())
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := tt.f(t, context.Background())

			t.Run("reg", func(t *testing.T) {
				t.Parallel()

				tt.wantReg(t, ctx)
			})

			t.Run("reg-both", func(t *testing.T) {
				t.Parallel()

				tt.wantBoth(t, ctx)
			})

			t.Run("new", func(t *testing.T) {
				t.Parallel()

				tt.wantNew(t, New(ctx))
			})

			t.Run("new-both", func(t *testing.T) {
				t.Parallel()

				tt.wantBoth(t, New(ctx))
			})
		})
	}
}
