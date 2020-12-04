// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package filesession

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

// validSession should be the same data as `testdata/valid.yaml`.
var validSession = sessionCache{
	TypeMeta: metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "SessionCache"},
	Sessions: []sessionEntry{
		{
			Key: oidcclient.SessionCacheKey{
				Issuer:      "test-issuer",
				ClientID:    "test-client-id",
				Scopes:      []string{"email", "offline_access", "openid", "profile"},
				RedirectURI: "http://localhost:0/callback",
			},
			CreationTimestamp: metav1.NewTime(time.Date(2020, 10, 20, 18, 42, 7, 0, time.UTC).Local()),
			LastUsedTimestamp: metav1.NewTime(time.Date(2020, 10, 20, 18, 45, 31, 0, time.UTC).Local()),
			Tokens: oidctypes.Token{
				AccessToken: &oidctypes.AccessToken{
					Token:  "test-access-token",
					Type:   "Bearer",
					Expiry: metav1.NewTime(time.Date(2020, 10, 20, 19, 46, 30, 0, time.UTC).Local()),
				},
				IDToken: &oidctypes.IDToken{
					Token:  "test-id-token",
					Expiry: metav1.NewTime(time.Date(2020, 10, 20, 19, 42, 07, 0, time.UTC).Local()),
					Claims: map[string]interface{}{
						"foo": "bar",
						"nested": map[string]interface{}{
							"key1": "value1",
							"key2": "value2",
						},
					},
				},
				RefreshToken: &oidctypes.RefreshToken{
					Token: "test-refresh-token",
				},
			},
		},
	},
}

func TestReadSessionCache(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		path    string
		want    *sessionCache
		wantErr string
	}{
		{
			name: "does not exist",
			path: "./testdata/does-not-exist.yaml",
			want: &sessionCache{
				TypeMeta: metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "SessionCache"},
				Sessions: []sessionEntry{},
			},
		},
		{
			name:    "other file error",
			path:    "./testdata/",
			wantErr: "could not read session file: read ./testdata/: is a directory",
		},
		{
			name:    "invalid YAML",
			path:    "./testdata/invalid.yaml",
			wantErr: "invalid session file: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type filesession.sessionCache",
		},
		{
			name:    "wrong version",
			path:    "./testdata/wrong-version.yaml",
			wantErr: `unsupported session version: v1.TypeMeta{Kind:"NotASessionCache", APIVersion:"config.supervisor.pinniped.dev/v2alpha6"}`,
		},
		{
			name: "valid",
			path: "./testdata/valid.yaml",
			want: &validSession,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := readSessionCache(tt.path)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestEmptySessionCache(t *testing.T) {
	t.Parallel()
	got := emptySessionCache()
	require.Equal(t, metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "SessionCache"}, got.TypeMeta)
	require.Equal(t, 0, len(got.Sessions))
	require.Equal(t, 1, cap(got.Sessions))
}

func TestWriteTo(t *testing.T) {
	t.Parallel()
	t.Run("io error", func(t *testing.T) {
		t.Parallel()
		tmp := testutil.TempDir(t) + "/sessions.yaml"
		require.NoError(t, os.Mkdir(tmp, 0700))
		err := validSession.writeTo(tmp)
		require.EqualError(t, err, "open "+tmp+": is a directory")
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, validSession.writeTo(testutil.TempDir(t)+"/sessions.yaml"))
	})
}

func TestNormalized(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, emptySessionCache(), emptySessionCache().normalized())
	})

	t.Run("nonempty", func(t *testing.T) {
		t.Parallel()
		input := emptySessionCache()
		now := time.Now()
		input.Sessions = []sessionEntry{
			// ID token is empty, but not nil.
			{
				LastUsedTimestamp: metav1.NewTime(now),
				Tokens: oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Token:  "",
						Expiry: metav1.NewTime(now.Add(1 * time.Minute)),
					},
				},
			},
			// ID token is expired.
			{
				LastUsedTimestamp: metav1.NewTime(now),
				Tokens: oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Token:  "test-id-token",
						Expiry: metav1.NewTime(now.Add(-1 * time.Minute)),
					},
				},
			},
			// Access token is empty, but not nil.
			{
				LastUsedTimestamp: metav1.NewTime(now),
				Tokens: oidctypes.Token{
					AccessToken: &oidctypes.AccessToken{
						Token:  "",
						Expiry: metav1.NewTime(now.Add(1 * time.Minute)),
					},
				},
			},
			// Access token is expired.
			{
				LastUsedTimestamp: metav1.NewTime(now),
				Tokens: oidctypes.Token{
					AccessToken: &oidctypes.AccessToken{
						Token:  "test-access-token",
						Expiry: metav1.NewTime(now.Add(-1 * time.Minute)),
					},
				},
			},
			// Refresh token is empty, but not nil.
			{
				LastUsedTimestamp: metav1.NewTime(now),
				Tokens: oidctypes.Token{
					RefreshToken: &oidctypes.RefreshToken{
						Token: "",
					},
				},
			},
			// Session has a refresh token but it hasn't been used in >90 days.
			{
				LastUsedTimestamp: metav1.NewTime(now.AddDate(-1, 0, 0)),
				Tokens: oidctypes.Token{
					RefreshToken: &oidctypes.RefreshToken{
						Token: "test-refresh-token",
					},
				},
			},
			// Two entries that are still valid.
			{
				CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
				LastUsedTimestamp: metav1.NewTime(now),
				Tokens: oidctypes.Token{
					RefreshToken: &oidctypes.RefreshToken{
						Token: "test-refresh-token2",
					},
				},
			},
			{
				CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
				LastUsedTimestamp: metav1.NewTime(now),
				Tokens: oidctypes.Token{
					RefreshToken: &oidctypes.RefreshToken{
						Token: "test-refresh-token1",
					},
				},
			},
		}

		// Expect that all but the last two valid session are pruned, and that they're sorted.
		require.Equal(t, &sessionCache{
			TypeMeta: metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "SessionCache"},
			Sessions: []sessionEntry{
				{
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now),
					Tokens: oidctypes.Token{
						RefreshToken: &oidctypes.RefreshToken{
							Token: "test-refresh-token1",
						},
					},
				},
				{
					CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now),
					Tokens: oidctypes.Token{
						RefreshToken: &oidctypes.RefreshToken{
							Token: "test-refresh-token2",
						},
					},
				},
			},
		}, input.normalized())
	})
}

func TestLookup(t *testing.T) {
	t.Parallel()
	require.Nil(t, validSession.lookup(oidcclient.SessionCacheKey{}))
	require.NotNil(t, validSession.lookup(oidcclient.SessionCacheKey{
		Issuer:      "test-issuer",
		ClientID:    "test-client-id",
		Scopes:      []string{"email", "offline_access", "openid", "profile"},
		RedirectURI: "http://localhost:0/callback",
	}))
}

func TestInsert(t *testing.T) {
	t.Parallel()
	c := emptySessionCache()
	c.insert(sessionEntry{})
	require.Len(t, c.Sessions, 1)
}
