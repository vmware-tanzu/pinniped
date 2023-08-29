// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execcredcache

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

var (
	// validCache should be the same data as `testdata/valid.yaml`.
	validCache = credCache{
		TypeMeta: metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "CredentialCache"},
		Entries: []entry{
			{
				Key:               "test-key",
				CreationTimestamp: metav1.NewTime(time.Date(2020, 10, 20, 18, 42, 7, 0, time.UTC).Local()),
				LastUsedTimestamp: metav1.NewTime(time.Date(2020, 10, 20, 18, 45, 31, 0, time.UTC).Local()),
				Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
					Token:               "test-token",
					ExpirationTimestamp: &expTime,
				},
			},
		},
	}
	expTime = metav1.NewTime(time.Date(2020, 10, 20, 19, 46, 30, 0, time.UTC).Local())
)

func TestReadCache(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		path    string
		want    *credCache
		wantErr string
	}{
		{
			name: "does not exist",
			path: "./testdata/does-not-exist.yaml",
			want: &credCache{
				TypeMeta: metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "CredentialCache"},
				Entries:  []entry{},
			},
		},
		{
			name:    "other file error",
			path:    "./testdata/",
			wantErr: "could not read cache file: read ./testdata/: is a directory",
		},
		{
			name:    "invalid YAML",
			path:    "./testdata/invalid.yaml",
			wantErr: "invalid cache file: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type execcredcache.credCache",
		},
		{
			name:    "wrong version",
			path:    "./testdata/wrong-version.yaml",
			wantErr: `unsupported credential cache version: v1.TypeMeta{Kind:"NotACredentialCache", APIVersion:"config.supervisor.pinniped.dev/v2alpha6"}`,
		},
		{
			name: "valid",
			path: "./testdata/valid.yaml",
			want: &validCache,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := readCache(tt.path)
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

func TestEmptyCache(t *testing.T) {
	t.Parallel()
	got := emptyCache()
	require.Equal(t, metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "CredentialCache"}, got.TypeMeta)
	require.Equal(t, 0, len(got.Entries))
	require.Equal(t, 1, cap(got.Entries))
}

func TestWriteTo(t *testing.T) {
	t.Parallel()
	t.Run("io error", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir() + "/credentials.yaml"
		require.NoError(t, os.Mkdir(tmp, 0700))
		err := validCache.writeTo(tmp)
		require.EqualError(t, err, "open "+tmp+": is a directory")
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, validCache.writeTo(t.TempDir()+"/credentials.yaml"))
	})
}

func TestNormalized(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, emptyCache(), emptyCache().normalized())
	})

	t.Run("nonempty", func(t *testing.T) {
		t.Parallel()
		input := emptyCache()
		now := time.Now()
		oneMinuteAgo := metav1.NewTime(now.Add(-1 * time.Minute))
		oneHourFromNow := metav1.NewTime(now.Add(1 * time.Hour))
		input.Entries = []entry{
			// Credential is nil.
			{
				Key:               "nil-credential-key",
				LastUsedTimestamp: metav1.NewTime(now),
				Credential:        nil,
			},
			// Credential's expiration is nil.
			{
				Key:               "nil-expiration-key",
				LastUsedTimestamp: metav1.NewTime(now),
				Credential:        &clientauthenticationv1beta1.ExecCredentialStatus{},
			},
			// Credential is expired.
			{
				Key:               "expired-key",
				LastUsedTimestamp: metav1.NewTime(now),
				Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: &oneMinuteAgo,
					Token:               "expired-token",
				},
			},
			// Credential is still valid but is older than maxCacheDuration.
			{
				Key:               "too-old-key",
				LastUsedTimestamp: metav1.NewTime(now),
				CreationTimestamp: metav1.NewTime(now.Add(-3 * time.Hour)),
				Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: &oneHourFromNow,
					Token:               "too-old-token",
				},
			},
			// Two entries that are still valid but are out of order.
			{
				Key:               "key-two",
				CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
				LastUsedTimestamp: metav1.NewTime(now),
				Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: &oneHourFromNow,
					Token:               "token-two",
				},
			},
			{
				Key:               "key-one",
				CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Minute)),
				LastUsedTimestamp: metav1.NewTime(now),
				Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: &oneHourFromNow,
					Token:               "token-one",
				},
			},
		}

		// Expect that all but the last two valid entries are pruned, and that they're sorted.
		require.Equal(t, &credCache{
			TypeMeta: metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "CredentialCache"},
			Entries: []entry{
				{
					Key:               "key-one",
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Minute)),
					LastUsedTimestamp: metav1.NewTime(now),
					Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
						ExpirationTimestamp: &oneHourFromNow,
						Token:               "token-one",
					},
				},
				{
					Key:               "key-two",
					CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
					LastUsedTimestamp: metav1.NewTime(now),
					Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
						ExpirationTimestamp: &oneHourFromNow,
						Token:               "token-two",
					},
				},
			},
		}, input.normalized())
	})
}
