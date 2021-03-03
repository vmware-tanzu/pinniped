// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package filecredcache

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/internal/testutil"
)

func TestNew(t *testing.T) {
	t.Parallel()
	tmp := testutil.TempDir(t) + "/sessions.yaml"
	c := New(tmp)
	require.NotNil(t, c)
	require.Equal(t, tmp, c.path)
	require.NotNil(t, c.errReporter)
	c.errReporter(fmt.Errorf("some error"))
}

func TestGetClusterCredential(t *testing.T) {
	t.Parallel()
	now := time.Now().Round(1 * time.Second)
	tests := []struct {
		name         string
		makeTestFile func(t *testing.T, tmp string)
		trylockFunc  func(*testing.T) error
		unlockFunc   func(*testing.T) error
		key          string
		want         *clientauthenticationv1beta1.ExecCredentialStatus
		wantErrors   []string
		wantTestFile func(t *testing.T, tmp string)
	}{
		{
			name: "not found",
			key:  "some-key",
		},
		{
			name:         "file lock error",
			makeTestFile: func(t *testing.T, tmp string) { require.NoError(t, ioutil.WriteFile(tmp, []byte(""), 0600)) },
			trylockFunc:  func(t *testing.T) error { return fmt.Errorf("some lock error") },
			unlockFunc:   func(t *testing.T) error { require.Fail(t, "should not be called"); return nil },
			key:          "some-key",
			wantErrors:   []string{"could not lock credential cache file: some lock error"},
		},
		{
			name: "invalid file",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, ioutil.WriteFile(tmp, []byte("invalid yaml"), 0600))
			},
			key: "some-key",
			wantErrors: []string{
				"failed to read cache, resetting: invalid credential cache file: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type filecredcache.credCache",
			},
		},
		{
			name:         "invalid file, fail to unlock",
			makeTestFile: func(t *testing.T, tmp string) { require.NoError(t, ioutil.WriteFile(tmp, []byte("invalid"), 0600)) },
			trylockFunc:  func(t *testing.T) error { return nil },
			unlockFunc:   func(t *testing.T) error { return fmt.Errorf("some unlock error") },
			key:          "some-key",
			wantErrors: []string{
				"failed to read cache, resetting: invalid credential cache file: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type filecredcache.credCache",
				"could not unlock credential cache file: some unlock error",
			},
		},
		{
			name: "unreadable file",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, os.Mkdir(tmp, 0700))
			},
			key: "some-key",
			wantErrors: []string{
				"failed to read cache, resetting: could not read credential cache file: read TEMPFILE: is a directory",
				"could not write credential cache: open TEMPFILE: is a directory",
			},
		},
		{
			name: "valid file but cache miss",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptyCredCache()
				validCache.insert(credEntry{
					Key:               "some-other-key",
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					Credential: clientauthenticationv1beta1.ExecCredentialStatus{
						Token: "some-token",
					},
				})
				require.NoError(t, validCache.writeTo(tmp))
			},
			key:        "some-key",
			wantErrors: []string{},
		},
		{
			name: "valid file with cache hit",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptyCredCache()
				validCache.insert(credEntry{
					Key:               "some-key",
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					Credential: clientauthenticationv1beta1.ExecCredentialStatus{
						Token: "some-token",
					},
				})
				require.NoError(t, validCache.writeTo(tmp))
			},
			key:        "some-key",
			wantErrors: []string{},
			want: &clientauthenticationv1beta1.ExecCredentialStatus{
				Token: "some-token",
			},
			wantTestFile: func(t *testing.T, tmp string) {
				cache, err := readCredCache(tmp)
				require.NoError(t, err)
				require.Len(t, cache.Credentials, 1)
				require.Less(t, time.Since(cache.Credentials[0].LastUsedTimestamp.Time).Nanoseconds(), (5 * time.Second).Nanoseconds())
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tmp := testutil.TempDir(t) + "/sessions.yaml"
			if tt.makeTestFile != nil {
				tt.makeTestFile(t, tmp)
			}

			// Initialize a cache with a reporter that collects errors
			errors := errorCollector{t: t}
			c := New(tmp, errors.collect())
			if tt.trylockFunc != nil {
				c.trylockFunc = func() error { return tt.trylockFunc(t) }
			}
			if tt.unlockFunc != nil {
				c.unlockFunc = func() error { return tt.unlockFunc(t) }
			}

			got := c.GetClusterCredential(tt.key)
			require.Equal(t, tt.want, got)
			errors.require(tt.wantErrors, "TEMPFILE", tmp)
			if tt.wantTestFile != nil {
				tt.wantTestFile(t, tmp)
			}
		})
	}
}

func TestPutClusterCredential(t *testing.T) {
	t.Parallel()
	now := time.Now().Round(1 * time.Second)
	tests := []struct {
		name         string
		makeTestFile func(t *testing.T, tmp string)
		key          string
		cred         *clientauthenticationv1beta1.ExecCredentialStatus
		wantErrors   []string
		wantTestFile func(t *testing.T, tmp string)
	}{
		{
			name: "fail to create directory",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, ioutil.WriteFile(filepath.Dir(tmp), []byte{}, 0600))
			},
			wantErrors: []string{
				"could not create credential cache directory: mkdir TEMPDIR: not a directory",
			},
		},
		{
			name: "update to existing entry",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptyCredCache()
				validCache.insert(credEntry{
					Key:               "some-key",
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					Credential: clientauthenticationv1beta1.ExecCredentialStatus{
						Token: "some-old-token",
					},
				})
				require.NoError(t, os.MkdirAll(filepath.Dir(tmp), 0700))
				require.NoError(t, validCache.writeTo(tmp))
			},
			key: "some-key",
			cred: &clientauthenticationv1beta1.ExecCredentialStatus{
				Token: "some-new-token",
			},
			wantTestFile: func(t *testing.T, tmp string) {
				cache, err := readCredCache(tmp)
				require.NoError(t, err)
				require.Len(t, cache.Credentials, 1)
				require.Less(t, time.Since(cache.Credentials[0].LastUsedTimestamp.Time).Nanoseconds(), (5 * time.Second).Nanoseconds())
				require.Equal(t, clientauthenticationv1beta1.ExecCredentialStatus{
					Token: "some-new-token",
				}, cache.Credentials[0].Credential)
			},
		},
		{
			name: "new entry",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptyCredCache()
				validCache.insert(credEntry{
					Key:               "some-other-key",
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					Credential: clientauthenticationv1beta1.ExecCredentialStatus{
						Token: "some-other-token",
					},
				})
				require.NoError(t, os.MkdirAll(filepath.Dir(tmp), 0700))
				require.NoError(t, validCache.writeTo(tmp))
			},
			key: "some-new-key",
			cred: &clientauthenticationv1beta1.ExecCredentialStatus{
				Token: "some-new-token",
			},
			wantTestFile: func(t *testing.T, tmp string) {
				cache, err := readCredCache(tmp)
				require.NoError(t, err)
				require.Len(t, cache.Credentials, 2)
				require.Less(t, time.Since(cache.Credentials[1].LastUsedTimestamp.Time).Nanoseconds(), (5 * time.Second).Nanoseconds())
				require.Equal(t, clientauthenticationv1beta1.ExecCredentialStatus{
					Token: "some-new-token",
				}, cache.Credentials[1].Credential)
			},
		},
		{
			name: "error writing cache",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, os.MkdirAll(tmp, 0700))
			},
			key: "some-key",
			cred: &clientauthenticationv1beta1.ExecCredentialStatus{
				Token: "some-new-token",
			},
			wantErrors: []string{
				"failed to read cache, resetting: could not read credential cache file: read TEMPFILE: is a directory",
				"could not write credential cache: open TEMPFILE: is a directory",
			},
			wantTestFile: func(t *testing.T, tmp string) {
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tmp := testutil.TempDir(t) + "/sessiondir/sessions.yaml"
			if tt.makeTestFile != nil {
				tt.makeTestFile(t, tmp)
			}
			// Initialize a cache with a reporter that collects errors
			errors := errorCollector{t: t}
			c := New(tmp, errors.collect())
			c.PutClusterCredential(tt.key, tt.cred)
			errors.require(tt.wantErrors, "TEMPFILE", tmp, "TEMPDIR", filepath.Dir(tmp))
			if tt.wantTestFile != nil {
				tt.wantTestFile(t, tmp)
			}
		})
	}
}

type errorCollector struct {
	t   *testing.T
	saw []error
}

func (e *errorCollector) collect() Option {
	return WithErrorReporter(func(err error) {
		e.saw = append(e.saw, err)
	})
}

func (e *errorCollector) require(want []string, subs ...string) {
	require.Len(e.t, e.saw, len(want))
	for i, w := range want {
		for i := 0; i < len(subs); i += 2 {
			w = strings.ReplaceAll(w, subs[i], subs[i+1])
		}
		require.EqualError(e.t, e.saw[i], w)
	}
}
