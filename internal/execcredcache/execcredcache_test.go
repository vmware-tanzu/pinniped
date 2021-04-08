// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execcredcache

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
	tmp := testutil.TempDir(t) + "/credentials.yaml"
	c := New(tmp)
	require.NotNil(t, c)
	require.Equal(t, tmp, c.path)
	require.NotNil(t, c.errReporter)
	c.errReporter(fmt.Errorf("some error"))
}

func TestGet(t *testing.T) {
	t.Parallel()
	now := time.Now().Round(1 * time.Second)
	oneHourFromNow := metav1.NewTime(now.Add(1 * time.Hour))

	type testKey struct{ K1, K2 string }

	tests := []struct {
		name         string
		makeTestFile func(t *testing.T, tmp string)
		trylockFunc  func(*testing.T) error
		unlockFunc   func(*testing.T) error
		key          testKey
		want         *clientauthenticationv1beta1.ExecCredential
		wantErrors   []string
		wantTestFile func(t *testing.T, tmp string)
	}{
		{
			name: "not found",
			key:  testKey{},
		},
		{
			name:         "file lock error",
			makeTestFile: func(t *testing.T, tmp string) { require.NoError(t, ioutil.WriteFile(tmp, []byte(""), 0600)) },
			trylockFunc:  func(t *testing.T) error { return fmt.Errorf("some lock error") },
			unlockFunc:   func(t *testing.T) error { require.Fail(t, "should not be called"); return nil },
			key:          testKey{},
			wantErrors:   []string{"could not lock cache file: some lock error"},
		},
		{
			name: "invalid file",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, ioutil.WriteFile(tmp, []byte("invalid yaml"), 0600))
			},
			key: testKey{},
			wantErrors: []string{
				"failed to read cache, resetting: invalid cache file: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type execcredcache.credCache",
			},
		},
		{
			name:         "invalid file, fail to unlock",
			makeTestFile: func(t *testing.T, tmp string) { require.NoError(t, ioutil.WriteFile(tmp, []byte("invalid"), 0600)) },
			trylockFunc:  func(t *testing.T) error { return nil },
			unlockFunc:   func(t *testing.T) error { return fmt.Errorf("some unlock error") },
			key:          testKey{},
			wantErrors: []string{
				"failed to read cache, resetting: invalid cache file: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type execcredcache.credCache",
				"could not unlock cache file: some unlock error",
			},
		},
		{
			name: "unreadable file",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, os.Mkdir(tmp, 0700))
			},
			key: testKey{},
			wantErrors: []string{
				"failed to read cache, resetting: could not read cache file: read TEMPFILE: is a directory",
				"could not write cache: open TEMPFILE: is a directory",
			},
		},
		{
			name: "valid file but cache miss",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptyCache()
				validCache.Entries = []entry{{
					Key:               jsonSHA256Hex(testKey{K1: "v3", K2: "v4"}),
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Minute)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
					Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
						Token:               "test-token",
						ExpirationTimestamp: &oneHourFromNow,
					},
				}}
				require.NoError(t, validCache.writeTo(tmp))
			},
			key:        testKey{K1: "v1", K2: "v2"},
			wantErrors: []string{},
		},
		{
			name: "valid file but expired cache hit",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptyCache()
				oneMinuteAgo := metav1.NewTime(now.Add(-1 * time.Minute))
				validCache.Entries = []entry{{
					Key:               jsonSHA256Hex(testKey{K1: "v1", K2: "v2"}),
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Minute)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
					Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
						Token:               "test-token",
						ExpirationTimestamp: &oneMinuteAgo,
					},
				}}
				require.NoError(t, validCache.writeTo(tmp))
			},
			key:        testKey{K1: "v1", K2: "v2"},
			wantErrors: []string{},
		},
		{
			name: "valid file with cache hit",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptyCache()

				validCache.Entries = []entry{{
					Key:               jsonSHA256Hex(testKey{K1: "v1", K2: "v2"}),
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Minute)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
					Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
						Token:               "test-token",
						ExpirationTimestamp: &oneHourFromNow,
					},
				}}
				require.NoError(t, validCache.writeTo(tmp))
			},
			key:        testKey{K1: "v1", K2: "v2"},
			wantErrors: []string{},
			want: &clientauthenticationv1beta1.ExecCredential{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ExecCredential",
					APIVersion: "client.authentication.k8s.io/v1beta1",
				},
				Spec: clientauthenticationv1beta1.ExecCredentialSpec{},
				Status: &clientauthenticationv1beta1.ExecCredentialStatus{
					Token:               "test-token",
					ExpirationTimestamp: &oneHourFromNow,
				},
			},
			wantTestFile: func(t *testing.T, tmp string) {
				cache, err := readCache(tmp)
				require.NoError(t, err)
				require.Len(t, cache.Entries, 1)
				require.Less(t, time.Since(cache.Entries[0].LastUsedTimestamp.Time).Nanoseconds(), (5 * time.Second).Nanoseconds())
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
			c := New(tmp)
			c.errReporter = errors.report
			if tt.trylockFunc != nil {
				c.trylockFunc = func() error { return tt.trylockFunc(t) }
			}
			if tt.unlockFunc != nil {
				c.unlockFunc = func() error { return tt.unlockFunc(t) }
			}

			got := c.Get(tt.key)
			require.Equal(t, tt.want, got)
			errors.require(tt.wantErrors, "TEMPFILE", tmp)
			if tt.wantTestFile != nil {
				tt.wantTestFile(t, tmp)
			}
		})
	}
}

func TestPutToken(t *testing.T) {
	t.Parallel()
	now := time.Now().Round(1 * time.Second)

	type testKey struct{ K1, K2 string }

	tests := []struct {
		name         string
		makeTestFile func(t *testing.T, tmp string)
		key          testKey
		cred         *clientauthenticationv1beta1.ExecCredential
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
				validCache := emptyCache()
				validCache.Entries = []entry{
					{
						Key:               jsonSHA256Hex(testKey{K1: "v1", K2: "v2"}),
						CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Minute)),
						LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
						Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
							ExpirationTimestamp: timePtr(now.Add(1 * time.Hour)),
							Token:               "token-one",
						},
					},

					// A second entry that was created over a day ago.
					{
						Key:               jsonSHA256Hex(testKey{K1: "v3", K2: "v4"}),
						CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
						LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
						Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
							ExpirationTimestamp: timePtr(now.Add(1 * time.Hour)),
							Token:               "token-two",
						},
					},
				}
				require.NoError(t, os.MkdirAll(filepath.Dir(tmp), 0700))
				require.NoError(t, validCache.writeTo(tmp))
			},
			key: testKey{K1: "v1", K2: "v2"},
			cred: &clientauthenticationv1beta1.ExecCredential{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ExecCredential",
					APIVersion: "client.authentication.k8s.io/v1beta1",
				},
				Status: &clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: timePtr(now.Add(1 * time.Hour)),
					Token:               "token-one",
				},
			},
			wantTestFile: func(t *testing.T, tmp string) {
				cache, err := readCache(tmp)
				require.NoError(t, err)
				require.Len(t, cache.Entries, 1)
				require.Less(t, time.Since(cache.Entries[0].LastUsedTimestamp.Time).Nanoseconds(), (5 * time.Second).Nanoseconds())
				require.Equal(t, &clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: timePtr(now.Add(1 * time.Hour).Local()),
					Token:               "token-one",
				}, cache.Entries[0].Credential)
			},
		},
		{
			name: "new entry",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptyCache()
				validCache.Entries = []entry{
					{
						Key:               jsonSHA256Hex(testKey{K1: "v3", K2: "v4"}),
						CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Minute)),
						LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
						Credential: &clientauthenticationv1beta1.ExecCredentialStatus{
							ExpirationTimestamp: timePtr(now.Add(1 * time.Hour)),
							Token:               "other-token",
						},
					},
				}
				require.NoError(t, os.MkdirAll(filepath.Dir(tmp), 0700))
				require.NoError(t, validCache.writeTo(tmp))
			},
			key: testKey{K1: "v1", K2: "v2"},
			cred: &clientauthenticationv1beta1.ExecCredential{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ExecCredential",
					APIVersion: "client.authentication.k8s.io/v1beta1",
				},
				Status: &clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: timePtr(now.Add(1 * time.Hour)),
					Token:               "token-one",
				},
			},
			wantTestFile: func(t *testing.T, tmp string) {
				cache, err := readCache(tmp)
				require.NoError(t, err)
				require.Len(t, cache.Entries, 2)
				require.Less(t, time.Since(cache.Entries[1].LastUsedTimestamp.Time).Nanoseconds(), (5 * time.Second).Nanoseconds())
				require.Equal(t, &clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: timePtr(now.Add(1 * time.Hour).Local()),
					Token:               "token-one",
				}, cache.Entries[1].Credential)
			},
		},
		{
			name: "error writing cache",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, os.MkdirAll(tmp, 0700))
			},
			key: testKey{K1: "v1", K2: "v2"},
			cred: &clientauthenticationv1beta1.ExecCredential{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ExecCredential",
					APIVersion: "client.authentication.k8s.io/v1beta1",
				},
				Status: &clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: timePtr(now.Add(1 * time.Hour)),
					Token:               "token-one",
				},
			},
			wantErrors: []string{
				"failed to read cache, resetting: could not read cache file: read TEMPFILE: is a directory",
				"could not write cache: open TEMPFILE: is a directory",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tmp := testutil.TempDir(t) + "/cachedir/credentials.yaml"
			if tt.makeTestFile != nil {
				tt.makeTestFile(t, tmp)
			}
			// Initialize a cache with a reporter that collects errors
			errors := errorCollector{t: t}
			c := New(tmp)
			c.errReporter = errors.report
			c.Put(tt.key, tt.cred)
			errors.require(tt.wantErrors, "TEMPFILE", tmp, "TEMPDIR", filepath.Dir(tmp))
			if tt.wantTestFile != nil {
				tt.wantTestFile(t, tmp)
			}
		})
	}
}

func TestHashing(t *testing.T) {
	type testKey struct{ K1, K2 string }
	require.Equal(t, "38e0b9de817f645c4bec37c0d4a3e58baecccb040f5718dc069a72c7385a0bed", jsonSHA256Hex(nil))
	require.Equal(t, "625bb1f93dc90a1bda400fdaceb8c96328e567a0c6aaf81e7fccc68958b4565d", jsonSHA256Hex([]string{"k1", "k2"}))
	require.Equal(t, "8fb659f5dd266ffd8d0c96116db1d96fe10e3879f9cb6f7e9ace016696ff69f6", jsonSHA256Hex(testKey{K1: "v1", K2: "v2"}))
	require.Equal(t, "42c783a2c29f91127b064df368bda61788181d2dd1709b417f9506102ea8da67", jsonSHA256Hex(testKey{K1: "v3", K2: "v4"}))
	require.Panics(t, func() { jsonSHA256Hex(&unmarshalable{}) })
}

type errorCollector struct {
	t   *testing.T
	saw []error
}

func (e *errorCollector) report(err error) {
	e.saw = append(e.saw, err)
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

func timePtr(from time.Time) *metav1.Time {
	t := metav1.NewTime(from)
	return &t
}

type unmarshalable struct{}

func (*unmarshalable) MarshalJSON() ([]byte, error) { return nil, fmt.Errorf("some MarshalJSON error") }
