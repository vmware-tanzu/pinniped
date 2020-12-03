// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package filesession

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

	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
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

func TestGetToken(t *testing.T) {
	t.Parallel()
	now := time.Now().Round(1 * time.Second)
	tests := []struct {
		name         string
		makeTestFile func(t *testing.T, tmp string)
		trylockFunc  func(*testing.T) error
		unlockFunc   func(*testing.T) error
		key          oidcclient.SessionCacheKey
		want         *oidctypes.Token
		wantErrors   []string
		wantTestFile func(t *testing.T, tmp string)
	}{
		{
			name: "not found",
			key:  oidcclient.SessionCacheKey{},
		},
		{
			name:         "file lock error",
			makeTestFile: func(t *testing.T, tmp string) { require.NoError(t, ioutil.WriteFile(tmp, []byte(""), 0600)) },
			trylockFunc:  func(t *testing.T) error { return fmt.Errorf("some lock error") },
			unlockFunc:   func(t *testing.T) error { require.Fail(t, "should not be called"); return nil },
			key:          oidcclient.SessionCacheKey{},
			wantErrors:   []string{"could not lock session file: some lock error"},
		},
		{
			name: "invalid file",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, ioutil.WriteFile(tmp, []byte("invalid yaml"), 0600))
			},
			key: oidcclient.SessionCacheKey{},
			wantErrors: []string{
				"failed to read cache, resetting: invalid session file: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type filesession.sessionCache",
			},
		},
		{
			name:         "invalid file, fail to unlock",
			makeTestFile: func(t *testing.T, tmp string) { require.NoError(t, ioutil.WriteFile(tmp, []byte("invalid"), 0600)) },
			trylockFunc:  func(t *testing.T) error { return nil },
			unlockFunc:   func(t *testing.T) error { return fmt.Errorf("some unlock error") },
			key:          oidcclient.SessionCacheKey{},
			wantErrors: []string{
				"failed to read cache, resetting: invalid session file: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type filesession.sessionCache",
				"could not unlock session file: some unlock error",
			},
		},
		{
			name: "unreadable file",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, os.Mkdir(tmp, 0700))
			},
			key: oidcclient.SessionCacheKey{},
			wantErrors: []string{
				"failed to read cache, resetting: could not read session file: read TEMPFILE: is a directory",
				"could not write session cache: open TEMPFILE: is a directory",
			},
		},
		{
			name: "valid file but cache miss",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptySessionCache()
				validCache.insert(sessionEntry{
					Key: oidcclient.SessionCacheKey{
						Issuer:      "not-the-test-issuer",
						ClientID:    "not-the-test-client-id",
						Scopes:      []string{"email", "offline_access", "openid", "profile"},
						RedirectURI: "http://localhost:0/callback",
					},
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					Tokens: oidctypes.Token{
						AccessToken: &oidctypes.AccessToken{
							Token:  "test-access-token",
							Type:   "Bearer",
							Expiry: metav1.NewTime(now.Add(1 * time.Hour)),
						},
						IDToken: &oidctypes.IDToken{
							Token:  "test-id-token",
							Expiry: metav1.NewTime(now.Add(1 * time.Hour)),
						},
						RefreshToken: &oidctypes.RefreshToken{
							Token: "test-refresh-token",
						},
					},
				})
				require.NoError(t, validCache.writeTo(tmp))
			},
			key: oidcclient.SessionCacheKey{
				Issuer:      "test-issuer",
				ClientID:    "test-client-id",
				Scopes:      []string{"email", "offline_access", "openid", "profile"},
				RedirectURI: "http://localhost:0/callback",
			},
			wantErrors: []string{},
		},
		{
			name: "valid file with cache hit",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptySessionCache()
				validCache.insert(sessionEntry{
					Key: oidcclient.SessionCacheKey{
						Issuer:      "test-issuer",
						ClientID:    "test-client-id",
						Scopes:      []string{"email", "offline_access", "openid", "profile"},
						RedirectURI: "http://localhost:0/callback",
					},
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					Tokens: oidctypes.Token{
						AccessToken: &oidctypes.AccessToken{
							Token:  "test-access-token",
							Type:   "Bearer",
							Expiry: metav1.NewTime(now.Add(1 * time.Hour)),
						},
						IDToken: &oidctypes.IDToken{
							Token:  "test-id-token",
							Expiry: metav1.NewTime(now.Add(1 * time.Hour)),
						},
						RefreshToken: &oidctypes.RefreshToken{
							Token: "test-refresh-token",
						},
					},
				})
				require.NoError(t, validCache.writeTo(tmp))
			},
			key: oidcclient.SessionCacheKey{
				Issuer:      "test-issuer",
				ClientID:    "test-client-id",
				Scopes:      []string{"email", "offline_access", "openid", "profile"},
				RedirectURI: "http://localhost:0/callback",
			},
			wantErrors: []string{},
			want: &oidctypes.Token{
				AccessToken: &oidctypes.AccessToken{
					Token:  "test-access-token",
					Type:   "Bearer",
					Expiry: metav1.NewTime(now.Add(1 * time.Hour).Local()),
				},
				IDToken: &oidctypes.IDToken{
					Token:  "test-id-token",
					Expiry: metav1.NewTime(now.Add(1 * time.Hour).Local()),
				},
				RefreshToken: &oidctypes.RefreshToken{
					Token: "test-refresh-token",
				},
			},
			wantTestFile: func(t *testing.T, tmp string) {
				cache, err := readSessionCache(tmp)
				require.NoError(t, err)
				require.Len(t, cache.Sessions, 1)
				require.Less(t, time.Since(cache.Sessions[0].LastUsedTimestamp.Time).Nanoseconds(), (5 * time.Second).Nanoseconds())
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

			got := c.GetToken(tt.key)
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
	tests := []struct {
		name         string
		makeTestFile func(t *testing.T, tmp string)
		key          oidcclient.SessionCacheKey
		token        *oidctypes.Token
		wantErrors   []string
		wantTestFile func(t *testing.T, tmp string)
	}{
		{
			name: "fail to create directory",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, ioutil.WriteFile(filepath.Dir(tmp), []byte{}, 0600))
			},
			wantErrors: []string{
				"could not create session cache directory: mkdir TEMPDIR: not a directory",
			},
		},
		{
			name: "update to existing entry",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptySessionCache()
				validCache.insert(sessionEntry{
					Key: oidcclient.SessionCacheKey{
						Issuer:      "test-issuer",
						ClientID:    "test-client-id",
						Scopes:      []string{"email", "offline_access", "openid", "profile"},
						RedirectURI: "http://localhost:0/callback",
					},
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					Tokens: oidctypes.Token{
						AccessToken: &oidctypes.AccessToken{
							Token:  "old-access-token",
							Type:   "Bearer",
							Expiry: metav1.NewTime(now.Add(1 * time.Hour)),
						},
						IDToken: &oidctypes.IDToken{
							Token:  "old-id-token",
							Expiry: metav1.NewTime(now.Add(1 * time.Hour)),
						},
						RefreshToken: &oidctypes.RefreshToken{
							Token: "old-refresh-token",
						},
					},
				})
				require.NoError(t, os.MkdirAll(filepath.Dir(tmp), 0700))
				require.NoError(t, validCache.writeTo(tmp))
			},
			key: oidcclient.SessionCacheKey{
				Issuer:      "test-issuer",
				ClientID:    "test-client-id",
				Scopes:      []string{"email", "offline_access", "openid", "profile"},
				RedirectURI: "http://localhost:0/callback",
			},
			token: &oidctypes.Token{
				AccessToken: &oidctypes.AccessToken{
					Token:  "new-access-token",
					Type:   "Bearer",
					Expiry: metav1.NewTime(now.Add(2 * time.Hour).Local()),
				},
				IDToken: &oidctypes.IDToken{
					Token:  "new-id-token",
					Expiry: metav1.NewTime(now.Add(2 * time.Hour).Local()),
				},
				RefreshToken: &oidctypes.RefreshToken{
					Token: "new-refresh-token",
				},
			},
			wantTestFile: func(t *testing.T, tmp string) {
				cache, err := readSessionCache(tmp)
				require.NoError(t, err)
				require.Len(t, cache.Sessions, 1)
				require.Less(t, time.Since(cache.Sessions[0].LastUsedTimestamp.Time).Nanoseconds(), (5 * time.Second).Nanoseconds())
				require.Equal(t, oidctypes.Token{
					AccessToken: &oidctypes.AccessToken{
						Token:  "new-access-token",
						Type:   "Bearer",
						Expiry: metav1.NewTime(now.Add(2 * time.Hour).Local()),
					},
					IDToken: &oidctypes.IDToken{
						Token:  "new-id-token",
						Expiry: metav1.NewTime(now.Add(2 * time.Hour).Local()),
					},
					RefreshToken: &oidctypes.RefreshToken{
						Token: "new-refresh-token",
					},
				}, cache.Sessions[0].Tokens)
			},
		},
		{
			name: "new entry",
			makeTestFile: func(t *testing.T, tmp string) {
				validCache := emptySessionCache()
				validCache.insert(sessionEntry{
					Key: oidcclient.SessionCacheKey{
						Issuer:      "not-the-test-issuer",
						ClientID:    "not-the-test-client-id",
						Scopes:      []string{"email", "offline_access", "openid", "profile"},
						RedirectURI: "http://localhost:0/callback",
					},
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					Tokens: oidctypes.Token{
						AccessToken: &oidctypes.AccessToken{
							Token:  "old-access-token",
							Type:   "Bearer",
							Expiry: metav1.NewTime(now.Add(1 * time.Hour)),
						},
						IDToken: &oidctypes.IDToken{
							Token:  "old-id-token",
							Expiry: metav1.NewTime(now.Add(1 * time.Hour)),
						},
						RefreshToken: &oidctypes.RefreshToken{
							Token: "old-refresh-token",
						},
					},
				})
				require.NoError(t, os.MkdirAll(filepath.Dir(tmp), 0700))
				require.NoError(t, validCache.writeTo(tmp))
			},
			key: oidcclient.SessionCacheKey{
				Issuer:      "test-issuer",
				ClientID:    "test-client-id",
				Scopes:      []string{"email", "offline_access", "openid", "profile"},
				RedirectURI: "http://localhost:0/callback",
			},
			token: &oidctypes.Token{
				AccessToken: &oidctypes.AccessToken{
					Token:  "new-access-token",
					Type:   "Bearer",
					Expiry: metav1.NewTime(now.Add(2 * time.Hour).Local()),
				},
				IDToken: &oidctypes.IDToken{
					Token:  "new-id-token",
					Expiry: metav1.NewTime(now.Add(2 * time.Hour).Local()),
				},
				RefreshToken: &oidctypes.RefreshToken{
					Token: "new-refresh-token",
				},
			},
			wantTestFile: func(t *testing.T, tmp string) {
				cache, err := readSessionCache(tmp)
				require.NoError(t, err)
				require.Len(t, cache.Sessions, 2)
				require.Less(t, time.Since(cache.Sessions[1].LastUsedTimestamp.Time).Nanoseconds(), (5 * time.Second).Nanoseconds())
				require.Equal(t, oidctypes.Token{
					AccessToken: &oidctypes.AccessToken{
						Token:  "new-access-token",
						Type:   "Bearer",
						Expiry: metav1.NewTime(now.Add(2 * time.Hour).Local()),
					},
					IDToken: &oidctypes.IDToken{
						Token:  "new-id-token",
						Expiry: metav1.NewTime(now.Add(2 * time.Hour).Local()),
					},
					RefreshToken: &oidctypes.RefreshToken{
						Token: "new-refresh-token",
					},
				}, cache.Sessions[1].Tokens)
			},
		},
		{
			name: "error writing cache",
			makeTestFile: func(t *testing.T, tmp string) {
				require.NoError(t, os.MkdirAll(tmp, 0700))
				// require.NoError(t, emptySessionCache().writeTo(tmp))
				// require.NoError(t, os.Chmod(tmp, 0400))
			},
			key: oidcclient.SessionCacheKey{
				Issuer:      "test-issuer",
				ClientID:    "test-client-id",
				Scopes:      []string{"email", "offline_access", "openid", "profile"},
				RedirectURI: "http://localhost:0/callback",
			},
			token: &oidctypes.Token{
				AccessToken: &oidctypes.AccessToken{
					Token:  "new-access-token",
					Type:   "Bearer",
					Expiry: metav1.NewTime(now.Add(2 * time.Hour).Local()),
				},
				IDToken: &oidctypes.IDToken{
					Token:  "new-id-token",
					Expiry: metav1.NewTime(now.Add(2 * time.Hour).Local()),
				},
				RefreshToken: &oidctypes.RefreshToken{
					Token: "new-refresh-token",
				},
			},
			wantErrors: []string{
				"failed to read cache, resetting: could not read session file: read TEMPFILE: is a directory",
				"could not write session cache: open TEMPFILE: is a directory",
			},
			wantTestFile: func(t *testing.T, tmp string) {
				// cache, err := readSessionCache(tmp)
				// require.NoError(t, err)
				// require.Len(t, cache.Sessions, 0)
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
			c.PutToken(tt.key, tt.token)
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
