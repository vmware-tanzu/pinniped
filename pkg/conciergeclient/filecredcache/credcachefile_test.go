// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package filecredcache

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/testutil"
)

func mustRead(filename string) []byte {
	out, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	return out
}

var (
	t1       = metav1.NewTime(time.Date(2020, 10, 20, 18, 46, 7, 0, time.UTC).Local())
	testCert = mustRead("./testdata/test.crt")
	testKey  = mustRead("./testdata/test.key")
)

// validCredCache should be the same data as `testdata/valid.yaml`.
var validCredCache = credCache{
	TypeMeta: metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "ClusterCredentialCache"},
	Credentials: []credEntry{
		{
			Key:               "testkey",
			CreationTimestamp: metav1.NewTime(time.Date(2020, 10, 20, 18, 42, 7, 0, time.UTC).Local()),
			LastUsedTimestamp: metav1.NewTime(time.Date(2020, 10, 20, 18, 45, 31, 0, time.UTC).Local()),
			Credential: clientauthenticationv1beta1.ExecCredentialStatus{
				ExpirationTimestamp:   &t1,
				ClientCertificateData: base64.StdEncoding.EncodeToString(testCert),
				ClientKeyData:         base64.StdEncoding.EncodeToString(testKey),
			},
		},
	},
}

func TestReadCredentialCache(t *testing.T) {
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
				TypeMeta:    metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "ClusterCredentialCache"},
				Credentials: []credEntry{},
			},
		},
		{
			name:    "other file error",
			path:    "./testdata/",
			wantErr: "could not read credential cache file: read ./testdata/: is a directory",
		},
		{
			name:    "invalid YAML",
			path:    "./testdata/invalid.yaml",
			wantErr: "invalid credential cache file: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type filecredcache.credCache",
		},
		{
			name:    "wrong version",
			path:    "./testdata/wrong-version.yaml",
			wantErr: `unsupported session version: v1.TypeMeta{Kind:"NotAClusterCredentialCache", APIVersion:"config.supervisor.pinniped.dev/v2alpha6"}`,
		},
		{
			name: "valid",
			path: "./testdata/valid.yaml",
			want: &validCredCache,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := readCredCache(tt.path)
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

func TestEmptyCredentialCache(t *testing.T) {
	t.Parallel()
	got := emptyCredCache()
	require.Equal(t, metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "ClusterCredentialCache"}, got.TypeMeta)
	require.Equal(t, 0, len(got.Credentials))
	require.Equal(t, 1, cap(got.Credentials))
}

func TestWriteTo(t *testing.T) {
	t.Parallel()
	t.Run("io error", func(t *testing.T) {
		t.Parallel()
		tmp := testutil.TempDir(t) + "/sessions.yaml"
		require.NoError(t, os.Mkdir(tmp, 0700))
		err := validCredCache.writeTo(tmp)
		require.EqualError(t, err, "open "+tmp+": is a directory")
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, validCredCache.writeTo(testutil.TempDir(t)+"/sessions.yaml"))
	})
}

func TestNormalized(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, emptyCredCache(), emptyCredCache().normalized())
	})

	t.Run("nonempty", func(t *testing.T) {
		t.Parallel()

		testCA, err := certauthority.New(pkix.Name{CommonName: "test-ca"}, 1*time.Hour)
		require.NoError(t, err)
		expiredCertPEM, expiredKeyPEM, err := testCA.IssuePEM(pkix.Name{CommonName: "test-cert-expired"}, nil, -1*time.Hour)
		require.NoError(t, err)

		validCertPEM, validKeyPEM, err := testCA.IssuePEM(pkix.Name{CommonName: "test-cert-valid"}, nil, time.Hour)
		require.NoError(t, err)

		input := emptyCredCache()
		now := time.Now()
		oneHourFromNow := metav1.NewTime(now.Add(1 * time.Hour))
		oneHourAgo := metav1.NewTime(now.Add(-1 * time.Hour))
		input.Credentials = []credEntry{
			// expired entry should be pruned
			{
				Key:               "test-key-1",
				CreationTimestamp: oneHourFromNow,
				LastUsedTimestamp: oneHourFromNow,
				Credential: clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: &oneHourAgo,
				},
			},
			// entry with only token should be pruned
			{
				Key:               "test-key-2",
				CreationTimestamp: oneHourFromNow,
				LastUsedTimestamp: oneHourFromNow,
				Credential: clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp: &oneHourFromNow,
					Token:               "some-test-token",
				},
			},
			// entry with invalid cert base64 should be pruned
			{
				Key:               "test-key-3",
				CreationTimestamp: oneHourFromNow,
				LastUsedTimestamp: oneHourFromNow,
				Credential: clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp:   &oneHourFromNow,
					ClientCertificateData: "invalid-base64",
					ClientKeyData:         "aW52YWxpZC1wZW0tYmxvY2s=",
				},
			},
			// entry with invalid key base64 should be pruned
			{
				Key:               "test-key-4",
				CreationTimestamp: oneHourFromNow,
				LastUsedTimestamp: oneHourFromNow,
				Credential: clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp:   &oneHourFromNow,
					ClientCertificateData: "aW52YWxpZC1wZW0tYmxvY2s=",
					ClientKeyData:         "invalid-base64",
				},
			},
			// entry with invalid PEM should be pruned
			{
				Key:               "test-key-5",
				CreationTimestamp: oneHourFromNow,
				LastUsedTimestamp: oneHourFromNow,
				Credential: clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp:   &oneHourFromNow,
					ClientCertificateData: "aW52YWxpZC1wZW0tYmxvY2s=",
					ClientKeyData:         "aW52YWxpZC1wZW0tYmxvY2s=",
				},
			},
			// entry with expired cert should be pruned
			{
				Key:               "test-key-6",
				CreationTimestamp: oneHourFromNow,
				LastUsedTimestamp: oneHourFromNow,
				Credential: clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp:   &oneHourFromNow,
					ClientCertificateData: base64.StdEncoding.EncodeToString(expiredCertPEM),
					ClientKeyData:         base64.StdEncoding.EncodeToString(expiredKeyPEM),
				},
			},
			// entry that's valid but hasn't been recently used should be pruned
			{
				Key:               "test-key-7",
				CreationTimestamp: oneHourAgo,
				LastUsedTimestamp: metav1.NewTime(now.AddDate(-1, 0, 0)),
				Credential: clientauthenticationv1beta1.ExecCredentialStatus{
					ExpirationTimestamp:   &oneHourFromNow,
					ClientCertificateData: base64.StdEncoding.EncodeToString(validCertPEM),
					ClientKeyData:         base64.StdEncoding.EncodeToString(validKeyPEM),
				},
			},
			// two entries with valid certs should be retained and sorted
			{
				Key:               "test-key-8",
				CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
				LastUsedTimestamp: metav1.NewTime(now),
				Credential: clientauthenticationv1beta1.ExecCredentialStatus{
					ClientCertificateData: base64.StdEncoding.EncodeToString(validCertPEM),
					ClientKeyData:         base64.StdEncoding.EncodeToString(validKeyPEM),
				},
			},
			{
				Key:               "test-key-9",
				CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
				LastUsedTimestamp: metav1.NewTime(now),
				Credential: clientauthenticationv1beta1.ExecCredentialStatus{
					ClientCertificateData: base64.StdEncoding.EncodeToString(validCertPEM),
					ClientKeyData:         base64.StdEncoding.EncodeToString(validKeyPEM),
				},
			},
		}

		// Expect that all but the last two valid session are pruned, and that they're sorted.
		require.Equal(t, &credCache{
			TypeMeta: metav1.TypeMeta{APIVersion: "config.supervisor.pinniped.dev/v1alpha1", Kind: "ClusterCredentialCache"},
			Credentials: []credEntry{
				{
					Key:               "test-key-9",
					CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now),
					Credential: clientauthenticationv1beta1.ExecCredentialStatus{
						ClientCertificateData: base64.StdEncoding.EncodeToString(validCertPEM),
						ClientKeyData:         base64.StdEncoding.EncodeToString(validKeyPEM),
					},
				},
				{
					Key:               "test-key-8",
					CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					LastUsedTimestamp: metav1.NewTime(now),
					Credential: clientauthenticationv1beta1.ExecCredentialStatus{
						ClientCertificateData: base64.StdEncoding.EncodeToString(validCertPEM),
						ClientKeyData:         base64.StdEncoding.EncodeToString(validKeyPEM),
					},
				},
			},
		}, input.normalized())
	})
}

func TestLookup(t *testing.T) {
	t.Parallel()
	require.Nil(t, validCredCache.lookup(""))
	require.NotNil(t, validCredCache.lookup("testkey"))
}

func TestInsert(t *testing.T) {
	t.Parallel()
	c := emptyCredCache()
	c.insert(credEntry{})
	require.Len(t, c.Credentials, 1)
}
