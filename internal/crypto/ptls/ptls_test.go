// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/server/options"
)

func TestDefaultServing(t *testing.T) {
	t.Parallel()

	opts := &options.SecureServingOptionsWithLoopback{SecureServingOptions: &options.SecureServingOptions{}}
	defaultServing(opts)
	require.Equal(t, options.SecureServingOptionsWithLoopback{
		SecureServingOptions: &options.SecureServingOptions{
			CipherSuites: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			},
			MinTLSVersion: "VersionTLS12",
		},
	}, *opts)
}

func TestSecureServing(t *testing.T) {
	t.Parallel()

	opts := &options.SecureServingOptionsWithLoopback{SecureServingOptions: &options.SecureServingOptions{}}
	secureServing(opts)
	require.Equal(t, options.SecureServingOptionsWithLoopback{
		SecureServingOptions: &options.SecureServingOptions{
			MinTLSVersion: "VersionTLS13",
		},
	}, *opts)
}

func TestMerge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		tlsConfigFunc ConfigFunc
		tlsConfig     *tls.Config
		want          *tls.Config
	}{
		{
			name:          "default no protos",
			tlsConfigFunc: Default,
			tlsConfig: &tls.Config{ //nolint:gosec // not concerned with TLS MinVersion here
				ServerName: "something-to-check-passthrough",
			},
			want: &tls.Config{
				ServerName: "something-to-check-passthrough",
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				NextProtos: []string{"h2", "http/1.1"},
			},
		},
		{
			name:          "default with protos",
			tlsConfigFunc: Default,
			tlsConfig: &tls.Config{ //nolint:gosec // not concerned with TLS MinVersion here
				ServerName: "a different thing for passthrough",
				NextProtos: []string{"panda"},
			},
			want: &tls.Config{
				ServerName: "a different thing for passthrough",
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				NextProtos: []string{"panda"},
			},
		},
		{
			name:          "secure no protos",
			tlsConfigFunc: Secure,
			tlsConfig: &tls.Config{ //nolint:gosec // not concerned with TLS MinVersion here
				ServerName: "something-to-check-passthrough",
			},
			want: &tls.Config{
				ServerName: "something-to-check-passthrough",
				MinVersion: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
				NextProtos: []string{"h2", "http/1.1"},
			},
		},
		{
			name:          "secure with protos",
			tlsConfigFunc: Secure,
			tlsConfig: &tls.Config{ //nolint:gosec // not concerned with TLS MinVersion here
				ServerName: "a different thing for passthrough",
				NextProtos: []string{"panda"},
			},
			want: &tls.Config{
				ServerName: "a different thing for passthrough",
				MinVersion: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
				NextProtos: []string{"panda"},
			},
		},
		{
			name:          "default ldap no protos",
			tlsConfigFunc: DefaultLDAP,
			tlsConfig: &tls.Config{ //nolint:gosec // not concerned with TLS MinVersion here
				ServerName: "something-to-check-passthrough",
			},
			want: &tls.Config{
				ServerName: "something-to-check-passthrough",
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, //nolint:gosec  // yeah, I know it is a bad cipher, but AD sucks
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				},
				NextProtos: []string{"h2", "http/1.1"},
			},
		},
		{
			name:          "default ldap with protos",
			tlsConfigFunc: DefaultLDAP,
			tlsConfig: &tls.Config{
				ServerName: "a different thing for passthrough",
				NextProtos: []string{"panda"},
			},
			want: &tls.Config{
				ServerName: "a different thing for passthrough",
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, //nolint:gosec  // yeah, I know it is a bad cipher, but AD sucks
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				},
				NextProtos: []string{"panda"},
			},
		},
		{
			name:          "legacy no protos",
			tlsConfigFunc: Legacy,
			tlsConfig: &tls.Config{
				ServerName: "something-to-check-passthrough",
			},
			want: &tls.Config{
				ServerName: "something-to-check-passthrough",
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_RSA_WITH_AES_128_CBC_SHA, //nolint:gosec  // yeah, I know it is a bad cipher, this is the legacy config
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				NextProtos: []string{"h2", "http/1.1"},
			},
		},
		{
			name:          "legacy with protos",
			tlsConfigFunc: Legacy,
			tlsConfig: &tls.Config{
				ServerName: "a different thing for passthrough",
				NextProtos: []string{"panda"},
			},
			want: &tls.Config{
				ServerName: "a different thing for passthrough",
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_RSA_WITH_AES_128_CBC_SHA, //nolint:gosec  // yeah, I know it is a bad cipher, this is the legacy config
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				NextProtos: []string{"panda"},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			Merge(tt.tlsConfigFunc, tt.tlsConfig)
			require.Equal(t, tt.want, tt.tlsConfig)
		})
	}
}
