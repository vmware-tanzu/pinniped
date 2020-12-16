// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dynamiccodec

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCodec(t *testing.T) {
	tests := []struct {
		name                   string
		lifespan               time.Duration
		keys                   func(encoderSigningKey, encoderEncryptionKey, decoderSigningKey, decoderEncryptionKey *[]byte)
		wantEncoderErrorPrefix string
		wantDecoderError       string
	}{
		{
			name: "good signing and encryption keys",
		},
		{
			name: "good signing keys and no encryption key",
			keys: func(encoderSigningKey, encoderEncryptionKey, decoderSigningKey, decoderEncryptionKey *[]byte) {
				*encoderEncryptionKey = nil
				*decoderEncryptionKey = nil
			},
		},
		{
			name: "good signing keys and bad encoding encryption key",
			keys: func(encoderSigningKey, encoderEncryptionKey, decoderSigningKey, decoderEncryptionKey *[]byte) {
				*encoderEncryptionKey = []byte("this-secret-is-not-16-bytes")
			},
			wantEncoderErrorPrefix: "securecookie: error - caused by: crypto/aes: invalid key size 27",
		},
		{
			name: "good signing keys and bad decoding encryption key",
			keys: func(encoderSigningKey, encoderEncryptionKey, decoderSigningKey, decoderEncryptionKey *[]byte) {
				*decoderEncryptionKey = []byte("this-secret-is-not-16-bytes")
			},
			wantDecoderError: "securecookie: error - caused by: crypto/aes: invalid key size 27",
		},
		{
			name:             "aaa encoder times stuff out",
			lifespan:         time.Second,
			wantDecoderError: "securecookie: expired timestamp",
		},
		{
			name: "bad encoder signing key",
			keys: func(encoderSigningKey, encoderEncryptionKey, decoderSigningKey, decoderEncryptionKey *[]byte) {
				*encoderSigningKey = nil
			},
			wantEncoderErrorPrefix: "securecookie: hash key is not set",
		},
		{
			name: "bad decoder signing key",
			keys: func(encoderSigningKey, encoderEncryptionKey, decoderSigningKey, decoderEncryptionKey *[]byte) {
				*decoderSigningKey = nil
			},
			wantDecoderError: "securecookie: hash key is not set",
		},
		{
			name: "signing key mismatch",
			keys: func(encoderSigningKey, encoderEncryptionKey, decoderSigningKey, decoderEncryptionKey *[]byte) {
				*encoderSigningKey = []byte("this key does not match the decoder key")
			},
			wantDecoderError: "securecookie: the value is not valid",
		},
		{
			name: "encryption key mismatch",
			keys: func(encoderSigningKey, encoderEncryptionKey, decoderSigningKey, decoderEncryptionKey *[]byte) {
				*encoderEncryptionKey = []byte("16-byte-no-match")
			},
			wantDecoderError: "securecookie: error - caused by: securecookie: error - caused by: ",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var (
				encoderSigningKey    = []byte("some-signing-key")
				encoderEncryptionKey = []byte("16-byte-encr-key")
				decoderSigningKey    = []byte("some-signing-key")
				decoderEncryptionKey = []byte("16-byte-encr-key")
			)
			if test.keys != nil {
				test.keys(&encoderSigningKey, &encoderEncryptionKey, &decoderSigningKey, &decoderEncryptionKey)
			}

			lifespan := test.lifespan
			if lifespan == 0 {
				lifespan = time.Hour
			}

			encoder := New(lifespan, func() []byte { return encoderSigningKey },
				func() []byte { return encoderEncryptionKey })

			encoded, err := encoder.Encode("some-name", "some-message")
			if test.wantEncoderErrorPrefix != "" {
				require.EqualError(t, err, test.wantEncoderErrorPrefix)
				return
			}
			require.NoError(t, err)

			if test.lifespan != 0 {
				time.Sleep(test.lifespan + time.Second)
			}

			decoder := New(lifespan, func() []byte { return decoderSigningKey },
				func() []byte { return decoderEncryptionKey })

			var decoded string
			err = decoder.Decode("some-name", encoded, &decoded)
			if test.wantDecoderError != "" {
				require.Error(t, err)
				require.True(t, strings.HasPrefix(err.Error(), test.wantDecoderError), "expected %q to start with %q", err.Error(), test.wantDecoderError)
				return
			}
			require.NoError(t, err)

			require.Equal(t, "some-message", decoded)
		})
	}
}
