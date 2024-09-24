// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Use this package to avoid import loops with internal/testutil/tlsserver
package ptls_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/tlsserver"
)

func TestDialer(t *testing.T) {
	secureServerIPv4, secureServerIPv4CA := tlsserver.TestServerIPv4(t, nil, nil)
	secureServerIPv6, secureServerIPv6CA := tlsserver.TestServerIPv6(t, nil, nil)
	insecureServer := httptest.NewServer(nil)

	fakeCert, _, err := testutil.CreateCertificate(time.Now().Add(-1*time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, err)

	tests := []struct {
		name      string
		fullURL   string
		certPool  *x509.CertPool
		wantError string
	}{
		{
			name:     "happy path with TLS-enabled IPv4",
			fullURL:  secureServerIPv4.URL,
			certPool: bytesToCertPool(secureServerIPv4CA),
		},
		{
			name:     "happy path with TLS-enabled IPv6",
			fullURL:  secureServerIPv6.URL,
			certPool: bytesToCertPool(secureServerIPv6CA),
		},
		{
			name:      "returns error when connecting to a non-TLS server",
			fullURL:   insecureServer.URL,
			wantError: "tls: first record does not look like a TLS handshake",
		},
		{
			name:      "returns error when using the wrong bundle",
			fullURL:   secureServerIPv4.URL,
			certPool:  bytesToCertPool(fakeCert),
			wantError: "tls: failed to verify certificate: x509: certificate signed by unknown authority",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dialer := ptls.NewDialer()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			err := dialer.IsReachableAndTLSValidationSucceeds(
				context.Background(),
				urlToAddress(t, test.fullURL),
				test.certPool,
				logger,
			)
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDialer_TimeoutAfter15s(t *testing.T) {
	t.Parallel()

	dialTimeout := 15 * time.Second

	maxDurationForTest := 2 * dialTimeout
	maxTimeForTest := time.After(maxDurationForTest)
	testPassed := make(chan bool)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()

		var log bytes.Buffer
		logger := plog.TestLogger(t, &log)

		dialer := ptls.NewDialer()
		err := dialer.IsReachableAndTLSValidationSucceeds(
			ctx, // replace with context.Background() to verify that this hangs indefinitely
			setupHangingServer(t),
			nil,
			logger,
		)
		require.EqualError(t, err, "context deadline exceeded")
		testPassed <- true
	}()

	select {
	case <-maxTimeForTest:
		t.Errorf("timeout not honored: test did not complete within %s", maxDurationForTest)
		t.FailNow()
	case <-testPassed:
		t.Log("everything ok!")
	}
}

func TestDialer_WithoutDeadline_Uses30sTimeout(t *testing.T) {
	t.Parallel()

	maxDurationForTest := 40 * time.Second
	maxTimeForTest := time.After(maxDurationForTest)
	testPassed := make(chan bool)
	go func() {
		var log bytes.Buffer
		logger := plog.TestLogger(t, &log)

		dialer := ptls.NewDialer()
		err := dialer.IsReachableAndTLSValidationSucceeds(
			context.Background(),
			setupHangingServer(t),
			nil,
			logger,
		)
		require.EqualError(t, err, "context deadline exceeded")
		testPassed <- true
	}()

	select {
	case <-maxTimeForTest:
		t.Errorf("timeout not honored: test did not complete within %s", maxDurationForTest)
		t.FailNow()
	case <-testPassed:
		t.Log("everything ok!")
	}
}

func TestDialer_WithNilContext_Uses30sTimeout(t *testing.T) {
	t.Parallel()

	maxDurationForTest := 40 * time.Second
	maxTimeForTest := time.After(maxDurationForTest)
	testPassed := make(chan bool)
	go func() {
		var log bytes.Buffer
		logger := plog.TestLogger(t, &log)

		dialer := ptls.NewDialer()
		err := dialer.IsReachableAndTLSValidationSucceeds(
			nil, //nolint:staticcheck // Unit testing nil handling.
			setupHangingServer(t),
			nil,
			logger,
		)
		require.EqualError(t, err, "context deadline exceeded")
		testPassed <- true
	}()

	select {
	case <-maxTimeForTest:
		t.Errorf("timeout not honored: test did not complete within %s", maxDurationForTest)
		t.FailNow()
	case <-testPassed:
		t.Log("everything ok!")
	}
}

func setupHangingServer(t *testing.T) string {
	startedTLSListener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// This causes the dial to hang. I'm actually not quite sure why.
			return nil, nil
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, startedTLSListener.Close())
	})

	return startedTLSListener.Addr().String()
}

func urlToAddress(t *testing.T, urlAsString string) string {
	u, err := url.Parse(urlAsString)
	require.NoError(t, err)
	return u.Host
}

func bytesToCertPool(ca []byte) *x509.CertPool {
	x509CertPool := x509.NewCertPool()
	x509CertPool.AppendCertsFromPEM(ca)
	return x509CertPool
}
