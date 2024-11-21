// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dynamiccert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/pkg/storage/names"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/test/testlib"
)

func TestProviderWithDynamicServingCertificateController(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		buildCertPool     func(t *testing.T, ca Provider) *x509.CertPool
		buildServingCerts func(t *testing.T, certKey Private) []tls.Certificate
	}{
		{
			name: "no-op leave everything alone",
			buildCertPool: func(t *testing.T, ca Provider) *x509.CertPool {
				pool := x509.NewCertPool()
				ok := pool.AppendCertsFromPEM(ca.CurrentCABundleContent())
				require.True(t, ok, "should have valid non-empty CA bundle")

				return pool
			},
			buildServingCerts: func(t *testing.T, certKey Private) []tls.Certificate {
				cert, err := tls.X509KeyPair(certKey.CurrentCertKeyContent())
				require.NoError(t, err)

				return []tls.Certificate{cert}
			},
		},
		{
			name: "unset the CA",
			buildCertPool: func(t *testing.T, ca Provider) *x509.CertPool {
				ca.UnsetCertKeyContent()

				return nil
			},
			buildServingCerts: func(t *testing.T, certKey Private) []tls.Certificate {
				cert, err := tls.X509KeyPair(certKey.CurrentCertKeyContent())
				require.NoError(t, err)

				return []tls.Certificate{cert}
			},
		},
		{
			name: "unset the serving cert - still serves the old content",
			buildCertPool: func(t *testing.T, ca Provider) *x509.CertPool {
				pool := x509.NewCertPool()
				ok := pool.AppendCertsFromPEM(ca.CurrentCABundleContent())
				require.True(t, ok, "should have valid non-empty CA bundle")

				return pool
			},
			buildServingCerts: func(t *testing.T, certKey Private) []tls.Certificate {
				cert, err := tls.X509KeyPair(certKey.CurrentCertKeyContent())
				require.NoError(t, err)

				certKey.UnsetCertKeyContent()

				return []tls.Certificate{cert}
			},
		},
		{
			name: "change to a new CA",
			buildCertPool: func(t *testing.T, ca Provider) *x509.CertPool {
				// use unique names for all CAs to make sure the pool subjects are different
				newCA, err := certauthority.New(names.SimpleNameGenerator.GenerateName("new-ca"), time.Hour)
				require.NoError(t, err)
				caKey, err := newCA.PrivateKeyToPEM()
				require.NoError(t, err)
				err = ca.SetCertKeyContent(newCA.Bundle(), caKey)
				require.NoError(t, err)

				return newCA.Pool()
			},
			buildServingCerts: func(t *testing.T, certKey Private) []tls.Certificate {
				cert, err := tls.X509KeyPair(certKey.CurrentCertKeyContent())
				require.NoError(t, err)

				return []tls.Certificate{cert}
			},
		},
		{
			name: "change to new serving cert",
			buildCertPool: func(t *testing.T, ca Provider) *x509.CertPool {
				pool := x509.NewCertPool()
				ok := pool.AppendCertsFromPEM(ca.CurrentCABundleContent())
				require.True(t, ok, "should have valid non-empty CA bundle")

				return pool
			},
			buildServingCerts: func(t *testing.T, certKey Private) []tls.Certificate {
				// use unique names for all CAs to make sure the pool subjects are different
				newCA, err := certauthority.New(names.SimpleNameGenerator.GenerateName("new-ca"), time.Hour)
				require.NoError(t, err)

				pem, err := newCA.IssueServerCertPEM(nil, []net.IP{net.ParseIP("127.0.0.2")}, time.Hour)
				require.NoError(t, err)

				err = certKey.SetCertKeyContent(pem.CertPEM, pem.KeyPEM)
				require.NoError(t, err)

				cert, err := tls.X509KeyPair(pem.CertPEM, pem.KeyPEM)
				require.NoError(t, err)

				return []tls.Certificate{cert}
			},
		},
		{
			name: "change both CA and serving cert",
			buildCertPool: func(t *testing.T, ca Provider) *x509.CertPool {
				// use unique names for all CAs to make sure the pool subjects are different
				newOtherCA, err := certauthority.New(names.SimpleNameGenerator.GenerateName("new-other-ca"), time.Hour)
				require.NoError(t, err)
				caKey, err := newOtherCA.PrivateKeyToPEM()
				require.NoError(t, err)
				err = ca.SetCertKeyContent(newOtherCA.Bundle(), caKey)
				require.NoError(t, err)

				return newOtherCA.Pool()
			},
			buildServingCerts: func(t *testing.T, certKey Private) []tls.Certificate {
				// use unique names for all CAs to make sure the pool subjects are different
				newCA, err := certauthority.New(names.SimpleNameGenerator.GenerateName("new-ca"), time.Hour)
				require.NoError(t, err)

				pem, err := newCA.IssueServerCertPEM(nil, []net.IP{net.ParseIP("127.0.0.3")}, time.Hour)
				require.NoError(t, err)

				err = certKey.SetCertKeyContent(pem.CertPEM, pem.KeyPEM)
				require.NoError(t, err)

				cert, err := tls.X509KeyPair(pem.CertPEM, pem.KeyPEM)
				require.NoError(t, err)

				return []tls.Certificate{cert}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// use unique names for all CAs to make sure the pool subjects are different
			ca, err := certauthority.New(names.SimpleNameGenerator.GenerateName("ca"), time.Hour)
			require.NoError(t, err)
			caKey, err := ca.PrivateKeyToPEM()
			require.NoError(t, err)
			caContent := NewCA("ca")
			err = caContent.SetCertKeyContent(ca.Bundle(), caKey)
			require.NoError(t, err)

			pem, err := ca.IssueServerCertPEM(nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
			require.NoError(t, err)
			certKeyContent := NewServingCert("cert-key")
			err = certKeyContent.SetCertKeyContent(pem.CertPEM, pem.KeyPEM)
			require.NoError(t, err)

			tlsConfig := ptls.Default(nil)
			tlsConfig.ClientAuth = tls.RequestClientCert

			dynamicCertificateController := dynamiccertificates.NewDynamicServingCertificateController(
				tlsConfig,
				caContent,
				certKeyContent,
				nil, // we do not care about SNI
				nil, // we do not care about events
			)

			caContent.AddListener(dynamicCertificateController)
			certKeyContent.AddListener(dynamicCertificateController)

			err = dynamicCertificateController.RunOnce()
			require.NoError(t, err)

			stopCh := make(chan struct{})
			defer close(stopCh)
			go dynamicCertificateController.Run(1, stopCh)

			tlsConfig.GetConfigForClient = dynamicCertificateController.GetConfigForClient

			wantClientPool := tt.buildCertPool(t, caContent)
			wantServingCerts := tt.buildServingCerts(t, certKeyContent)

			var lastTLSConfig *tls.Config

			// it will take some time for the controller to catch up
			err = wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
				actualTLSConfig, err := tlsConfig.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "force-standard-sni"})
				if err != nil {
					return false, err
				}

				lastTLSConfig = actualTLSConfig

				return wantClientPool.Equal(actualTLSConfig.ClientCAs) &&
					reflect.DeepEqual(wantServingCerts, actualTLSConfig.Certificates), nil
			})

			if err != nil && lastTLSConfig != nil {
				// for debugging failures
				t.Log("diff between serving certs:\n", cmp.Diff(
					testlib.Sdump(wantServingCerts),
					testlib.Sdump(lastTLSConfig.Certificates),
				))
			}
			require.NoError(t, err)
		})
	}
}

func TestNewServingCert(t *testing.T) {
	got := NewServingCert("")

	ok1 := assert.Implements(fakeT{}, (*Private)(nil), got)
	ok2 := assert.Implements(fakeT{}, (*Public)(nil), got)
	ok3 := assert.Implements(fakeT{}, (*Provider)(nil), got)

	require.True(t, ok1, "NewServingCert must implement Private")
	require.False(t, ok2, "NewServingCert must not implement Public")
	require.False(t, ok3, "NewServingCert must not implement Provider")
}

type fakeT struct{}

func (fakeT) Errorf(string, ...any) {}
