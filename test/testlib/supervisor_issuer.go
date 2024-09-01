// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import (
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/certauthority"
)

type SupervisorIssuer struct {
	issuerURL *url.URL
	ip        net.IP
}

func NewSupervisorIssuer(t *testing.T, issuer string) SupervisorIssuer {
	t.Helper()

	t.Logf("NewSupervisorIssuer: %s", issuer)

	issuerURL, err := url.Parse(issuer)
	require.NoError(t, err)
	require.NotEmpty(t, issuerURL.Hostname(), "hostname cannot be empty, usually this happens when the scheme is empty. issuer=%q", issuer)

	ip := net.ParseIP(issuerURL.Hostname())

	return SupervisorIssuer{
		issuerURL: issuerURL,
		ip:        ip,
	}
}

func (s SupervisorIssuer) Issuer() string {
	return s.issuerURL.String()
}

func (s SupervisorIssuer) Address() string {
	return s.issuerURL.Host
}

func (s SupervisorIssuer) Hostname() string {
	return s.issuerURL.Hostname()
}

func (s SupervisorIssuer) Port(defaultPort string) string {
	port := s.issuerURL.Port()
	if port == "" {
		return defaultPort
	}
	return s.issuerURL.Port()
}

func (s SupervisorIssuer) Hostnames() []string {
	if s.IsIPAddress() {
		return nil // don't want DNS records in the cert when using IP address
	}
	return []string{s.issuerURL.Hostname()}
}

func (s SupervisorIssuer) IPs() []net.IP {
	if !s.IsIPAddress() {
		return nil
	}
	return []net.IP{s.ip}
}

func (s SupervisorIssuer) IssuerServerCert(
	t *testing.T,
	ca *certauthority.CA,
) ([]byte, []byte) {
	t.Helper()

	cert, err := ca.IssueServerCert(s.Hostnames(), s.IPs(), 24*time.Hour)
	require.NoError(t, err)
	certPEM, keyPEM, err := certauthority.ToPEM(cert)
	require.NoError(t, err)
	t.Logf("issued server cert for Supervisor: hostname=%+v, ips=%+v\n%s",
		s.Hostnames(), s.IPs(),
		certPEM)
	return certPEM, keyPEM
}

func (s SupervisorIssuer) IsIPAddress() bool {
	return s.ip != nil
}
