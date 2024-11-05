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
	issuerURL        *url.URL
	ip               net.IP
	alternativeNames []string
}

func NewSupervisorIssuer(t *testing.T, issuer string) *SupervisorIssuer {
	t.Helper()

	t.Logf("NewSupervisorIssuer: %s", issuer)

	issuerURL, err := url.Parse(issuer)
	require.NoError(t, err)
	require.NotEmpty(t, issuerURL.Hostname(), "hostname cannot be empty, usually this happens when the scheme is empty. issuer=%q", issuer)

	ip := net.ParseIP(issuerURL.Hostname())

	return &SupervisorIssuer{
		issuerURL: issuerURL,
		ip:        ip,
	}
}

// AddAlternativeName adds a SAN for the cert. It is not intended to take an IP address as its argument.
func (s *SupervisorIssuer) AddAlternativeName(san string) {
	s.alternativeNames = append(s.alternativeNames, san)
}

func (s *SupervisorIssuer) Issuer() string {
	return s.issuerURL.String()
}

func (s *SupervisorIssuer) Address() string {
	return s.issuerURL.Host
}

func (s *SupervisorIssuer) Hostname() string {
	return s.issuerURL.Hostname()
}

func (s *SupervisorIssuer) Port(defaultPort string) string {
	port := s.issuerURL.Port()
	if port == "" {
		return defaultPort
	}
	return s.issuerURL.Port()
}

func (s *SupervisorIssuer) hostnamesForCert() []string {
	var hostnames []string
	if !s.IsIPAddress() {
		hostnames = append(hostnames, s.issuerURL.Hostname())
	}
	if s.alternativeNames != nil {
		hostnames = append(hostnames, s.alternativeNames...)
	}
	return hostnames
}

func (s *SupervisorIssuer) ipsForCert() []net.IP {
	if !s.IsIPAddress() {
		return nil
	}
	return []net.IP{s.ip}
}

func (s *SupervisorIssuer) IssuerServerCert(
	t *testing.T,
	ca *certauthority.CA,
) ([]byte, []byte) {
	t.Helper()

	cert, err := ca.IssueServerCert(s.hostnamesForCert(), s.ipsForCert(), 24*time.Hour)
	require.NoError(t, err)
	certPEM, keyPEM, err := certauthority.ToPEM(cert)
	require.NoError(t, err)
	t.Logf("issued server cert for Supervisor: hostname=%+v, ips=%+v\n%s",
		s.hostnamesForCert(), s.ipsForCert(),
		certPEM)
	return certPEM, keyPEM
}

func (s *SupervisorIssuer) IsIPAddress() bool {
	return s.ip != nil
}
