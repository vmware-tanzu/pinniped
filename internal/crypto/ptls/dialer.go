// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

type Dialer interface {
	IsReachableAndTLSValidationSucceeds(
		address string,
		certPool *x509.CertPool,
		logger ErrorOnlyLogger,
	) error
}

type ErrorOnlyLogger interface {
	Error(msg string, err error, keysAndValues ...any)
}

type internalDialer struct {
	dialer *net.Dialer
}

func NewDialer() *internalDialer {
	return &internalDialer{
		dialer: &net.Dialer{
			Timeout: 15 * time.Second,
		},
	}
}

func (i *internalDialer) WithTimeout(timeout time.Duration) Dialer {
	i.dialer.Timeout = timeout
	return i
}

func (i *internalDialer) IsReachableAndTLSValidationSucceeds(
	address string,
	certPool *x509.CertPool,
	logger ErrorOnlyLogger,
) error {
	connection, err := tls.DialWithDialer(i.dialer, "tcp", address, Default(certPool))
	if err != nil {
		// Don't wrap this error message since this is just a helper function.
		return err
	}
	err = connection.Close()
	if err != nil { // untested
		// Log it just so that it doesn't completely disappear.
		logger.Error("Failed to close connection: ", err)
	}
	return nil
}
