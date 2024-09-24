// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"

	"go.pinniped.dev/internal/plog"
)

type Dialer interface {
	IsReachableAndTLSValidationSucceeds(
		ctx context.Context,
		address string,
		certPool *x509.CertPool,
		logger plog.Logger,
	) error
}

type internalDialer struct {
}

func NewDialer() *internalDialer {
	return &internalDialer{}
}

func (i *internalDialer) IsReachableAndTLSValidationSucceeds(
	ctx context.Context,
	address string,
	certPool *x509.CertPool,
	logger plog.Logger,
) error {
	if ctx == nil {
		ctx = context.Background()
	}

	_, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	dialer := tls.Dialer{
		Config: Default(certPool),
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		// Don't wrap this error message since this is just a helper function.
		return err
	}
	err = conn.Close()
	if err != nil { // untested
		// Log it just so that it doesn't completely disappear.
		logger.Error("Failed to close connection: ", err)
	}
	return nil
}
