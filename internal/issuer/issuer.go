// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuer

import (
	"time"

	"k8s.io/apimachinery/pkg/util/errors"

	"go.pinniped.dev/internal/constable"
)

const defaultCertIssuerErr = constable.Error("failed to issue cert")

type ClientCertIssuer interface {
	IssueClientCertPEM(username string, groups []string, ttl time.Duration) (certPEM, keyPEM []byte, err error)
}

var _ ClientCertIssuer = ClientCertIssuers{}

type ClientCertIssuers []ClientCertIssuer

func (c ClientCertIssuers) IssueClientCertPEM(username string, groups []string, ttl time.Duration) ([]byte, []byte, error) {
	var errs []error

	for _, issuer := range c {
		certPEM, keyPEM, err := issuer.IssueClientCertPEM(username, groups, ttl)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return certPEM, keyPEM, nil
	}

	if err := errors.NewAggregate(errs); err != nil {
		return nil, nil, err
	}

	return nil, nil, defaultCertIssuerErr
}
