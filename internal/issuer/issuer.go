// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuer

import (
	"crypto/x509/pkix"
	"time"

	"k8s.io/apimachinery/pkg/util/errors"

	"go.pinniped.dev/internal/constable"
)

const defaultCertIssuerErr = constable.Error("failed to issue cert")

type CertIssuer interface {
	IssuePEM(subject pkix.Name, dnsNames []string, ttl time.Duration) (certPEM, keyPEM []byte, err error)
}

var _ CertIssuer = CertIssuers{}

type CertIssuers []CertIssuer

func (c CertIssuers) IssuePEM(subject pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, []byte, error) {
	var errs []error

	for _, issuer := range c {
		certPEM, keyPEM, err := issuer.IssuePEM(subject, dnsNames, ttl)
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
