/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package webhook provides a way to use an HTTP webhook to authenticate a user.
package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/suzerain-io/placeholder-name/pkg/authentication"
)

// Config describes a Webhook.
type Config struct {
	// URL at which Webhook is running (must be 'https').
	URL string

	// CABundlePath is the local path at which the CA bundle is located that can be
	// used to verify TLS connections to the webhook.
	CABundlePath string
}

// Webhook is a webhook client that makes it easier to validate tokens against a
// webhook.
//
// This webhook must be contactable over an HTTP URL.
type Webhook struct {
	url    *url.URL
	client http.Client
}

// FromConfig tries to create a Webhook from the provided config.
//
// The only supported URL scheme is 'https'.
func FromConfig(config *Config) (*Webhook, error) {
	url, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if url.Scheme != "https" {
		return nil, unsupportedSchemeError{scheme: url.Scheme}
	}

	caBundle, err := ioutil.ReadFile(config.CABundlePath)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle path: %w", err)
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caBundle) {
		return nil, fmt.Errorf("append CA bundle certs: %w", err)
	}

	return &Webhook{
		url: url,
		client: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: rootCAs,
				},
			},
		},
	}, nil
}

func (w *Webhook) Authenticate(
	ctx context.Context,
	cred authentication.Credential,
) (*authentication.Status, bool, error) {
	return nil, false, nil
}
