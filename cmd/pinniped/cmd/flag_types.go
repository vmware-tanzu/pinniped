// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/spf13/pflag"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
)

// conciergeMode represents the method by which we should connect to the Concierge on a cluster during login.
// this is meant to be a valid flag.Value implementation.
type conciergeMode int

var _ flag.Value = new(conciergeMode)

const (
	modeUnknown conciergeMode = iota
	modeTokenCredentialRequestAPI
	modeImpersonationProxy
)

func (c *conciergeMode) String() string {
	switch *c {
	case modeImpersonationProxy:
		return "ImpersonationProxy"
	case modeTokenCredentialRequestAPI:
		return "TokenCredentialRequestAPI"
	case modeUnknown:
		fallthrough
	default:
		return "TokenCredentialRequestAPI"
	}
}

func (c *conciergeMode) Set(s string) error {
	if strings.EqualFold(s, "") {
		*c = modeUnknown
		return nil
	}
	if strings.EqualFold(s, "TokenCredentialRequestAPI") {
		*c = modeTokenCredentialRequestAPI
		return nil
	}
	if strings.EqualFold(s, "ImpersonationProxy") {
		*c = modeImpersonationProxy
		return nil
	}
	return fmt.Errorf("invalid mode %q, valid modes are TokenCredentialRequestAPI and ImpersonationProxy", s)
}

func (c *conciergeMode) Type() string {
	return "mode"
}

// MatchesFrontend returns true iff the flag matches the type of the provided frontend.
func (c *conciergeMode) MatchesFrontend(frontend *configv1alpha1.CredentialIssuerFrontend) bool {
	switch *c {
	case modeImpersonationProxy:
		return frontend.Type == configv1alpha1.ImpersonationProxyFrontendType
	case modeTokenCredentialRequestAPI:
		return frontend.Type == configv1alpha1.TokenCredentialRequestAPIFrontendType
	case modeUnknown:
		fallthrough
	default:
		return true
	}
}

// caBundlePathsVar represents a list of CA bundle paths, which load from disk when the flag is populated.
type caBundleVar []byte

var _ pflag.Value = new(caBundleVar)

func (c *caBundleVar) String() string {
	return string(*c)
}

func (c *caBundleVar) Set(path string) error {
	pem, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read CA bundle path: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("failed to load any CA certificates from %q", path)
	}
	if len(*c) == 0 {
		*c = pem
		return nil
	}
	*c = bytes.Join([][]byte{*c, pem}, []byte("\n"))
	return nil
}

func (c *caBundleVar) Type() string {
	return "path"
}
