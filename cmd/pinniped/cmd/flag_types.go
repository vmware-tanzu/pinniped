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

// conciergeModeFlag represents the method by which we should connect to the Concierge on a cluster during login.
// this is meant to be a valid flag.Value implementation.
type conciergeModeFlag int

var _ flag.Value = new(conciergeModeFlag)

const (
	modeUnknown conciergeModeFlag = iota
	modeTokenCredentialRequestAPI
	modeImpersonationProxy
)

func (f *conciergeModeFlag) String() string {
	switch *f {
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

func (f *conciergeModeFlag) Set(s string) error {
	if strings.EqualFold(s, "") {
		*f = modeUnknown
		return nil
	}
	if strings.EqualFold(s, "TokenCredentialRequestAPI") {
		*f = modeTokenCredentialRequestAPI
		return nil
	}
	if strings.EqualFold(s, "ImpersonationProxy") {
		*f = modeImpersonationProxy
		return nil
	}
	return fmt.Errorf("invalid mode %q, valid modes are TokenCredentialRequestAPI and ImpersonationProxy", s)
}

func (f *conciergeModeFlag) Type() string {
	return "mode"
}

// MatchesFrontend returns true iff the flag matches the type of the provided frontend.
func (f *conciergeModeFlag) MatchesFrontend(frontend *configv1alpha1.CredentialIssuerFrontend) bool {
	switch *f {
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
type caBundleFlag []byte

var _ pflag.Value = new(caBundleFlag)

func (f *caBundleFlag) String() string {
	return string(*f)
}

func (f *caBundleFlag) Set(path string) error {
	pem, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read CA bundle path: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("failed to load any CA certificates from %q", path)
	}
	if len(*f) == 0 {
		*f = pem
		return nil
	}
	*f = bytes.Join([][]byte{*f, pem}, []byte("\n"))
	return nil
}

func (f *caBundleFlag) Type() string {
	return "path"
}
