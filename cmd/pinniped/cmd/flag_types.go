// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"flag"
	"fmt"
	"strings"

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
	default:
		return true
	}
}
