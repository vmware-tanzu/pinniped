// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"flag"
	"fmt"
	"strings"
)

// conciergeMode represents the method by which we should connect to the Concierge on a cluster during login.
// this is meant to be a valid flag.Value implementation.
type conciergeMode int

var _ flag.Value = new(conciergeMode)

const (
	modeTokenCredentialRequestAPI conciergeMode = iota
	modeImpersonationProxy        conciergeMode = iota
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
