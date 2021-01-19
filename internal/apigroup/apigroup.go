// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package apigroup provides centralized logic around Pinniped's API group parameterization.
package apigroup

import (
	"fmt"
	"strings"
)

// defaultAPIGroupSuffix is the default suffix of the Concierge API group. Our generated code uses
// this suffix, so we know that we can replace this suffix with the configured API group suffix.
const defaultAPIGroupSuffix = "pinniped.dev"

// Make constructs an API group from a baseAPIGroup and a parameterized apiGroupSuffix.
//
// We assume that all apiGroup's will end in "pinniped.dev", and therefore we can safely replace the
// reference to "pinniped.dev" with the provided apiGroupSuffix. If the provided baseAPIGroup does
// not end in "pinniped.dev", then this function will return an empty string and false.
//
// See Example_loginv1alpha1 and Example_string for more information on input/output pairs.
func Make(baseAPIGroup, apiGroupSuffix string) (string, bool) {
	if !strings.HasSuffix(baseAPIGroup, defaultAPIGroupSuffix) {
		return "", false
	}
	i := strings.LastIndex(baseAPIGroup, defaultAPIGroupSuffix)
	return fmt.Sprintf("%s%s", baseAPIGroup[:i], apiGroupSuffix), true
}
