// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import "github.com/davecgh/go-spew/spew"

func Sdump(a ...any) string {
	config := spew.ConfigState{
		Indent:                  "\t",
		MaxDepth:                10, // prevent log explosion
		DisableMethods:          true,
		DisablePointerMethods:   true,
		DisablePointerAddresses: true,
		DisableCapacities:       true,
		ContinueOnMethod:        true,
		SortKeys:                true,
		SpewKeys:                true,
	}
	return config.Sdump(a...)
}
