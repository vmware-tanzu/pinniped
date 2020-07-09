/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package library

import "github.com/davecgh/go-spew/spew"

func Sdump(a ...interface{}) string {
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
