// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import "fmt"

func AddPrefixToEach(prefix string, addToEach []string) []string {
	result := make([]string, len(addToEach))
	for i, s := range addToEach {
		result[i] = fmt.Sprintf("%s%s", prefix, s)
	}
	return result
}
