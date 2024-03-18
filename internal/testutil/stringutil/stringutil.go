// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package stringutil

import "strings"

func SplitByNewline(logs string) []string {
	if len(logs) == 0 {
		return nil
	}

	return strings.Split(strings.TrimSpace(logs), "\n")
}
