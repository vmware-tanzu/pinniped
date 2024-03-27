// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import "strings"

func SplitByNewline(lineToSplit string) []string {
	if len(lineToSplit) == 0 {
		return nil
	}

	return strings.Split(strings.TrimSpace(lineToSplit), "\n")
}
