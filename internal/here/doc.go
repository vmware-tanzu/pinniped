// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package here

import (
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
)

const (
	tab        = "\t"
	fourSpaces = "    "
)

func Doc(s string) string {
	return strings.ReplaceAll(heredoc.Doc(s), tab, fourSpaces)
}

func Docf(raw string, args ...interface{}) string {
	return strings.ReplaceAll(heredoc.Docf(raw, args...), tab, fourSpaces)
}
