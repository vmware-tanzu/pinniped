// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package responseutil

import (
	"fmt"
	"net/http"
)

func HTTPErrorf(w http.ResponseWriter, code int, errorFmt string, a ...any) {
	http.Error(w,
		fmt.Sprintf("%s: %s", http.StatusText(code), fmt.Sprintf(errorFmt, a...)),
		code,
	)
}
