// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package requestutil

import "net/http"

func SNIServerName(req *http.Request) string {
	name := ""
	if req.TLS != nil {
		name = req.TLS.ServerName
	}
	return name
}
