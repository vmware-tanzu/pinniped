/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package handlers

import "net/http"

const JsonMimeType = "application/json; charset=utf-8"
const HeaderNameContentType = "Content-Type"

func New() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/healthz", newHealthzHandler())
	return mux
}
