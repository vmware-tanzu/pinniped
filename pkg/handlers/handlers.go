/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package handlers

import "net/http"

const jsonMimeType = "application/json; charset=utf-8"
const headerNameContentType = "Content-Type"

func New() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/healthz", newHealthzHandler())
	return mux
}
