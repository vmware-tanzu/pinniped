/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package handlers

import (
	"encoding/json"
	"net/http"
)

type healthzResponse struct {
	Status string `json:"status"`
}

type healthzHandler struct{}

func (h healthzHandler) ServeHTTP(responseWriter http.ResponseWriter, _ *http.Request) {
	response := healthzResponse{"OK"}
	js, _ := json.Marshal(response)
	responseWriter.Header().Set(headerNameContentType, jsonMimeType)
	_, _ = responseWriter.Write(js)
}

func newHealthzHandler() http.Handler {
	return healthzHandler{}
}
