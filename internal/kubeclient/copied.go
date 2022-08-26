// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"bytes"
	"encoding/hex"
	"net/url"

	"k8s.io/apimachinery/pkg/runtime/schema"
	restclient "k8s.io/client-go/rest"

	"go.pinniped.dev/internal/plog"
)

// defaultServerUrlFor was copied from k8s.io/client-go/rest/url_utils.go.
func defaultServerUrlFor(config *restclient.Config) (*url.URL, string, error) { //nolint:revive
	hasCA := len(config.CAFile) != 0 || len(config.CAData) != 0
	hasCert := len(config.CertFile) != 0 || len(config.CertData) != 0
	defaultTLS := hasCA || hasCert || config.Insecure
	host := config.Host
	if host == "" {
		host = "localhost"
	}

	if config.GroupVersion != nil {
		return restclient.DefaultServerURL(host, config.APIPath, *config.GroupVersion, defaultTLS)
	}
	return restclient.DefaultServerURL(host, config.APIPath, schema.GroupVersion{}, defaultTLS)
}

// glogBody logs a body output that could be either JSON or protobuf. It explicitly guards against
// allocating a new string for the body output unless necessary. Uses a simple heuristic to determine
// whether the body is printable.
func glogBody(prefix string, body []byte) {
	if plog.Enabled(plog.LevelAll) {
		if bytes.IndexFunc(body, func(r rune) bool {
			return r < 0x0a
		}) != -1 {
			plog.All(prefix, "body", hex.Dump(body))
		} else {
			plog.All(prefix, "body", string(body))
		}
	}
}
