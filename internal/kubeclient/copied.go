// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/url"

	"k8s.io/apimachinery/pkg/runtime/schema"
	restclient "k8s.io/client-go/rest"

	"go.pinniped.dev/internal/plog"
)

// defaultServerUrlFor was copied from k8s.io/client-go/rest/url_utils.go.
//nolint: golint
func defaultServerUrlFor(config *restclient.Config) (*url.URL, string, error) {
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

// truncateBody was copied from k8s.io/client-go/rest/request.go
// ...except i changed klog invocations to analogous plog invocations
//
// truncateBody decides if the body should be truncated, based on the glog Verbosity.
func truncateBody(body string) string {
	max := 0
	switch {
	case plog.Enabled(plog.LevelAll):
		return body
	case plog.Enabled(plog.LevelTrace):
		max = 10240
	case plog.Enabled(plog.LevelDebug):
		max = 1024
	}

	if len(body) <= max {
		return body
	}

	return body[:max] + fmt.Sprintf(" [truncated %d chars]", len(body)-max)
}

// glogBody logs a body output that could be either JSON or protobuf. It explicitly guards against
// allocating a new string for the body output unless necessary. Uses a simple heuristic to determine
// whether the body is printable.
func glogBody(prefix string, body []byte) {
	if plog.Enabled(plog.LevelDebug) {
		if bytes.IndexFunc(body, func(r rune) bool {
			return r < 0x0a
		}) != -1 {
			plog.Debug(prefix, "body", truncateBody(hex.Dump(body)))
		} else {
			plog.Debug(prefix, "body", truncateBody(string(body)))
		}
	}
}
