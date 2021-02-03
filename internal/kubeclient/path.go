// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	restclient "k8s.io/client-go/rest"
)

func updatePathNewGVK(reqURL *url.URL, result *mutationResult, apiPathPrefix string, reqInfo *genericapirequest.RequestInfo) (*url.URL, error) {
	if !result.gvkChanged {
		return reqURL, nil
	}

	if len(result.origGVK.Group) == 0 {
		return nil, fmt.Errorf("invalid attempt to change core group")
	}

	newURL := &url.URL{}
	*newURL = *reqURL

	// replace old GVK with new GVK
	apiRoot := path.Join(apiPathPrefix, reqInfo.APIPrefix)
	oldPrefix := restclient.DefaultVersionedAPIPath(apiRoot, result.origGVK.GroupVersion())
	newPrefix := restclient.DefaultVersionedAPIPath(apiRoot, result.newGVK.GroupVersion())

	newURL.Path = path.Join(newPrefix, strings.TrimPrefix(newURL.Path, oldPrefix))

	return newURL, nil
}

func getHostAndAPIPathPrefix(config *restclient.Config) (string, string, error) {
	hostURL, _, err := defaultServerUrlFor(config)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse host URL from rest config: %w", err)
	}

	return hostURL.String(), hostURL.Path, nil
}

func reqWithoutPrefix(req *http.Request, hostURL, apiPathPrefix string) *http.Request {
	if len(apiPathPrefix) == 0 {
		return req
	}

	if !strings.HasSuffix(hostURL, "/") {
		hostURL += "/"
	}

	if !strings.HasPrefix(req.URL.String(), hostURL) {
		return req
	}

	if !strings.HasPrefix(apiPathPrefix, "/") {
		apiPathPrefix = "/" + apiPathPrefix
	}
	if !strings.HasSuffix(apiPathPrefix, "/") {
		apiPathPrefix += "/"
	}

	reqCopy := req.WithContext(req.Context())
	urlCopy := &url.URL{}
	*urlCopy = *reqCopy.URL
	urlCopy.Path = "/" + strings.TrimPrefix(urlCopy.Path, apiPathPrefix)
	reqCopy.URL = urlCopy

	return reqCopy
}
