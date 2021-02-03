// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"fmt"
	"mime"
	"net/http"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	restclient "k8s.io/client-go/rest"
)

type passthroughDecoder struct{}

func (d passthroughDecoder) Decode(data []byte, _ *schema.GroupVersionKind, _ runtime.Object) (runtime.Object, *schema.GroupVersionKind, error) {
	return &runtime.Unknown{Raw: data}, &schema.GroupVersionKind{}, nil
}

func getSerializerInfo(config *restclient.Config, negotiatedSerializer runtime.NegotiatedSerializer, resp *http.Response, middlewareReq *request) (runtime.SerializerInfo, error) {
	contentType := resp.Header.Get("Content-Type")
	if len(contentType) == 0 {
		contentType = config.ContentType
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return runtime.SerializerInfo{}, fmt.Errorf("failed to parse content type for %#v: %w", middlewareReq, err)
	}

	respInfo, ok := runtime.SerializerInfoForMediaType(negotiatedSerializer.SupportedMediaTypes(), mediaType)
	if !ok || respInfo.Serializer == nil || respInfo.StreamSerializer == nil || respInfo.StreamSerializer.Serializer == nil || respInfo.StreamSerializer.Framer == nil {
		return runtime.SerializerInfo{}, fmt.Errorf("unable to find resp serialier for %#v with content-type %s", middlewareReq, mediaType)
	}

	return respInfo, nil
}
