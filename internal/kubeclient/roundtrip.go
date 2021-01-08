// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"
)

// TODO unit test

func configWithWrapper(config *restclient.Config, negotiatedSerializer runtime.NegotiatedSerializer, middlewares []Middleware) *restclient.Config {
	// no need for any wrapping when we have no middleware to inject
	if len(middlewares) == 0 {
		return config
	}

	info, ok := runtime.SerializerInfoForMediaType(negotiatedSerializer.SupportedMediaTypes(), config.ContentType)
	if !ok {
		panic(fmt.Errorf("unknown content type: %s ", config.ContentType)) // static input, programmer error
	}
	serializer := info.Serializer // should perform no conversion

	f := func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// ignore everything that has an unreadable body
			if req.GetBody == nil {
				return rt.RoundTrip(req)
			}

			var reqMiddlewares []Middleware
			for _, middleware := range middlewares {
				middleware := middleware
				if middleware.Handles(req.Method) {
					reqMiddlewares = append(reqMiddlewares, middleware)
				}
			}

			// no middleware to handle this request
			if len(reqMiddlewares) == 0 {
				return rt.RoundTrip(req)
			}

			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("get body failed: %w", err)
			}
			defer body.Close()
			data, err := ioutil.ReadAll(body)
			if err != nil {
				return nil, fmt.Errorf("read body failed: %w", err)
			}

			// attempt to decode with no defaults or into specified, i.e. defer to the decoder
			// this should result in the a straight decode with no conversion
			obj, _, err := serializer.Decode(data, nil, nil)
			if err != nil {
				return nil, fmt.Errorf("body decode failed: %w", err)
			}

			accessor, err := meta.Accessor(obj)
			if err != nil {
				return rt.RoundTrip(req) // ignore everything that has no object meta for now
			}

			// run all the mutating operations
			var reqMutated bool
			for _, reqMiddleware := range reqMiddlewares {
				mutated := reqMiddleware.Mutate(accessor)
				reqMutated = mutated || reqMutated
			}

			// no mutation occurred, keep the original request
			if !reqMutated {
				return rt.RoundTrip(req)
			}

			// we plan on making a new request so make sure to close the original request's body
			_ = req.Body.Close()

			newData, err := runtime.Encode(serializer, obj)
			if err != nil {
				return nil, fmt.Errorf("new body encode failed: %w", err)
			}

			// TODO log newData at high loglevel similar to REST client

			// simplest way to reuse the body creation logic
			newReqForBody, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(newData))
			if err != nil {
				return nil, fmt.Errorf("failed to create new req for body: %w", err) // this should never happen
			}

			// shallow copy because we want to preserve all the headers and such but not mutate the original request
			newReq := req.WithContext(req.Context())

			// replace the body with the new data
			newReq.ContentLength = newReqForBody.ContentLength
			newReq.Body = newReqForBody.Body
			newReq.GetBody = newReqForBody.GetBody

			return rt.RoundTrip(newReq)
		})
	}

	cc := restclient.CopyConfig(config)
	cc.Wrap(f)
	return cc
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
