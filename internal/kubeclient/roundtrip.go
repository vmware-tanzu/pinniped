// Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"go.pinniped.dev/internal/httputil/roundtripper"
	"go.pinniped.dev/internal/plog"
)

func configWithWrapper(config *restclient.Config, scheme *runtime.Scheme, negotiatedSerializer runtime.NegotiatedSerializer, middlewares []Middleware, wrapper transport.WrapperFunc) *restclient.Config {
	hostURL, apiPathPrefix, err := getHostAndAPIPathPrefix(config)
	if err != nil {
		plog.DebugErr("invalid rest config", err)
		return config // invalid input config, will fail existing client-go validation
	}

	var middlewareWrapper transport.WrapperFunc
	if len(middlewares) > 0 {
		info, ok := runtime.SerializerInfoForMediaType(negotiatedSerializer.SupportedMediaTypes(), config.ContentType)
		if !ok {
			panic(fmt.Errorf("unknown content type: %s ", config.ContentType)) // static input, programmer error
		}
		regSerializer := info.Serializer // should perform no conversion

		resolver := server.NewRequestInfoResolver(server.NewConfig(serializer.CodecFactory{}))

		schemeRestMapperFunc := schemeRestMapper(scheme)

		middlewareWrapper = newWrapper(hostURL, apiPathPrefix, config, resolver, regSerializer, negotiatedSerializer, schemeRestMapperFunc, middlewares)
	}

	cc := restclient.CopyConfig(config)
	if middlewareWrapper != nil {
		cc.Wrap(middlewareWrapper)
	}
	if wrapper != nil {
		cc.Wrap(wrapper)
	}
	return cc
}

type roundTripperFunc func(req *http.Request) (bool, *http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	// always attempt to close the body, as long as we are the ones that handled the request
	// see http.RoundTripper doc:
	//   "RoundTrip must always close the body, including on errors, ..."
	handled, resp, err := f(req)
	if handled && req.Body != nil {
		_ = req.Body.Close()
	}
	return resp, err
}

func newWrapper(
	hostURL, apiPathPrefix string,
	config *restclient.Config,
	resolver genericapirequest.RequestInfoResolver,
	regSerializer runtime.Serializer,
	negotiatedSerializer runtime.NegotiatedSerializer,
	schemeRestMapperFunc func(schema.GroupVersionResource, Verb) (schema.GroupVersionKind, bool),
	middlewares []Middleware,
) transport.WrapperFunc {
	return func(rt http.RoundTripper) http.RoundTripper {
		return roundtripper.WrapFunc(rt, roundTripperFunc(func(req *http.Request) (bool, *http.Response, error) {
			reqInfo, err := resolver.NewRequestInfo(reqWithoutPrefix(req, hostURL, apiPathPrefix))
			if err != nil || !reqInfo.IsResourceRequest {
				resp, err := rt.RoundTrip(req) // we only handle kube resource requests
				return false, resp, err
			}

			middlewareReq := &request{
				verb:      verb(reqInfo.Verb),
				namespace: reqInfo.Namespace,
				resource: schema.GroupVersionResource{
					Group:    reqInfo.APIGroup,
					Version:  reqInfo.APIVersion,
					Resource: reqInfo.Resource,
				},
				subresource: reqInfo.Subresource,
			}

			for _, middleware := range middlewares {
				middleware.Handle(req.Context(), middlewareReq)
			}

			if len(middlewareReq.reqFuncs) == 0 && len(middlewareReq.respFuncs) == 0 {
				resp, err := rt.RoundTrip(req) // no middleware wanted to mutate this request
				return false, resp, err
			}

			switch v := middlewareReq.Verb(); v {
			case VerbCreate, VerbUpdate:
				return handleCreateOrUpdate(req, middlewareReq, regSerializer, rt, apiPathPrefix, reqInfo, config, negotiatedSerializer)

			case VerbGet, VerbList, VerbDelete, VerbDeleteCollection, VerbPatch, VerbWatch:
				return handleOtherVerbs(v, req, middlewareReq, schemeRestMapperFunc, rt, apiPathPrefix, reqInfo, config, negotiatedSerializer)

			case VerbProxy: // for now we do not support proxy interception
				fallthrough

			default:
				resp, err := rt.RoundTrip(req) // we only handle certain verbs
				return false, resp, err
			}
		}).RoundTrip)
	}
}

func handleOtherVerbs(
	v Verb,
	req *http.Request,
	middlewareReq *request,
	schemeRestMapperFunc func(schema.GroupVersionResource, Verb) (schema.GroupVersionKind, bool),
	rt http.RoundTripper,
	apiPathPrefix string,
	reqInfo *genericapirequest.RequestInfo,
	config *restclient.Config,
	negotiatedSerializer runtime.NegotiatedSerializer,
) (bool, *http.Response, error) {
	mapperGVK, ok := schemeRestMapperFunc(middlewareReq.Resource(), v)
	if !ok {
		return true, nil, fmt.Errorf("unable to determine GVK for middleware request %#v", middlewareReq)
	}

	// no need to do anything with object meta since we only support GVK changes
	obj := &metav1.PartialObjectMetadata{}
	obj.APIVersion, obj.Kind = mapperGVK.ToAPIVersionAndKind()

	result, err := middlewareReq.mutateRequest(obj)
	if err != nil {
		return true, nil, fmt.Errorf("middleware request for %#v failed to mutate: %w", middlewareReq, err)
	}

	if !result.mutated {
		resp, err := rt.RoundTrip(req) // no middleware mutated the request
		return false, resp, err
	}

	// sanity check to make sure mutation is to type meta and/or the response
	unexpectedMutation := len(middlewareReq.respFuncs) == 0 && !result.gvkChanged
	metaIsZero := apiequality.Semantic.DeepEqual(obj.ObjectMeta, metav1.ObjectMeta{})
	if unexpectedMutation || !metaIsZero {
		return true, nil, fmt.Errorf("invalid object meta mutation: %#v", middlewareReq)
	}

	reqURL, err := updatePathNewGVK(req.URL, result, apiPathPrefix, reqInfo)
	if err != nil {
		return true, nil, err
	}

	// shallow copy because we want to preserve all the headers and such but not mutate the original request
	newReq := req.WithContext(req.Context())

	// replace the body and path with the new data
	newReq.URL = reqURL

	glogBody("mutated request url", []byte(reqURL.String()))

	resp, err := rt.RoundTrip(newReq)
	if err != nil {
		return false, nil, fmt.Errorf("middleware request for %#v failed: %w", middlewareReq, err)
	}

	switch v {
	case VerbDelete, VerbDeleteCollection:
		return false, resp, nil // we do not need to fix the response on delete

	case VerbWatch:
		resp, err := handleWatchResponseNewGVK(config, negotiatedSerializer, resp, middlewareReq, result)
		return false, resp, err

	default: // VerbGet, VerbList, VerbPatch
		resp, err := handleResponseNewGVK(config, negotiatedSerializer, resp, middlewareReq, result)
		return false, resp, err
	}
}

func handleCreateOrUpdate(
	req *http.Request,
	middlewareReq *request,
	regSerializer runtime.Serializer,
	rt http.RoundTripper,
	apiPathPrefix string,
	reqInfo *genericapirequest.RequestInfo,
	config *restclient.Config,
	negotiatedSerializer runtime.NegotiatedSerializer,
) (bool, *http.Response, error) {
	if req.GetBody == nil {
		return true, nil, fmt.Errorf("unreadable body for request: %#v", middlewareReq) // this should never happen
	}

	body, err := req.GetBody()
	if err != nil {
		return true, nil, fmt.Errorf("get body failed: %w", err)
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return true, nil, fmt.Errorf("read body failed: %w", err)
	}

	// attempt to decode with no defaults or into specified, i.e. defer to the decoder
	// this should result in the a straight decode with no conversion
	decodedObj, err := runtime.Decode(regSerializer, data)
	if err != nil {
		return true, nil, fmt.Errorf("body decode failed: %w", err)
	}

	obj, ok := decodedObj.(Object)
	if !ok {
		return true, nil, fmt.Errorf("middleware request for %#v has invalid object semantics: %T", middlewareReq, decodedObj)
	}

	result, err := middlewareReq.mutateRequest(obj)
	if err != nil {
		return true, nil, fmt.Errorf("middleware request for %#v failed to mutate: %w", middlewareReq, err)
	}

	if !result.mutated {
		resp, err := rt.RoundTrip(req) // no middleware mutated the request
		return false, resp, err
	}

	reqURL, err := updatePathNewGVK(req.URL, result, apiPathPrefix, reqInfo)
	if err != nil {
		return true, nil, err
	}

	newData, err := runtime.Encode(regSerializer, obj)
	if err != nil {
		return true, nil, fmt.Errorf("new body encode failed: %w", err)
	}

	// simplest way to reuse the body creation logic
	newReqForBody, err := http.NewRequestWithContext(req.Context(), req.Method, reqURL.String(), bytes.NewReader(newData))
	if err != nil {
		return true, nil, fmt.Errorf("failed to create new req for body: %w", err) // this should never happen
	}

	// shallow copy because we want to preserve all the headers and such but not mutate the original request
	newReq := req.WithContext(req.Context())

	// replace the body and path with the new data
	newReq.URL = reqURL
	newReq.ContentLength = newReqForBody.ContentLength
	newReq.Body = newReqForBody.Body
	newReq.GetBody = newReqForBody.GetBody

	glogBody("mutated request", newData)

	resp, err := rt.RoundTrip(newReq)
	if err != nil {
		return true, nil, fmt.Errorf("middleware request for %#v failed: %w", middlewareReq, err)
	}

	if !result.gvkChanged && len(middlewareReq.respFuncs) == 0 {
		return true, resp, nil // we did not change the GVK, so we do not need to mess with the incoming data
	}

	resp, err = handleResponseNewGVK(config, negotiatedSerializer, resp, middlewareReq, result)
	return true, resp, err
}

func handleResponseNewGVK(
	config *restclient.Config,
	negotiatedSerializer runtime.NegotiatedSerializer,
	resp *http.Response,
	middlewareReq *request,
	result *mutationResult,
) (*http.Response, error) {
	// defer these status codes to client-go
	switch {
	case resp.StatusCode == http.StatusSwitchingProtocols,
		resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusPartialContent:
		return resp, nil
	}

	// always make sure we close the body, even if reading from it fails
	defer resp.Body.Close()
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	serializerInfo, err := getSerializerInfo(config, negotiatedSerializer, resp, middlewareReq)
	if err != nil {
		return nil, err
	}

	fixedRespData, err := maybeRestoreGVK(serializerInfo.Serializer, respData, result)
	if err != nil {
		return nil, fmt.Errorf("unable to restore GVK for %#v: %w", middlewareReq, err)
	}

	fixedRespData, err = maybeMutateResponse(serializerInfo.Serializer, fixedRespData, middlewareReq, result)
	if err != nil {
		return nil, fmt.Errorf("unable to mutate response for %#v: %w", middlewareReq, err)
	}

	newResp := &http.Response{}
	*newResp = *resp

	newResp.Body = io.NopCloser(bytes.NewBuffer(fixedRespData))
	return newResp, nil
}

func maybeMutateResponse(serializer runtime.Serializer, fixedRespData []byte, middlewareReq *request, result *mutationResult) ([]byte, error) {
	if len(middlewareReq.respFuncs) == 0 {
		return fixedRespData, nil
	}

	decodedObj, err := runtime.Decode(serializer, fixedRespData)
	if err != nil {
		return fixedRespData, nil // if we cannot decode it, it is not for us - let client-go figure out what to do
	}

	if decodedObj.GetObjectKind().GroupVersionKind() != result.origGVK {
		return fixedRespData, nil
	}

	var mutated bool

	switch middlewareReq.Verb() {
	case VerbList:
		if err := meta.EachListItem(decodedObj, func(listObj runtime.Object) error {
			obj, ok := listObj.(Object)
			if !ok {
				return fmt.Errorf("middleware request for %#v has invalid object semantics: %T", middlewareReq, decodedObj)
			}

			singleMutated, err := middlewareReq.mutateResponse(obj)
			if err != nil {
				return fmt.Errorf("response mutation failed for %#v: %w", middlewareReq, err)
			}

			mutated = mutated || singleMutated

			return nil
		}); err != nil {
			return nil, fmt.Errorf("failed to iterate over list for %#v: %T", middlewareReq, decodedObj)
		}

	default:
		obj, ok := decodedObj.(Object)
		if !ok {
			return nil, fmt.Errorf("middleware request for %#v has invalid object semantics: %T", middlewareReq, decodedObj)
		}

		mutated, err = middlewareReq.mutateResponse(obj)
		if err != nil {
			return nil, fmt.Errorf("response mutation failed for %#v: %w", middlewareReq, err)
		}
	}

	if !mutated {
		return fixedRespData, nil
	}

	newData, err := runtime.Encode(serializer, decodedObj)
	if err != nil {
		return nil, fmt.Errorf("new body encode failed: %w", err)
	}

	// only log if we mutated the response; we only need to log the unmutated response since client-go
	// will log the mutated response for us
	glogBody("unmutated response", fixedRespData)

	return newData, nil
}
