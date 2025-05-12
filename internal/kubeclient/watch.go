// Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	stderrors "errors"
	"fmt"
	"io"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/streaming"
	"k8s.io/apimachinery/pkg/util/net"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	restclient "k8s.io/client-go/rest"
	restclientwatch "k8s.io/client-go/rest/watch"

	"go.pinniped.dev/internal/plog"
)

func handleWatchResponseNewGVK(
	config *restclient.Config,
	negotiatedSerializer runtime.NegotiatedSerializer,
	resp *http.Response,
	middlewareReq *request,
	result *mutationResult,
) (*http.Response, error) {
	// defer non-success cases to client-go
	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}

	var goRoutineStarted bool
	defer func() {
		if goRoutineStarted {
			return
		}
		// always drain and close the body if we do not get to the point of starting our go routine
		drainAndMaybeCloseBody(resp, true)
	}()

	serializerInfo, err := getSerializerInfo(config, negotiatedSerializer, resp, middlewareReq)
	if err != nil {
		return nil, err
	}

	newResp := &http.Response{}
	*newResp = *resp

	newBodyReader, newBodyWriter := io.Pipe()

	newResp.Body = newBodyReader // client-go is responsible for closing this reader

	goRoutineStarted = true
	go func() {
		var sourceDecoder watch.Decoder
		defer utilruntime.HandleCrash()
		defer func() {
			// the sourceDecoder will close the resp body. we want to make sure the drain the body before
			// we do that
			drainAndMaybeCloseBody(resp, false)
			if sourceDecoder != nil {
				sourceDecoder.Close()
			}
		}()
		defer newBodyWriter.Close()

		frameReader := serializerInfo.StreamSerializer.NewFrameReader(resp.Body)
		watchEventDecoder := streaming.NewDecoder(frameReader, serializerInfo.StreamSerializer.Serializer)
		sourceDecoder = restclientwatch.NewDecoder(watchEventDecoder, &passthroughDecoder{})
		defer sourceDecoder.Close()

		frameWriter := serializerInfo.StreamSerializer.NewFrameWriter(newBodyWriter)
		watchEventEncoder := streaming.NewEncoder(frameWriter, serializerInfo.StreamSerializer.Serializer)

		for {
			ok, err := sendWatchEvent(sourceDecoder, serializerInfo.Serializer, middlewareReq, result, watchEventEncoder)
			if err != nil {
				if stderrors.Is(err, io.ErrClosedPipe) {
					return // calling newBodyReader.Close() will send this to all newBodyWriter.Write()
				}

				// CloseWithError always returns nil
				// all newBodyReader.Read() will get this error
				_ = newBodyWriter.CloseWithError(err)

				return
			}

			if !ok {
				return
			}
		}
	}()

	return newResp, nil
}

func sendWatchEvent(sourceDecoder watch.Decoder, s runtime.Serializer, middlewareReq *request, result *mutationResult, watchEventEncoder streaming.Encoder) (bool, error) {
	// partially copied from watch.NewStreamWatcher.receive
	eventType, obj, err := sourceDecoder.Decode()
	if err != nil {
		switch {
		case stderrors.Is(err, io.EOF):
			// watch closed normally
		case stderrors.Is(err, io.ErrUnexpectedEOF):
			plog.InfoErr("Unexpected EOF during watch stream event decoding", err)
		case net.IsProbableEOF(err), net.IsTimeout(err):
			plog.TraceErr("Unable to decode an event from the watch stream", err)
		default:
			return false, fmt.Errorf("unexpected watch decode error for %#v: %w", middlewareReq, err)
		}
		return false, nil // all errors end watch
	}

	unknown, ok := obj.(*runtime.Unknown)
	if !ok || len(unknown.Raw) == 0 {
		return false, fmt.Errorf("unexpected decode type: %T", obj)
	}

	respData := unknown.Raw
	fixedRespData, err := maybeRestoreGVK(s, respData, result)
	if err != nil {
		return false, fmt.Errorf("unable to restore GVK for %#v: %w", middlewareReq, err)
	}

	fixedRespData, err = maybeMutateResponse(s, fixedRespData, middlewareReq, result)
	if err != nil {
		return false, fmt.Errorf("unable to mutate response for %#v: %w", middlewareReq, err)
	}

	event := &metav1.WatchEvent{
		Type:   string(eventType),
		Object: runtime.RawExtension{Raw: fixedRespData},
	}

	if err := watchEventEncoder.Encode(event); err != nil {
		return false, fmt.Errorf("failed to encode watch event for %#v: %w", middlewareReq, err)
	}

	return true, nil
}

// drainAndMaybeCloseBody attempts to drain and optionallt close the provided body.
//
// We want to drain used HTTP response bodies so that the underlying TCP connection can be
// reused. However, if the underlying response body is extremely large or a never-ending stream,
// then we don't want to wait for the read to finish. In these cases, we give up on the TCP
// connection and just close the body.
func drainAndMaybeCloseBody(resp *http.Response, close bool) {
	// from k8s.io/client-go/rest/request.go...
	const maxBodySlurpSize = 2 << 10
	if resp.ContentLength <= maxBodySlurpSize {
		_, _ = io.Copy(io.Discard, &io.LimitedReader{R: resp.Body, N: maxBodySlurpSize})
	}
	if close {
		resp.Body.Close()
	}
}
