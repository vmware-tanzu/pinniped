// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package fakekubeapi contains a *very* simple httptest.Server that can be used to stand in for
// a real Kube API server in tests.
//
// Usage:
//   func TestSomething(t *testing.T) {
//     resources := map[string]kubeclient.Object{
//       // store preexisting resources here
//       "/api/v1/namespaces/default/pods/some-pod-name": &corev1.Pod{...},
//     }
//     server, restConfig := fakekubeapi.Start(t, resources)
//     defer server.Close()
//     client := kubeclient.New(kubeclient.WithConfig(restConfig))
//     // do stuff with client...
//   }
package fakekubeapi

import (
	"encoding/pem"
	"io/ioutil"
	"mime"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	aggregatorclientscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"

	pinnipedconciergeclientsetscheme "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned/scheme"
	pinnipedsupervisorclientsetscheme "go.pinniped.dev/generated/1.20/client/supervisor/clientset/versioned/scheme"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/multierror"
)

// Unlike the standard httperr.New(), this one does not prepend error messages with any prefix.
type plainHTTPErr struct {
	code int
	msg  string
}

func (e plainHTTPErr) Error() string {
	return e.msg
}

func (e plainHTTPErr) Respond(w http.ResponseWriter) {
	http.Error(w, e.msg, e.code)
}

// Start starts an httptest.Server (with TLS) that pretends to be a Kube API server.
//
// The server uses the provided resources map to store API Object's. The map should be from API path
// to Object (e.g., /api/v1/namespaces/default/pods/some-pod-name => &corev1.Pod{}).
//
// Start returns an already started httptest.Server and a restclient.Config that can be used to talk
// to the server.
//
// Note! Only these following verbs are (partially) supported: create, get, update, delete.
func Start(t *testing.T, resources map[string]metav1.Object) (*httptest.Server, *restclient.Config) {
	if resources == nil {
		resources = make(map[string]metav1.Object)
	}

	server := httptest.NewTLSServer(httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (err error) {
		obj, err := decodeObj(r)
		if err != nil {
			return err
		}

		obj, err = handleObj(r, obj, resources)
		if err != nil {
			return err
		}

		if r.Method != http.MethodDelete && obj == nil {
			return &plainHTTPErr{
				code: http.StatusNotFound,
				// This is representative of a real Kube 404 message body.
				msg: `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"not found","reason":"NotFound","details":{"name":"not-found","kind":"pods"},"code":404}`,
			}
		}

		if err := encodeObj(w, r, obj); err != nil {
			return err
		}

		return nil
	}))
	restConfig := &restclient.Config{
		Host: server.URL,
		TLSClientConfig: restclient.TLSClientConfig{
			CAData: pem.EncodeToMemory(&pem.Block{Bytes: server.Certificate().Raw, Type: "CERTIFICATE"}),
		},
	}
	return server, restConfig
}

func decodeObj(r *http.Request) (metav1.Object, error) {
	switch r.Method {
	case http.MethodPut, http.MethodPost:
	default:
		return nil, nil
	}

	contentType := r.Header.Get("Content-Type")
	if len(contentType) == 0 {
		return nil, httperr.New(http.StatusUnsupportedMediaType, "empty content-type header is not allowed")
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, httperr.Wrap(http.StatusUnsupportedMediaType, "could not parse mime type from content-type header", err)
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, httperr.Wrap(http.StatusInternalServerError, "read body", err)
	}

	var obj metav1.Object
	multiErr := multierror.New()
	codecsThatWeUseInOurCode := []runtime.NegotiatedSerializer{
		kubescheme.Codecs,
		aggregatorclientscheme.Codecs,
		pinnipedconciergeclientsetscheme.Codecs,
		pinnipedsupervisorclientsetscheme.Codecs,
	}
	for _, codec := range codecsThatWeUseInOurCode {
		obj, err = tryDecodeObj(mediaType, body, codec)
		if err == nil {
			return obj, nil
		}
		multiErr.Add(err)
	}
	return nil, multiErr.ErrOrNil()
}

func tryDecodeObj(
	mediaType string,
	body []byte,
	negotiatedSerializer runtime.NegotiatedSerializer,
) (metav1.Object, error) {
	serializerInfo, ok := runtime.SerializerInfoForMediaType(negotiatedSerializer.SupportedMediaTypes(), mediaType)
	if !ok {
		return nil, httperr.Newf(http.StatusInternalServerError, "unable to find serialier with content-type %s", mediaType)
	}

	obj, err := runtime.Decode(serializerInfo.Serializer, body)
	if err != nil {
		return nil, httperr.Wrap(http.StatusInternalServerError, "decode obj", err)
	}

	return obj.(metav1.Object), nil
}

func handleObj(r *http.Request, obj metav1.Object, resources map[string]metav1.Object) (metav1.Object, error) {
	switch r.Method {
	case http.MethodGet:
		obj = resources[r.URL.Path]
	case http.MethodPost, http.MethodPut:
		resources[path.Join(r.URL.Path, obj.GetName())] = obj
	case http.MethodDelete:
		if _, ok := resources[r.URL.Path]; !ok {
			return nil, httperr.Newf(http.StatusNotFound, "no resource with path %q", r.URL.Path)
		}
		delete(resources, r.URL.Path)
	default:
		return nil, httperr.New(http.StatusMethodNotAllowed, "check source code for methods supported")
	}

	return obj, nil
}

func encodeObj(w http.ResponseWriter, r *http.Request, obj metav1.Object) error {
	if r.Method == http.MethodDelete {
		return nil
	}

	accepts := strings.Split(r.Header.Get("Accept"), ",")
	contentType := findGoodContentType(accepts)
	if len(contentType) == 0 {
		return httperr.Newf(http.StatusUnsupportedMediaType, "can't find good content type in %s", accepts)
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return httperr.Wrap(http.StatusUnsupportedMediaType, "could not parse mime type from accept header", err)
	}

	serializerInfo, ok := runtime.SerializerInfoForMediaType(kubescheme.Codecs.SupportedMediaTypes(), mediaType)
	if !ok {
		return httperr.Newf(http.StatusInternalServerError, "unable to find serialier with content-type %s", mediaType)
	}

	data, err := runtime.Encode(serializerInfo.Serializer, obj.(runtime.Object))
	if err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "decode obj", err)
	}

	w.Header().Set("Content-Type", contentType)
	if _, err := w.Write(data); err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "write response", err)
	}

	return nil
}

func findGoodContentType(contentTypes []string) string {
	for _, contentType := range contentTypes {
		if strings.Contains(contentType, "json") || strings.Contains(contentType, "yaml") || strings.Contains(contentType, "protobuf") {
			return contentType
		}
	}
	return ""
}
