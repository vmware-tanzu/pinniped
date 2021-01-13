// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/1.20/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/internal/testutil/fakekubeapi"
)

const (
	someClusterName = "some cluster name"
)

var (
	podGVK  = corev1.SchemeGroupVersion.WithKind("Pod")
	goodPod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "good-pod",
			Namespace: "good-namespace",
		},
	}

	apiServiceGVK  = apiregistrationv1.SchemeGroupVersion.WithKind("APIService")
	goodAPIService = &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: "good-api-service",
		},
	}

	tokenCredentialRequestGVK  = loginv1alpha1.SchemeGroupVersion.WithKind("TokenCredentialRequest")
	goodTokenCredentialRequest = &loginv1alpha1.TokenCredentialRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "good-token-credential-request",
			Namespace: "good-namespace",
		},
	}

	federationDomainGVK  = configv1alpha1.SchemeGroupVersion.WithKind("FederationDomain")
	goodFederationDomain = &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "good-federation-domain",
			Namespace: "good-namespace",
		},
	}

	middlewareAnnotations = map[string]string{"some-annotation": "thing 1"}
	middlewareLabels      = map[string]string{"some-label": "thing 2"}
)

// TestKubeclient tests a subset of kubeclient functionality (from the public interface down). We
// intend for the following list of things to be tested with the integration tests:
//   list (running in every informer cache)
//   watch (running in every informer cache)
//   discovery
//   api errors
func TestKubeclient(t *testing.T) {
	// plog.ValidateAndSetLogLevelGlobally(plog.LevelDebug) // uncomment me to get some more debug logs

	tests := []struct {
		name                                    string
		editRestConfig                          func(t *testing.T, restConfig *rest.Config)
		middlewares                             func(t *testing.T) []*spyMiddleware
		reallyRunTest                           func(t *testing.T, c *Client)
		wantMiddlewareReqs, wantMiddlewareResps [][]Object
	}{
		{
			name: "crud core api",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{newAnnotationMiddleware(t), newLabelMiddleware(t)}
			},
			reallyRunTest: func(t *testing.T, c *Client) {
				// create
				pod, err := c.Kubernetes.
					CoreV1().
					Pods(goodPod.Namespace).
					Create(context.Background(), goodPod, metav1.CreateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodPod, pod)

				// read
				pod, err = c.Kubernetes.
					CoreV1().
					Pods(pod.Namespace).
					Get(context.Background(), pod.Name, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, with(goodPod, annotations(), labels()), pod)

				// read when not found
				_, err = c.Kubernetes.
					CoreV1().
					Pods(pod.Namespace).
					Get(context.Background(), "this-pod-does-not-exist", metav1.GetOptions{})
				require.EqualError(t, err, "the server could not find the requested resource (get pods this-pod-does-not-exist)")

				// update
				goodPodWithAnnotationsAndLabelsAndClusterName := with(goodPod, annotations(), labels(), clusterName()).(*corev1.Pod)
				pod, err = c.Kubernetes.
					CoreV1().
					Pods(pod.Namespace).
					Update(context.Background(), goodPodWithAnnotationsAndLabelsAndClusterName, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodPodWithAnnotationsAndLabelsAndClusterName, pod)

				// delete
				err = c.Kubernetes.
					CoreV1().
					Pods(pod.Namespace).
					Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			wantMiddlewareReqs: [][]Object{
				{
					with(goodPod, gvk(podGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(podGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(podGVK)),
					with(goodPod, annotations(), labels(), clusterName(), gvk(podGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(podGVK)),
				},
				{
					with(goodPod, annotations(), gvk(podGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(podGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(podGVK)),
					with(goodPod, annotations(), labels(), clusterName(), gvk(podGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(podGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{
				{
					with(goodPod, annotations(), labels(), gvk(podGVK)),
					with(goodPod, annotations(), labels(), gvk(podGVK)),
					with(goodPod, annotations(), labels(), clusterName(), gvk(podGVK)),
				},
				{
					with(goodPod, emptyAnnotations(), labels(), gvk(podGVK)),
					with(goodPod, annotations(), labels(), gvk(podGVK)),
					with(goodPod, annotations(), labels(), clusterName(), gvk(podGVK)),
				},
			},
		},
		{
			name: "crud core api without middlewares",
			reallyRunTest: func(t *testing.T, c *Client) {
				// create
				pod, err := c.Kubernetes.
					CoreV1().
					Pods(goodPod.Namespace).
					Create(context.Background(), goodPod, metav1.CreateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodPod, pod)

				// read
				pod, err = c.Kubernetes.
					CoreV1().
					Pods(pod.Namespace).
					Get(context.Background(), pod.Name, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, with(goodPod), pod)

				// update
				pod, err = c.Kubernetes.
					CoreV1().
					Pods(pod.Namespace).
					Update(context.Background(), goodPod, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodPod, pod)

				// delete
				err = c.Kubernetes.
					CoreV1().
					Pods(pod.Namespace).
					Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
			},
		},
		{
			name: "crud aggregation api",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{newAnnotationMiddleware(t), newLabelMiddleware(t)}
			},
			reallyRunTest: func(t *testing.T, c *Client) {
				// create
				apiService, err := c.Aggregation.
					ApiregistrationV1().
					APIServices().
					Create(context.Background(), goodAPIService, metav1.CreateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodAPIService, apiService)

				// read
				apiService, err = c.Aggregation.
					ApiregistrationV1().
					APIServices().
					Get(context.Background(), apiService.Name, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, with(goodAPIService, annotations(), labels()), apiService)

				// update
				goodAPIServiceWithAnnotationsAndLabelsAndClusterName := with(goodAPIService, annotations(), labels(), clusterName()).(*apiregistrationv1.APIService)
				apiService, err = c.Aggregation.
					ApiregistrationV1().
					APIServices().
					Update(context.Background(), goodAPIServiceWithAnnotationsAndLabelsAndClusterName, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodAPIServiceWithAnnotationsAndLabelsAndClusterName, apiService)

				// delete
				err = c.Aggregation.
					ApiregistrationV1().
					APIServices().
					Delete(context.Background(), apiService.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			wantMiddlewareReqs: [][]Object{
				{
					with(goodAPIService, gvk(apiServiceGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), clusterName(), gvk(apiServiceGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(apiServiceGVK)),
				},
				{
					with(goodAPIService, annotations(), gvk(apiServiceGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), clusterName(), gvk(apiServiceGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(apiServiceGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{
				{
					with(goodAPIService, annotations(), labels(), gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), clusterName(), gvk(apiServiceGVK)),
				},
				{
					with(goodAPIService, emptyAnnotations(), labels(), gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), clusterName(), gvk(apiServiceGVK)),
				},
			},
		},
		{
			name: "crud concierge api",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{newAnnotationMiddleware(t), newLabelMiddleware(t)}
			},
			reallyRunTest: func(t *testing.T, c *Client) {
				// create
				tokenCredentialRequest, err := c.PinnipedConcierge.
					LoginV1alpha1().
					TokenCredentialRequests(goodTokenCredentialRequest.Namespace).
					Create(context.Background(), goodTokenCredentialRequest, metav1.CreateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodTokenCredentialRequest, tokenCredentialRequest)

				// read
				tokenCredentialRequest, err = c.PinnipedConcierge.
					LoginV1alpha1().
					TokenCredentialRequests(tokenCredentialRequest.Namespace).
					Get(context.Background(), tokenCredentialRequest.Name, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, with(goodTokenCredentialRequest, annotations(), labels()), tokenCredentialRequest)

				// update
				goodTokenCredentialRequestWithAnnotationsAndLabelsAndClusterName := with(goodTokenCredentialRequest, annotations(), labels(), clusterName()).(*loginv1alpha1.TokenCredentialRequest)
				tokenCredentialRequest, err = c.PinnipedConcierge.
					LoginV1alpha1().
					TokenCredentialRequests(tokenCredentialRequest.Namespace).
					Update(context.Background(), goodTokenCredentialRequestWithAnnotationsAndLabelsAndClusterName, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodTokenCredentialRequestWithAnnotationsAndLabelsAndClusterName, tokenCredentialRequest)

				// delete
				err = c.PinnipedConcierge.
					LoginV1alpha1().
					TokenCredentialRequests(tokenCredentialRequest.Namespace).
					Delete(context.Background(), tokenCredentialRequest.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			wantMiddlewareReqs: [][]Object{
				{
					with(goodTokenCredentialRequest, gvk(tokenCredentialRequestGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(tokenCredentialRequestGVK)),
					with(goodTokenCredentialRequest, annotations(), labels(), clusterName(), gvk(tokenCredentialRequestGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(tokenCredentialRequestGVK)),
				},
				{
					with(goodTokenCredentialRequest, annotations(), gvk(tokenCredentialRequestGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(tokenCredentialRequestGVK)),
					with(goodTokenCredentialRequest, annotations(), labels(), clusterName(), gvk(tokenCredentialRequestGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(tokenCredentialRequestGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{
				{
					with(goodTokenCredentialRequest, annotations(), labels(), gvk(tokenCredentialRequestGVK)),
					with(goodTokenCredentialRequest, annotations(), labels(), gvk(tokenCredentialRequestGVK)),
					with(goodTokenCredentialRequest, annotations(), labels(), clusterName(), gvk(tokenCredentialRequestGVK)),
				},
				{
					with(goodTokenCredentialRequest, emptyAnnotations(), labels(), gvk(tokenCredentialRequestGVK)),
					with(goodTokenCredentialRequest, annotations(), labels(), gvk(tokenCredentialRequestGVK)),
					with(goodTokenCredentialRequest, annotations(), labels(), clusterName(), gvk(tokenCredentialRequestGVK)),
				},
			},
		},
		{
			name: "crud supervisor api",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{newAnnotationMiddleware(t), newLabelMiddleware(t)}
			},
			reallyRunTest: func(t *testing.T, c *Client) {
				// create
				federationDomain, err := c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(goodFederationDomain.Namespace).
					Create(context.Background(), goodFederationDomain, metav1.CreateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodFederationDomain, federationDomain)

				// read
				federationDomain, err = c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(federationDomain.Namespace).
					Get(context.Background(), federationDomain.Name, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, with(goodFederationDomain, annotations(), labels()), federationDomain)

				// update
				goodFederationDomainWithAnnotationsAndLabelsAndClusterName := with(goodFederationDomain, annotations(), labels(), clusterName()).(*configv1alpha1.FederationDomain)
				federationDomain, err = c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(federationDomain.Namespace).
					Update(context.Background(), goodFederationDomainWithAnnotationsAndLabelsAndClusterName, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodFederationDomainWithAnnotationsAndLabelsAndClusterName, federationDomain)

				// delete
				err = c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(federationDomain.Namespace).
					Delete(context.Background(), federationDomain.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			wantMiddlewareReqs: [][]Object{
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), clusterName(), gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
				{
					with(goodFederationDomain, annotations(), gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), clusterName(), gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{
				{
					with(goodFederationDomain, annotations(), labels(), gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), clusterName(), gvk(federationDomainGVK)),
				},
				{
					with(goodFederationDomain, emptyAnnotations(), labels(), gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), clusterName(), gvk(federationDomainGVK)),
				},
			},
		},
		{
			name: "we don't call any middleware if there are no mutation funcs",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{newSimpleMiddleware(t, false, false, false), newSimpleMiddleware(t, false, false, false)}
			},
			reallyRunTest:       createGetFederationDomainTest,
			wantMiddlewareReqs:  [][]Object{nil, nil},
			wantMiddlewareResps: [][]Object{nil, nil},
		},
		{
			name: "we don't call any resp middleware if there was no req mutations done and there are no resp mutation funcs",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{newSimpleMiddleware(t, true, false, false), newSimpleMiddleware(t, true, false, false)}
			},
			reallyRunTest: createGetFederationDomainTest,
			wantMiddlewareReqs: [][]Object{
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{nil, nil},
		},
		{
			name: "we don't call any resp middleware if there are no resp mutation funcs even if there was req mutations done",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{newSimpleMiddleware(t, true, true, false), newSimpleMiddleware(t, true, true, false)}
			},
			reallyRunTest: func(t *testing.T, c *Client) {
				// create
				federationDomain, err := c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(goodFederationDomain.Namespace).
					Create(context.Background(), goodFederationDomain, metav1.CreateOptions{})
				require.NoError(t, err)
				require.Equal(t, with(goodFederationDomain, clusterName()), federationDomain)

				// read
				federationDomain, err = c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(federationDomain.Namespace).
					Get(context.Background(), federationDomain.Name, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, with(goodFederationDomain, clusterName()), federationDomain)
			},
			wantMiddlewareReqs: [][]Object{
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
				{
					with(goodFederationDomain, clusterName(), gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{nil, nil},
		},
		{
			name: "we still call resp middleware if there is a resp mutation func even if there were req mutation funcs",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{newSimpleMiddleware(t, false, false, true), newSimpleMiddleware(t, false, false, true)}
			},
			reallyRunTest:      createGetFederationDomainTest,
			wantMiddlewareReqs: [][]Object{nil, nil},
			wantMiddlewareResps: [][]Object{
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(goodFederationDomain, gvk(federationDomainGVK)),
				},
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(goodFederationDomain, gvk(federationDomainGVK)),
				},
			},
		},
		{
			name: "we still call resp middleware if there is a resp mutation func even if there was no req mutation",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{newSimpleMiddleware(t, true, false, true), newSimpleMiddleware(t, true, false, true)}
			},
			reallyRunTest: createGetFederationDomainTest,
			wantMiddlewareReqs: [][]Object{
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(goodFederationDomain, gvk(federationDomainGVK)),
				},
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(goodFederationDomain, gvk(federationDomainGVK)),
				},
			},
		},
		{
			name: "mutating object meta on a get request is not allowed since that isn't pertinent to the api request",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{{
					name: "non-pertinent mutater",
					t:    t,
					mutateReq: func(rt RoundTrip, obj Object) {
						clusterName()(obj)
					},
				}}
			},
			reallyRunTest: func(t *testing.T, c *Client) {
				_, err := c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(goodFederationDomain.Namespace).
					Get(context.Background(), goodFederationDomain.Name, metav1.GetOptions{})
				require.Error(t, err)
				require.Contains(t, err.Error(), "invalid object meta mutation")
			},
			wantMiddlewareReqs:  [][]Object{{with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK))}},
			wantMiddlewareResps: [][]Object{nil},
		},
		{
			name: "when the client gets errors from the api server",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{newSimpleMiddleware(t, true, false, false)}
			},
			editRestConfig: func(t *testing.T, restConfig *rest.Config) {
				restConfig.Dial = func(_ context.Context, _, _ string) (net.Conn, error) {
					return nil, fmt.Errorf("some fake connection error")
				}
			},
			reallyRunTest: func(t *testing.T, c *Client) {
				_, err := c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(goodFederationDomain.Namespace).
					Get(context.Background(), goodFederationDomain.Name, metav1.GetOptions{})
				require.Error(t, err)
				require.Contains(t, err.Error(), ": some fake connection error")
			},
			wantMiddlewareReqs:  [][]Object{{with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK))}},
			wantMiddlewareResps: [][]Object{nil},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			server, restConfig := fakekubeapi.Start(t, nil)
			defer server.Close()

			if test.editRestConfig != nil {
				test.editRestConfig(t, restConfig)
			}

			// our rt chain is:
			//  kubeclient -> wantCloseResp -> http.DefaultTransport -> wantCloseResp -> kubeclient
			restConfig.Wrap(wantCloseRespWrapper(t))

			var middlewares []*spyMiddleware
			if test.middlewares != nil {
				middlewares = test.middlewares(t)
			}

			opts := []Option{WithConfig(restConfig)}
			for _, middleware := range middlewares {
				opts = append(opts, WithMiddleware(middleware))
			}
			client, err := New(opts...)
			require.NoError(t, err)

			test.reallyRunTest(t, client)

			for i, spyMiddleware := range middlewares {
				require.Equalf(t, test.wantMiddlewareReqs[i], spyMiddleware.reqObjs, "unexpected req obj in middleware %q (index %d)", spyMiddleware.name, i)
				require.Equalf(t, test.wantMiddlewareResps[i], spyMiddleware.respObjs, "unexpected resp obj in middleware %q (index %d)", spyMiddleware.name, i)
			}
		})
	}
}

type spyMiddleware struct {
	name       string
	t          *testing.T
	mutateReq  func(RoundTrip, Object)
	mutateResp func(RoundTrip, Object)
	reqObjs    []Object
	respObjs   []Object
}

func (s *spyMiddleware) Handle(_ context.Context, rt RoundTrip) {
	s.t.Log(s.name, "handling", reqStr(rt, nil))

	if s.mutateReq != nil {
		rt.MutateRequest(func(obj Object) {
			s.t.Log(s.name, "mutating request", reqStr(rt, obj))
			s.reqObjs = append(s.reqObjs, obj.DeepCopyObject().(Object))
			s.mutateReq(rt, obj)
		})
	}

	if s.mutateResp != nil {
		rt.MutateResponse(func(obj Object) {
			s.t.Log(s.name, "mutating response", reqStr(rt, obj))
			s.respObjs = append(s.respObjs, obj.DeepCopyObject().(Object))
			s.mutateResp(rt, obj)
		})
	}
}

func reqStr(rt RoundTrip, obj Object) string {
	b := strings.Builder{}
	fmt.Fprintf(&b, "%s /%s", rt.Verb(), rt.Resource().GroupVersion())
	if rt.NamespaceScoped() {
		fmt.Fprintf(&b, "/namespaces/%s", rt.Namespace())
	}
	fmt.Fprintf(&b, "/%s", rt.Resource().Resource)
	if obj != nil {
		fmt.Fprintf(&b, "/%s", obj.GetName())
	}
	return b.String()
}

func newAnnotationMiddleware(t *testing.T) *spyMiddleware {
	return &spyMiddleware{
		name: "annotater",
		t:    t,
		mutateReq: func(rt RoundTrip, obj Object) {
			if rt.Verb() == VerbCreate {
				annotations()(obj)
			}
		},
		mutateResp: func(rt RoundTrip, obj Object) {
			if rt.Verb() == VerbCreate {
				for key := range middlewareAnnotations {
					delete(obj.GetAnnotations(), key)
				}
			}
		},
	}
}

func newLabelMiddleware(t *testing.T) *spyMiddleware {
	return &spyMiddleware{
		name: "labeler",
		t:    t,
		mutateReq: func(rt RoundTrip, obj Object) {
			if rt.Verb() == VerbCreate {
				labels()(obj)
			}
		},
		mutateResp: func(rt RoundTrip, obj Object) {
			if rt.Verb() == VerbCreate {
				for key := range middlewareLabels {
					delete(obj.GetLabels(), key)
				}
			}
		},
	}
}

func newSimpleMiddleware(t *testing.T, hasMutateReqFunc, mutatedReq, hasMutateRespFunc bool) *spyMiddleware {
	m := &spyMiddleware{
		name: "nop",
		t:    t,
	}
	if hasMutateReqFunc {
		m.mutateReq = func(rt RoundTrip, obj Object) {
			if mutatedReq {
				if rt.Verb() == VerbCreate {
					obj.SetClusterName(someClusterName)
				}
			}
		}
	}
	if hasMutateRespFunc {
		m.mutateResp = func(rt RoundTrip, obj Object) {}
	}
	return m
}

type wantCloser struct {
	io.ReadCloser
	closeCount                      int
	couldReadBytesJustBeforeClosing bool
}

func (wc *wantCloser) Close() error {
	wc.closeCount++
	n, _ := wc.ReadCloser.Read([]byte{0})
	if n > 0 {
		// there were still bytes left to be read
		wc.couldReadBytesJustBeforeClosing = true
	}
	return wc.ReadCloser.Close()
}

// wantCloseRespWrapper returns a transport.WrapperFunc that validates that the http.Response
// returned by the underlying http.RoundTripper is closed properly.
func wantCloseRespWrapper(t *testing.T) transport.WrapperFunc {
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "???"
		line = 0
	}
	return func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (bool, *http.Response, error) {
			resp, err := rt.RoundTrip(req)
			if err != nil {
				// request failed, so there is no response body to watch for Close() calls on
				return false, resp, err
			}
			wc := &wantCloser{ReadCloser: resp.Body}
			t.Cleanup(func() {
				require.False(t, wc.couldReadBytesJustBeforeClosing, "did not consume all response body bytes before closing %s:%d", file, line)
				require.Equalf(t, wc.closeCount, 1, "did not close resp body at %s:%d", file, line)
			})
			resp.Body = wc
			return false, resp, err
		})
	}
}

type withFunc func(obj Object)

func with(obj Object, withFuncs ...withFunc) Object {
	obj = obj.DeepCopyObject().(Object)
	for _, withFunc := range withFuncs {
		withFunc(obj)
	}
	return obj
}

func gvk(gvk schema.GroupVersionKind) withFunc {
	return func(obj Object) {
		obj.GetObjectKind().SetGroupVersionKind(gvk)
	}
}

func annotations() withFunc {
	return func(obj Object) {
		obj.SetAnnotations(middlewareAnnotations)
	}
}

func emptyAnnotations() withFunc {
	return func(obj Object) {
		obj.SetAnnotations(make(map[string]string))
	}
}

func labels() withFunc {
	return func(obj Object) {
		obj.SetLabels(middlewareLabels)
	}
}

func clusterName() withFunc {
	return func(obj Object) {
		obj.SetClusterName(someClusterName)
	}
}

func createGetFederationDomainTest(t *testing.T, client *Client) {
	t.Helper()

	// create
	federationDomain, err := client.PinnipedSupervisor.
		ConfigV1alpha1().
		FederationDomains(goodFederationDomain.Namespace).
		Create(context.Background(), goodFederationDomain, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, goodFederationDomain, federationDomain)

	// read
	federationDomain, err = client.PinnipedSupervisor.
		ConfigV1alpha1().
		FederationDomains(federationDomain.Namespace).
		Get(context.Background(), federationDomain.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, goodFederationDomain, federationDomain)
}
