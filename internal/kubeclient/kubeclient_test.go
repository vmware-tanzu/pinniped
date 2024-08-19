// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/net"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/transport"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	// register all client-go auth plugins.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/httputil/roundtripper"
	"go.pinniped.dev/internal/testutil/fakekubeapi"
)

const (
	someUID = "some fake UID"
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

	credentialIssuerGVK  = conciergeconfigv1alpha1.SchemeGroupVersion.WithKind("CredentialIssuer")
	goodCredentialIssuer = &conciergeconfigv1alpha1.CredentialIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "good-credential-issuer",
		},
	}

	federationDomainGVK  = supervisorconfigv1alpha1.SchemeGroupVersion.WithKind("FederationDomain")
	goodFederationDomain = &supervisorconfigv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "good-federation-domain",
			Namespace: "good-namespace",
		},
	}

	middlewareAnnotations = map[string]string{"some-annotation": "thing 1"}
	middlewareLabels      = map[string]string{"some-label": "thing 2"}
)

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
				require.EqualError(t, err, `couldn't find object for path "/api/v1/namespaces/good-namespace/pods/this-pod-does-not-exist"`)

				// update
				goodPodWithAnnotationsAndLabelsAndUID := with(goodPod, annotations(), labels(), uid()).(*corev1.Pod)
				pod, err = c.Kubernetes.
					CoreV1().
					Pods(pod.Namespace).
					Update(context.Background(), goodPodWithAnnotationsAndLabelsAndUID, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodPodWithAnnotationsAndLabelsAndUID, pod)

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
					with(goodPod, annotations(), labels(), uid(), gvk(podGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(podGVK)),
				},
				{
					with(goodPod, annotations(), gvk(podGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(podGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(podGVK)),
					with(goodPod, annotations(), labels(), uid(), gvk(podGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(podGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{
				{
					with(goodPod, annotations(), labels(), gvk(podGVK)),
					with(goodPod, annotations(), labels(), gvk(podGVK)),
					with(goodPod, annotations(), labels(), uid(), gvk(podGVK)),
				},
				{
					with(goodPod, emptyAnnotations(), labels(), gvk(podGVK)),
					with(goodPod, annotations(), labels(), gvk(podGVK)),
					with(goodPod, annotations(), labels(), uid(), gvk(podGVK)),
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
				goodAPIServiceWithAnnotationsAndLabelsAndUID := with(goodAPIService, annotations(), labels(), uid()).(*apiregistrationv1.APIService)
				apiService, err = c.Aggregation.
					ApiregistrationV1().
					APIServices().
					Update(context.Background(), goodAPIServiceWithAnnotationsAndLabelsAndUID, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodAPIServiceWithAnnotationsAndLabelsAndUID, apiService)

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
					with(goodAPIService, annotations(), labels(), uid(), gvk(apiServiceGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(apiServiceGVK)),
				},
				{
					with(goodAPIService, annotations(), gvk(apiServiceGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), uid(), gvk(apiServiceGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(apiServiceGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{
				{
					with(goodAPIService, annotations(), labels(), gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), uid(), gvk(apiServiceGVK)),
				},
				{
					with(goodAPIService, emptyAnnotations(), labels(), gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), gvk(apiServiceGVK)),
					with(goodAPIService, annotations(), labels(), uid(), gvk(apiServiceGVK)),
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
					ConfigV1alpha1().
					CredentialIssuers().
					Create(context.Background(), goodCredentialIssuer, metav1.CreateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodCredentialIssuer, tokenCredentialRequest)

				// read
				tokenCredentialRequest, err = c.PinnipedConcierge.
					ConfigV1alpha1().
					CredentialIssuers().
					Get(context.Background(), tokenCredentialRequest.Name, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, with(goodCredentialIssuer, annotations(), labels()), tokenCredentialRequest)

				// update
				goodCredentialIssuerWithAnnotationsAndLabelsAndUID := with(goodCredentialIssuer, annotations(), labels(), uid()).(*conciergeconfigv1alpha1.CredentialIssuer)
				tokenCredentialRequest, err = c.PinnipedConcierge.
					ConfigV1alpha1().
					CredentialIssuers().
					Update(context.Background(), goodCredentialIssuerWithAnnotationsAndLabelsAndUID, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodCredentialIssuerWithAnnotationsAndLabelsAndUID, tokenCredentialRequest)

				// delete
				err = c.PinnipedConcierge.
					ConfigV1alpha1().
					CredentialIssuers().
					Delete(context.Background(), tokenCredentialRequest.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			wantMiddlewareReqs: [][]Object{
				{
					with(goodCredentialIssuer, gvk(credentialIssuerGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(credentialIssuerGVK)),
					with(goodCredentialIssuer, annotations(), labels(), uid(), gvk(credentialIssuerGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(credentialIssuerGVK)),
				},
				{
					with(goodCredentialIssuer, annotations(), gvk(credentialIssuerGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(credentialIssuerGVK)),
					with(goodCredentialIssuer, annotations(), labels(), uid(), gvk(credentialIssuerGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(credentialIssuerGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{
				{
					with(goodCredentialIssuer, annotations(), labels(), gvk(credentialIssuerGVK)),
					with(goodCredentialIssuer, annotations(), labels(), gvk(credentialIssuerGVK)),
					with(goodCredentialIssuer, annotations(), labels(), uid(), gvk(credentialIssuerGVK)),
				},
				{
					with(goodCredentialIssuer, emptyAnnotations(), labels(), gvk(credentialIssuerGVK)),
					with(goodCredentialIssuer, annotations(), labels(), gvk(credentialIssuerGVK)),
					with(goodCredentialIssuer, annotations(), labels(), uid(), gvk(credentialIssuerGVK)),
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
				goodFederationDomainWithAnnotationsAndLabelsAndUID := with(goodFederationDomain, annotations(), labels(), uid()).(*supervisorconfigv1alpha1.FederationDomain)
				federationDomain, err = c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(federationDomain.Namespace).
					Update(context.Background(), goodFederationDomainWithAnnotationsAndLabelsAndUID, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.Equal(t, goodFederationDomainWithAnnotationsAndLabelsAndUID, federationDomain)

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
					with(goodFederationDomain, annotations(), labels(), uid(), gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
				{
					with(goodFederationDomain, annotations(), gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), uid(), gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
			},
			wantMiddlewareResps: [][]Object{
				{
					with(goodFederationDomain, annotations(), labels(), gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), uid(), gvk(federationDomainGVK)),
				},
				{
					with(goodFederationDomain, emptyAnnotations(), labels(), gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), gvk(federationDomainGVK)),
					with(goodFederationDomain, annotations(), labels(), uid(), gvk(federationDomainGVK)),
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
				require.Equal(t, with(goodFederationDomain, uid()), federationDomain)

				// read
				federationDomain, err = c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(federationDomain.Namespace).
					Get(context.Background(), federationDomain.Name, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, with(goodFederationDomain, uid()), federationDomain)
			},
			wantMiddlewareReqs: [][]Object{
				{
					with(goodFederationDomain, gvk(federationDomainGVK)),
					with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK)),
				},
				{
					with(goodFederationDomain, uid(), gvk(federationDomainGVK)),
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
					mutateReq: func(rt RoundTrip, obj Object) error {
						uid()(obj)
						return nil
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
				// avoid messing with restConfig.Dial since it breaks client-go TLS cache logic
				restConfig.Wrap(func(rt http.RoundTripper) http.RoundTripper {
					return roundtripper.WrapFunc(rt, func(_ *http.Request) (*http.Response, error) {
						return nil, fmt.Errorf("some fake connection error")
					})
				})
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
		{
			name: "when there are request middleware failures, we return an error and don't send the request",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{
					// use 3 middleware to ensure that we collect all errors from all middlewares
					newFailingMiddleware(t, "aaa", true, false),
					newFailingMiddleware(t, "bbb", false, false),
					newFailingMiddleware(t, "ccc", true, false),
				}
			},
			reallyRunTest: func(t *testing.T, c *Client) {
				_, err := c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(goodFederationDomain.Namespace).
					Get(context.Background(), goodFederationDomain.Name, metav1.GetOptions{})
				require.Error(t, err)
				require.Contains(t, err.Error(), ": request mutation failed: [aaa: request error, ccc: request error]")
			},
			wantMiddlewareReqs: [][]Object{
				{with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK))},
				{with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK))},
				{with(&metav1.PartialObjectMetadata{}, gvk(federationDomainGVK))},
			},
			wantMiddlewareResps: [][]Object{
				nil,
				nil,
				nil,
			},
		},
		{
			name: "when there are response middleware failures, we return an error",
			middlewares: func(t *testing.T) []*spyMiddleware {
				return []*spyMiddleware{
					// use 3 middleware to ensure that we collect all errors from all middlewares
					newFailingMiddleware(t, "aaa", false, true),
					newFailingMiddleware(t, "bbb", false, false),
					newFailingMiddleware(t, "ccc", false, true),
				}
			},
			reallyRunTest: func(t *testing.T, c *Client) {
				_, err := c.PinnipedSupervisor.
					ConfigV1alpha1().
					FederationDomains(goodFederationDomain.Namespace).
					Create(context.Background(), goodFederationDomain, metav1.CreateOptions{})
				require.Error(t, err)
				require.Contains(t, err.Error(), ": response mutation failed: [aaa: response error, ccc: response error]")
			},
			wantMiddlewareReqs: [][]Object{
				{with(goodFederationDomain, gvk(federationDomainGVK))},
				{with(goodFederationDomain, gvk(federationDomainGVK))},
				{with(goodFederationDomain, gvk(federationDomainGVK))},
			},
			wantMiddlewareResps: [][]Object{
				{with(goodFederationDomain, gvk(federationDomainGVK))},
				{with(goodFederationDomain, gvk(federationDomainGVK))},
				{with(goodFederationDomain, gvk(federationDomainGVK))},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, restConfig := fakekubeapi.Start(t, nil)

			if test.editRestConfig != nil {
				test.editRestConfig(t, restConfig)
			}

			var middlewares []*spyMiddleware
			if test.middlewares != nil {
				middlewares = test.middlewares(t)
			}

			// our rt chain is:
			//  wantCloseReq -> kubeclient -> wantCloseResp -> http.DefaultTransport -> wantCloseResp -> kubeclient -> wantCloseReq
			restConfig.Wrap(wantCloseRespWrapper(t))
			opts := []Option{WithConfig(restConfig), WithTransportWrapper(wantCloseReqWrapper(t))}
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
	mutateReq  func(RoundTrip, Object) error
	mutateResp func(RoundTrip, Object) error
	reqObjs    []Object
	respObjs   []Object
}

func (s *spyMiddleware) Handle(_ context.Context, rt RoundTrip) {
	s.t.Log(s.name, "handling", reqStr(rt, nil))

	if s.mutateReq != nil {
		rt.MutateRequest(func(obj Object) error {
			s.t.Log(s.name, "mutating request", reqStr(rt, obj))
			s.reqObjs = append(s.reqObjs, obj.DeepCopyObject().(Object))
			return s.mutateReq(rt, obj)
		})
	}

	if s.mutateResp != nil {
		rt.MutateResponse(func(obj Object) error {
			s.t.Log(s.name, "mutating response", reqStr(rt, obj))
			s.respObjs = append(s.respObjs, obj.DeepCopyObject().(Object))
			return s.mutateResp(rt, obj)
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
		mutateReq: func(rt RoundTrip, obj Object) error {
			if rt.Verb() == VerbCreate {
				annotations()(obj)
			}
			return nil
		},
		mutateResp: func(rt RoundTrip, obj Object) error {
			if rt.Verb() == VerbCreate {
				for key := range middlewareAnnotations {
					delete(obj.GetAnnotations(), key)
				}
			}
			return nil
		},
	}
}

func newLabelMiddleware(t *testing.T) *spyMiddleware {
	return &spyMiddleware{
		name: "labeler",
		t:    t,
		mutateReq: func(rt RoundTrip, obj Object) error {
			if rt.Verb() == VerbCreate {
				labels()(obj)
			}
			return nil
		},
		mutateResp: func(rt RoundTrip, obj Object) error {
			if rt.Verb() == VerbCreate {
				for key := range middlewareLabels {
					delete(obj.GetLabels(), key)
				}
			}
			return nil
		},
	}
}

func newSimpleMiddleware(t *testing.T, hasMutateReqFunc, mutatedReq, hasMutateRespFunc bool) *spyMiddleware {
	m := &spyMiddleware{
		name: "simple",
		t:    t,
	}
	if hasMutateReqFunc {
		m.mutateReq = func(rt RoundTrip, obj Object) error {
			if mutatedReq {
				if rt.Verb() == VerbCreate {
					obj.SetUID(someUID)
				}
			}
			return nil
		}
	}
	if hasMutateRespFunc {
		m.mutateResp = func(rt RoundTrip, obj Object) error {
			return nil
		}
	}
	return m
}

func newFailingMiddleware(t *testing.T, name string, mutateReqFails, mutateRespFails bool) *spyMiddleware {
	m := &spyMiddleware{
		name: "failing-middleware-" + name,
		t:    t,
	}

	m.mutateReq = func(rt RoundTrip, obj Object) error {
		if mutateReqFails {
			return fmt.Errorf("%s: request error", name)
		}
		return nil
	}

	m.mutateResp = func(rt RoundTrip, obj Object) error {
		if mutateRespFails {
			return fmt.Errorf("%s: response error", name)
		}
		return nil
	}

	return m
}

type wantCloser struct {
	m sync.Mutex

	_rc                              io.ReadCloser
	_closeCalls                      []string
	_couldReadBytesJustBeforeClosing bool
}

func (w *wantCloser) Close() error {
	w.m.Lock()
	defer w.m.Unlock()

	w._closeCalls = append(w._closeCalls, getCaller())
	n, _ := w._rc.Read([]byte{0})
	if n > 0 {
		// there were still bytes left to be read
		w._couldReadBytesJustBeforeClosing = true
	}
	return w._rc.Close()
}

func (w *wantCloser) Read(p []byte) (int, error) {
	w.m.Lock()
	defer w.m.Unlock()

	return w._rc.Read(p)
}

func (w *wantCloser) couldRead() bool {
	w.m.Lock()
	defer w.m.Unlock()

	return w._couldReadBytesJustBeforeClosing
}

func (w *wantCloser) calls() []string {
	w.m.Lock()
	defer w.m.Unlock()

	return w._closeCalls
}

func getCaller() string {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "???"
		line = 0
	}
	return fmt.Sprintf("%s:%d", file, line)
}

// wantCloseReqWrapper returns a transport.WrapperFunc that validates that the http.Request
// passed to the underlying http.RoundTripper is closed properly.
func wantCloseReqWrapper(t *testing.T) transport.WrapperFunc {
	caller := getCaller()
	return func(rt http.RoundTripper) http.RoundTripper {
		return roundtripper.WrapFunc(rt, roundTripperFunc(func(req *http.Request) (bool, *http.Response, error) {
			if req.Body != nil {
				wc := &wantCloser{_rc: req.Body}
				t.Cleanup(func() {
					require.Eventuallyf(t, func() bool {
						return 1 == len(wc.calls())
					}, 5*time.Second, 100*time.Millisecond,
						"did not close req body expected number of times at %s for req %#v; actual calls = %s", caller, req, wc.calls())
				})
				req.Body = wc
			}

			if req.GetBody != nil {
				originalBodyCopy, originalErr := req.GetBody()
				req.GetBody = func() (io.ReadCloser, error) {
					if originalErr != nil {
						return nil, originalErr
					}
					wc := &wantCloser{_rc: originalBodyCopy}
					t.Cleanup(func() {
						require.Eventuallyf(t, func() bool {
							return 1 == len(wc.calls())
						}, 5*time.Second, 100*time.Millisecond,
							"did not close req body copy expected number of times at %s for req %#v; actual calls = %s", caller, req, wc.calls())
					})
					return wc, nil
				}
			}

			resp, err := rt.RoundTrip(req)
			return false, resp, err
		}).RoundTrip)
	}
}

// wantCloseRespWrapper returns a transport.WrapperFunc that validates that the http.Response
// returned by the underlying http.RoundTripper is closed properly.
func wantCloseRespWrapper(t *testing.T) transport.WrapperFunc {
	caller := getCaller()
	return func(rt http.RoundTripper) http.RoundTripper {
		return roundtripper.WrapFunc(rt, roundTripperFunc(func(req *http.Request) (bool, *http.Response, error) {
			resp, err := rt.RoundTrip(req)
			if err != nil {
				// request failed, so there is no response body to watch for Close() calls on
				return false, resp, err
			}
			wc := &wantCloser{_rc: resp.Body}
			t.Cleanup(func() {
				require.Eventuallyf(t, func() bool {
					return wc.couldRead() == false &&
						1 == len(wc.calls())
				}, 5*time.Second, 10*time.Millisecond,
					`did not close resp body expected number of times at %s for req %#v; actual calls = %s
did not consume all response body bytes before closing %s, couldRead=%v`, caller, req, wc.calls(), caller, wc.couldRead())
			})
			resp.Body = wc
			return false, resp, err
		}).RoundTrip)
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

func uid() withFunc {
	return func(obj Object) {
		obj.SetUID(someUID)
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

// TestUnwrap ensures that the Client struct returned by this package only contains
// transports that can be fully unwrapped to get access to the underlying TLS config.
func TestUnwrap(t *testing.T) {
	t.Parallel() // make sure to run in parallel to confirm that our client-go TLS cache busting works (i.e. assert no data races)

	server, restConfig := fakekubeapi.Start(t, nil)

	serverCertPool := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	t.Run("regular client", func(t *testing.T) {
		t.Parallel() // make sure to run in parallel to confirm that our client-go TLS cache busting works (i.e. assert no data races)

		regularClient := makeClient(t, restConfig, func(_ *rest.Config) {})

		testUnwrap(t, regularClient, serverCertPool, ptls.Secure)
	})

	t.Run("exec client", func(t *testing.T) {
		t.Parallel() // make sure to run in parallel to confirm that our client-go TLS cache busting works (i.e. assert no data races)

		execClient := makeClient(t, restConfig, func(config *rest.Config) {
			config.ExecProvider = &clientcmdapi.ExecConfig{
				Command:         "echo",
				Args:            []string{"pandas are awesome"},
				APIVersion:      clientauthenticationv1.SchemeGroupVersion.String(),
				InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
			}
		})

		testUnwrap(t, execClient, serverCertPool, ptls.Secure)
	})

	t.Run("oidc client", func(t *testing.T) {
		t.Parallel() // make sure to run in parallel to confirm that our client-go TLS cache busting works (i.e. assert no data races)

		oidcClient := makeClient(t, restConfig, func(config *rest.Config) {
			config.AuthProvider = &clientcmdapi.AuthProviderConfig{
				Name: "oidc",
				Config: map[string]string{
					"idp-issuer-url": "https://pandas.local",
					"client-id":      "walrus",
				},
			}
		})

		testUnwrap(t, oidcClient, serverCertPool, ptls.Secure)
	})

	t.Run("regular client with ptls.Default", func(t *testing.T) {
		t.Parallel() // make sure to run in parallel to confirm that our client-go TLS cache busting works (i.e. assert no data races)

		regularClient := makeClient(t, restConfig, func(_ *rest.Config) {}, WithTLSConfigFunc(ptls.Default))

		testUnwrap(t, regularClient, serverCertPool, ptls.Default)
	})

	t.Run("exec client with ptls.Default", func(t *testing.T) {
		t.Parallel() // make sure to run in parallel to confirm that our client-go TLS cache busting works (i.e. assert no data races)

		execClient := makeClient(t, restConfig, func(config *rest.Config) {
			config.ExecProvider = &clientcmdapi.ExecConfig{
				Command:         "echo",
				Args:            []string{"pandas are awesome"},
				APIVersion:      clientauthenticationv1.SchemeGroupVersion.String(),
				InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
			}
		}, WithTLSConfigFunc(ptls.Default))

		testUnwrap(t, execClient, serverCertPool, ptls.Default)
	})

	t.Run("oidc client with ptls.Default", func(t *testing.T) {
		t.Parallel() // make sure to run in parallel to confirm that our client-go TLS cache busting works (i.e. assert no data races)

		oidcClient := makeClient(t, restConfig, func(config *rest.Config) {
			config.AuthProvider = &clientcmdapi.AuthProviderConfig{
				Name: "oidc",
				Config: map[string]string{
					"idp-issuer-url": "https://pandas.local",
					"client-id":      "walrus",
				},
			}
		}, WithTLSConfigFunc(ptls.Default))

		testUnwrap(t, oidcClient, serverCertPool, ptls.Default)
	})
}

func testUnwrap(t *testing.T, client *Client, serverCertPool *x509.CertPool, tlsConfigFuncForExpectedValues ptls.ConfigFunc) {
	tests := []struct {
		name           string
		rt             http.RoundTripper
		wantConfigFunc ptls.ConfigFunc
	}{
		{
			name:           "core v1",
			rt:             extractTransport(client.Kubernetes.CoreV1()),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "coordination v1",
			rt:             extractTransport(client.Kubernetes.CoordinationV1()),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "api registration v1",
			rt:             extractTransport(client.Aggregation.ApiregistrationV1()),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "concierge login",
			rt:             extractTransport(client.PinnipedConcierge.LoginV1alpha1()),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "concierge config",
			rt:             extractTransport(client.PinnipedConcierge.ConfigV1alpha1()),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "supervisor idp",
			rt:             extractTransport(client.PinnipedSupervisor.IDPV1alpha1()),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "supervisor config",
			rt:             extractTransport(client.PinnipedSupervisor.ConfigV1alpha1()),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "json config",
			rt:             configToTransport(t, client.JSONConfig),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "proto config",
			rt:             configToTransport(t, client.ProtoConfig),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "anonymous json config",
			rt:             configToTransport(t, SecureAnonymousClientConfig(client.JSONConfig)),
			wantConfigFunc: ptls.Secure, // SecureAnonymousClientConfig is always ptls.Secure
		},
		{
			name:           "anonymous proto config",
			rt:             configToTransport(t, SecureAnonymousClientConfig(client.ProtoConfig)),
			wantConfigFunc: ptls.Secure, // SecureAnonymousClientConfig is always ptls.Secure
		},
		{
			name:           "json config - no cache",
			rt:             configToTransport(t, bustTLSCache(client.JSONConfig)),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "proto config - no cache",
			rt:             configToTransport(t, bustTLSCache(client.ProtoConfig)),
			wantConfigFunc: tlsConfigFuncForExpectedValues,
		},
		{
			name:           "anonymous json config - no cache, inner bust",
			rt:             configToTransport(t, SecureAnonymousClientConfig(bustTLSCache(client.JSONConfig))),
			wantConfigFunc: ptls.Secure, // SecureAnonymousClientConfig is always ptls.Secure
		},
		{
			name:           "anonymous proto config - no cache, inner bust",
			rt:             configToTransport(t, SecureAnonymousClientConfig(bustTLSCache(client.ProtoConfig))),
			wantConfigFunc: ptls.Secure, // SecureAnonymousClientConfig is always ptls.Secure
		},
		{
			name:           "anonymous json config - no cache, double bust",
			rt:             configToTransport(t, bustTLSCache(SecureAnonymousClientConfig(bustTLSCache(client.JSONConfig)))),
			wantConfigFunc: ptls.Secure, // SecureAnonymousClientConfig is always ptls.Secure
		},
		{
			name:           "anonymous proto config - no cache, double bust",
			rt:             configToTransport(t, bustTLSCache(SecureAnonymousClientConfig(bustTLSCache(client.ProtoConfig)))),
			wantConfigFunc: ptls.Secure, // SecureAnonymousClientConfig is always ptls.Secure
		},
		{
			name:           "anonymous json config - no cache, outer bust",
			rt:             configToTransport(t, bustTLSCache(SecureAnonymousClientConfig(client.JSONConfig))),
			wantConfigFunc: ptls.Secure, // SecureAnonymousClientConfig is always ptls.Secure
		},
		{
			name:           "anonymous proto config - no cache, outer bust",
			rt:             configToTransport(t, bustTLSCache(SecureAnonymousClientConfig(client.ProtoConfig))),
			wantConfigFunc: ptls.Secure, // SecureAnonymousClientConfig is always ptls.Secure
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel() // make sure to run in parallel to confirm that our client-go TLS cache busting works (i.e. assert no data races)

			tlsConfig, err := net.TLSClientConfig(tt.rt)
			require.NoError(t, err)
			require.NotNil(t, tlsConfig)

			ptlsConfig := tt.wantConfigFunc(nil)

			require.Equal(t, ptlsConfig.MinVersion, tlsConfig.MinVersion)
			require.Equal(t, ptlsConfig.CipherSuites, tlsConfig.CipherSuites)
			require.Equal(t, ptlsConfig.NextProtos, tlsConfig.NextProtos)
			require.True(t, serverCertPool.Equal(tlsConfig.RootCAs))
		})
	}
}

type restClientGetter interface {
	RESTClient() rest.Interface
}

func extractTransport(getter restClientGetter) http.RoundTripper {
	return getter.RESTClient().(*rest.RESTClient).Client.Transport
}

func configToTransport(t *testing.T, config *rest.Config) http.RoundTripper {
	t.Helper()

	rt, err := rest.TransportFor(config)
	require.NoError(t, err)
	return rt
}

func bustTLSCache(config *rest.Config) *rest.Config {
	c := rest.CopyConfig(config)
	c.Proxy = func(h *http.Request) (*url.URL, error) {
		return nil, nil // having a non-nil proxy func makes client-go not cache the TLS config
	}
	return c
}

func makeClient(t *testing.T, restConfig *rest.Config, f func(*rest.Config), opts ...Option) *Client {
	t.Helper()

	restConfig = rest.CopyConfig(restConfig)

	f(restConfig)

	client, err := New(slices.Concat([]Option{WithConfig(restConfig)}, opts)...)
	require.NoError(t, err)

	return client
}
