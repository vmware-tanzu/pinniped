// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"context"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/features"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/httputil/roundtripper"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/testutil"
)

func TestImpersonator(t *testing.T) {
	const port = 9444

	ca, err := certauthority.New("ca", time.Hour)
	require.NoError(t, err)
	caKey, err := ca.PrivateKeyToPEM()
	require.NoError(t, err)
	caContent := dynamiccert.NewCA("ca")
	err = caContent.SetCertKeyContent(ca.Bundle(), caKey)
	require.NoError(t, err)

	cert, key, err := ca.IssueServerCertPEM(nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	require.NoError(t, err)
	certKeyContent := dynamiccert.NewServingCert("cert-key")
	err = certKeyContent.SetCertKeyContent(cert, key)
	require.NoError(t, err)

	unrelatedCA, err := certauthority.New("ca", time.Hour)
	require.NoError(t, err)

	// Punch out just enough stuff to make New actually run without error.
	recOpts := func(options *genericoptions.RecommendedOptions) {
		options.Authentication.RemoteKubeConfigFileOptional = true
		options.Authorization.RemoteKubeConfigFileOptional = true
		options.CoreAPI = nil
		options.Admission = nil
	}
	defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.APIPriorityAndFairness, false)()

	tests := []struct {
		name                               string
		clientCert                         *clientCert
		clientImpersonateUser              rest.ImpersonationConfig
		clientMutateHeaders                func(http.Header)
		kubeAPIServerClientBearerTokenFile string
		kubeAPIServerStatusCode            int
		wantKubeAPIServerRequestHeaders    http.Header
		wantError                          string
		wantConstructionError              string
	}{
		{
			name:                               "happy path",
			clientCert:                         newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":  {"test-username"},
				"Impersonate-Group": {"test-group1", "test-group2", "system:authenticated"},
				"Authorization":     {"Bearer some-service-account-token"},
				"User-Agent":        {"test-agent"},
				"Accept":            {"application/vnd.kubernetes.protobuf,application/json"},
				"Accept-Encoding":   {"gzip"},
				"X-Forwarded-For":   {"127.0.0.1"},
			},
		},
		{
			name:                               "user is authenticated but the kube API request returns an error",
			kubeAPIServerStatusCode:            http.StatusNotFound,
			clientCert:                         newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          `the server could not find the requested resource (get namespaces)`,
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":  {"test-username"},
				"Impersonate-Group": {"test-group1", "test-group2", "system:authenticated"},
				"Authorization":     {"Bearer some-service-account-token"},
				"User-Agent":        {"test-agent"},
				"Accept":            {"application/vnd.kubernetes.protobuf,application/json"},
				"Accept-Encoding":   {"gzip"},
				"X-Forwarded-For":   {"127.0.0.1"},
			},
		},
		{
			name:                               "when there is no client cert on request, it is an anonymous request",
			clientCert:                         &clientCert{},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":  {"system:anonymous"},
				"Impersonate-Group": {"system:unauthenticated"},
				"Authorization":     {"Bearer some-service-account-token"},
				"User-Agent":        {"test-agent"},
				"Accept":            {"application/vnd.kubernetes.protobuf,application/json"},
				"Accept-Encoding":   {"gzip"},
				"X-Forwarded-For":   {"127.0.0.1"},
			},
		},
		{
			name:                               "failed client cert authentication",
			clientCert:                         newClientCert(t, unrelatedCA, "test-username", []string{"test-group1"}),
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Unauthorized",
		},
		{
			name:                               "double impersonation is not allowed by regular users",
			clientCert:                         newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientImpersonateUser:              rest.ImpersonationConfig{UserName: "some-other-username"},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError: `users "some-other-username" is forbidden: User "test-username" ` +
				`cannot impersonate resource "users" in API group "" at the cluster scope: impersonation is not allowed or invalid verb`,
		},
		{
			name:                               "double impersonation is not allowed by admin users",
			clientCert:                         newClientCert(t, ca, "test-admin", []string{"system:masters", "test-group2"}),
			clientImpersonateUser:              rest.ImpersonationConfig{UserName: "some-other-username"},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError: `users "some-other-username" is forbidden: User "test-admin" ` +
				`cannot impersonate resource "users" in API group "" at the cluster scope: impersonation is not allowed or invalid verb`,
		},
		{
			name:                  "no bearer token file in Kube API server client config",
			wantConstructionError: "invalid impersonator loopback rest config has wrong bearer token semantics",
		},
		{
			name:       "header canonicalization user header",
			clientCert: newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientMutateHeaders: func(header http.Header) {
				header.Set("imPerSonaTE-USer", "PANDA")
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError: `users "PANDA" is forbidden: User "test-username" ` +
				`cannot impersonate resource "users" in API group "" at the cluster scope: impersonation is not allowed or invalid verb`,
		},
		{
			name:       "header canonicalization future UID header",
			clientCert: newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientMutateHeaders: func(header http.Header) {
				header.Set("imPerSonaTE-uid", "007")
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Internal error occurred: invalid impersonation",
		},
		{
			name:       "future UID header",
			clientCert: newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientMutateHeaders: func(header http.Header) {
				header.Set("Impersonate-Uid", "008")
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Internal error occurred: invalid impersonation",
		},
	}
	for _, tt := range tests {
		tt := tt
		// This is a serial test because the production code binds to the port.
		t.Run(tt.name, func(t *testing.T) {
			// After failing to start and after shutdown, the impersonator port should be available again.
			defer requireCanBindToPort(t, port)

			if tt.kubeAPIServerStatusCode == 0 {
				tt.kubeAPIServerStatusCode = http.StatusOK
			}

			// Set up a fake Kube API server which will stand in for the real one. The impersonator
			// will proxy incoming calls to this fake server.
			testKubeAPIServerWasCalled := false
			var testKubeAPIServerSawHeaders http.Header
			testKubeAPIServerCA, testKubeAPIServerURL := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method)
				switch r.URL.Path {
				case "/api/v1/namespaces/kube-system/configmaps":
					// The production code uses NewDynamicCAFromConfigMapController which fetches a ConfigMap,
					// so treat that differently. It wants to read the Kube API server CA from that ConfigMap
					// to use it to validate client certs. We don't need it for this test, so return NotFound.
					http.NotFound(w, r)
					return
				case "/api/v1/namespaces":
					testKubeAPIServerWasCalled = true
					testKubeAPIServerSawHeaders = r.Header
					if tt.kubeAPIServerStatusCode != http.StatusOK {
						w.WriteHeader(tt.kubeAPIServerStatusCode)
					} else {
						w.Header().Add("Content-Type", "application/json; charset=UTF-8")
						_, _ = w.Write([]byte(here.Doc(`
						{
							"kind": "NamespaceList",
							"apiVersion":"v1",
							"items": [
								{"metadata":{"name": "namespace1"}},
								{"metadata":{"name": "namespace2"}}
							]
						}
					`)))
					}
				default:
					require.Fail(t, "fake Kube API server got an unexpected request")
				}
			})

			// Create the client config that the impersonation server should use to talk to the Kube API server.
			testKubeAPIServerKubeconfig := rest.Config{
				Host:            testKubeAPIServerURL,
				BearerToken:     "some-service-account-token",
				TLSClientConfig: rest.TLSClientConfig{CAData: []byte(testKubeAPIServerCA)},
				BearerTokenFile: tt.kubeAPIServerClientBearerTokenFile,
			}
			clientOpts := []kubeclient.Option{kubeclient.WithConfig(&testKubeAPIServerKubeconfig)}

			// Create an impersonator.
			runner, constructionErr := newInternal(port, certKeyContent, caContent, clientOpts, recOpts)
			if len(tt.wantConstructionError) > 0 {
				require.EqualError(t, constructionErr, tt.wantConstructionError)
				require.Nil(t, runner)
				// The rest of the test doesn't make sense when you expect a construction error, so stop here.
				return
			}
			require.NoError(t, constructionErr)
			require.NotNil(t, runner)

			// Start the impersonator.
			stopCh := make(chan struct{})
			errCh := make(chan error)
			go func() {
				stopErr := runner(stopCh)
				errCh <- stopErr
			}()

			// Create a kubeconfig to talk to the impersonator as a client.
			clientKubeconfig := &rest.Config{
				Host: "https://127.0.0.1:" + strconv.Itoa(port),
				TLSClientConfig: rest.TLSClientConfig{
					CAData:   ca.Bundle(),
					CertData: tt.clientCert.certPEM,
					KeyData:  tt.clientCert.keyPEM,
				},
				UserAgent: "test-agent",
				// BearerToken should be ignored during auth when there are valid client certs,
				// and it should not passed into the impersonator handler func as an authorization header.
				BearerToken: "must-be-ignored",
				Impersonate: tt.clientImpersonateUser,
				WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
					if tt.clientMutateHeaders == nil {
						return rt
					}

					return roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						req = req.Clone(req.Context())
						tt.clientMutateHeaders(req.Header)
						return rt.RoundTrip(req)
					})
				},
			}

			// Create a real Kube client to make API requests to the impersonator.
			client, err := kubeclient.New(kubeclient.WithConfig(clientKubeconfig))
			require.NoError(t, err)

			// The fake Kube API server knows how to to list namespaces, so make that request using the client
			// through the impersonator.
			listResponse, err := client.Kubernetes.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			if len(tt.wantError) > 0 {
				require.EqualError(t, err, tt.wantError)
				require.Equal(t, &corev1.NamespaceList{}, listResponse)
			} else {
				require.NoError(t, err)
				require.Equal(t, &corev1.NamespaceList{
					Items: []corev1.Namespace{
						{ObjectMeta: metav1.ObjectMeta{Name: "namespace1"}},
						{ObjectMeta: metav1.ObjectMeta{Name: "namespace2"}},
					},
				}, listResponse)
			}

			// If we expect to see some headers, then the fake KAS should have been called.
			require.Equal(t, len(tt.wantKubeAPIServerRequestHeaders) != 0, testKubeAPIServerWasCalled)
			// If the impersonator proxied the request to the fake Kube API server, we should see the headers
			// of the original request mutated by the impersonator.  Otherwise the headers should be nil.
			require.Equal(t, tt.wantKubeAPIServerRequestHeaders, testKubeAPIServerSawHeaders)

			// Stop the impersonator server.
			close(stopCh)
			exitErr := <-errCh
			require.NoError(t, exitErr)
		})
	}
}

func TestImpersonatorHTTPHandler(t *testing.T) {
	const testUser = "test-user"

	testGroups := []string{"test-group-1", "test-group-2"}
	testExtra := map[string][]string{
		"extra-1": {"some", "extra", "stuff"},
		"extra-2": {"some", "more", "extra", "stuff"},
	}

	validURL, _ := url.Parse("http://pinniped.dev/blah")
	newRequest := func(h http.Header, userInfo user.Info) *http.Request {
		ctx := context.Background()
		if userInfo != nil {
			ctx = request.WithUser(ctx, userInfo)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, validURL.String(), nil)
		require.NoError(t, err)
		r.Header = h
		reqInfo := &request.RequestInfo{
			IsResourceRequest: false,
			Path:              validURL.Path,
			Verb:              "get",
		}
		r = r.WithContext(request.WithRequestInfo(ctx, reqInfo))
		return r
	}

	tests := []struct {
		name                            string
		restConfig                      *rest.Config
		wantCreationErr                 string
		request                         *http.Request
		wantHTTPBody                    string
		wantHTTPStatus                  int
		wantKubeAPIServerRequestHeaders http.Header
		kubeAPIServerStatusCode         int
	}{
		{
			name:            "invalid kubeconfig host",
			restConfig:      &rest.Config{Host: ":"},
			wantCreationErr: "could not parse host URL from in-cluster config: parse \":\": missing protocol scheme",
		},
		{
			name: "invalid transport config",
			restConfig: &rest.Config{
				Host:         "pinniped.dev/blah",
				ExecProvider: &api.ExecConfig{},
				AuthProvider: &api.AuthProviderConfig{},
			},
			wantCreationErr: "could not get http/1.1 round tripper: could not get in-cluster transport config: execProvider and authProvider cannot be used in combination",
		},
		{
			name: "fail to get transport from config",
			restConfig: &rest.Config{
				Host:            "pinniped.dev/blah",
				BearerToken:     "test-bearer-token",
				Transport:       http.DefaultTransport,
				TLSClientConfig: rest.TLSClientConfig{Insecure: true},
			},
			wantCreationErr: "could not get http/1.1 round tripper: using a custom transport with TLS certificate options or the insecure flag is not allowed",
		},
		{
			name:           "Impersonate-User header already in request",
			request:        newRequest(map[string][]string{"Impersonate-User": {"some-user"}}, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-Group header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Group": {"some-group"}}, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-Extra header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Extra-something": {"something"}}, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-* header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Something": {"some-newfangled-impersonate-header"}}, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "unexpected authorization header",
			request:        newRequest(map[string][]string{"Authorization": {"panda"}}, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid authorization header","reason":"InternalError","details":{"causes":[{"message":"invalid authorization header"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "missing user",
			request:        newRequest(map[string][]string{}, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid user","reason":"InternalError","details":{"causes":[{"message":"invalid user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "unexpected UID",
			request:        newRequest(map[string][]string{}, &user.DefaultInfo{UID: "007"}),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		// happy path
		{
			name: "authenticated user",
			request: newRequest(map[string][]string{
				"User-Agent":      {"test-user-agent"},
				"Accept":          {"some-accepted-format"},
				"Accept-Encoding": {"some-accepted-encoding"},
				"Connection":      {"Upgrade"}, // the value "Upgrade" is handled in a special way by `httputil.NewSingleHostReverseProxy`
				"Upgrade":         {"some-upgrade"},
				"Content-Type":    {"some-type"},
				"Content-Length":  {"some-length"},
				"Other-Header":    {"test-header-value-1"}, // this header will be passed through
			}, &user.DefaultInfo{
				Name:   testUser,
				Groups: testGroups,
				Extra:  testExtra,
			}),
			wantKubeAPIServerRequestHeaders: map[string][]string{
				"Authorization":             {"Bearer some-service-account-token"},
				"Impersonate-Extra-Extra-1": {"some", "extra", "stuff"},
				"Impersonate-Extra-Extra-2": {"some", "more", "extra", "stuff"},
				"Impersonate-Group":         {"test-group-1", "test-group-2"},
				"Impersonate-User":          {"test-user"},
				"User-Agent":                {"test-user-agent"},
				"Accept":                    {"some-accepted-format"},
				"Accept-Encoding":           {"some-accepted-encoding"},
				"Connection":                {"Upgrade"},
				"Upgrade":                   {"some-upgrade"},
				"Content-Type":              {"some-type"},
				"Other-Header":              {"test-header-value-1"},
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
		},
		{
			name: "user is authenticated but the kube API request returns an error",
			request: newRequest(map[string][]string{
				"User-Agent": {"test-user-agent"},
			}, &user.DefaultInfo{
				Name:   testUser,
				Groups: testGroups,
				Extra:  testExtra,
			}),
			kubeAPIServerStatusCode: http.StatusNotFound,
			wantKubeAPIServerRequestHeaders: map[string][]string{
				"Accept-Encoding":           {"gzip"}, // because the rest client used in this test does not disable compression
				"Authorization":             {"Bearer some-service-account-token"},
				"Impersonate-Extra-Extra-1": {"some", "extra", "stuff"},
				"Impersonate-Extra-Extra-2": {"some", "more", "extra", "stuff"},
				"Impersonate-Group":         {"test-group-1", "test-group-2"},
				"Impersonate-User":          {"test-user"},
				"User-Agent":                {"test-user-agent"},
			},
			wantHTTPStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.kubeAPIServerStatusCode == 0 {
				tt.kubeAPIServerStatusCode = http.StatusOK
			}

			testKubeAPIServerWasCalled := false
			testKubeAPIServerSawHeaders := http.Header{}
			testKubeAPIServerCA, testKubeAPIServerURL := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				testKubeAPIServerWasCalled = true
				testKubeAPIServerSawHeaders = r.Header
				if tt.kubeAPIServerStatusCode != http.StatusOK {
					w.WriteHeader(tt.kubeAPIServerStatusCode)
				} else {
					_, _ = w.Write([]byte("successful proxied response"))
				}
			})
			testKubeAPIServerKubeconfig := rest.Config{
				Host:            testKubeAPIServerURL,
				BearerToken:     "some-service-account-token",
				TLSClientConfig: rest.TLSClientConfig{CAData: []byte(testKubeAPIServerCA)},
			}
			if tt.restConfig == nil {
				tt.restConfig = &testKubeAPIServerKubeconfig
			}

			impersonatorHTTPHandlerFunc, err := newImpersonationReverseProxyFunc(tt.restConfig)
			if tt.wantCreationErr != "" {
				require.EqualError(t, err, tt.wantCreationErr)
				require.Nil(t, impersonatorHTTPHandlerFunc)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, impersonatorHTTPHandlerFunc)

			// this is not a valid way to get a server config, but it is good enough for a unit test
			scheme := runtime.NewScheme()
			metav1.AddToGroupVersion(scheme, metav1.Unversioned)
			codecs := serializer.NewCodecFactory(scheme)
			serverConfig := genericapiserver.NewRecommendedConfig(codecs)
			serverConfig.Config.LongRunningFunc = func(_ *http.Request, _ *request.RequestInfo) bool {
				// take the HTTP/2.0 vs HTTP/1.1 branch randomly to make sure we exercise both branches
				return rand.Int()%2 == 0 //nolint:gosec // we don't care whether this is cryptographically secure or not
			}

			w := httptest.NewRecorder()
			requestBeforeServe := tt.request.Clone(tt.request.Context())
			impersonatorHTTPHandlerFunc(&serverConfig.Config).ServeHTTP(w, tt.request)

			require.Equal(t, requestBeforeServe, tt.request, "ServeHTTP() mutated the request, and it should not per http.Handler docs")
			if tt.wantHTTPStatus != 0 {
				require.Equalf(t, tt.wantHTTPStatus, w.Code, "fyi, response body was %q", w.Body.String())
			}
			if tt.wantHTTPBody != "" {
				require.Equal(t, tt.wantHTTPBody, w.Body.String())
			}

			if tt.wantHTTPStatus == http.StatusOK || tt.kubeAPIServerStatusCode != http.StatusOK {
				require.True(t, testKubeAPIServerWasCalled, "Should have proxied the request to the Kube API server, but didn't")
				require.Equal(t, tt.wantKubeAPIServerRequestHeaders, testKubeAPIServerSawHeaders)
			} else {
				require.False(t, testKubeAPIServerWasCalled, "Should not have proxied the request to the Kube API server, but did")
			}
		})
	}
}

type clientCert struct {
	certPEM, keyPEM []byte
}

func newClientCert(t *testing.T, ca *certauthority.CA, username string, groups []string) *clientCert {
	certPEM, keyPEM, err := ca.IssueClientCertPEM(username, groups, time.Hour)
	require.NoError(t, err)
	return &clientCert{
		certPEM: certPEM,
		keyPEM:  keyPEM,
	}
}

func requireCanBindToPort(t *testing.T, port int) {
	ln, _, listenErr := genericoptions.CreateListener("", "0.0.0.0:"+strconv.Itoa(port), net.ListenConfig{})
	require.NoError(t, listenErr)
	require.NoError(t, ln.Close())
}
