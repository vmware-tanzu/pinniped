// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"context"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/features"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/testutil"
)

func TestNew(t *testing.T) {
	const port = 8444

	ca, err := certauthority.New(pkix.Name{CommonName: "ca"}, time.Hour)
	require.NoError(t, err)
	caKey, err := ca.PrivateKeyToPEM()
	require.NoError(t, err)
	caContent := dynamiccert.New("ca")
	err = caContent.SetCertKeyContent(ca.Bundle(), caKey)
	require.NoError(t, err)

	cert, key, err := ca.IssuePEM(pkix.Name{CommonName: "example.com"}, []string{"example.com"}, time.Hour)
	require.NoError(t, err)
	certKeyContent := dynamiccert.New("cert-key")
	err = certKeyContent.SetCertKeyContent(cert, key)
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
		name       string
		clientOpts []kubeclient.Option
		wantErr    string
	}{
		{
			name: "happy path",
			clientOpts: []kubeclient.Option{
				kubeclient.WithConfig(&rest.Config{
					BearerToken:     "should-be-ignored",
					BearerTokenFile: "required-to-be-set",
				}),
			},
		},
		{
			name: "no bearer token file",
			clientOpts: []kubeclient.Option{
				kubeclient.WithConfig(&rest.Config{
					BearerToken: "should-be-ignored",
				}),
			},
			wantErr: "invalid impersonator loopback rest config has wrong bearer token semantics",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// This is a serial test because the production code binds to the port.
			runner, constructionErr := newInternal(port, certKeyContent, caContent, tt.clientOpts, recOpts)

			if len(tt.wantErr) != 0 {
				require.EqualError(t, constructionErr, tt.wantErr)
				require.Nil(t, runner)
			} else {
				require.NoError(t, constructionErr)
				require.NotNil(t, runner)

				stopCh := make(chan struct{})
				errCh := make(chan error)
				go func() {
					stopErr := runner(stopCh)
					errCh <- stopErr
				}()

				select {
				case unexpectedExit := <-errCh:
					t.Errorf("unexpected exit, err=%v (even nil error is failure)", unexpectedExit)
				case <-time.After(10 * time.Second):
				}

				close(stopCh)
				exitErr := <-errCh
				require.NoError(t, exitErr)
			}

			// assert listener is closed is both cases above by trying to make another one on the same port
			ln, _, listenErr := genericoptions.CreateListener("", "0.0.0.0:"+strconv.Itoa(port), net.ListenConfig{})
			defer func() {
				if ln == nil {
					return
				}
				require.NoError(t, ln.Close())
			}()
			require.NoError(t, listenErr)

			// TODO: create some client certs and assert the authorizer works correctly with system:masters
			//  and nested impersonation - we could also try to test what headers are sent to KAS
		})
	}
}

func TestImpersonator(t *testing.T) {
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
			wantCreationErr: "could not get in-cluster transport config: execProvider and authProvider cannot be used in combination",
		},
		{
			name: "fail to get transport from config",
			restConfig: &rest.Config{
				Host:            "pinniped.dev/blah",
				BearerToken:     "test-bearer-token",
				Transport:       http.DefaultTransport,
				TLSClientConfig: rest.TLSClientConfig{Insecure: true},
			},
			wantCreationErr: "could not get in-cluster transport: using a custom transport with TLS certificate options or the insecure flag is not allowed",
		},
		{
			name:           "Impersonate-User header already in request",
			request:        newRequest(map[string][]string{"Impersonate-User": {"some-user"}}, nil),
			wantHTTPBody:   "invalid impersonation\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-Group header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Group": {"some-group"}}, nil),
			wantHTTPBody:   "invalid impersonation\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-Extra header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Extra-something": {"something"}}, nil),
			wantHTTPBody:   "invalid impersonation\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-* header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Something": {"some-newfangled-impersonate-header"}}, nil),
			wantHTTPBody:   "invalid impersonation\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "unexpected authorization header",
			request:        newRequest(map[string][]string{"Authorization": {"panda"}}, nil),
			wantHTTPBody:   "invalid authorization header\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "missing user",
			request:        newRequest(map[string][]string{}, nil),
			wantHTTPBody:   "invalid user\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "unexpected UID",
			request:        newRequest(map[string][]string{}, &user.DefaultInfo{UID: "007"}),
			wantHTTPBody:   "unexpected uid\n",
			wantHTTPStatus: http.StatusUnprocessableEntity,
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
			if tt.kubeAPIServerStatusCode == 0 {
				tt.kubeAPIServerStatusCode = http.StatusOK
			}

			serverWasCalled := false
			serverSawHeaders := http.Header{}
			testServerCA, testServerURL := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				serverWasCalled = true
				serverSawHeaders = r.Header
				if tt.kubeAPIServerStatusCode != http.StatusOK {
					w.WriteHeader(tt.kubeAPIServerStatusCode)
				} else {
					_, _ = w.Write([]byte("successful proxied response"))
				}
			})
			testServerKubeconfig := rest.Config{
				Host:            testServerURL,
				BearerToken:     "some-service-account-token",
				TLSClientConfig: rest.TLSClientConfig{CAData: []byte(testServerCA)},
			}
			if tt.restConfig == nil {
				tt.restConfig = &testServerKubeconfig
			}

			proxy, err := newImpersonationReverseProxy(tt.restConfig)
			if tt.wantCreationErr != "" {
				require.EqualError(t, err, tt.wantCreationErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, proxy)
			w := httptest.NewRecorder()
			requestBeforeServe := tt.request.Clone(tt.request.Context())
			proxy.ServeHTTP(w, tt.request)
			require.Equal(t, requestBeforeServe, tt.request, "ServeHTTP() mutated the request, and it should not per http.Handler docs")
			if tt.wantHTTPStatus != 0 {
				require.Equalf(t, tt.wantHTTPStatus, w.Code, "fyi, response body was %q", w.Body.String())
			}
			if tt.wantHTTPBody != "" {
				require.Equal(t, tt.wantHTTPBody, w.Body.String())
			}

			if tt.wantHTTPStatus == http.StatusOK || tt.kubeAPIServerStatusCode != http.StatusOK {
				require.True(t, serverWasCalled, "Should have proxied the request to the Kube API server, but didn't")
				require.Equal(t, tt.wantKubeAPIServerRequestHeaders, serverSawHeaders)
			} else {
				require.False(t, serverWasCalled, "Should not have proxied the request to the Kube API server, but did")
			}
		})
	}
}
