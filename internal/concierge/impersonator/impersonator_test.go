// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	"go.pinniped.dev/generated/latest/apis/concierge/login"
	conciergescheme "go.pinniped.dev/internal/concierge/scheme"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/mocks/mocktokenauthenticator"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/impersonationtoken"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestImpersonator(t *testing.T) {
	const (
		defaultAPIGroup = "pinniped.dev"
		customAPIGroup  = "walrus.tld"

		testUser = "test-user"
	)

	testGroups := []string{"test-group-1", "test-group-2"}
	testExtra := map[string][]string{
		"extra-1": {"some", "extra", "stuff"},
		"extra-2": {"some", "more", "extra", "stuff"},
	}

	validURL, _ := url.Parse("http://pinniped.dev/blah")
	newRequest := func(h http.Header) *http.Request {
		r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, validURL.String(), nil)
		require.NoError(t, err)
		r.Header = h
		return r
	}

	goodAuthenticator := corev1.TypedLocalObjectReference{
		Name:     "authenticator-one",
		APIGroup: stringPtr(authenticationv1alpha1.GroupName),
	}
	badAuthenticator := corev1.TypedLocalObjectReference{
		Name:     "",
		APIGroup: stringPtr(authenticationv1alpha1.GroupName),
	}

	tests := []struct {
		name                            string
		apiGroupOverride                string
		getKubeconfig                   func() (*rest.Config, error)
		wantCreationErr                 string
		request                         *http.Request
		wantHTTPBody                    string
		wantHTTPStatus                  int
		wantLogs                        []string
		wantKubeAPIServerRequestHeaders http.Header
		wantKubeAPIServerStatusCode     int
		expectMockToken                 func(*testing.T, *mocktokenauthenticator.MockTokenMockRecorder)
	}{
		{
			name: "fail to get in-cluster config",
			getKubeconfig: func() (*rest.Config, error) {
				return nil, fmt.Errorf("some kubernetes error")
			},
			wantCreationErr: "could not get in-cluster config: some kubernetes error",
		},
		{
			name: "invalid kubeconfig host",
			getKubeconfig: func() (*rest.Config, error) {
				return &rest.Config{Host: ":"}, nil
			},
			wantCreationErr: "could not parse host URL from in-cluster config: parse \":\": missing protocol scheme",
		},
		{
			name: "invalid transport config",
			getKubeconfig: func() (*rest.Config, error) {
				return &rest.Config{
					Host:         "pinniped.dev/blah",
					ExecProvider: &api.ExecConfig{},
					AuthProvider: &api.AuthProviderConfig{},
				}, nil
			},
			wantCreationErr: "could not get in-cluster transport config: execProvider and authProvider cannot be used in combination",
		},
		{
			name: "fail to get transport from config",
			getKubeconfig: func() (*rest.Config, error) {
				return &rest.Config{
					Host:            "pinniped.dev/blah",
					BearerToken:     "test-bearer-token",
					Transport:       http.DefaultTransport,
					TLSClientConfig: rest.TLSClientConfig{Insecure: true},
				}, nil
			},
			wantCreationErr: "could not get in-cluster transport: using a custom transport with TLS certificate options or the insecure flag is not allowed",
		},
		{
			name:           "Impersonate-User header already in request",
			request:        newRequest(map[string][]string{"Impersonate-User": {"some-user"}}),
			wantHTTPBody:   "impersonation header already exists\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"\\\"Impersonate-User\\\" header already exists\" \"msg\"=\"impersonation header already exists\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:           "Impersonate-Group header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Group": {"some-group"}}),
			wantHTTPBody:   "impersonation header already exists\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"\\\"Impersonate-Group\\\" header already exists\" \"msg\"=\"impersonation header already exists\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:           "Impersonate-Extra header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Extra-something": {"something"}}),
			wantHTTPBody:   "impersonation header already exists\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"\\\"Impersonate-Extra-\\\" header already exists\" \"msg\"=\"impersonation header already exists\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:           "missing authorization header",
			request:        newRequest(map[string][]string{}),
			wantHTTPBody:   "invalid token encoding\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"token authenticator did not find token\" \"msg\"=\"invalid token encoding\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:           "authorization header missing bearer prefix",
			request:        newRequest(map[string][]string{"Authorization": {impersonationtoken.Make(t, "test-token", &goodAuthenticator, defaultAPIGroup)}}),
			wantHTTPBody:   "invalid token encoding\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"token authenticator did not find token\" \"msg\"=\"invalid token encoding\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:           "token is not base64 encoded",
			request:        newRequest(map[string][]string{"Authorization": {"Bearer !!!"}}),
			wantHTTPBody:   "invalid token encoding\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"invalid base64 in encoded bearer token: illegal base64 data at input byte 0\" \"msg\"=\"invalid token encoding\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:           "base64 encoded token is not valid json",
			request:        newRequest(map[string][]string{"Authorization": {"Bearer aGVsbG8gd29ybGQK"}}), // aGVsbG8gd29ybGQK is "hello world" base64 encoded
			wantHTTPBody:   "invalid token encoding\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"invalid object encoded in bearer token: couldn't get version/kind; json parse error: invalid character 'h' looking for beginning of value\" \"msg\"=\"invalid token encoding\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:             "base64 encoded token is encoded with default api group but we are expecting custom api group",
			apiGroupOverride: customAPIGroup,
			request:          newRequest(map[string][]string{"Authorization": {"Bearer " + impersonationtoken.Make(t, "test-token", &goodAuthenticator, defaultAPIGroup)}}),
			wantHTTPBody:     "invalid token encoding\n",
			wantHTTPStatus:   http.StatusBadRequest,
			wantLogs:         []string{"\"error\"=\"invalid object encoded in bearer token: no kind \\\"TokenCredentialRequest\\\" is registered for version \\\"login.concierge.pinniped.dev/v1alpha1\\\" in scheme \\\"pkg/runtime/scheme.go:100\\\"\" \"msg\"=\"invalid token encoding\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:           "base64 encoded token is encoded with custom api group but we are expecting default api group",
			request:        newRequest(map[string][]string{"Authorization": {"Bearer " + impersonationtoken.Make(t, "test-token", &goodAuthenticator, customAPIGroup)}}),
			wantHTTPBody:   "invalid token encoding\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"invalid object encoded in bearer token: no kind \\\"TokenCredentialRequest\\\" is registered for version \\\"login.concierge.walrus.tld/v1alpha1\\\" in scheme \\\"pkg/runtime/scheme.go:100\\\"\" \"msg\"=\"invalid token encoding\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:           "token could not be authenticated",
			request:        newRequest(map[string][]string{"Authorization": {"Bearer " + impersonationtoken.Make(t, "", &badAuthenticator, defaultAPIGroup)}}),
			wantHTTPBody:   "invalid token\n",
			wantHTTPStatus: http.StatusUnauthorized,
			wantLogs:       []string{"\"error\"=\"no such authenticator\" \"msg\"=\"received invalid token\" \"authenticator\"={\"apiGroup\":\"authentication.concierge.pinniped.dev\",\"kind\":\"\",\"name\":\"\"} \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:    "token authenticates as nil",
			request: newRequest(map[string][]string{"Authorization": {"Bearer " + impersonationtoken.Make(t, "test-token", &goodAuthenticator, defaultAPIGroup)}}),
			expectMockToken: func(t *testing.T, recorder *mocktokenauthenticator.MockTokenMockRecorder) {
				recorder.AuthenticateToken(gomock.Any(), "test-token").Return(nil, false, nil)
			},
			wantHTTPBody:   "not authenticated\n",
			wantHTTPStatus: http.StatusUnauthorized,
			wantLogs:       []string{"\"level\"=0 \"msg\"=\"received token that did not authenticate\" \"authenticator\"={\"apiGroup\":\"authentication.concierge.pinniped.dev\",\"kind\":\"\",\"name\":\"authenticator-one\"} \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		// happy path
		{
			name: "token validates",
			request: newRequest(map[string][]string{
				"Authorization":    {"Bearer " + impersonationtoken.Make(t, "test-token", &goodAuthenticator, defaultAPIGroup)},
				"User-Agent":       {"test-user-agent"},
				"Accept":           {"some-accepted-format"},
				"Accept-Encoding":  {"some-accepted-encoding"},
				"Connection":       {"Upgrade"}, // the value "Upgrade" is handled in a special way by `httputil.NewSingleHostReverseProxy`
				"Upgrade":          {"some-upgrade"},
				"Content-Type":     {"some-type"},
				"Content-Length":   {"some-length"},
				"Malicious-Header": {"test-header-value-1"}, // this header should not be forwarded to the Kube API server
			}),
			expectMockToken: func(t *testing.T, recorder *mocktokenauthenticator.MockTokenMockRecorder) {
				userInfo := user.DefaultInfo{
					Name:   testUser,
					Groups: testGroups,
					UID:    "test-uid",
					Extra:  testExtra,
				}
				response := &authenticator.Response{User: &userInfo}
				recorder.AuthenticateToken(gomock.Any(), "test-token").Return(response, true, nil)
			},
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
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
			wantLogs:       []string{"\"level\"=0 \"msg\"=\"proxying authenticated request\" \"authenticator\"={\"apiGroup\":\"authentication.concierge.pinniped.dev\",\"kind\":\"\",\"name\":\"authenticator-one\"} \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\" \"userID\"=\"test-uid\""},
		},
		{
			name: "token validates and the kube API request returns an error",
			request: newRequest(map[string][]string{
				"Authorization":    {"Bearer " + impersonationtoken.Make(t, "test-token", &goodAuthenticator, defaultAPIGroup)},
				"Malicious-Header": {"test-header-value-1"},
				"User-Agent":       {"test-user-agent"},
			}),
			expectMockToken: func(t *testing.T, recorder *mocktokenauthenticator.MockTokenMockRecorder) {
				userInfo := user.DefaultInfo{
					Name:   testUser,
					Groups: testGroups,
					UID:    "test-uid",
					Extra:  testExtra,
				}
				response := &authenticator.Response{User: &userInfo}
				recorder.AuthenticateToken(gomock.Any(), "test-token").Return(response, true, nil)
			},
			wantKubeAPIServerStatusCode: http.StatusNotFound,
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
			wantLogs:       []string{"\"level\"=0 \"msg\"=\"proxying authenticated request\" \"authenticator\"={\"apiGroup\":\"authentication.concierge.pinniped.dev\",\"kind\":\"\",\"name\":\"authenticator-one\"} \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\" \"userID\"=\"test-uid\""},
		},
		{
			name:             "token validates with custom api group",
			apiGroupOverride: customAPIGroup,
			request: newRequest(map[string][]string{
				"Authorization":    {"Bearer " + impersonationtoken.Make(t, "test-token", &goodAuthenticator, customAPIGroup)},
				"Malicious-Header": {"test-header-value-1"},
				"User-Agent":       {"test-user-agent"},
			}),
			expectMockToken: func(t *testing.T, recorder *mocktokenauthenticator.MockTokenMockRecorder) {
				userInfo := user.DefaultInfo{
					Name:   testUser,
					Groups: testGroups,
					UID:    "test-uid",
					Extra:  testExtra,
				}
				response := &authenticator.Response{User: &userInfo}
				recorder.AuthenticateToken(gomock.Any(), "test-token").Return(response, true, nil)
			},
			wantKubeAPIServerRequestHeaders: map[string][]string{
				"Accept-Encoding":           {"gzip"}, // because the rest client used in this test does not disable compression
				"Authorization":             {"Bearer some-service-account-token"},
				"Impersonate-Extra-Extra-1": {"some", "extra", "stuff"},
				"Impersonate-Extra-Extra-2": {"some", "more", "extra", "stuff"},
				"Impersonate-Group":         {"test-group-1", "test-group-2"},
				"Impersonate-User":          {"test-user"},
				"User-Agent":                {"test-user-agent"},
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
			wantLogs:       []string{"\"level\"=0 \"msg\"=\"proxying authenticated request\" \"authenticator\"={\"apiGroup\":\"authentication.concierge.pinniped.dev\",\"kind\":\"\",\"name\":\"authenticator-one\"} \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\" \"userID\"=\"test-uid\""},
		},
	}

	for _, tt := range tests {
		tt := tt
		testLog := testlogger.New(t)
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if t.Failed() {
					for i, line := range testLog.Lines() {
						t.Logf("testLog line %d: %q", i+1, line)
					}
				}
			}()

			if tt.wantKubeAPIServerStatusCode == 0 {
				tt.wantKubeAPIServerStatusCode = http.StatusOK
			}

			serverWasCalled := false
			serverSawHeaders := http.Header{}
			testServerCA, testServerURL := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				serverWasCalled = true
				serverSawHeaders = r.Header
				if tt.wantKubeAPIServerStatusCode != http.StatusOK {
					w.WriteHeader(tt.wantKubeAPIServerStatusCode)
				} else {
					_, _ = w.Write([]byte("successful proxied response"))
				}
			})
			testServerKubeconfig := rest.Config{
				Host:            testServerURL,
				BearerToken:     "some-service-account-token",
				TLSClientConfig: rest.TLSClientConfig{CAData: []byte(testServerCA)},
			}
			if tt.getKubeconfig == nil {
				tt.getKubeconfig = func() (*rest.Config, error) {
					return &testServerKubeconfig, nil
				}
			}

			// stole this from cache_test, hopefully it is sufficient
			cacheWithMockAuthenticator := authncache.New()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			key := authncache.Key{Name: "authenticator-one", APIGroup: *goodAuthenticator.APIGroup}
			mockToken := mocktokenauthenticator.NewMockToken(ctrl)
			cacheWithMockAuthenticator.Store(key, mockToken)

			if tt.expectMockToken != nil {
				tt.expectMockToken(t, mockToken.EXPECT())
			}

			apiGroup := defaultAPIGroup
			if tt.apiGroupOverride != "" {
				apiGroup = tt.apiGroupOverride
			}

			proxy, err := newInternal(cacheWithMockAuthenticator, makeDecoder(t, apiGroup), testLog, tt.getKubeconfig)
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
			if tt.wantLogs != nil {
				require.Equal(t, tt.wantLogs, testLog.Lines())
			}

			if tt.wantHTTPStatus == http.StatusOK || tt.wantKubeAPIServerStatusCode != http.StatusOK {
				require.True(t, serverWasCalled, "Should have proxied the request to the Kube API server, but didn't")
				require.Equal(t, tt.wantKubeAPIServerRequestHeaders, serverSawHeaders)
			} else {
				require.False(t, serverWasCalled, "Should not have proxied the request to the Kube API server, but did")
			}
		})
	}
}

func stringPtr(s string) *string { return &s }

func makeDecoder(t *testing.T, apiGroupSuffix string) runtime.Decoder {
	t.Helper()

	scheme, loginGV, _ := conciergescheme.New(apiGroupSuffix)
	codecs := serializer.NewCodecFactory(scheme)
	respInfo, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), runtime.ContentTypeJSON)
	require.True(t, ok, "couldn't find serializer info for media type")

	return codecs.DecoderToVersion(respInfo.Serializer, schema.GroupVersion{
		Group:   loginGV.Group,
		Version: login.SchemeGroupVersion.Version,
	})
}
