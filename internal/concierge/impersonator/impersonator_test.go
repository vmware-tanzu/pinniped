// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"

	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/mocks/mocktokenauthenticator"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestImpersonator(t *testing.T) {
	validURL, _ := url.Parse("http://pinniped.dev/blah")
	testServerCA, testServerURL := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Expect that the request is authenticated based on the kubeconfig credential.
		if r.Header.Get("Authorization") != "Bearer some-service-account-token" {
			http.Error(w, "expected to see service account token", http.StatusForbidden)
			return
		}
		// Fail if we see the malicious header passed through the proxy (it's not on the allowlist).
		if r.Header.Get("Malicious-Header") != "" {
			http.Error(w, "didn't expect to see malicious header", http.StatusForbidden)
			return
		}
		// Expect to see the user agent header passed through.
		if r.Header.Get("User-Agent") != "test-user-agent" {
			http.Error(w, "got unexpected user agent header", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("successful proxied response"))
	})
	testServerKubeconfig := rest.Config{
		Host:            testServerURL,
		BearerToken:     "some-service-account-token",
		TLSClientConfig: rest.TLSClientConfig{CAData: []byte(testServerCA)},
	}

	tests := []struct {
		name            string
		getKubeconfig   func() (*rest.Config, error)
		wantCreationErr string
		request         *http.Request
		wantHTTPBody    string
		wantHTTPStatus  int
		wantLogs        []string
		expectMockToken func(*testing.T, *mocktokenauthenticator.MockTokenMockRecorder)
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
			name:          "missing authorization header",
			getKubeconfig: func() (*rest.Config, error) { return &testServerKubeconfig, nil },
			request: &http.Request{
				Method: "GET",
				Header: map[string][]string{},
				URL:    validURL,
			},
			wantHTTPBody:   "invalid token encoding\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"missing authorization header\" \"msg\"=\"invalid token encoding\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:          "authorization header missing bearer prefix",
			getKubeconfig: func() (*rest.Config, error) { return &testServerKubeconfig, nil },
			request: &http.Request{
				Method: "GET",
				Header: map[string][]string{"Authorization": {makeTestTokenRequest("foo", "authenticator-one", "test-token")}},
				URL:    validURL,
			},
			wantHTTPBody:   "invalid token encoding\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"authorization header must be of type Bearer\" \"msg\"=\"invalid token encoding\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:          "token is not base64 encoded",
			getKubeconfig: func() (*rest.Config, error) { return &testServerKubeconfig, nil },
			request: &http.Request{
				Method: "GET",
				Header: map[string][]string{"Authorization": {"Bearer !!!"}},
				URL:    validURL,
			},
			wantHTTPBody:   "invalid token encoding\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"invalid base64 in encoded bearer token: illegal base64 data at input byte 0\" \"msg\"=\"invalid token encoding\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:          "base64 encoded token is not valid json",
			getKubeconfig: func() (*rest.Config, error) { return &testServerKubeconfig, nil },
			request: &http.Request{
				Method: "GET",
				Header: map[string][]string{"Authorization": {"Bearer abc"}},
				URL:    validURL,
			},
			wantHTTPBody:   "invalid token encoding\n",
			wantHTTPStatus: http.StatusBadRequest,
			wantLogs:       []string{"\"error\"=\"invalid TokenCredentialRequest encoded in bearer token: invalid character 'i' looking for beginning of value\" \"msg\"=\"invalid token encoding\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:          "token could not be authenticated",
			getKubeconfig: func() (*rest.Config, error) { return &testServerKubeconfig, nil },
			request: &http.Request{
				Method: "GET",
				Header: map[string][]string{"Authorization": {"Bearer " + makeTestTokenRequest("", "", "")}},
				URL:    validURL,
			},
			wantHTTPBody:   "invalid token\n",
			wantHTTPStatus: http.StatusUnauthorized,
			wantLogs:       []string{"\"error\"=\"no such authenticator\" \"msg\"=\"received invalid token\" \"authenticator\"={\"apiGroup\":null,\"kind\":\"\",\"name\":\"\"} \"authenticatorNamespace\"=\"\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		{
			name:          "token authenticates as nil",
			getKubeconfig: func() (*rest.Config, error) { return &testServerKubeconfig, nil },
			request: &http.Request{
				Method: "GET",
				Header: map[string][]string{"Authorization": {"Bearer " + makeTestTokenRequest("foo", "authenticator-one", "test-token")}},
				URL:    validURL,
			},
			expectMockToken: func(t *testing.T, recorder *mocktokenauthenticator.MockTokenMockRecorder) {
				recorder.AuthenticateToken(gomock.Any(), "test-token").Return(nil, false, nil)
			},
			wantHTTPBody:   "not authenticated\n",
			wantHTTPStatus: http.StatusUnauthorized,
			wantLogs:       []string{"\"level\"=0 \"msg\"=\"received token that did not authenticate\" \"authenticator\"={\"apiGroup\":null,\"kind\":\"\",\"name\":\"authenticator-one\"} \"authenticatorNamespace\"=\"foo\" \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\""},
		},
		// happy path
		{
			name:          "token validates",
			getKubeconfig: func() (*rest.Config, error) { return &testServerKubeconfig, nil },
			request: &http.Request{
				Method: "GET",
				Header: map[string][]string{
					"Authorization":    {"Bearer " + makeTestTokenRequest("foo", "authenticator-one", "test-token")},
					"Malicious-Header": {"test-header-value-1"},
					"User-Agent":       {"test-user-agent"},
				},
				URL: validURL,
			},
			expectMockToken: func(t *testing.T, recorder *mocktokenauthenticator.MockTokenMockRecorder) {
				userInfo := user.DefaultInfo{Name: "test-user", Groups: []string{"test-group-1", "test-group-2"}}
				response := &authenticator.Response{User: &userInfo}
				recorder.AuthenticateToken(gomock.Any(), "test-token").Return(response, true, nil)
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
			wantLogs:       []string{"\"level\"=0 \"msg\"=\"proxying authenticated request\" \"authenticator\"={\"apiGroup\":null,\"kind\":\"\",\"name\":\"authenticator-one\"} \"authenticatorNamespace\"=\"foo\" \"groups\"=[\"test-group-1\",\"test-group-2\"] \"method\"=\"GET\" \"url\"=\"http://pinniped.dev/blah\" \"user\"=\"test-user\""},
		},
	}

	for _, tt := range tests {
		tt := tt
		testLog := testlogger.New(t)
		t.Run(tt.name, func(t *testing.T) {
			// stole this from cache_test, hopefully it is sufficient
			cacheWithMockAuthenticator := authncache.New()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			key := authncache.Key{Namespace: "foo", Name: "authenticator-one"}
			mockToken := mocktokenauthenticator.NewMockToken(ctrl)
			cacheWithMockAuthenticator.Store(key, mockToken)

			if tt.expectMockToken != nil {
				tt.expectMockToken(t, mockToken.EXPECT())
			}

			proxy, err := newInternal(cacheWithMockAuthenticator, testLog, tt.getKubeconfig)
			if tt.wantCreationErr != "" {
				require.EqualError(t, err, tt.wantCreationErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, proxy)
			w := httptest.NewRecorder()
			proxy.ServeHTTP(w, tt.request)
			if tt.wantHTTPStatus != 0 {
				require.Equal(t, tt.wantHTTPStatus, w.Code)
			}
			if tt.wantHTTPBody != "" {
				require.Equal(t, tt.wantHTTPBody, w.Body.String())
			}
			if tt.wantLogs != nil {
				require.Equal(t, tt.wantLogs, testLog.Lines())
			}
		})
	}
}

func makeTestTokenRequest(namespace string, name string, token string) string {
	reqJSON, err := json.Marshal(&loginv1alpha1.TokenCredentialRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "TokenCredentialRequest",
			APIVersion: loginv1alpha1.GroupName + "/v1alpha1",
		},
		Spec: loginv1alpha1.TokenCredentialRequestSpec{
			Token:         token,
			Authenticator: corev1.TypedLocalObjectReference{Name: name},
		},
	})
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(reqJSON)
}
