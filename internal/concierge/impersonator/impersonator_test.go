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
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/httpstream"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
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

	// turn off this code path for all tests because it does not handle the config we remove correctly
	defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.APIPriorityAndFairness, false)()

	tests := []struct {
		name                               string
		clientCert                         *clientCert
		clientImpersonateUser              rest.ImpersonationConfig
		clientMutateHeaders                func(http.Header)
		clientNextProtos                   []string
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
			name:                               "happy path with upgrade",
			clientCert:                         newClientCert(t, ca, "test-username2", []string{"test-group3", "test-group4"}),
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			clientMutateHeaders: func(header http.Header) {
				header.Add("Connection", "Upgrade")
				header.Add("Upgrade", "spdy/3.1")

				if ok := httpstream.IsUpgradeRequest(&http.Request{Header: header}); !ok {
					panic("request must be upgrade in this test")
				}
			},
			clientNextProtos: []string{"http/1.1"}, // we need to use http1 as http2 does not support upgrades, see http2checkConnHeaders
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":  {"test-username2"},
				"Impersonate-Group": {"test-group3", "test-group4", "system:authenticated"},
				"Authorization":     {"Bearer some-service-account-token"},
				"User-Agent":        {"test-agent"},
				"Accept":            {"application/vnd.kubernetes.protobuf,application/json"},
				"Accept-Encoding":   {"gzip"},
				"X-Forwarded-For":   {"127.0.0.1"},
				"Connection":        {"Upgrade"},
				"Upgrade":           {"spdy/3.1"},
			},
		},
		{
			name:                               "happy path ignores forwarded header",
			clientCert:                         newClientCert(t, ca, "test-username2", []string{"test-group3", "test-group4"}),
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			clientMutateHeaders: func(header http.Header) {
				header.Add("X-Forwarded-For", "example.com")
			},
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":  {"test-username2"},
				"Impersonate-Group": {"test-group3", "test-group4", "system:authenticated"},
				"Authorization":     {"Bearer some-service-account-token"},
				"User-Agent":        {"test-agent"},
				"Accept":            {"application/vnd.kubernetes.protobuf,application/json"},
				"Accept-Encoding":   {"gzip"},
				"X-Forwarded-For":   {"127.0.0.1"},
			},
		},
		{
			name:                               "happy path ignores forwarded header canonicalization",
			clientCert:                         newClientCert(t, ca, "test-username2", []string{"test-group3", "test-group4"}),
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			clientMutateHeaders: func(header http.Header) {
				header["x-FORWARDED-for"] = append(header["x-FORWARDED-for"], "example.com")
			},
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":  {"test-username2"},
				"Impersonate-Group": {"test-group3", "test-group4", "system:authenticated"},
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
			name:                               "nested impersonation by regular users calls delegating authorizer",
			clientCert:                         newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientImpersonateUser:              rest.ImpersonationConfig{UserName: "some-other-username"},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			// this fails because the delegating authorizer in this test only allows system:masters and fails everything else
			wantError: `users "some-other-username" is forbidden: User "test-username" ` +
				`cannot impersonate resource "users" in API group "" at the cluster scope`,
		},
		{
			name:       "nested impersonation by admin users calls delegating authorizer",
			clientCert: newClientCert(t, ca, "test-admin", []string{"system:masters", "test-group2"}),
			clientImpersonateUser: rest.ImpersonationConfig{
				UserName: "fire",
				Groups:   []string{"elements"},
				Extra: map[string][]string{
					"colors": {"red", "orange", "blue"},

					// gke
					"iam.gke.io/user-assertion":       {"good", "stuff"},
					"user-assertion.cloud.google.com": {"smaller", "things"},

					// openshift
					"scopes.authorization.openshift.io": {"user:info", "user:full", "user:check-access"},

					// openstack
					"alpha.kubernetes.io/identity/roles":            {"a-role1", "a-role2"},
					"alpha.kubernetes.io/identity/project/id":       {"a-project-id"},
					"alpha.kubernetes.io/identity/project/name":     {"a-project-name"},
					"alpha.kubernetes.io/identity/user/domain/id":   {"a-domain-id"},
					"alpha.kubernetes.io/identity/user/domain/name": {"a-domain-name"},
				},
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":                                                                {"fire"},
				"Impersonate-Group":                                                               {"elements", "system:authenticated"},
				"Impersonate-Extra-Colors":                                                        {"red", "orange", "blue"},
				"Impersonate-Extra-Iam.gke.io%2fuser-Assertion":                                   {"good", "stuff"},
				"Impersonate-Extra-User-Assertion.cloud.google.com":                               {"smaller", "things"},
				"Impersonate-Extra-Scopes.authorization.openshift.io":                             {"user:info", "user:full", "user:check-access"},
				"Impersonate-Extra-Alpha.kubernetes.io%2fidentity%2froles":                        {"a-role1", "a-role2"},
				"Impersonate-Extra-Alpha.kubernetes.io%2fidentity%2fproject%2fid":                 {"a-project-id"},
				"Impersonate-Extra-Alpha.kubernetes.io%2fidentity%2fproject%2fname":               {"a-project-name"},
				"Impersonate-Extra-Alpha.kubernetes.io%2fidentity%2fuser%2fdomain%2fid":           {"a-domain-id"},
				"Impersonate-Extra-Alpha.kubernetes.io%2fidentity%2fuser%2fdomain%2fname":         {"a-domain-name"},
				"Impersonate-Extra-Original-User-Info.impersonation-Proxy.concierge.pinniped.dev": {`{"username":"test-admin","groups":["test-group2","system:masters","system:authenticated"]}`},
				"Authorization":   {"Bearer some-service-account-token"},
				"User-Agent":      {"test-agent"},
				"Accept":          {"application/vnd.kubernetes.protobuf,application/json"},
				"Accept-Encoding": {"gzip"},
				"X-Forwarded-For": {"127.0.0.1"},
			},
		},
		{
			name:                  "nested impersonation by admin users cannot impersonate UID",
			clientCert:            newClientCert(t, ca, "test-admin", []string{"system:masters", "test-group2"}),
			clientImpersonateUser: rest.ImpersonationConfig{UserName: "some-other-username"},
			clientMutateHeaders: func(header http.Header) {
				header["Impersonate-Uid"] = []string{"root"}
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Internal error occurred: invalid impersonation",
		},
		{
			name:                  "nested impersonation by admin users cannot impersonate UID header canonicalization",
			clientCert:            newClientCert(t, ca, "test-admin", []string{"system:masters", "test-group2"}),
			clientImpersonateUser: rest.ImpersonationConfig{UserName: "some-other-username"},
			clientMutateHeaders: func(header http.Header) {
				header["imPerSoNaTE-uid"] = []string{"magic"}
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Internal error occurred: invalid impersonation",
		},
		{
			name:       "nested impersonation by admin users cannot use reserved key",
			clientCert: newClientCert(t, ca, "test-admin", []string{"system:masters", "test-group2"}),
			clientImpersonateUser: rest.ImpersonationConfig{
				UserName: "other-user-to-impersonate",
				Groups:   []string{"other-peeps"},
				Extra: map[string][]string{
					"key": {"good"},
					"something.impersonation-proxy.concierge.pinniped.dev": {"bad data"},
				},
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Internal error occurred: unimplemented functionality - unable to act as current user",
		},
		{
			name:       "nested impersonation by admin users cannot use invalid key",
			clientCert: newClientCert(t, ca, "test-admin", []string{"system:masters", "test-group2"}),
			clientImpersonateUser: rest.ImpersonationConfig{
				UserName: "panda",
				Groups:   []string{"other-peeps"},
				Extra: map[string][]string{
					"party~~time": {"danger"},
				},
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Internal error occurred: unimplemented functionality - unable to act as current user",
		},
		{
			name:       "nested impersonation by admin users can use uppercase key because impersonation is lossy",
			clientCert: newClientCert(t, ca, "test-admin", []string{"system:masters", "test-group2"}),
			clientImpersonateUser: rest.ImpersonationConfig{
				UserName: "panda",
				Groups:   []string{"other-peeps"},
				Extra: map[string][]string{
					"ROAR": {"tiger"}, // by the time our code sees this key, it is lowercased to "roar"
				},
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":       {"panda"},
				"Impersonate-Group":      {"other-peeps", "system:authenticated"},
				"Impersonate-Extra-Roar": {"tiger"},
				"Impersonate-Extra-Original-User-Info.impersonation-Proxy.concierge.pinniped.dev": {`{"username":"test-admin","groups":["test-group2","system:masters","system:authenticated"]}`},
				"Authorization":   {"Bearer some-service-account-token"},
				"User-Agent":      {"test-agent"},
				"Accept":          {"application/vnd.kubernetes.protobuf,application/json"},
				"Accept-Encoding": {"gzip"},
				"X-Forwarded-For": {"127.0.0.1"},
			},
		},
		{
			name:                  "no bearer token file in Kube API server client config",
			wantConstructionError: "invalid impersonator loopback rest config has wrong bearer token semantics",
		},
		{
			name:       "header canonicalization user header",
			clientCert: newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientMutateHeaders: func(header http.Header) {
				header["imPerSonaTE-USer"] = []string{"PANDA"}
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError: `users "PANDA" is forbidden: User "test-username" ` +
				`cannot impersonate resource "users" in API group "" at the cluster scope`,
		},
		{
			name:       "header canonicalization future UID header",
			clientCert: newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientMutateHeaders: func(header http.Header) {
				header["imPerSonaTE-uid"] = []string{"007"}
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Internal error occurred: invalid impersonation",
		},
		{
			name:       "future UID header",
			clientCert: newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientMutateHeaders: func(header http.Header) {
				header["Impersonate-Uid"] = []string{"008"}
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Internal error occurred: invalid impersonation",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// we need to create this listener ourselves because the API server
			// code treats (port == 0 && listener == nil) to mean "do nothing"
			listener, port, err := genericoptions.CreateListener("", "127.0.0.1:0", net.ListenConfig{})
			require.NoError(t, err)

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

			// Punch out just enough stuff to make New actually run without error.
			recOpts := func(options *genericoptions.RecommendedOptions) {
				options.Authentication.RemoteKubeConfigFileOptional = true
				options.Authorization.RemoteKubeConfigFileOptional = true
				options.CoreAPI = nil
				options.Admission = nil
				options.SecureServing.Listener = listener // use our listener with the dynamic port
			}

			// Create an impersonator.  Use an invalid port number to make sure our listener override works.
			runner, constructionErr := newInternal(-1000, certKeyContent, caContent, clientOpts, recOpts)
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
					CAData:     ca.Bundle(),
					CertData:   tt.clientCert.certPEM,
					KeyData:    tt.clientCert.keyPEM,
					NextProtos: tt.clientNextProtos,
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
	newRequest := func(h http.Header, userInfo user.Info, event *auditinternal.Event) *http.Request {
		ctx := context.Background()

		if userInfo != nil {
			ctx = request.WithUser(ctx, userInfo)
		}

		ae := &auditinternal.Event{Level: auditinternal.LevelMetadata}
		if event != nil {
			ae = event
		}
		ctx = request.WithAuditEvent(ctx, ae)

		reqInfo := &request.RequestInfo{
			IsResourceRequest: false,
			Path:              validURL.Path,
			Verb:              "get",
		}
		ctx = request.WithRequestInfo(ctx, reqInfo)

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
			request:        newRequest(map[string][]string{"Impersonate-User": {"some-user"}}, nil, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-Group header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Group": {"some-group"}}, nil, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-Extra header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Extra-something": {"something"}}, nil, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-* header already in request",
			request:        newRequest(map[string][]string{"Impersonate-Something": {"some-newfangled-impersonate-header"}}, nil, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "unexpected authorization header",
			request:        newRequest(map[string][]string{"Authorization": {"panda"}}, nil, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid authorization header","reason":"InternalError","details":{"causes":[{"message":"invalid authorization header"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "missing user",
			request:        newRequest(map[string][]string{}, nil, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid user","reason":"InternalError","details":{"causes":[{"message":"invalid user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "unexpected UID",
			request:        newRequest(map[string][]string{}, &user.DefaultInfo{UID: "007"}, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user but missing audit event",
			request: func() *http.Request {
				req := newRequest(map[string][]string{
					"User-Agent":   {"test-user-agent"},
					"Connection":   {"Upgrade"},
					"Upgrade":      {"some-upgrade"},
					"Other-Header": {"test-header-value-1"},
				}, &user.DefaultInfo{
					Name:   testUser,
					Groups: testGroups,
					Extra:  testExtra,
				}, nil)
				ctx := request.WithAuditEvent(req.Context(), nil)
				req = req.WithContext(ctx)
				return req
			}(),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid audit event","reason":"InternalError","details":{"causes":[{"message":"invalid audit event"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with upper case extra",
			request: newRequest(map[string][]string{
				"User-Agent":     {"test-user-agent"},
				"Connection":     {"Upgrade"},
				"Upgrade":        {"some-upgrade"},
				"Content-Type":   {"some-type"},
				"Content-Length": {"some-length"},
				"Other-Header":   {"test-header-value-1"},
			}, &user.DefaultInfo{
				Name:   testUser,
				Groups: testGroups,
				Extra: map[string][]string{
					"valid-key":   {"valid-value"},
					"Invalid-key": {"still-valid-value"},
				},
			}, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with upper case extra across multiple lines",
			request: newRequest(map[string][]string{
				"User-Agent":     {"test-user-agent"},
				"Connection":     {"Upgrade"},
				"Upgrade":        {"some-upgrade"},
				"Content-Type":   {"some-type"},
				"Content-Length": {"some-length"},
				"Other-Header":   {"test-header-value-1"},
			}, &user.DefaultInfo{
				Name:   testUser,
				Groups: testGroups,
				Extra: map[string][]string{
					"valid-key":               {"valid-value"},
					"valid-data\nInvalid-key": {"still-valid-value"},
				},
			}, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with reserved extra key",
			request: newRequest(map[string][]string{
				"User-Agent":     {"test-user-agent"},
				"Connection":     {"Upgrade"},
				"Upgrade":        {"some-upgrade"},
				"Content-Type":   {"some-type"},
				"Content-Length": {"some-length"},
				"Other-Header":   {"test-header-value-1"},
			}, &user.DefaultInfo{
				Name:   testUser,
				Groups: testGroups,
				Extra: map[string][]string{
					"valid-key": {"valid-value"},
					"foo.impersonation-proxy.concierge.pinniped.dev": {"still-valid-value"},
				},
			}, nil),
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
			}, nil),
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
			name: "authenticated gke user",
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
				Name:   "username@company.com",
				Groups: []string{"system:authenticated"},
				Extra: map[string][]string{
					// make sure we can handle these keys
					"iam.gke.io/user-assertion":       {"ABC"},
					"user-assertion.cloud.google.com": {"XYZ"},
				},
			}, nil),
			wantKubeAPIServerRequestHeaders: map[string][]string{
				"Authorization": {"Bearer some-service-account-token"},
				"Impersonate-Extra-Iam.gke.io%2fuser-Assertion":     {"ABC"},
				"Impersonate-Extra-User-Assertion.cloud.google.com": {"XYZ"},
				"Impersonate-Group": {"system:authenticated"},
				"Impersonate-User":  {"username@company.com"},
				"User-Agent":        {"test-user-agent"},
				"Accept":            {"some-accepted-format"},
				"Accept-Encoding":   {"some-accepted-encoding"},
				"Connection":        {"Upgrade"},
				"Upgrade":           {"some-upgrade"},
				"Content-Type":      {"some-type"},
				"Other-Header":      {"test-header-value-1"},
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
		},
		{
			name: "authenticated openshift/openstack user",
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
				Name: "kube:admin",
				// both of these auth stacks set UID but we cannot handle it today
				// UID:    "user-id",
				Groups: []string{"system:cluster-admins", "system:authenticated"},
				Extra: map[string][]string{
					// openshift
					"scopes.authorization.openshift.io": {"user:info", "user:full"},

					// openstack
					"alpha.kubernetes.io/identity/roles":            {"role1", "role2"},
					"alpha.kubernetes.io/identity/project/id":       {"project-id"},
					"alpha.kubernetes.io/identity/project/name":     {"project-name"},
					"alpha.kubernetes.io/identity/user/domain/id":   {"domain-id"},
					"alpha.kubernetes.io/identity/user/domain/name": {"domain-name"},
				},
			}, nil),
			wantKubeAPIServerRequestHeaders: map[string][]string{
				"Authorization": {"Bearer some-service-account-token"},
				"Impersonate-Extra-Scopes.authorization.openshift.io":                     {"user:info", "user:full"},
				"Impersonate-Extra-Alpha.kubernetes.io%2fidentity%2froles":                {"role1", "role2"},
				"Impersonate-Extra-Alpha.kubernetes.io%2fidentity%2fproject%2fid":         {"project-id"},
				"Impersonate-Extra-Alpha.kubernetes.io%2fidentity%2fproject%2fname":       {"project-name"},
				"Impersonate-Extra-Alpha.kubernetes.io%2fidentity%2fuser%2fdomain%2fid":   {"domain-id"},
				"Impersonate-Extra-Alpha.kubernetes.io%2fidentity%2fuser%2fdomain%2fname": {"domain-name"},
				"Impersonate-Group": {"system:cluster-admins", "system:authenticated"},
				"Impersonate-User":  {"kube:admin"},
				"User-Agent":        {"test-user-agent"},
				"Accept":            {"some-accepted-format"},
				"Accept-Encoding":   {"some-accepted-encoding"},
				"Connection":        {"Upgrade"},
				"Upgrade":           {"some-upgrade"},
				"Content-Type":      {"some-type"},
				"Other-Header":      {"test-header-value-1"},
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
		},
		{
			name: "authenticated user with almost reserved key",
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
				Name:   "username@company.com",
				Groups: []string{"system:authenticated"},
				Extra: map[string][]string{
					"foo.iimpersonation-proxy.concierge.pinniped.dev": {"still-valid-value"},
				},
			}, nil),
			wantKubeAPIServerRequestHeaders: map[string][]string{
				"Authorization": {"Bearer some-service-account-token"},
				"Impersonate-Extra-Foo.iimpersonation-Proxy.concierge.pinniped.dev": {"still-valid-value"},
				"Impersonate-Group": {"system:authenticated"},
				"Impersonate-User":  {"username@company.com"},
				"User-Agent":        {"test-user-agent"},
				"Accept":            {"some-accepted-format"},
				"Accept-Encoding":   {"some-accepted-encoding"},
				"Connection":        {"Upgrade"},
				"Upgrade":           {"some-upgrade"},
				"Content-Type":      {"some-type"},
				"Other-Header":      {"test-header-value-1"},
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
		},
		{
			name: "authenticated user with almost reserved key and nested impersonation",
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
				Name:   "username@company.com",
				Groups: []string{"system:authenticated"},
				Extra: map[string][]string{
					"original-user-info.impersonation-proxyy.concierge.pinniped.dev": {"log confusion stuff here"},
				},
			},
				&auditinternal.Event{
					User: authenticationv1.UserInfo{
						Username: "panda",
						UID:      "0x001",
						Groups:   []string{"bears", "friends"},
						Extra: map[string]authenticationv1.ExtraValue{
							"original-user-info.impersonation-proxy.concierge.pinniped.dev": {"this is allowed"},
						},
					},
					ImpersonatedUser: &authenticationv1.UserInfo{},
				},
			),
			wantKubeAPIServerRequestHeaders: map[string][]string{
				"Authorization": {"Bearer some-service-account-token"},
				"Impersonate-Extra-Original-User-Info.impersonation-Proxyy.concierge.pinniped.dev": {"log confusion stuff here"},
				"Impersonate-Extra-Original-User-Info.impersonation-Proxy.concierge.pinniped.dev":  {`{"username":"panda","uid":"0x001","groups":["bears","friends"],"extra":{"original-user-info.impersonation-proxy.concierge.pinniped.dev":["this is allowed"]}}`},
				"Impersonate-Group": {"system:authenticated"},
				"Impersonate-User":  {"username@company.com"},
				"User-Agent":        {"test-user-agent"},
				"Accept":            {"some-accepted-format"},
				"Accept-Encoding":   {"some-accepted-encoding"},
				"Connection":        {"Upgrade"},
				"Upgrade":           {"some-upgrade"},
				"Content-Type":      {"some-type"},
				"Other-Header":      {"test-header-value-1"},
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
		},
		{
			name: "authenticated user with nested impersonation",
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
			},
				&auditinternal.Event{
					User: authenticationv1.UserInfo{
						Username: "panda",
						UID:      "0x001",
						Groups:   []string{"bears", "friends"},
						Extra: map[string]authenticationv1.ExtraValue{
							"assertion": {"sha", "md5"},
							"req-id":    {"0123"},
						},
					},
					ImpersonatedUser: &authenticationv1.UserInfo{},
				},
			),
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
				"Impersonate-Extra-Original-User-Info.impersonation-Proxy.concierge.pinniped.dev": {`{"username":"panda","uid":"0x001","groups":["bears","friends"],"extra":{"assertion":["sha","md5"],"req-id":["0123"]}}`},
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
		},
		{
			name: "authenticated gke user with nested impersonation",
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
			},
				&auditinternal.Event{
					User: authenticationv1.UserInfo{
						Username: "username@company.com",
						Groups:   []string{"system:authenticated"},
						Extra: map[string]authenticationv1.ExtraValue{
							// make sure we can handle these keys
							"iam.gke.io/user-assertion":       {"ABC"},
							"user-assertion.cloud.google.com": {"999"},
						},
					},
					ImpersonatedUser: &authenticationv1.UserInfo{},
				},
			),
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
				"Impersonate-Extra-Original-User-Info.impersonation-Proxy.concierge.pinniped.dev": {`{"username":"username@company.com","groups":["system:authenticated"],"extra":{"iam.gke.io/user-assertion":["ABC"],"user-assertion.cloud.google.com":["999"]}}`},
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
		},
		{
			name: "authenticated user with nested impersonation of gke user",
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
				Name:   "username@company.com",
				Groups: []string{"system:authenticated"},
				Extra: map[string][]string{
					// make sure we can handle these keys
					"iam.gke.io/user-assertion":       {"DEF"},
					"user-assertion.cloud.google.com": {"XYZ"},
				},
			},
				&auditinternal.Event{
					User: authenticationv1.UserInfo{
						Username: "panda",
						UID:      "0x001",
						Groups:   []string{"bears", "friends"},
						Extra: map[string]authenticationv1.ExtraValue{
							"assertion": {"sha", "md5"},
							"req-id":    {"0123"},
						},
					},
					ImpersonatedUser: &authenticationv1.UserInfo{},
				},
			),
			wantKubeAPIServerRequestHeaders: map[string][]string{
				"Authorization": {"Bearer some-service-account-token"},
				"Impersonate-Extra-Iam.gke.io%2fuser-Assertion":     {"DEF"},
				"Impersonate-Extra-User-Assertion.cloud.google.com": {"XYZ"},
				"Impersonate-Group": {"system:authenticated"},
				"Impersonate-User":  {"username@company.com"},
				"User-Agent":        {"test-user-agent"},
				"Accept":            {"some-accepted-format"},
				"Accept-Encoding":   {"some-accepted-encoding"},
				"Connection":        {"Upgrade"},
				"Upgrade":           {"some-upgrade"},
				"Content-Type":      {"some-type"},
				"Other-Header":      {"test-header-value-1"},
				"Impersonate-Extra-Original-User-Info.impersonation-Proxy.concierge.pinniped.dev": {`{"username":"panda","uid":"0x001","groups":["bears","friends"],"extra":{"assertion":["sha","md5"],"req-id":["0123"]}}`},
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
			}, nil),
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

			w := httptest.NewRecorder()

			r := tt.request
			wantKubeAPIServerRequestHeaders := tt.wantKubeAPIServerRequestHeaders

			// take the isUpgradeRequest branch randomly to make sure we exercise both branches
			forceUpgradeRequest := rand.Int()%2 == 0 //nolint:gosec // we do not care if this is cryptographically secure
			if forceUpgradeRequest && len(r.Header.Get("Upgrade")) == 0 {
				r = r.Clone(r.Context())
				r.Header.Add("Connection", "Upgrade")
				r.Header.Add("Upgrade", "spdy/3.1")

				wantKubeAPIServerRequestHeaders = wantKubeAPIServerRequestHeaders.Clone()
				if wantKubeAPIServerRequestHeaders == nil {
					wantKubeAPIServerRequestHeaders = http.Header{}
				}
				wantKubeAPIServerRequestHeaders.Add("Connection", "Upgrade")
				wantKubeAPIServerRequestHeaders.Add("Upgrade", "spdy/3.1")
			}

			requestBeforeServe := r.Clone(r.Context())
			impersonatorHTTPHandlerFunc(&serverConfig.Config).ServeHTTP(w, r)

			require.Equal(t, requestBeforeServe, r, "ServeHTTP() mutated the request, and it should not per http.Handler docs")
			if tt.wantHTTPStatus != 0 {
				require.Equalf(t, tt.wantHTTPStatus, w.Code, "fyi, response body was %q", w.Body.String())
			}
			if tt.wantHTTPBody != "" {
				require.Equal(t, tt.wantHTTPBody, w.Body.String())
			}

			if tt.wantHTTPStatus == http.StatusOK || tt.kubeAPIServerStatusCode != http.StatusOK {
				require.True(t, testKubeAPIServerWasCalled, "Should have proxied the request to the Kube API server, but didn't")
				require.Equal(t, wantKubeAPIServerRequestHeaders, testKubeAPIServerSawHeaders)
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
	t.Helper()
	certPEM, keyPEM, err := ca.IssueClientCertPEM(username, groups, time.Hour)
	require.NoError(t, err)
	return &clientCert{
		certPEM: certPEM,
		keyPEM:  keyPEM,
	}
}

func requireCanBindToPort(t *testing.T, port int) {
	t.Helper()
	ln, _, listenErr := genericoptions.CreateListener("", "0.0.0.0:"+strconv.Itoa(port), net.ListenConfig{})
	require.NoError(t, listenErr)
	require.NoError(t, ln.Close())
}

func Test_deleteKnownImpersonationHeaders(t *testing.T) {
	tests := []struct {
		name          string
		headers, want http.Header
	}{
		{
			name: "no impersonation",
			headers: map[string][]string{
				"a":               {"b"},
				"Accept-Encoding": {"gzip"},
				"User-Agent":      {"test-user-agent"},
			},
			want: map[string][]string{
				"a":               {"b"},
				"Accept-Encoding": {"gzip"},
				"User-Agent":      {"test-user-agent"},
			},
		},
		{
			name: "impersonate user header is dropped",
			headers: map[string][]string{
				"a":                {"b"},
				"Impersonate-User": {"panda"},
				"Accept-Encoding":  {"gzip"},
				"User-Agent":       {"test-user-agent"},
			},
			want: map[string][]string{
				"a":               {"b"},
				"Accept-Encoding": {"gzip"},
				"User-Agent":      {"test-user-agent"},
			},
		},
		{
			name: "all known impersonate headers are dropped",
			headers: map[string][]string{
				"Accept-Encoding":           {"gzip"},
				"Authorization":             {"Bearer some-service-account-token"},
				"Impersonate-Extra-Extra-1": {"some", "extra", "stuff"},
				"Impersonate-Extra-Extra-2": {"some", "more", "extra", "stuff"},
				"Impersonate-Group":         {"test-group-1", "test-group-2"},
				"Impersonate-User":          {"test-user"},
				"User-Agent":                {"test-user-agent"},
			},
			want: map[string][]string{
				"Accept-Encoding": {"gzip"},
				"Authorization":   {"Bearer some-service-account-token"},
				"User-Agent":      {"test-user-agent"},
			},
		},
		{
			name: "future UID header is not dropped",
			headers: map[string][]string{
				"Accept-Encoding":           {"gzip"},
				"Authorization":             {"Bearer some-service-account-token"},
				"Impersonate-Extra-Extra-1": {"some", "extra", "stuff"},
				"Impersonate-Extra-Extra-2": {"some", "more", "extra", "stuff"},
				"Impersonate-Group":         {"test-group-1", "test-group-2"},
				"Impersonate-User":          {"test-user"},
				"Impersonate-Uid":           {"008"},
				"User-Agent":                {"test-user-agent"},
			},
			want: map[string][]string{
				"Accept-Encoding": {"gzip"},
				"Authorization":   {"Bearer some-service-account-token"},
				"User-Agent":      {"test-user-agent"},
				"Impersonate-Uid": {"008"},
			},
		},
		{
			name: "future UID header is not dropped, no other headers",
			headers: map[string][]string{
				"Impersonate-Uid": {"009"},
			},
			want: map[string][]string{
				"Impersonate-Uid": {"009"},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			inputReq := (&http.Request{Header: tt.headers}).WithContext(context.Background())
			inputReqCopy := inputReq.Clone(inputReq.Context())

			delegate := http.HandlerFunc(func(w http.ResponseWriter, outputReq *http.Request) {
				require.Nil(t, w)

				// assert only headers mutated
				outputReqCopy := outputReq.Clone(outputReq.Context())
				outputReqCopy.Header = tt.headers
				require.Equal(t, inputReqCopy, outputReqCopy)

				require.Equal(t, tt.want, outputReq.Header)

				if ensureNoImpersonationHeaders(inputReq) == nil {
					require.True(t, inputReq == outputReq, "expect req to passed through when no modification needed")
				}
			})

			deleteKnownImpersonationHeaders(delegate).ServeHTTP(nil, inputReq)
			require.Equal(t, inputReqCopy, inputReq) // assert no mutation occurred
		})
	}
}
