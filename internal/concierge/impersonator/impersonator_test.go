// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured/unstructuredscheme"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/httpstream"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/features"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/utils/pointer"

	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/groupsuffix"
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
		kubeAPIServerHealthz               http.Handler
		anonymousAuthDisabled              bool
		wantKubeAPIServerRequestHeaders    http.Header
		wantError                          string
		wantConstructionError              string
		wantAuthorizerAttributes           []authorizer.AttributesRecord
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
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-username", UID: "", Groups: []string{"test-group1", "test-group2", "system:authenticated"}, Extra: nil},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
			},
		},
		{
			name:                               "happy path with forbidden healthz",
			clientCert:                         newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			kubeAPIServerHealthz: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("no healthz for you"))
			}),
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":  {"test-username"},
				"Impersonate-Group": {"test-group1", "test-group2", "system:authenticated"},
				"Authorization":     {"Bearer some-service-account-token"},
				"User-Agent":        {"test-agent"},
				"Accept":            {"application/vnd.kubernetes.protobuf,application/json"},
				"Accept-Encoding":   {"gzip"},
				"X-Forwarded-For":   {"127.0.0.1"},
			},
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-username", UID: "", Groups: []string{"test-group1", "test-group2", "system:authenticated"}, Extra: nil},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
			},
		},
		{
			name:                               "happy path with unauthorized healthz",
			clientCert:                         newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			kubeAPIServerHealthz: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("no healthz for you"))
			}),
			anonymousAuthDisabled: true,
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":  {"test-username"},
				"Impersonate-Group": {"test-group1", "test-group2", "system:authenticated"},
				"Authorization":     {"Bearer some-service-account-token"},
				"User-Agent":        {"test-agent"},
				"Accept":            {"application/vnd.kubernetes.protobuf,application/json"},
				"Accept-Encoding":   {"gzip"},
				"X-Forwarded-For":   {"127.0.0.1"},
			},
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-username", UID: "", Groups: []string{"test-group1", "test-group2", "system:authenticated"}, Extra: nil},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
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
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-username2", UID: "", Groups: []string{"test-group3", "test-group4", "system:authenticated"}, Extra: nil},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
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
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-username2", UID: "", Groups: []string{"test-group3", "test-group4", "system:authenticated"}, Extra: nil},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
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
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-username2", UID: "", Groups: []string{"test-group3", "test-group4", "system:authenticated"}, Extra: nil},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
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
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-username", UID: "", Groups: []string{"test-group1", "test-group2", "system:authenticated"}, Extra: nil},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
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
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "system:anonymous", UID: "", Groups: []string{"system:unauthenticated"}, Extra: nil},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
			},
		},
		{
			name:       "when there is no client cert on request but it has basic auth, it is still an anonymous request",
			clientCert: &clientCert{},
			clientMutateHeaders: func(header http.Header) {
				header.Set("Test", "val")
				req := &http.Request{Header: header}
				req.SetBasicAuth("foo", "bar")
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantKubeAPIServerRequestHeaders: http.Header{
				"Impersonate-User":  {"system:anonymous"},
				"Impersonate-Group": {"system:unauthenticated"},
				"Authorization":     {"Bearer some-service-account-token"},
				"User-Agent":        {"test-agent"},
				"Accept":            {"application/vnd.kubernetes.protobuf,application/json"},
				"Accept-Encoding":   {"gzip"},
				"X-Forwarded-For":   {"127.0.0.1"},
				"Test":              {"val"},
			},
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "system:anonymous", UID: "", Groups: []string{"system:unauthenticated"}, Extra: nil},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
			},
		},
		{
			name:                               "failed client cert authentication",
			clientCert:                         newClientCert(t, unrelatedCA, "test-username", []string{"test-group1"}),
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Unauthorized",
			wantAuthorizerAttributes:           nil,
		},
		{
			name:                               "nested impersonation by regular users calls delegating authorizer",
			clientCert:                         newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientImpersonateUser:              rest.ImpersonationConfig{UserName: "some-other-username"},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			// this fails because the delegating authorizer in this test only allows system:masters and fails everything else
			wantError: `users "some-other-username" is forbidden: User "test-username" ` +
				`cannot impersonate resource "users" in API group "" at the cluster scope: ` +
				`decision made by impersonation-proxy.concierge.pinniped.dev`,
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-username", UID: "", Groups: []string{"test-group1", "test-group2", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "users", Subresource: "", Name: "some-other-username", ResourceRequest: true, Path: "",
				},
			},
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
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "users", Subresource: "", Name: "fire", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "groups", Subresource: "", Name: "elements", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "iam.gke.io/user-assertion", Name: "good", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "iam.gke.io/user-assertion", Name: "stuff", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "alpha.kubernetes.io/identity/roles", Name: "a-role1", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "alpha.kubernetes.io/identity/roles", Name: "a-role2", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "user-assertion.cloud.google.com", Name: "smaller", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "user-assertion.cloud.google.com", Name: "things", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "colors", Name: "red", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "colors", Name: "orange", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "colors", Name: "blue", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "scopes.authorization.openshift.io", Name: "user:info", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "scopes.authorization.openshift.io", Name: "user:full", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "scopes.authorization.openshift.io", Name: "user:check-access", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "alpha.kubernetes.io/identity/project/name", Name: "a-project-name", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "alpha.kubernetes.io/identity/user/domain/id", Name: "a-domain-id", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "alpha.kubernetes.io/identity/user/domain/name", Name: "a-domain-name", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "alpha.kubernetes.io/identity/project/id", Name: "a-project-id", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "fire", UID: "", Groups: []string{"elements", "system:authenticated"},
						Extra: map[string][]string{
							"alpha.kubernetes.io/identity/project/id":       {"a-project-id"},
							"alpha.kubernetes.io/identity/project/name":     {"a-project-name"},
							"alpha.kubernetes.io/identity/roles":            {"a-role1", "a-role2"},
							"alpha.kubernetes.io/identity/user/domain/id":   {"a-domain-id"},
							"alpha.kubernetes.io/identity/user/domain/name": {"a-domain-name"},
							"colors":                            {"red", "orange", "blue"},
							"iam.gke.io/user-assertion":         {"good", "stuff"},
							"scopes.authorization.openshift.io": {"user:info", "user:full", "user:check-access"},
							"user-assertion.cloud.google.com":   {"smaller", "things"},
						},
					},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
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
			wantError:                          "Internal error occurred: unimplemented functionality - unable to act as current user",
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "users", Subresource: "", Name: "some-other-username", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "uids", Subresource: "", Name: "root", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "some-other-username", UID: "root", Groups: []string{"system:authenticated"}, Extra: map[string][]string{}},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
			},
		},
		{
			name:                  "nested impersonation by admin users cannot impersonate UID header canonicalization",
			clientCert:            newClientCert(t, ca, "test-admin", []string{"system:masters", "test-group2"}),
			clientImpersonateUser: rest.ImpersonationConfig{UserName: "some-other-username"},
			clientMutateHeaders: func(header http.Header) {
				header["imPerSoNaTE-uid"] = []string{"magic"}
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          "Internal error occurred: unimplemented functionality - unable to act as current user",
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "users", Subresource: "", Name: "some-other-username", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "uids", Subresource: "", Name: "magic", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "some-other-username", UID: "magic", Groups: []string{"system:authenticated"}, Extra: map[string][]string{}},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
			},
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
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "users", Subresource: "", Name: "other-user-to-impersonate", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "groups", Subresource: "", Name: "other-peeps", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "something.impersonation-proxy.concierge.pinniped.dev", Name: "bad data", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "key", Name: "good", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "other-user-to-impersonate", UID: "", Groups: []string{"other-peeps", "system:authenticated"},
						Extra: map[string][]string{
							"key": {"good"},
							"something.impersonation-proxy.concierge.pinniped.dev": {"bad data"},
						},
					},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
			},
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
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "users", Subresource: "", Name: "panda", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "groups", Subresource: "", Name: "other-peeps", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "party~~time", Name: "danger", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "panda", UID: "", Groups: []string{"other-peeps", "system:authenticated"}, Extra: map[string][]string{"party~~time": {"danger"}}},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
			},
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
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "users", Subresource: "", Name: "panda", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "groups", Subresource: "", Name: "other-peeps", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "test-admin", UID: "", Groups: []string{"test-group2", "system:masters", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "authentication.k8s.io", APIVersion: "v1", Resource: "userextras", Subresource: "roar", Name: "tiger", ResourceRequest: true, Path: "",
				},
				{
					User: &user.DefaultInfo{Name: "panda", UID: "", Groups: []string{"other-peeps", "system:authenticated"}, Extra: map[string][]string{"roar": {"tiger"}}},
					Verb: "list", Namespace: "", APIGroup: "", APIVersion: "v1", Resource: "namespaces", Subresource: "", Name: "", ResourceRequest: true, Path: "/api/v1/namespaces",
				},
			},
		},
		{
			name:                     "no bearer token file in Kube API server client config",
			wantConstructionError:    "invalid impersonator loopback rest config has wrong bearer token semantics",
			wantAuthorizerAttributes: nil,
		},
		{
			name: "unexpected healthz response",
			kubeAPIServerHealthz: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("broken"))
			}),
			wantConstructionError:    `could not detect if anonymous authentication is enabled: an error on the server ("broken") has prevented the request from succeeding`,
			wantAuthorizerAttributes: nil,
		},
		{
			name:       "header canonicalization user header",
			clientCert: newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientMutateHeaders: func(header http.Header) {
				header["imPerSonaTE-USer"] = []string{"PANDA"}
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError: `users "PANDA" is forbidden: User "test-username" ` +
				`cannot impersonate resource "users" in API group "" at the cluster scope: ` +
				`decision made by impersonation-proxy.concierge.pinniped.dev`,
			wantAuthorizerAttributes: []authorizer.AttributesRecord{
				{
					User: &user.DefaultInfo{Name: "test-username", UID: "", Groups: []string{"test-group1", "test-group2", "system:authenticated"}, Extra: nil},
					Verb: "impersonate", Namespace: "", APIGroup: "", APIVersion: "", Resource: "users", Subresource: "", Name: "PANDA", ResourceRequest: true, Path: "",
				},
			},
		},
		{
			name:       "header canonicalization future UID header", // no longer future as it exists in Kube v1.22
			clientCert: newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientMutateHeaders: func(header http.Header) {
				header["imPerSonaTE-uid"] = []string{"007"}
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          `an error on the server ("Internal Server Error: \"/api/v1/namespaces\": requested [{UID  007  authentication.k8s.io/v1  }] without impersonating a user") has prevented the request from succeeding (get namespaces)`,
			wantAuthorizerAttributes:           []authorizer.AttributesRecord{},
		},
		{
			name:       "future UID header", // no longer future as it exists in Kube v1.22
			clientCert: newClientCert(t, ca, "test-username", []string{"test-group1", "test-group2"}),
			clientMutateHeaders: func(header http.Header) {
				header["Impersonate-Uid"] = []string{"008"}
			},
			kubeAPIServerClientBearerTokenFile: "required-to-be-set",
			wantError:                          `an error on the server ("Internal Server Error: \"/api/v1/namespaces\": requested [{UID  008  authentication.k8s.io/v1  }] without impersonating a user") has prevented the request from succeeding (get namespaces)`,
			wantAuthorizerAttributes:           []authorizer.AttributesRecord{},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			t.Cleanup(cancel)

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
				switch r.URL.Path {
				case "/api/v1/namespaces/kube-system/configmaps":
					require.Equal(t, http.MethodGet, r.Method)

					// The production code uses NewDynamicCAFromConfigMapController which fetches a ConfigMap,
					// so treat that differently. It wants to read the Kube API server CA from that ConfigMap
					// to use it to validate client certs. We don't need it for this test, so return NotFound.
					http.NotFound(w, r)
					return

				case "/api/v1/namespaces":
					require.Equal(t, http.MethodGet, r.Method)

					testKubeAPIServerWasCalled = true
					testKubeAPIServerSawHeaders = r.Header
					if tt.kubeAPIServerStatusCode != http.StatusOK {
						w.WriteHeader(tt.kubeAPIServerStatusCode)
						return
					}

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
					return

				case "/probe":
					require.Equal(t, http.MethodGet, r.Method)

					_, _ = fmt.Fprint(w, "probed")
					return

				case "/healthz":
					require.Equal(t, http.MethodGet, r.Method)
					require.Empty(t, r.Header.Get("Authorization"))
					require.Contains(t, r.Header.Get("User-Agent"), "kubernetes")

					if tt.kubeAPIServerHealthz != nil {
						tt.kubeAPIServerHealthz.ServeHTTP(w, r)
						return
					}

					// by default just match the KAS /healthz endpoint
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					w.Header().Set("X-Content-Type-Options", "nosniff")
					_, _ = fmt.Fprint(w, "ok")
					return

				case "/apis/login.concierge.pinniped.dev/v1alpha1/tokencredentialrequests":
					require.Equal(t, http.MethodPost, r.Method)

					w.Header().Add("Content-Type", "application/json; charset=UTF-8")
					_, _ = w.Write([]byte(`{}`))
					return

				case "/apis/login.concierge.walrus.tld/v1alpha1/tokencredentialrequests":
					require.Equal(t, http.MethodPost, r.Method)

					w.Header().Add("Content-Type", "application/json; charset=UTF-8")
					_, _ = w.Write([]byte(`{}`))
					return

				case "/apis/not-concierge.walrus.tld/v1/tokencredentialrequests":
					require.Equal(t, http.MethodGet, r.Method)

					w.Header().Add("Content-Type", "application/json; charset=UTF-8")
					_, _ = w.Write([]byte(`{"hello": "quack"}`))
					return

				case "/apis/not-concierge.walrus.tld/v1/ducks":
					require.Equal(t, http.MethodGet, r.Method)

					w.Header().Add("Content-Type", "application/json; charset=UTF-8")
					_, _ = w.Write([]byte(`{"hello": "birds"}`))
					return

				default:
					require.Fail(t, "fake Kube API server got an unexpected request", "path: %s", r.URL.Path)
					return
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

			recorder := &attributeRecorder{}
			defer func() {
				require.ElementsMatch(t, tt.wantAuthorizerAttributes, recorder.attributes)
				require.Len(t, recorder.attributes, len(tt.wantAuthorizerAttributes))
			}()

			// Allow standard REST verbs to be authorized so that tests pass without invasive changes
			recConfig := func(config *genericapiserver.RecommendedConfig) {
				authz := config.Authorization.Authorizer.(*comparableAuthorizer)
				delegate := authz.authorizerFunc
				authz.authorizerFunc = func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
					recorder.record(a)
					switch a.GetVerb() {
					case "create", "get", "list":
						return authorizer.DecisionAllow, "standard verbs are allowed in tests", nil
					default:
						return delegate(ctx, a)
					}
				}
			}

			// Create an impersonator.  Use an invalid port number to make sure our listener override works.
			runner, constructionErr := newInternal(-1000, certKeyContent, caContent, clientOpts, recOpts, recConfig)
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
			listResponse, err := client.Kubernetes.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
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

			// these authorization checks are caused by the anonymous auth checks below
			tt.wantAuthorizerAttributes = append(tt.wantAuthorizerAttributes,
				authorizer.AttributesRecord{
					User: &user.DefaultInfo{Name: "system:anonymous", UID: "", Groups: []string{"system:unauthenticated"}, Extra: nil},
					Verb: "create", Namespace: "", APIGroup: "login.concierge.pinniped.dev", APIVersion: "v1alpha1", Resource: "tokencredentialrequests", Subresource: "", Name: "", ResourceRequest: true, Path: "/apis/login.concierge.pinniped.dev/v1alpha1/tokencredentialrequests",
				},
				authorizer.AttributesRecord{
					User: &user.DefaultInfo{Name: "system:anonymous", UID: "", Groups: []string{"system:unauthenticated"}, Extra: nil},
					Verb: "create", Namespace: "", APIGroup: "login.concierge.walrus.tld", APIVersion: "v1alpha1", Resource: "tokencredentialrequests", Subresource: "", Name: "", ResourceRequest: true, Path: "/apis/login.concierge.walrus.tld/v1alpha1/tokencredentialrequests",
				},
			)
			if !tt.anonymousAuthDisabled {
				tt.wantAuthorizerAttributes = append(tt.wantAuthorizerAttributes,
					authorizer.AttributesRecord{
						User: &user.DefaultInfo{Name: "system:anonymous", UID: "", Groups: []string{"system:unauthenticated"}, Extra: nil},
						Verb: "get", Namespace: "", APIGroup: "", APIVersion: "", Resource: "", Subresource: "", Name: "", ResourceRequest: false, Path: "/probe",
					},
					authorizer.AttributesRecord{
						User: &user.DefaultInfo{Name: "system:anonymous", UID: "", Groups: []string{"system:unauthenticated"}, Extra: nil},
						Verb: "list", Namespace: "", APIGroup: "not-concierge.walrus.tld", APIVersion: "v1", Resource: "tokencredentialrequests", Subresource: "", Name: "", ResourceRequest: true, Path: "/apis/not-concierge.walrus.tld/v1/tokencredentialrequests",
					},
					authorizer.AttributesRecord{
						User: &user.DefaultInfo{Name: "system:anonymous", UID: "", Groups: []string{"system:unauthenticated"}, Extra: nil},
						Verb: "list", Namespace: "", APIGroup: "not-concierge.walrus.tld", APIVersion: "v1", Resource: "ducks", Subresource: "", Name: "", ResourceRequest: true, Path: "/apis/not-concierge.walrus.tld/v1/ducks",
					},
				)
			}

			// anonymous TCR should always work

			tcrRegGroup, err := kubeclient.New(kubeclient.WithConfig(rest.AnonymousClientConfig(clientKubeconfig)))
			require.NoError(t, err)

			tcrOtherGroup, err := kubeclient.New(kubeclient.WithConfig(rest.AnonymousClientConfig(clientKubeconfig)),
				kubeclient.WithMiddleware(groupsuffix.New("walrus.tld")))
			require.NoError(t, err)

			_, errTCR := tcrRegGroup.PinnipedConcierge.LoginV1alpha1().TokenCredentialRequests().Create(ctx, &loginv1alpha1.TokenCredentialRequest{}, metav1.CreateOptions{})
			require.NoError(t, errTCR)

			_, errTCROtherGroup := tcrOtherGroup.PinnipedConcierge.LoginV1alpha1().TokenCredentialRequests().Create(ctx,
				&loginv1alpha1.TokenCredentialRequest{
					Spec: loginv1alpha1.TokenCredentialRequestSpec{
						Authenticator: corev1.TypedLocalObjectReference{
							APIGroup: pointer.String("anything.pinniped.dev"),
						},
					},
				}, metav1.CreateOptions{})
			require.NoError(t, errTCROtherGroup)

			// these calls should only work when anonymous auth is enabled

			anonymousConfig := rest.AnonymousClientConfig(clientKubeconfig)
			anonymousConfig.GroupVersion = &schema.GroupVersion{
				Group:   "not-concierge.walrus.tld",
				Version: "v1",
			}
			anonymousConfig.APIPath = "/apis"
			anonymousConfig.NegotiatedSerializer = unstructuredscheme.NewUnstructuredNegotiatedSerializer()
			rc, err := rest.RESTClientFor(anonymousConfig)
			require.NoError(t, err)

			probeBody, errProbe := rc.Get().AbsPath("/probe").DoRaw(ctx)
			if tt.anonymousAuthDisabled {
				require.True(t, errors.IsUnauthorized(errProbe), errProbe)
				require.Equal(t, `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`+"\n", string(probeBody))
			} else {
				require.NoError(t, errProbe)
				require.Equal(t, "probed", string(probeBody))
			}

			notTCRBody, errNotTCR := rc.Get().Resource("tokencredentialrequests").DoRaw(ctx)
			if tt.anonymousAuthDisabled {
				require.True(t, errors.IsUnauthorized(errNotTCR), errNotTCR)
				require.Equal(t, `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`+"\n", string(notTCRBody))
			} else {
				require.NoError(t, errNotTCR)
				require.Equal(t, `{"hello": "quack"}`, string(notTCRBody))
			}

			ducksBody, errDucks := rc.Get().Resource("ducks").DoRaw(ctx)
			if tt.anonymousAuthDisabled {
				require.True(t, errors.IsUnauthorized(errDucks), errDucks)
				require.Equal(t, `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`+"\n", string(ducksBody))
			} else {
				require.NoError(t, errDucks)
				require.Equal(t, `{"hello": "birds"}`, string(ducksBody))
			}

			// this should always fail as unauthorized (even for TCR) because the cert is not valid

			badCertConfig := rest.AnonymousClientConfig(clientKubeconfig)
			badCert := newClientCert(t, unrelatedCA, "bad-user", []string{"bad-group"})
			badCertConfig.TLSClientConfig.CertData = badCert.certPEM
			badCertConfig.TLSClientConfig.KeyData = badCert.keyPEM

			tcrBadCert, err := kubeclient.New(kubeclient.WithConfig(badCertConfig))
			require.NoError(t, err)

			_, errBadCert := tcrBadCert.PinnipedConcierge.LoginV1alpha1().TokenCredentialRequests().Create(ctx, &loginv1alpha1.TokenCredentialRequest{}, metav1.CreateOptions{})
			require.True(t, errors.IsUnauthorized(errBadCert), errBadCert)
			require.EqualError(t, errBadCert, "Unauthorized")

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

	tests := []struct {
		name                            string
		restConfig                      *rest.Config
		wantCreationErr                 string
		request                         *http.Request
		authenticator                   authenticator.Request
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
			request:        newRequest(t, map[string][]string{"Impersonate-User": {"some-user"}}, nil, nil, ""),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-Group header already in request",
			request:        newRequest(t, map[string][]string{"Impersonate-Group": {"some-group"}}, nil, nil, ""),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-Extra header already in request",
			request:        newRequest(t, map[string][]string{"Impersonate-Extra-something": {"something"}}, nil, nil, ""),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "Impersonate-* header already in request",
			request:        newRequest(t, map[string][]string{"Impersonate-Something": {"some-newfangled-impersonate-header"}}, nil, nil, ""),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid impersonation","reason":"InternalError","details":{"causes":[{"message":"invalid impersonation"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "unexpected authorization header",
			request:        newRequest(t, map[string][]string{"Authorization": {"panda"}}, nil, nil, ""),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid authorization header","reason":"InternalError","details":{"causes":[{"message":"invalid authorization header"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "missing user",
			request:        newRequest(t, map[string][]string{}, nil, nil, ""),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid user","reason":"InternalError","details":{"causes":[{"message":"invalid user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name:           "unexpected UID",
			request:        newRequest(t, map[string][]string{}, &user.DefaultInfo{UID: "007"}, nil, ""),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user but missing audit event",
			request: func() *http.Request {
				req := newRequest(t, map[string][]string{
					"User-Agent":   {"test-user-agent"},
					"Connection":   {"Upgrade"},
					"Upgrade":      {"some-upgrade"},
					"Other-Header": {"test-header-value-1"},
				}, &user.DefaultInfo{
					Name:   testUser,
					Groups: testGroups,
					Extra:  testExtra,
				}, nil, "")
				ctx := request.WithAuditEvent(req.Context(), nil)
				req = req.WithContext(ctx)
				return req
			}(),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: invalid audit event","reason":"InternalError","details":{"causes":[{"message":"invalid audit event"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with upper case extra",
			request: newRequest(t, map[string][]string{
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
			}, nil, ""),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with upper case extra across multiple lines",
			request: newRequest(t, map[string][]string{
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
			}, nil, ""),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with reserved extra key",
			request: newRequest(t, map[string][]string{
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
			}, nil, ""),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with UID but no bearer token",
			request: newRequest(t, map[string][]string{
				"User-Agent":     {"test-user-agent"},
				"Connection":     {"Upgrade"},
				"Upgrade":        {"some-upgrade"},
				"Content-Type":   {"some-type"},
				"Content-Length": {"some-length"},
				"Other-Header":   {"test-header-value-1"},
			}, &user.DefaultInfo{
				UID: "-", // anything non-empty, rest of the fields get ignored in this code path
			},
				&auditinternal.Event{
					User: authenticationv1.UserInfo{
						Username: testUser,
						UID:      "fancy-uid",
						Groups:   testGroups,
						Extra: map[string]authenticationv1.ExtraValue{
							"extra-1": {"some", "extra", "stuff"},
							"extra-2": {"some", "more", "extra", "stuff"},
						},
					},
					ImpersonatedUser: nil,
				},
				"",
			),
			authenticator:  nil,
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with UID and bearer token and nested impersonation",
			request: newRequest(t, map[string][]string{
				"User-Agent":     {"test-user-agent"},
				"Connection":     {"Upgrade"},
				"Upgrade":        {"some-upgrade"},
				"Content-Type":   {"some-type"},
				"Content-Length": {"some-length"},
				"Other-Header":   {"test-header-value-1"},
			}, &user.DefaultInfo{
				UID: "-", // anything non-empty, rest of the fields get ignored in this code path
			},
				&auditinternal.Event{
					User: authenticationv1.UserInfo{
						Username: "dude",
						UID:      "--1--",
						Groups:   []string{"--a--", "--b--"},
						Extra: map[string]authenticationv1.ExtraValue{
							"--c--": {"--d--"},
							"--e--": {"--f--"},
						},
					},
					ImpersonatedUser: &authenticationv1.UserInfo{},
				},
				"token-from-user-nested",
			),
			authenticator:  nil,
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with UID and bearer token results in error",
			request: newRequest(t, map[string][]string{
				"User-Agent":     {"test-user-agent"},
				"Connection":     {"Upgrade"},
				"Upgrade":        {"some-upgrade"},
				"Content-Type":   {"some-type"},
				"Content-Length": {"some-length"},
				"Other-Header":   {"test-header-value-1"},
			}, &user.DefaultInfo{
				UID: "-", // anything non-empty, rest of the fields get ignored in this code path
			},
				&auditinternal.Event{
					User: authenticationv1.UserInfo{
						Username: "dude",
						UID:      "--1--",
						Groups:   []string{"--a--", "--b--"},
						Extra: map[string]authenticationv1.ExtraValue{
							"--c--": {"--d--"},
							"--e--": {"--f--"},
						},
					},
					ImpersonatedUser: nil,
				},
				"some-non-empty-token",
			),
			authenticator:  testTokenAuthenticator(t, "", nil, constable.Error("some err")),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with UID and bearer token does not authenticate",
			request: newRequest(t, map[string][]string{
				"User-Agent":     {"test-user-agent"},
				"Connection":     {"Upgrade"},
				"Upgrade":        {"some-upgrade"},
				"Content-Type":   {"some-type"},
				"Content-Length": {"some-length"},
				"Other-Header":   {"test-header-value-1"},
			}, &user.DefaultInfo{
				UID: "-", // anything non-empty, rest of the fields get ignored in this code path
			},
				&auditinternal.Event{
					User: authenticationv1.UserInfo{
						Username: "dude",
						UID:      "--1--",
						Groups:   []string{"--a--", "--b--"},
						Extra: map[string]authenticationv1.ExtraValue{
							"--c--": {"--d--"},
							"--e--": {"--f--"},
						},
					},
					ImpersonatedUser: nil,
				},
				"this-token-does-not-work",
			),
			authenticator:  testTokenAuthenticator(t, "some-other-token-works", nil, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		{
			name: "authenticated user with UID and bearer token authenticates as different user",
			request: newRequest(t, map[string][]string{
				"User-Agent":     {"test-user-agent"},
				"Connection":     {"Upgrade"},
				"Upgrade":        {"some-upgrade"},
				"Content-Type":   {"some-type"},
				"Content-Length": {"some-length"},
				"Other-Header":   {"test-header-value-1"},
			}, &user.DefaultInfo{
				UID: "-", // anything non-empty, rest of the fields get ignored in this code path
			},
				&auditinternal.Event{
					User: authenticationv1.UserInfo{
						Username: "dude",
						UID:      "--1--",
						Groups:   []string{"--a--", "--b--"},
						Extra: map[string]authenticationv1.ExtraValue{
							"--c--": {"--d--"},
							"--e--": {"--f--"},
						},
					},
					ImpersonatedUser: nil,
				},
				"this-token-does-work",
			),
			authenticator:  testTokenAuthenticator(t, "this-token-does-work", &user.DefaultInfo{Name: "someone-else"}, nil),
			wantHTTPBody:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Internal error occurred: unimplemented functionality - unable to act as current user","reason":"InternalError","details":{"causes":[{"message":"unimplemented functionality - unable to act as current user"}]},"code":500}` + "\n",
			wantHTTPStatus: http.StatusInternalServerError,
		},
		// happy path
		{
			name: "authenticated user",
			request: newRequest(t, map[string][]string{
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
			}, nil, ""),
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
			name: "authenticated user with UID and bearer token",
			request: newRequest(t, map[string][]string{
				"User-Agent":      {"test-user-agent"},
				"Accept":          {"some-accepted-format"},
				"Accept-Encoding": {"some-accepted-encoding"},
				"Connection":      {"Upgrade"},
				"Upgrade":         {"some-upgrade"},
				"Content-Type":    {"some-type"},
				"Content-Length":  {"some-length"},
				"Other-Header":    {"test-header-value-1"},
			}, &user.DefaultInfo{
				UID: "-", // anything non-empty, rest of the fields get ignored in this code path
			},
				&auditinternal.Event{
					User: authenticationv1.UserInfo{
						Username: testUser,
						UID:      "fancy-uid",
						Groups:   testGroups,
						Extra: map[string]authenticationv1.ExtraValue{
							"extra-1": {"some", "extra", "stuff"},
							"extra-2": {"some", "more", "extra", "stuff"},
						},
					},
					ImpersonatedUser: nil,
				},
				"token-from-user",
			),
			authenticator: testTokenAuthenticator(
				t,
				"token-from-user",
				&user.DefaultInfo{
					Name:   testUser,
					UID:    "fancy-uid",
					Groups: testGroups,
					Extra:  testExtra,
				},
				nil,
			),
			wantKubeAPIServerRequestHeaders: map[string][]string{
				"Authorization":   {"Bearer token-from-user"},
				"User-Agent":      {"test-user-agent"},
				"Accept":          {"some-accepted-format"},
				"Accept-Encoding": {"some-accepted-encoding"},
				"Connection":      {"Upgrade"},
				"Upgrade":         {"some-upgrade"},
				"Content-Type":    {"some-type"},
				"Other-Header":    {"test-header-value-1"},
			},
			wantHTTPBody:   "successful proxied response",
			wantHTTPStatus: http.StatusOK,
		},
		{
			name: "authenticated gke user",
			request: newRequest(t, map[string][]string{
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
			}, nil, ""),
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
			request: newRequest(t, map[string][]string{
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
			}, nil, ""),
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
			request: newRequest(t, map[string][]string{
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
			}, nil, ""),
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
			request: newRequest(t, map[string][]string{
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
				"",
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
			request: newRequest(t, map[string][]string{
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
				"",
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
			request: newRequest(t, map[string][]string{
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
				"",
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
			request: newRequest(t, map[string][]string{
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
				"",
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
			request: newRequest(t, map[string][]string{
				"User-Agent": {"test-user-agent"},
			}, &user.DefaultInfo{
				Name:   testUser,
				Groups: testGroups,
				Extra:  testExtra,
			}, nil, ""),
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
			serverConfig.Authentication.Authenticator = tt.authenticator

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

func newRequest(t *testing.T, h http.Header, userInfo user.Info, event *auditinternal.Event, token string) *http.Request {
	t.Helper()

	validURL, err := url.Parse("http://pinniped.dev/blah")
	require.NoError(t, err)

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

	ctx = authenticator.WithAudiences(ctx, authenticator.Audiences{"must-be-ignored"})

	if len(token) != 0 {
		ctx = context.WithValue(ctx, tokenKey, token)
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithDeadline(ctx, time.Now().Add(time.Hour))
	t.Cleanup(cancel)

	r, err := http.NewRequestWithContext(ctx, http.MethodGet, validURL.String(), nil)
	require.NoError(t, err)

	r.Header = h

	return r
}

func testTokenAuthenticator(t *testing.T, token string, userInfo user.Info, err error) authenticator.Request {
	t.Helper()

	return authenticator.RequestFunc(func(r *http.Request) (*authenticator.Response, bool, error) {
		if auds, ok := authenticator.AudiencesFrom(r.Context()); ok || len(auds) != 0 {
			t.Errorf("unexpected audiences on request: %v", auds)
		}

		if ctxToken := tokenFrom(r.Context()); len(ctxToken) != 0 {
			t.Errorf("unexpected token on request: %v", ctxToken)
		}

		if _, ok := r.Context().Deadline(); !ok {
			t.Error("request should always have deadline")
		}

		if err != nil {
			return nil, false, err
		}

		var reqToken string
		_, _, _ = bearertoken.New(authenticator.TokenFunc(func(_ context.Context, token string) (*authenticator.Response, bool, error) {
			reqToken = token
			return nil, false, nil
		})).AuthenticateRequest(r)

		if reqToken != token {
			return nil, false, nil
		}

		return &authenticator.Response{User: userInfo}, true, nil
	})
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

func Test_withBearerTokenPreservation(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
	}{
		{
			name: "has bearer token",
			headers: map[string][]string{
				"Authorization": {"Bearer thingy"},
			},
			want: "thingy",
		},
		{
			name: "has bearer token but too many preceding spaces",
			headers: map[string][]string{
				"Authorization": {"Bearer      1"},
			},
			want: "",
		},
		{
			name: "has bearer token with space, only keeps first part",
			headers: map[string][]string{
				"Authorization": {"Bearer panda man"},
			},
			want: "panda",
		},
		{
			name: "has bearer token with surrounding whitespace",
			headers: map[string][]string{
				"Authorization": {"   Bearer cool   beans  "},
			},
			want: "cool",
		},
		{
			name: "has multiple bearer tokens",
			headers: map[string][]string{
				"Authorization": {"Bearer this thing", "what does this mean?"},
			},
			want: "this",
		},
		{
			name: "no bearer token",
			headers: map[string][]string{
				"Not-Authorization": {"Bearer not a token"},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			inputReq := (&http.Request{Header: tt.headers}).WithContext(context.Background())
			inputReqCopy := inputReq.Clone(inputReq.Context())

			var called bool
			delegate := http.HandlerFunc(func(w http.ResponseWriter, outputReq *http.Request) {
				called = true
				require.Nil(t, w)

				// assert only context is mutated
				outputReqCopy := outputReq.Clone(inputReq.Context())
				require.Equal(t, inputReqCopy, outputReqCopy)

				require.Equal(t, tt.want, tokenFrom(outputReq.Context()))

				if len(tt.want) == 0 {
					require.True(t, inputReq == outputReq, "expect req to passed through when no token expected")
				}
			})

			withBearerTokenPreservation(delegate).ServeHTTP(nil, inputReq)
			require.Equal(t, inputReqCopy, inputReq) // assert no mutation occurred
			require.True(t, called)
		})
	}
}

type attributeRecorder struct {
	lock       sync.Mutex
	attributes []authorizer.AttributesRecord
}

func (r *attributeRecorder) record(attributes authorizer.Attributes) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.attributes = append(r.attributes, *attributes.(*authorizer.AttributesRecord))
}
