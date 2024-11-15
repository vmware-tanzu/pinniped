// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/test/testlib"
)

// kubeClientWithoutPinnipedAPISuffix is much like testlib.NewKubernetesClientset but does not
// use middleware to change the Pinniped API suffix (kubeclient.WithMiddleware).
//
// The returned kubeclient is only for interacting with K8s-native objects, not Pinniped objects,
// so it does not need to be aware of Pinniped's API suffix.
func kubeClientWithoutPinnipedAPISuffix(t *testing.T) kubernetes.Interface {
	t.Helper()

	client, err := kubeclient.New(kubeclient.WithConfig(testlib.NewClientConfig(t)))
	require.NoError(t, err)

	return client.Kubernetes
}

func TestAuditLogsEmittedForDiscoveryEndpoints_Parallel(t *testing.T) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelFunc()

	env, kubeClientForK8sResourcesOnly, fakeIssuerForDisplayPurposes, ca, dnsOverrides := auditSetup(t, ctx)

	startTime := metav1.Now()
	//nolint:bodyclose // this is closed in the helper function
	_, _, auditID := requireSuccessEndpointResponse(
		t,
		fakeIssuerForDisplayPurposes.Issuer()+"/.well-known/openid-configuration",
		fakeIssuerForDisplayPurposes.Issuer(),
		ca.Bundle(),
		dnsOverrides,
	)

	allSupervisorPodLogsWithAuditID := getAuditLogsForAuditID(
		t,
		ctx,
		auditID,
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		startTime,
	)

	require.Equal(t, 2, len(allSupervisorPodLogsWithAuditID),
		"expected exactly two log lines with auditID=%s", auditID)

	require.Equal(t, []map[string]any{
		{
			"message":    "HTTP Request Received",
			"proto":      "HTTP/1.1",
			"method":     "GET",
			"host":       fakeIssuerForDisplayPurposes.Address(),
			"serverName": fakeIssuerForDisplayPurposes.Address(),
			"path":       "/federation/domain/for/auditing/.well-known/openid-configuration",
		},
		{
			"message":        "HTTP Request Completed",
			"path":           "/federation/domain/for/auditing/.well-known/openid-configuration",
			"responseStatus": float64(200),
			"location":       "no location header",
		},
	}, allSupervisorPodLogsWithAuditID)
}

// Certain endpoints will log their parameters with an "HTTP Request Parameters" audit event,
// although most values are redacted. This test sets up a failing call to each of the following:
// /oauth2/authorize, /callback, /login, and /oauth2/token.
func TestAuditLogsEmittedForEndpointsEvenWhenTheCallsAreInvalid_Parallel(t *testing.T) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelFunc()

	env, kubeClientForK8sResourcesOnly, fakeIssuerForDisplayPurposes, ca, dnsOverrides := auditSetup(t, ctx)

	// Call the /oauth2/authorize endpoint
	startTime := metav1.Now()
	//nolint:bodyclose // this is closed in the helper function
	_, _, auditID := requireEndpointResponse(
		t,
		fakeIssuerForDisplayPurposes.Issuer()+"/oauth2/authorize?foo=bar&foo=bar&scope=safe-to-log",
		fakeIssuerForDisplayPurposes.Issuer(),
		ca.Bundle(),
		dnsOverrides,
		http.StatusBadRequest,
	)

	allSupervisorPodLogsWithAuditID := getAuditLogsForAuditID(
		t,
		ctx,
		auditID,
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		startTime,
	)

	require.Equal(t, []map[string]any{
		{
			"message":    "HTTP Request Received",
			"proto":      "HTTP/1.1",
			"method":     "GET",
			"host":       fakeIssuerForDisplayPurposes.Address(),
			"serverName": fakeIssuerForDisplayPurposes.Address(),
			"path":       "/federation/domain/for/auditing/oauth2/authorize",
		},
		{
			"message": "HTTP Request Parameters",
			"multiValueParams": map[string]any{
				"foo": []any{"redacted", "redacted"},
			},
			"params": map[string]any{
				"scope": "safe-to-log",
				"foo":   "redacted",
			},
		},
		{
			"message":           "HTTP Request Custom Headers Used",
			"Pinniped-Password": false,
			"Pinniped-Username": false,
		},
		{
			"message":        "HTTP Request Completed",
			"path":           "/federation/domain/for/auditing/oauth2/authorize",
			"responseStatus": float64(http.StatusBadRequest),
			"location":       "no location header",
		},
	}, allSupervisorPodLogsWithAuditID)

	// Call the /callback endpoint
	startTime = metav1.Now()
	//nolint:bodyclose // this is closed in the helper function
	_, _, auditID = requireEndpointResponse(
		t,
		fakeIssuerForDisplayPurposes.Issuer()+"/callback?foo=bar&foo=bar&error=safe-to-log",
		fakeIssuerForDisplayPurposes.Issuer(),
		ca.Bundle(),
		dnsOverrides,
		http.StatusForbidden,
	)

	allSupervisorPodLogsWithAuditID = getAuditLogsForAuditID(
		t,
		ctx,
		auditID,
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		startTime,
	)

	require.Equal(t, []map[string]any{
		{
			"message":    "HTTP Request Received",
			"proto":      "HTTP/1.1",
			"method":     "GET",
			"host":       fakeIssuerForDisplayPurposes.Address(),
			"serverName": fakeIssuerForDisplayPurposes.Address(),
			"path":       "/federation/domain/for/auditing/callback",
		},
		{
			"message": "HTTP Request Parameters",
			"multiValueParams": map[string]any{
				"foo": []any{"redacted", "redacted"},
			},
			"params": map[string]any{
				"error": "safe-to-log",
				"foo":   "redacted",
			},
		},
		{
			"message":        "HTTP Request Completed",
			"path":           "/federation/domain/for/auditing/callback",
			"responseStatus": float64(http.StatusForbidden),
			"location":       "no location header",
		},
	}, allSupervisorPodLogsWithAuditID)

	// Call the /login endpoint
	startTime = metav1.Now()
	//nolint:bodyclose // this is closed in the helper function
	_, _, auditID = requireEndpointResponse(
		t,
		fakeIssuerForDisplayPurposes.Issuer()+"/login?foo=bar&foo=bar&err=safe-to-log",
		fakeIssuerForDisplayPurposes.Issuer(),
		ca.Bundle(),
		dnsOverrides,
		http.StatusForbidden,
	)

	allSupervisorPodLogsWithAuditID = getAuditLogsForAuditID(
		t,
		ctx,
		auditID,
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		startTime,
	)

	require.Equal(t, []map[string]any{
		{
			"message":    "HTTP Request Received",
			"proto":      "HTTP/1.1",
			"method":     "GET",
			"host":       fakeIssuerForDisplayPurposes.Address(),
			"serverName": fakeIssuerForDisplayPurposes.Address(),
			"path":       "/federation/domain/for/auditing/login",
		},
		{
			"message": "HTTP Request Parameters",
			"multiValueParams": map[string]any{
				"foo": []any{"redacted", "redacted"},
			},
			"params": map[string]any{
				"err": "safe-to-log",
				"foo": "redacted",
			},
		},
		{
			"message":        "HTTP Request Completed",
			"path":           "/federation/domain/for/auditing/login",
			"responseStatus": float64(http.StatusForbidden),
			"location":       "no location header",
		},
	}, allSupervisorPodLogsWithAuditID)

	// Call the /oauth2/token endpoint
	startTime = metav1.Now()
	//nolint:bodyclose // this is closed in the helper function
	_, _, auditID = requireEndpointResponse(
		t,
		fakeIssuerForDisplayPurposes.Issuer()+"/oauth2/token?foo=bar&foo=bar&grant_type=safe-to-log",
		fakeIssuerForDisplayPurposes.Issuer(),
		ca.Bundle(),
		dnsOverrides,
		http.StatusBadRequest,
	)

	allSupervisorPodLogsWithAuditID = getAuditLogsForAuditID(
		t,
		ctx,
		auditID,
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		startTime,
	)

	require.Equal(t, []map[string]any{
		{
			"message":    "HTTP Request Received",
			"proto":      "HTTP/1.1",
			"method":     "GET",
			"host":       fakeIssuerForDisplayPurposes.Address(),
			"serverName": fakeIssuerForDisplayPurposes.Address(),
			"path":       "/federation/domain/for/auditing/oauth2/token",
		},
		{
			"message": "HTTP Request Parameters",
			"multiValueParams": map[string]any{
				"foo": []any{"redacted", "redacted"},
			},
			"params": map[string]any{
				"grant_type": "safe-to-log",
				"foo":        "redacted",
			},
		},
		{
			"message":        "HTTP Request Completed",
			"path":           "/federation/domain/for/auditing/oauth2/token",
			"responseStatus": float64(http.StatusBadRequest),
			"location":       "no location header",
		},
	}, allSupervisorPodLogsWithAuditID)
}

func auditSetup(t *testing.T, ctx context.Context) (
	*testlib.TestEnv,
	kubernetes.Interface,
	*testlib.SupervisorIssuer,
	*certauthority.CA,
	map[string]string,
) {
	env := testlib.IntegrationEnv(t).WithKubeDistribution(testlib.KindDistro)

	kubeClientForK8sResourcesOnly := kubeClientWithoutPinnipedAPISuffix(t)

	// Use a unique hostname so that it won't interfere with any other FederationDomain,
	// which means this test can be run in _Parallel.
	fakeHostname := "pinniped-" + strings.ToLower(testlib.RandHex(t, 8)) + ".example.com"
	fakeIssuerForDisplayPurposes := testlib.NewSupervisorIssuer(t, "https://"+fakeHostname+"/federation/domain/for/auditing")

	// Generate a CA bundle with which to serve this provider.
	t.Logf("generating test CA")
	tlsServingCertForSupervisorSecretName := "federation-domain-serving-cert-" + testlib.RandHex(t, 8)

	ca := createTLSServingCertSecretForSupervisor(
		ctx,
		t,
		env,
		fakeIssuerForDisplayPurposes,
		tlsServingCertForSupervisorSecretName,
		kubeClientForK8sResourcesOnly,
	)

	// Create any IDP so that any FederationDomain created later by this test will see that exactly one IDP exists.
	idp := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
		Issuer: "https://example.cluster.local/fake-issuer-url-does-not-matter",
		Client: idpv1alpha1.OIDCClient{SecretName: "this-will-not-exist-but-does-not-matter"},
	}, idpv1alpha1.PhaseError)

	_ = testlib.CreateTestFederationDomain(ctx, t,
		supervisorconfigv1alpha1.FederationDomainSpec{
			Issuer: fakeIssuerForDisplayPurposes.Issuer(),
			TLS: &supervisorconfigv1alpha1.FederationDomainTLSSpec{
				SecretName: tlsServingCertForSupervisorSecretName,
			},
			IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
				{
					DisplayName: idp.GetName(),
					ObjectRef: corev1.TypedLocalObjectReference{
						APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
						Kind:     "OIDCIdentityProvider",
						Name:     idp.GetName(),
					},
				},
			},
		},
		supervisorconfigv1alpha1.FederationDomainPhaseReady,
	)

	// hostname and port WITHOUT SCHEME for direct access to the supervisor's port 8443
	physicalAddress := testlib.NewSupervisorIssuer(t, env.SupervisorHTTPSAddress).Address()

	dnsOverrides := map[string]string{
		fakeHostname + ":443": physicalAddress,
	}
	return env, kubeClientForK8sResourcesOnly, fakeIssuerForDisplayPurposes, ca, dnsOverrides
}

func cleanupAuditLog(t *testing.T, m *map[string]any, auditID string) {
	delete(*m, "caller")
	delete(*m, "remoteAddr")
	delete(*m, "userAgent")
	delete(*m, "timestamp")
	delete(*m, "latency")
	require.Equal(t, (*m)["level"], "info")
	delete(*m, "level")
	require.Equal(t, (*m)["auditEvent"], true)
	delete(*m, "auditEvent")
	require.Equal(t, (*m)["auditID"], auditID)
	delete(*m, "auditID")
}

func getAuditLogsForAuditID(
	t *testing.T,
	ctx context.Context,
	auditID string,
	kubeClient kubernetes.Interface,
	namespace string,
	appName string,
	startTime metav1.Time,
) []map[string]any {
	t.Helper()

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{
			"app": appName,
		}.String(),
	})
	require.NoError(t, err)

	var allPodLogsBuffer bytes.Buffer
	for _, pod := range pods.Items {
		_, err = io.Copy(&allPodLogsBuffer, getLogsForPodSince(t, ctx, kubeClient, pod, startTime))
		require.NoError(t, err)
	}

	allPodLogs := strings.Split(allPodLogsBuffer.String(), "\n")
	var allPodLogsWithAuditID []map[string]any
	for _, podLog := range allPodLogs {
		if strings.Contains(podLog, auditID) {
			var deserialized map[string]any
			err = json.Unmarshal([]byte(podLog), &deserialized)
			require.NoError(t, err)
			cleanupAuditLog(t, &deserialized, auditID)

			allPodLogsWithAuditID = append(allPodLogsWithAuditID, deserialized)
		}
	}

	return allPodLogsWithAuditID
}

func getLogsForPodSince(
	t *testing.T,
	ctx context.Context,
	kubeClient kubernetes.Interface,
	pod corev1.Pod,
	startTime metav1.Time,
) *bytes.Buffer {
	t.Helper()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req := kubeClient.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
		SinceTime: &startTime,
	})
	body, err := req.Stream(ctx)
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = io.Copy(&buf, body)
	require.NoError(t, err)
	require.NoError(t, body.Close())

	return &buf
}
