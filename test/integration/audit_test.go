// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/auditevent"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/config/concierge"
	"go.pinniped.dev/internal/config/supervisor"
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

// TestAuditLogsDuringLogin is an end-to-end login test which cares more about making audit log
// assertions than assertions about the login itself. Much of how this test performs a login was
// inspired by a test case from TestE2EFullIntegration_Browser. This test is Disruptive because
// it restarts the Supervisor and Concierge to reconfigure audit logging, and then restarts them
// again to put back the original configuration.
func TestAuditLogsDuringLogin_Disruptive(t *testing.T) {
	env := testEnvForPodShutdownTests(t)

	testStartTime := metav1.Now()

	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelFunc()

	kubeClient := testlib.NewKubernetesClientset(t)
	kubeClientForK8sResourcesOnly := kubeClientWithoutPinnipedAPISuffix(t)

	// Build pinniped CLI.
	pinnipedExe := testlib.PinnipedCLIPath(t)

	supervisorIssuer := env.InferSupervisorIssuerURL(t)

	// Generate a CA bundle with which to serve this provider.
	t.Logf("generating test CA")
	tlsServingCertForSupervisorSecretName := "federation-domain-serving-cert-" + testlib.RandHex(t, 8)

	federationDomainSelfSignedCA := createTLSServingCertSecretForSupervisor(
		ctx,
		t,
		env,
		supervisorIssuer,
		tlsServingCertForSupervisorSecretName,
		kubeClient,
	)

	// Save that bundle plus the one that signs the upstream issuer, for test purposes.
	federationDomainCABundlePath := filepath.Join(t.TempDir(), "test-ca.pem")
	federationDomainCABundlePEM := federationDomainSelfSignedCA.Bundle()
	require.NoError(t, os.WriteFile(federationDomainCABundlePath, federationDomainCABundlePEM, 0600))

	// Create the downstream FederationDomain.
	// This helper function will nil out spec.TLS if spec.Issuer is an IP address.
	federationDomain := testlib.CreateTestFederationDomain(ctx, t,
		supervisorconfigv1alpha1.FederationDomainSpec{
			Issuer: supervisorIssuer.Issuer(),
			TLS:    &supervisorconfigv1alpha1.FederationDomainTLSSpec{SecretName: tlsServingCertForSupervisorSecretName},
		},
		supervisorconfigv1alpha1.FederationDomainPhaseError, // in phase error until there is an IDP created
	)

	expectedUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
	expectedGroups := make([]any, len(env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs))
	for i, g := range env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs {
		expectedGroups[i] = g
	}

	// Create a JWTAuthenticator that will validate the tokens from the downstream issuer.
	// If the FederationDomain is not Ready, the JWTAuthenticator cannot be ready, either.
	clusterAudience := "test-cluster-" + testlib.RandHex(t, 8)
	defaultJWTAuthenticatorSpec := authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   federationDomain.Spec.Issuer,
		Audience: clusterAudience,
		TLS:      &authenticationv1alpha1.TLSSpec{CertificateAuthorityData: base64.StdEncoding.EncodeToString(federationDomainCABundlePEM)},
	}
	authenticator := testlib.CreateTestJWTAuthenticator(ctx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
	setupClusterForEndToEndLDAPTest(t, expectedUsername, env)
	testlib.WaitForFederationDomainStatusPhase(ctx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
	testlib.WaitForJWTAuthenticatorStatusPhase(ctx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

	tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests
	// Use a specific session cache for this test.
	sessionCachePath := tempDir + "/test-sessions.yaml"
	credentialCachePath := tempDir + "/test-credentials.yaml"

	kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
		"get", "kubeconfig",
		"--concierge-api-group-suffix", env.APIGroupSuffix,
		"--concierge-authenticator-type", "jwt",
		"--concierge-authenticator-name", authenticator.Name,
		"--oidc-session-cache", sessionCachePath,
		"--credential-cache", credentialCachePath,
		// use default for --oidc-scopes, which is to request all relevant scopes
	})

	t.Setenv("PINNIPED_USERNAME", expectedUsername)
	t.Setenv("PINNIPED_PASSWORD", env.SupervisorUpstreamLDAP.TestUserPassword)

	timeBeforeLogin := metav1.Now()

	// Run kubectl command which should run an LDAP-style login without interactive prompts for username and password.
	kubectlCmd := exec.CommandContext(ctx, "kubectl", "auth", "whoami", "--kubeconfig", kubeconfigPath)
	kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
	kubectlOutput, err := kubectlCmd.CombinedOutput()
	require.NoErrorf(t, err,
		"expected no error but got error, combined stdout/stderr was:\n----start of output\n%s\n----end of output", kubectlOutput)

	allSupervisorSessionStartedLogs := getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["message"] == string(auditevent.SessionStarted)
		},
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		timeBeforeLogin,
	)
	removeSomeKeysFromEachAuditLogEvent(allSupervisorSessionStartedLogs)
	// Also remove sessionID, which is a UUID that we can't predict for the assertions below.
	for _, log := range allSupervisorSessionStartedLogs {
		require.NotEmpty(t, log["sessionID"])
		delete(log, "sessionID")
	}

	// All values in the personalInfo map should be redacted by default.
	require.Equal(t, []map[string]any{
		{
			"message": "Session Started",
			"personalInfo": map[string]any{
				"username":         "redacted",
				"groups":           []any{"redacted 2 values"},
				"subject":          "redacted",
				"additionalClaims": map[string]any{"redacted": "redacted 0 keys"},
			},
			"warnings": []any{},
		},
	}, allSupervisorSessionStartedLogs)

	allConciergeTCRLogs := getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["message"] == string(auditevent.TokenCredentialRequestAuthenticatedUser)
		},
		kubeClientForK8sResourcesOnly,
		env.ConciergeNamespace,
		env.ConciergeAppName,
		timeBeforeLogin,
	)
	removeSomeKeysFromEachAuditLogEvent(allConciergeTCRLogs)
	// Also remove issuedClientCertExpires, which is a timestamp that we can't easily predict for the assertions below.
	for _, log := range allConciergeTCRLogs {
		require.NotEmpty(t, log["issuedClientCertExpires"])
		delete(log, "issuedClientCertExpires")
	}

	// All values in the personalInfo map should be redacted by default.
	require.Equal(t, []map[string]any{
		{
			"message": "TokenCredentialRequest Authenticated User",
			"authenticator": map[string]any{
				// this always pinniped.dev even when the API group suffix was customized because of the way that the production code works
				"apiGroup": "authentication.concierge.pinniped.dev",
				"kind":     "JWTAuthenticator",
				"name":     authenticator.Name,
			},
			"personalInfo": map[string]any{
				"username": "redacted",
				"groups":   []any{"redacted 2 values"},
			},
		},
	}, allConciergeTCRLogs)

	allSupervisorHealthzLogs := getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["path"] == "/healthz"
		},
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		testStartTime,
	)
	// There should be none, because /healthz audit logs are disabled by default.
	require.Empty(t, allSupervisorHealthzLogs)

	t.Log("updating Supervisor's static ConfigMap and restarting the pods")
	updateStaticConfigMapAndRestartApp(t,
		ctx,
		env.SupervisorNamespace,
		env.SupervisorAppName+"-static-config",
		env.SupervisorAppName,
		false,
		func(t *testing.T, configMapData string) string {
			t.Helper()

			var config supervisor.Config
			err := yaml.Unmarshal([]byte(configMapData), &config)
			require.NoError(t, err)

			// The Supervisor has two audit configuration options. Enable both.
			config.Audit.LogUsernamesAndGroups = "enabled"
			config.Audit.LogInternalPaths = "enabled"

			updatedConfig, err := yaml.Marshal(config)
			require.NoError(t, err)
			return string(updatedConfig)
		},
	)

	t.Log("updating Concierge's static ConfigMap and restarting the pods")
	updateStaticConfigMapAndRestartApp(t,
		ctx,
		env.ConciergeNamespace,
		env.ConciergeAppName+"-config",
		env.ConciergeAppName,
		true,
		func(t *testing.T, configMapData string) string {
			t.Helper()

			var config concierge.Config
			err := yaml.Unmarshal([]byte(configMapData), &config)
			require.NoError(t, err)

			// The Concierge has only one audit configuration option. Enable it.
			config.Audit.LogUsernamesAndGroups = "enabled"

			updatedConfig, err := yaml.Marshal(config)
			require.NoError(t, err)
			return string(updatedConfig)
		},
	)

	// Force a fresh login for the next kubectl command by removing the local caches.
	require.NoError(t, os.Remove(sessionCachePath))
	require.NoError(t, os.Remove(credentialCachePath))

	// Reset the start time before we do a second login.
	timeBeforeLogin = metav1.Now()

	// Do a second login, which should cause audit logs with non-redacted personal info.
	// Run kubectl command which should run an LDAP-style login without interactive prompts for username and password.
	kubectlCmd = exec.CommandContext(ctx, "kubectl", "auth", "whoami", "--kubeconfig", kubeconfigPath)
	kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
	kubectlOutput, err = kubectlCmd.CombinedOutput()
	require.NoErrorf(t, err,
		"expected no error but got error, combined stdout/stderr was:\n----start of output\n%s\n----end of output", kubectlOutput)

	allSupervisorSessionStartedLogs = getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["message"] == string(auditevent.SessionStarted)
		},
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		timeBeforeLogin,
	)
	removeSomeKeysFromEachAuditLogEvent(allSupervisorSessionStartedLogs)
	// Also remove sessionID, which is a UUID that we can't predict for the assertions below.
	for _, log := range allSupervisorSessionStartedLogs {
		require.NotEmpty(t, log["sessionID"])
		delete(log, "sessionID")
	}
	// Now that "subject" should not be redacted, remove it too because it also contains values that are hard to predict.
	for _, log := range allSupervisorSessionStartedLogs {
		p := log["personalInfo"].(map[string]any)
		require.NotEmpty(t, p)
		require.Contains(t, p["subject"], "ldaps://"+env.SupervisorUpstreamLDAP.Host+"?")
		delete(p, "subject")
	}

	// All values in the personalInfo map should not be redacted anymore.
	require.Equal(t, []map[string]any{
		{
			"message": "Session Started",
			"personalInfo": map[string]any{
				"username": expectedUsername,
				"groups":   expectedGroups,
				// note that we removed "subject" above
				"additionalClaims": map[string]any{},
			},
			"warnings": []any{},
		},
	}, allSupervisorSessionStartedLogs)

	allConciergeTCRLogs = getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["message"] == string(auditevent.TokenCredentialRequestAuthenticatedUser)
		},
		kubeClientForK8sResourcesOnly,
		env.ConciergeNamespace,
		env.ConciergeAppName,
		timeBeforeLogin,
	)
	removeSomeKeysFromEachAuditLogEvent(allConciergeTCRLogs)
	// Also remove issuedClientCertExpires, which is a timestamp that we can't easily predict for the assertions below.
	for _, log := range allConciergeTCRLogs {
		require.NotEmpty(t, log["issuedClientCertExpires"])
		delete(log, "issuedClientCertExpires")
	}

	// All values in the personalInfo map should not be redacted anymore.
	require.Equal(t, []map[string]any{
		{
			"message": "TokenCredentialRequest Authenticated User",
			"authenticator": map[string]any{
				"apiGroup": "authentication.concierge." + env.APIGroupSuffix,
				"kind":     "JWTAuthenticator",
				"name":     authenticator.Name,
			},
			"personalInfo": map[string]any{
				"username": expectedUsername,
				"groups":   expectedGroups,
			},
		},
	}, allConciergeTCRLogs)

	allSupervisorHealthzLogs = getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["path"] == "/healthz"
		},
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		testStartTime,
	)
	// There should be some, because we reconfigured the setting to enable them.
	t.Logf("saw %d audit logs where path=/healthz in Supervisor pod logs", len(allSupervisorHealthzLogs))
	require.NotEmpty(t, allSupervisorHealthzLogs)
}

func TestAuditLogsEmittedForDiscoveryEndpoints_Parallel(t *testing.T) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelFunc()

	env, kubeClientForK8sResourcesOnly, fakeIssuerForDisplayPurposes, ca, dnsOverrides := auditSetup(t, ctx)

	startTime := metav1.Now()
	//nolint:bodyclose // this is closed in the helper function
	_, _, auditID := requireSuccessEndpointResponse(t,
		fakeIssuerForDisplayPurposes.Issuer()+"/.well-known/openid-configuration",
		fakeIssuerForDisplayPurposes.Issuer(),
		ca.Bundle(),
		dnsOverrides,
	)

	allSupervisorPodLogsWithAuditID := getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["auditID"] == auditID
		},
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		startTime,
	)
	removeSomeKeysFromEachAuditLogEvent(allSupervisorPodLogsWithAuditID)

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
	_, _, auditID := requireEndpointResponse(t,
		fakeIssuerForDisplayPurposes.Issuer()+"/oauth2/authorize?foo=bar&foo=bar&scope=safe-to-log",
		fakeIssuerForDisplayPurposes.Issuer(),
		ca.Bundle(),
		dnsOverrides,
		http.StatusBadRequest,
	)

	allSupervisorPodLogsWithAuditID := getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["auditID"] == auditID
		},
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		startTime,
	)
	removeSomeKeysFromEachAuditLogEvent(allSupervisorPodLogsWithAuditID)

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
	_, _, auditID = requireEndpointResponse(t,
		fakeIssuerForDisplayPurposes.Issuer()+"/callback?foo=bar&foo=bar&error=safe-to-log",
		fakeIssuerForDisplayPurposes.Issuer(),
		ca.Bundle(),
		dnsOverrides,
		http.StatusForbidden,
	)

	allSupervisorPodLogsWithAuditID = getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["auditID"] == auditID
		},
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		startTime,
	)
	removeSomeKeysFromEachAuditLogEvent(allSupervisorPodLogsWithAuditID)

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
	_, _, auditID = requireEndpointResponse(t,
		fakeIssuerForDisplayPurposes.Issuer()+"/login?foo=bar&foo=bar&err=safe-to-log",
		fakeIssuerForDisplayPurposes.Issuer(),
		ca.Bundle(),
		dnsOverrides,
		http.StatusForbidden,
	)

	allSupervisorPodLogsWithAuditID = getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["auditID"] == auditID
		},
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		startTime,
	)
	removeSomeKeysFromEachAuditLogEvent(allSupervisorPodLogsWithAuditID)

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
	_, _, auditID = requireEndpointResponse(t,
		fakeIssuerForDisplayPurposes.Issuer()+"/oauth2/token?foo=bar&foo=bar&grant_type=safe-to-log",
		fakeIssuerForDisplayPurposes.Issuer(),
		ca.Bundle(),
		dnsOverrides,
		http.StatusBadRequest,
	)

	allSupervisorPodLogsWithAuditID = getFilteredAuditLogs(t, ctx,
		func(log map[string]any) bool {
			return log["auditID"] == auditID
		},
		kubeClientForK8sResourcesOnly,
		env.SupervisorNamespace,
		env.SupervisorAppName,
		startTime,
	)
	removeSomeKeysFromEachAuditLogEvent(allSupervisorPodLogsWithAuditID)

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

func removeSomeKeysFromEachAuditLogEvent(logs []map[string]any) {
	for _, log := range logs {
		delete(log, "level")
		delete(log, "auditEvent")
		delete(log, "caller")
		delete(log, "remoteAddr")
		delete(log, "userAgent")
		delete(log, "timestamp")
		delete(log, "latency")
		delete(log, "auditID")
	}
}

func getFilteredAuditLogs(
	t *testing.T,
	ctx context.Context,
	filterAuditLogEvent func(log map[string]any) bool,
	kubeClient kubernetes.Interface,
	namespace string,
	appName string,
	startTime metav1.Time,
) []map[string]any {
	t.Helper()

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{"app": appName}.String(),
	})
	require.NoError(t, err)

	var allPodLogsBuffer bytes.Buffer
	for _, pod := range pods.Items {
		_, err = io.Copy(&allPodLogsBuffer, getLogsForPodSince(t, ctx, kubeClient, pod, startTime))
		require.NoError(t, err)
	}

	allPodLogs := strings.Split(allPodLogsBuffer.String(), "\n")
	var filteredAuditLogs []map[string]any
	for _, podLog := range allPodLogs {
		if len(podLog) == 0 {
			continue
		}
		var deserializedPodLog map[string]any
		err = json.Unmarshal([]byte(podLog), &deserializedPodLog)
		require.NoErrorf(t, err, "error parsing line of pod log: %s", podLog)
		isAuditEventBool, hasAuditEvent := deserializedPodLog["auditEvent"]
		if hasAuditEvent {
			require.Equal(t, true, isAuditEventBool)
			require.Equal(t, "info", deserializedPodLog["level"])
		}
		if hasAuditEvent && filterAuditLogEvent(deserializedPodLog) {
			filteredAuditLogs = append(filteredAuditLogs, deserializedPodLog)
		}
	}

	return filteredAuditLogs
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
