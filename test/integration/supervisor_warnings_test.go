// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	authv1alpha "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/oidcclientvalidator"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
	"go.pinniped.dev/test/testlib"
	"go.pinniped.dev/test/testlib/browsertest"
)

func TestSupervisorWarnings_Browser(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelFunc()

	// Build pinniped CLI.
	pinnipedExe := testlib.PinnipedCLIPath(t)
	tempDir := testutil.TempDir(t)

	// Infer the downstream issuer URL from the callback associated with the upstream test client registration.
	issuerURL, err := url.Parse(env.SupervisorUpstreamOIDC.CallbackURL)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(issuerURL.Path, "/callback"))
	issuerURL.Path = strings.TrimSuffix(issuerURL.Path, "/callback")
	t.Logf("testing with downstream issuer URL %s", issuerURL.String())

	// Generate a CA bundle with which to serve this provider.
	t.Logf("generating test CA")
	ca, err := certauthority.New("Downstream Test CA", 1*time.Hour)
	require.NoError(t, err)

	// Save that bundle plus the one that signs the upstream issuer, for test purposes.
	testCABundlePath := filepath.Join(tempDir, "test-ca.pem")
	testCABundlePEM := []byte(string(ca.Bundle()) + "\n" + env.SupervisorUpstreamOIDC.CABundle)
	testCABundleBase64 := base64.StdEncoding.EncodeToString(testCABundlePEM)
	require.NoError(t, ioutil.WriteFile(testCABundlePath, testCABundlePEM, 0600))

	// Use the CA to issue a TLS server cert.
	t.Logf("issuing test certificate")
	tlsCert, err := ca.IssueServerCert([]string{issuerURL.Hostname()}, nil, 1*time.Hour)
	require.NoError(t, err)
	certPEM, keyPEM, err := certauthority.ToPEM(tlsCert)
	require.NoError(t, err)

	// Write the serving cert to a secret.
	certSecret := testlib.CreateTestSecret(t,
		env.SupervisorNamespace,
		"oidc-provider-tls",
		corev1.SecretTypeTLS,
		map[string]string{"tls.crt": string(certPEM), "tls.key": string(keyPEM)},
	)

	// Create the downstream FederationDomain and expect it to go into the success status condition.
	downstream := testlib.CreateTestFederationDomain(ctx, t,
		issuerURL.String(),
		certSecret.Name,
		configv1alpha1.SuccessFederationDomainStatusCondition,
	)

	// Create a JWTAuthenticator that will validate the tokens from the downstream issuer.
	clusterAudience := "test-cluster-" + testlib.RandHex(t, 8)
	authenticator := testlib.CreateTestJWTAuthenticator(ctx, t, authv1alpha.JWTAuthenticatorSpec{
		Issuer:   downstream.Spec.Issuer,
		Audience: clusterAudience,
		TLS:      &authv1alpha.TLSSpec{CertificateAuthorityData: testCABundleBase64},
	})

	const (
		yellowColor = "\u001b[33;1m"
		resetColor  = "\u001b[0m"
	)

	t.Run("LDAP group refresh flow", func(t *testing.T) {
		testlib.SkipTestWhenLDAPIsUnavailable(t, env)

		expectedUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue

		setupClusterForEndToEndLDAPTest(t, expectedUsername, env)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/ldap-test-refresh-sessions.yaml"
		credentialCachePath := tempDir + "/ldap-test-refresh-credentials.yaml"
		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			"--oidc-scopes", "offline_access,openid,pinniped:request-audience,groups",
		})

		// Run "kubectl get namespaces" which should trigger a cli-based login.
		start := time.Now()
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
		var kubectlStdoutPipe io.ReadCloser
		if runtime.GOOS != "darwin" {
			// For some unknown reason this breaks the pty library on some MacOS machines.
			// The problem doesn't reproduce for everyone, so this is just a workaround.
			kubectlStdoutPipe, err = kubectlCmd.StdoutPipe()
			require.NoError(t, err)
		}
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the username prompt, then type the user's username.
		readFromFileUntilStringIsSeen(t, ptyFile, "Username: ")
		_, err = ptyFile.WriteString(expectedUsername + "\n")
		require.NoError(t, err)

		// Wait for the subprocess to print the password prompt, then type the user's password.
		readFromFileUntilStringIsSeen(t, ptyFile, "Password: ")
		_, err = ptyFile.WriteString(env.SupervisorUpstreamLDAP.TestUserPassword + "\n")
		require.NoError(t, err)

		// Read all of the remaining output from the subprocess until EOF.
		t.Logf("waiting for kubectl to output namespace list")
		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlPtyOutputBytes, _ := ioutil.ReadAll(ptyFile)
		if kubectlStdoutPipe != nil {
			// On non-MacOS check that stdout of the CLI contains the expected output.
			kubectlStdOutOutputBytes, _ := ioutil.ReadAll(kubectlStdoutPipe)
			requireKubectlGetNamespaceOutput(t, env, string(kubectlStdOutOutputBytes))
		} else {
			// On MacOS check that the pty (stdout+stderr+stdin) of the CLI contains the expected output.
			requireKubectlGetNamespaceOutput(t, env, string(kubectlPtyOutputBytes))
		}

		t.Logf("first kubectl command took %s", time.Since(start).String())

		// To simulate the groups having changed without actually changing the groups the user belongs to in the LDAP
		// server, we update the refresh token secret to have a different value for the groups.
		// Then the refresh flow will update them back to their real values.
		// To do this, we get the refresh token signature out of the cache, use it to get the Secret, update it, and
		// put it back.
		cache := filesession.New(sessionCachePath, filesession.WithErrorReporter(func(err error) {
			require.NoError(t, err)
		}))

		// construct the cache key
		downstreamScopes := []string{"offline_access", "openid", "pinniped:request-audience", "groups"}
		sort.Strings(downstreamScopes)
		sessionCacheKey := oidcclient.SessionCacheKey{
			Issuer:      downstream.Spec.Issuer,
			ClientID:    "pinniped-cli",
			Scopes:      downstreamScopes,
			RedirectURI: "http://localhost:0/callback",
		}
		// use it to get the cache entry
		token := cache.GetToken(sessionCacheKey)
		require.NotNil(t, token)

		// using the refresh token signature contained in the cache, get the refresh token session
		// out of kube secret storage.
		supervisorSecretsClient := testlib.NewKubernetesClientset(t).CoreV1().Secrets(env.SupervisorNamespace)
		supervisorOIDCClientsClient := testlib.NewSupervisorClientset(t).ConfigV1alpha1().OIDCClients(env.SupervisorNamespace)
		oauthStore := oidc.NewKubeStorage(supervisorSecretsClient, supervisorOIDCClientsClient, oidc.DefaultOIDCTimeoutsConfiguration(), oidcclientvalidator.DefaultMinBcryptCost)
		refreshTokenSignature := strings.Split(token.RefreshToken.Token, ".")[1]
		storedRefreshSession, err := oauthStore.GetRefreshTokenSession(ctx, refreshTokenSignature, nil)
		require.NoError(t, err)

		// change the groups to simulate them changing in the IDP.
		pinnipedSession, ok := storedRefreshSession.GetSession().(*psession.PinnipedSession)
		require.True(t, ok, "should have been able to cast session data to PinnipedSession")
		pinnipedSession.Fosite.Claims.Extra["groups"] = []string{"some-wrong-group", "some-other-group"}

		require.NoError(t, oauthStore.DeleteRefreshTokenSession(ctx, refreshTokenSignature))
		require.NoError(t, oauthStore.CreateRefreshTokenSession(ctx, refreshTokenSignature, storedRefreshSession))

		// remove the credential cache, which includes the cached cert, so it won't be reused and the refresh flow will be triggered.
		err = os.Remove(credentialCachePath)
		require.NoError(t, err)

		// wait for the existing tokens to expire, triggering the refresh flow.
		ctx2, cancel2 := context.WithTimeout(ctx, 1*time.Minute)
		defer cancel2()

		// 	Run kubectl, which should work without any prompting for authentication.
		kubectlCmd2 := exec.CommandContext(ctx2, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd2.Env = append(os.Environ(), env.ProxyEnv()...)
		startTime2 := time.Now()
		var kubectlStdoutPipe2 io.ReadCloser
		if runtime.GOOS != "darwin" {
			// For some unknown reason this breaks the pty library on some MacOS machines.
			// The problem doesn't reproduce for everyone, so this is just a workaround.
			kubectlStdoutPipe2, err = kubectlCmd2.StdoutPipe()
			require.NoError(t, err)
		}
		ptyFile2, err := pty.Start(kubectlCmd2)
		require.NoError(t, err)

		// Read all of the remaining output from the subprocess until EOF.
		t.Logf("waiting for kubectl to output namespace list")
		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlPtyOutputBytes2, _ := ioutil.ReadAll(ptyFile2)
		if kubectlStdoutPipe2 != nil {
			// On non-MacOS check that stdout of the CLI contains the expected output.
			kubectlStdOutOutputBytes2, _ := ioutil.ReadAll(kubectlStdoutPipe2)
			requireKubectlGetNamespaceOutput(t, env, string(kubectlStdOutOutputBytes2))
		} else {
			// On MacOS check that the pty (stdout+stderr+stdin) of the CLI contains the expected output.
			requireKubectlGetNamespaceOutput(t, env, string(kubectlPtyOutputBytes2))
		}
		// the output should include a warning that the groups have changed.
		require.Contains(t, string(kubectlPtyOutputBytes2), fmt.Sprintf(`%sWarning:%s User %q has been added to the following groups: %q`+"\r\n", yellowColor, resetColor, env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs))
		require.Contains(t, string(kubectlPtyOutputBytes2), fmt.Sprintf(`%sWarning:%s User %q has been removed from the following groups: ["some-other-group" "some-wrong-group"]`+"\r\n", yellowColor, resetColor, env.SupervisorUpstreamLDAP.TestUserMailAttributeValue))

		t.Logf("second kubectl command took %s", time.Since(startTime2).String())
	})

	t.Run("Active Directory group refresh flow", func(t *testing.T) {
		testlib.SkipTestWhenActiveDirectoryIsUnavailable(t, env)

		expectedUsername, password := testlib.CreateFreshADTestUser(t, env)

		sAMAccountName := expectedUsername + "@" + env.SupervisorUpstreamActiveDirectory.Domain
		setupClusterForEndToEndActiveDirectoryTest(t, sAMAccountName, env)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/ldap-test-refresh-sessions.yaml"
		credentialCachePath := tempDir + "/ldap-test-refresh-credentials.yaml"
		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			"--oidc-scopes", "offline_access,openid,pinniped:request-audience,groups",
		})

		// Run "kubectl get namespaces" which should trigger a cli-based login.
		start := time.Now()
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
		var kubectlStdoutPipe io.ReadCloser
		if runtime.GOOS != "darwin" {
			// For some unknown reason this breaks the pty library on some MacOS machines.
			// The problem doesn't reproduce for everyone, so this is just a workaround.
			kubectlStdoutPipe, err = kubectlCmd.StdoutPipe()
			require.NoError(t, err)
		}
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the username prompt, then type the user's username.
		readFromFileUntilStringIsSeen(t, ptyFile, "Username: ")
		_, err = ptyFile.WriteString(expectedUsername + "\n")
		require.NoError(t, err)

		// Wait for the subprocess to print the password prompt, then type the user's password.
		readFromFileUntilStringIsSeen(t, ptyFile, "Password: ")
		_, err = ptyFile.WriteString(password + "\n")
		require.NoError(t, err)

		// Read all of the remaining output from the subprocess until EOF.
		t.Logf("waiting for kubectl to output namespace list")
		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlPtyOutputBytes, _ := ioutil.ReadAll(ptyFile)
		if kubectlStdoutPipe != nil {
			// On non-MacOS check that stdout of the CLI contains the expected output.
			kubectlStdOutOutputBytes, _ := ioutil.ReadAll(kubectlStdoutPipe)
			requireKubectlGetNamespaceOutput(t, env, string(kubectlStdOutOutputBytes))
		} else {
			// On MacOS check that the pty (stdout+stderr+stdin) of the CLI contains the expected output.
			requireKubectlGetNamespaceOutput(t, env, string(kubectlPtyOutputBytes))
		}

		t.Logf("first kubectl command took %s", time.Since(start).String())

		// create an active directory group, and add our user to it.
		groupName := testlib.CreateFreshADTestGroup(t, env)
		testlib.AddTestUserToGroup(t, env, groupName, expectedUsername)

		// remove the credential cache, which includes the cached cert, so it won't be reused and the refresh flow will be triggered.
		err = os.Remove(credentialCachePath)
		require.NoError(t, err)

		ctx2, cancel2 := context.WithTimeout(ctx, 1*time.Minute)
		defer cancel2()

		// Run kubectl, which should work without any prompting for authentication.
		kubectlCmd2 := exec.CommandContext(ctx2, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd2.Env = append(os.Environ(), env.ProxyEnv()...)
		startTime2 := time.Now()
		var kubectlStdoutPipe2 io.ReadCloser
		if runtime.GOOS != "darwin" {
			// For some unknown reason this breaks the pty library on some MacOS machines.
			// The problem doesn't reproduce for everyone, so this is just a workaround.
			kubectlStdoutPipe2, err = kubectlCmd2.StdoutPipe()
			require.NoError(t, err)
		}
		ptyFile2, err := pty.Start(kubectlCmd2)
		require.NoError(t, err)

		// Read all of the remaining output from the subprocess until EOF.
		t.Logf("waiting for kubectl to output namespace list")
		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlPtyOutputBytes2, _ := ioutil.ReadAll(ptyFile2)
		if kubectlStdoutPipe2 != nil {
			// On non-MacOS check that stdout of the CLI contains the expected output.
			kubectlStdOutOutputBytes2, _ := ioutil.ReadAll(kubectlStdoutPipe2)
			requireKubectlGetNamespaceOutput(t, env, string(kubectlStdOutOutputBytes2))
		} else {
			// On MacOS check that the pty (stdout+stderr+stdin) of the CLI contains the expected output.
			requireKubectlGetNamespaceOutput(t, env, string(kubectlPtyOutputBytes2))
		}
		// the output should include a warning that a group has been added.
		require.Contains(t, string(kubectlPtyOutputBytes2), fmt.Sprintf(`%sWarning:%s User %q has been added to the following groups: %q`+"\r\n", yellowColor, resetColor, sAMAccountName, []string{groupName + "@" + env.SupervisorUpstreamActiveDirectory.Domain}))
		// there should not be a warning about being removed from groups, since we haven't done so.
		require.NotContains(t, string(kubectlPtyOutputBytes2), "has been removed from")

		t.Logf("second kubectl command took %s", time.Since(startTime2).String())
	})

	t.Run("OIDC group refresh flow", func(t *testing.T) {
		if len(env.SupervisorUpstreamOIDC.ExpectedGroups) == 0 {
			t.Skip("Skipping OIDC group refresh test since there are no groups")
		}

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		page := browsertest.Open(t)

		expectedUsername := env.SupervisorUpstreamOIDC.Username

		// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
		testlib.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: expectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
		)
		testlib.WaitForUserToHaveAccess(t, expectedUsername, []string{}, &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		})

		// Create upstream OIDC provider and wait for it to become ready.
		testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorUpstreamOIDC.Issuer,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
			},
			AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes: env.SupervisorUpstreamOIDC.AdditionalScopes,
			},
			Claims: idpv1alpha1.OIDCClaims{
				Username: env.SupervisorUpstreamOIDC.UsernameClaim,
				Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
			},
			Client: idpv1alpha1.OIDCClient{
				SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}, idpv1alpha1.PhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/ldap-test-refresh-sessions.yaml"
		credentialCachePath := tempDir + "/ldap-test-refresh-credentials.yaml"
		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-skip-listen",
			"--oidc-ca-bundle", testCABundlePath,
			"--oidc-session-cache", sessionCachePath,
			"--oidc-scopes", "offline_access,openid,pinniped:request-audience,groups",
			"--credential-cache", credentialCachePath,
		})

		// Run "kubectl get namespaces" which should trigger a cli-based login.
		start := time.Now()
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
		var kubectlStdoutPipe io.ReadCloser
		if runtime.GOOS != "darwin" {
			// For some unknown reason this breaks the pty library on some MacOS machines.
			// The problem doesn't reproduce for everyone, so this is just a workaround.
			kubectlStdoutPipe, err = kubectlCmd.StdoutPipe()
			require.NoError(t, err)
		}
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the login prompt.
		t.Logf("waiting for CLI to output login URL and manual prompt")
		output := readFromFileUntilStringIsSeen(t, ptyFile, "Optionally, paste your authorization code: ")
		require.Contains(t, output, "Log in by visiting this link:")
		require.Contains(t, output, "Optionally, paste your authorization code: ")

		// Find the line with the login URL.
		var loginURL string
		for _, line := range strings.Split(output, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "https://") {
				loginURL = trimmed
			}
		}
		require.NotEmptyf(t, loginURL, "didn't find login URL in output: %s", output)

		t.Logf("navigating to login page")
		require.NoError(t, page.Navigate(loginURL))

		// Expect to be redirected to the upstream provider and log in.
		browsertest.LoginToUpstreamOIDC(t, page, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", downstream.Spec.Issuer)
		browsertest.WaitForURL(t, page, regexp.MustCompile(regexp.QuoteMeta(downstream.Spec.Issuer)))

		// The response page should have failed to automatically post, and should now be showing the manual instructions.
		authCode := formpostExpectManualState(t, page)

		// Enter the auth code in the waiting prompt, followed by a newline.
		t.Logf("'manually' pasting authorization code %q to waiting prompt", authCode)
		_, err = ptyFile.WriteString(authCode + "\n")
		require.NoError(t, err)

		// Read all of the remaining output from the subprocess until EOF.
		t.Logf("waiting for kubectl to output namespace list")
		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlPtyOutputBytes, _ := ioutil.ReadAll(ptyFile)
		if kubectlStdoutPipe != nil {
			// On non-MacOS check that stdout of the CLI contains the expected output.
			kubectlStdOutOutputBytes, _ := ioutil.ReadAll(kubectlStdoutPipe)
			requireKubectlGetNamespaceOutput(t, env, string(kubectlStdOutOutputBytes))
		} else {
			// On MacOS check that the pty (stdout+stderr+stdin) of the CLI contains the expected output.
			requireKubectlGetNamespaceOutput(t, env, string(kubectlPtyOutputBytes))
		}

		t.Logf("first kubectl command took %s", time.Since(start).String())

		// To simulate the groups having changed without actually changing the groups the user belongs to in the LDAP
		// server, we update the refresh token secret to have a different value for the groups.
		// Then the refresh flow will update them back to their real values.
		// To do this, we get the refresh token signature out of the cache, use it to get the Secret, update it, and
		// put it back.
		cache := filesession.New(sessionCachePath, filesession.WithErrorReporter(func(err error) {
			require.NoError(t, err)
		}))

		// construct the cache key
		downstreamScopes := []string{"offline_access", "openid", "pinniped:request-audience", "groups"}
		sort.Strings(downstreamScopes)
		sessionCacheKey := oidcclient.SessionCacheKey{
			Issuer:      downstream.Spec.Issuer,
			ClientID:    "pinniped-cli",
			Scopes:      downstreamScopes,
			RedirectURI: "http://localhost:0/callback",
		}
		// use it to get the cache entry
		token := cache.GetToken(sessionCacheKey)
		require.NotNil(t, token)

		// using the refresh token signature contained in the cache, get the refresh token session
		// out of kube secret storage.
		supervisorSecretsClient := testlib.NewKubernetesClientset(t).CoreV1().Secrets(env.SupervisorNamespace)
		supervisorOIDCClientsClient := testlib.NewSupervisorClientset(t).ConfigV1alpha1().OIDCClients(env.SupervisorNamespace)
		oauthStore := oidc.NewKubeStorage(supervisorSecretsClient, supervisorOIDCClientsClient, oidc.DefaultOIDCTimeoutsConfiguration(), oidcclientvalidator.DefaultMinBcryptCost)
		refreshTokenSignature := strings.Split(token.RefreshToken.Token, ".")[1]
		storedRefreshSession, err := oauthStore.GetRefreshTokenSession(ctx, refreshTokenSignature, nil)
		require.NoError(t, err)

		// change the groups to simulate them changing in the IDP.
		pinnipedSession, ok := storedRefreshSession.GetSession().(*psession.PinnipedSession)
		require.True(t, ok, "should have been able to cast session data to PinnipedSession")
		pinnipedSession.Fosite.Claims.Extra["groups"] = []string{"some-wrong-group", "some-other-group"}

		require.NoError(t, oauthStore.DeleteRefreshTokenSession(ctx, refreshTokenSignature))
		require.NoError(t, oauthStore.CreateRefreshTokenSession(ctx, refreshTokenSignature, storedRefreshSession))

		// remove the credential cache, which includes the cached cert, so it won't be reused and the refresh flow will be triggered.
		err = os.Remove(credentialCachePath)
		require.NoError(t, err)

		// wait for the existing tokens to expire, triggering the refresh flow.
		ctx2, cancel2 := context.WithTimeout(ctx, 1*time.Minute)
		defer cancel2()

		// 	Run kubectl, which should work without any prompting for authentication.
		kubectlCmd2 := exec.CommandContext(ctx2, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd2.Env = append(os.Environ(), env.ProxyEnv()...)
		startTime2 := time.Now()
		var kubectlStdoutPipe2 io.ReadCloser
		if runtime.GOOS != "darwin" {
			// For some unknown reason this breaks the pty library on some MacOS machines.
			// The problem doesn't reproduce for everyone, so this is just a workaround.
			kubectlStdoutPipe2, err = kubectlCmd2.StdoutPipe()
			require.NoError(t, err)
		}
		ptyFile2, err := pty.Start(kubectlCmd2)
		require.NoError(t, err)

		// Read all of the remaining output from the subprocess until EOF.
		t.Logf("waiting for kubectl to output namespace list")
		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlPtyOutputBytes2, _ := ioutil.ReadAll(ptyFile2)
		if kubectlStdoutPipe2 != nil {
			// On non-MacOS check that stdout of the CLI contains the expected output.
			kubectlStdOutOutputBytes2, _ := ioutil.ReadAll(kubectlStdoutPipe2)
			requireKubectlGetNamespaceOutput(t, env, string(kubectlStdOutOutputBytes2))
		} else {
			// On MacOS check that the pty (stdout+stderr+stdin) of the CLI contains the expected output.
			requireKubectlGetNamespaceOutput(t, env, string(kubectlPtyOutputBytes2))
		}
		// the output should include a warning that the groups have changed.
		require.Contains(t, string(kubectlPtyOutputBytes2), fmt.Sprintf(`%sWarning:%s User %q has been added to the following groups: %q`+"\r\n", yellowColor, resetColor, env.SupervisorUpstreamOIDC.Username, env.SupervisorUpstreamOIDC.ExpectedGroups))
		require.Contains(t, string(kubectlPtyOutputBytes2), fmt.Sprintf(`%sWarning:%s User %q has been removed from the following groups: ["some-other-group" "some-wrong-group"]`+"\r\n", yellowColor, resetColor, env.SupervisorUpstreamOIDC.Username))

		t.Logf("second kubectl command took %s", time.Since(startTime2).String())
	})
}
