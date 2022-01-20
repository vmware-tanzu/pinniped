// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/text/encoding/unicode"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
	"go.pinniped.dev/test/testlib"
	"go.pinniped.dev/test/testlib/browsertest"
)

// nolint:gocyclo
func TestSupervisorLogin(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	tests := []struct {
		name                                 string
		maybeSkip                            func(t *testing.T)
		createTestUser                       func(t *testing.T) (string, string)
		deleteTestUser                       func(t *testing.T, username string)
		requestAuthorization                 func(t *testing.T, downstreamAuthorizeURL, downstreamCallbackURL, username, password string, httpClient *http.Client)
		createIDP                            func(t *testing.T) string
		wantDownstreamIDTokenSubjectToMatch  string
		wantDownstreamIDTokenUsernameToMatch func(username string) string
		wantDownstreamIDTokenGroups          []string
		wantErrorDescription                 string
		wantErrorType                        string

		// Either revoke the user's session on the upstream provider, or manipulate the user's session
		// data in such a way that it should cause the next upstream refresh attempt to fail.
		breakRefreshSessionData func(t *testing.T, sessionData *psession.PinnipedSession, idpName, username string)
	}{
		{
			name: "oidc with default username and groups claim settings",
			maybeSkip: func(t *testing.T) {
				// never need to skip this test
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				oidcIDP := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: env.SupervisorUpstreamOIDC.Issuer,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
					},
					Client: idpv1alpha1.OIDCClient{
						SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
					},
				}, idpv1alpha1.PhaseReady)
				return oidcIDP.Name
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlow,
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				pinnipedSessionData := pinnipedSession.Custom
				pinnipedSessionData.OIDC.UpstreamIssuer = "wrong-issuer"
			},
			// the ID token Subject should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			// the ID token Username should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+" },
		},
		{
			name: "oidc with custom username and groups claim settings",
			maybeSkip: func(t *testing.T) {
				// never need to skip this test
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				oidcIDP := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: env.SupervisorUpstreamOIDC.Issuer,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
					},
					Client: idpv1alpha1.OIDCClient{
						SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
					},
					Claims: idpv1alpha1.OIDCClaims{
						Username: env.SupervisorUpstreamOIDC.UsernameClaim,
						Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
					},
					AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
						AdditionalScopes: env.SupervisorUpstreamOIDC.AdditionalScopes,
					},
				}, idpv1alpha1.PhaseReady)
				return oidcIDP.Name
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlow,
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				fositeSessionData := pinnipedSession.Fosite
				fositeSessionData.Claims.Extra["username"] = "some-incorrect-username"
			},
			wantDownstreamIDTokenSubjectToMatch:  "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Username) + "$" },
			wantDownstreamIDTokenGroups:          env.SupervisorUpstreamOIDC.ExpectedGroups,
		},
		{
			name: "oidc without refresh token",
			maybeSkip: func(t *testing.T) {
				// never need to skip this test
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				var additionalScopes []string
				// keep all the scopes except for offline access so we can test the access token based refresh flow.
				if len(env.ToolsNamespace) == 0 {
					additionalScopes = env.SupervisorUpstreamOIDC.AdditionalScopes
				} else {
					for _, additionalScope := range env.SupervisorUpstreamOIDC.AdditionalScopes {
						if additionalScope != "offline_access" {
							additionalScopes = append(additionalScopes, additionalScope)
						}
					}
				}
				oidcIDP := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: env.SupervisorUpstreamOIDC.Issuer,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
					},
					Client: idpv1alpha1.OIDCClient{
						SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
					},
					Claims: idpv1alpha1.OIDCClaims{
						Username: env.SupervisorUpstreamOIDC.UsernameClaim,
						Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
					},
					AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
						AdditionalScopes: additionalScopes,
					},
				}, idpv1alpha1.PhaseReady)
				return oidcIDP.Name
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlow,
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				fositeSessionData := pinnipedSession.Fosite
				fositeSessionData.Claims.Extra["username"] = "some-incorrect-username"
			},
			wantDownstreamIDTokenSubjectToMatch:  "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Username) + "$" },
			wantDownstreamIDTokenGroups:          env.SupervisorUpstreamOIDC.ExpectedGroups,
		},
		{
			name: "oidc with CLI password flow",
			maybeSkip: func(t *testing.T) {
				// never need to skip this test
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				oidcIDP := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: env.SupervisorUpstreamOIDC.Issuer,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
					},
					Client: idpv1alpha1.OIDCClient{
						SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
					},
					AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
						AllowPasswordGrant: true, // allow the CLI password flow for this OIDCIdentityProvider
					},
				}, idpv1alpha1.PhaseReady)
				return oidcIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamOIDC.Username, // username to present to server during login
					env.SupervisorUpstreamOIDC.Password, // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				require.Equal(t, psession.ProviderTypeOIDC, customSessionData.ProviderType)
				require.NotEmpty(t, customSessionData.OIDC.UpstreamRefreshToken)
				customSessionData.OIDC.UpstreamRefreshToken = "invalid-updated-refresh-token"
			},
			// the ID token Subject should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			// the ID token Username should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+" },
		},
		{
			name: "ldap with email as username and groups names as DNs and using an LDAP provider which supports TLS",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
					},
				)
				ldapIDP := testlib.CreateTestLDAPIdentityProvider(t, idpv1alpha1.LDAPIdentityProviderSpec{
					Host: env.SupervisorUpstreamLDAP.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.CABundle)),
					},
					Bind: idpv1alpha1.LDAPIdentityProviderBind{
						SecretName: secret.Name,
					},
					UserSearch: idpv1alpha1.LDAPIdentityProviderUserSearch{
						Base:   env.SupervisorUpstreamLDAP.UserSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderUserSearchAttributes{
							Username: env.SupervisorUpstreamLDAP.TestUserMailAttributeName,
							UID:      env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeName,
						},
					},
					GroupSearch: idpv1alpha1.LDAPIdentityProviderGroupSearch{
						Base:   env.SupervisorUpstreamLDAP.GroupSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderGroupSearchAttributes{
							GroupName: "dn",
						},
					},
				}, idpv1alpha1.LDAPPhaseReady)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamLDAP.Host, env.SupervisorUpstreamLDAP.BindUsername,
					secret.Name, secret.ResourceVersion,
				)
				requireSuccessfulLDAPIdentityProviderConditions(t, ldapIDP, expectedMsg)
				return ldapIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				require.Equal(t, psession.ProviderTypeLDAP, customSessionData.ProviderType)
				require.NotEmpty(t, customSessionData.LDAP.UserDN)
				fositeSessionData := pinnipedSession.Fosite
				fositeSessionData.Claims.Subject = "not-right"
			},
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamLDAP.Host+
					"?base="+url.QueryEscape(env.SupervisorUpstreamLDAP.UserSearchBase)+
					"&sub="+base64.RawURLEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeValue)),
			) + "$",
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "^" + regexp.QuoteMeta(env.SupervisorUpstreamLDAP.TestUserMailAttributeValue) + "$"
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs,
		},
		{
			name: "ldap with CN as username and group names as CNs and using an LDAP provider which only supports StartTLS", // try another variation of configuration options
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
					},
				)
				ldapIDP := testlib.CreateTestLDAPIdentityProvider(t, idpv1alpha1.LDAPIdentityProviderSpec{
					Host: env.SupervisorUpstreamLDAP.StartTLSOnlyHost,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.CABundle)),
					},
					Bind: idpv1alpha1.LDAPIdentityProviderBind{
						SecretName: secret.Name,
					},
					UserSearch: idpv1alpha1.LDAPIdentityProviderUserSearch{
						Base:   env.SupervisorUpstreamLDAP.UserSearchBase,
						Filter: "cn={}", // try using a non-default search filter
						Attributes: idpv1alpha1.LDAPIdentityProviderUserSearchAttributes{
							Username: "dn", // try using the user's DN as the downstream username
							UID:      env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeName,
						},
					},
					GroupSearch: idpv1alpha1.LDAPIdentityProviderGroupSearch{
						Base:   env.SupervisorUpstreamLDAP.GroupSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderGroupSearchAttributes{
							GroupName: "cn",
						},
					},
				}, idpv1alpha1.LDAPPhaseReady)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamLDAP.StartTLSOnlyHost, env.SupervisorUpstreamLDAP.BindUsername,
					secret.Name, secret.ResourceVersion,
				)
				requireSuccessfulLDAPIdentityProviderConditions(t, ldapIDP, expectedMsg)
				return ldapIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserCN,       // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword, // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				require.Equal(t, psession.ProviderTypeLDAP, customSessionData.ProviderType)
				require.NotEmpty(t, customSessionData.LDAP.UserDN)
				fositeSessionData := pinnipedSession.Fosite
				fositeSessionData.Claims.Extra["username"] = "not-the-same"
			},
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamLDAP.StartTLSOnlyHost+
					"?base="+url.QueryEscape(env.SupervisorUpstreamLDAP.UserSearchBase)+
					"&sub="+base64.RawURLEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeValue)),
			) + "$",
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamLDAP.TestUserDN) + "$" },
			wantDownstreamIDTokenGroups:          env.SupervisorUpstreamLDAP.TestUserDirectGroupsCNs,
		},
		{
			name: "logging in to ldap with the wrong password fails",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
					},
				)
				ldapIDP := testlib.CreateTestLDAPIdentityProvider(t, idpv1alpha1.LDAPIdentityProviderSpec{
					Host: env.SupervisorUpstreamLDAP.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.CABundle)),
					},
					Bind: idpv1alpha1.LDAPIdentityProviderBind{
						SecretName: secret.Name,
					},
					UserSearch: idpv1alpha1.LDAPIdentityProviderUserSearch{
						Base:   env.SupervisorUpstreamLDAP.UserSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderUserSearchAttributes{
							Username: env.SupervisorUpstreamLDAP.TestUserMailAttributeName,
							UID:      env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeName,
						},
					},
					GroupSearch: idpv1alpha1.LDAPIdentityProviderGroupSearch{
						Base:   env.SupervisorUpstreamLDAP.GroupSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderGroupSearchAttributes{
							GroupName: "dn",
						},
					},
				}, idpv1alpha1.LDAPPhaseReady)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamLDAP.Host, env.SupervisorUpstreamLDAP.BindUsername,
					secret.Name, secret.ResourceVersion,
				)
				requireSuccessfulLDAPIdentityProviderConditions(t, ldapIDP, expectedMsg)
				return ldapIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					"incorrect", // password to present to server during login
					httpClient,
					true,
				)
			},
			wantErrorDescription: "The resource owner or authorization server denied the request. Username/password not accepted by LDAP provider.",
			wantErrorType:        "access_denied",
		},
		{
			name: "ldap login still works after updating bind secret",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()

				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
					},
				)
				secretName := secret.Name
				ldapIDP := testlib.CreateTestLDAPIdentityProvider(t, idpv1alpha1.LDAPIdentityProviderSpec{
					Host: env.SupervisorUpstreamLDAP.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.CABundle)),
					},
					Bind: idpv1alpha1.LDAPIdentityProviderBind{
						SecretName: secretName,
					},
					UserSearch: idpv1alpha1.LDAPIdentityProviderUserSearch{
						Base:   env.SupervisorUpstreamLDAP.UserSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderUserSearchAttributes{
							Username: env.SupervisorUpstreamLDAP.TestUserMailAttributeName,
							UID:      env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeName,
						},
					},
					GroupSearch: idpv1alpha1.LDAPIdentityProviderGroupSearch{
						Base:   env.SupervisorUpstreamLDAP.GroupSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderGroupSearchAttributes{
							GroupName: "dn",
						},
					},
				}, idpv1alpha1.LDAPPhaseReady)

				secret.Annotations = map[string]string{"pinniped.dev/test": "", "another-label": "another-key"}
				// update that secret, which will cause the cache to recheck tls and search base values
				client := testlib.NewKubernetesClientset(t)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				updatedSecret, err := client.CoreV1().Secrets(env.SupervisorNamespace).Update(ctx, secret, metav1.UpdateOptions{})
				require.NoError(t, err)

				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamLDAP.Host, env.SupervisorUpstreamLDAP.BindUsername,
					updatedSecret.Name, updatedSecret.ResourceVersion,
				)
				supervisorClient := testlib.NewSupervisorClientset(t)
				testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					ldapIDP, err = supervisorClient.IDPV1alpha1().LDAPIdentityProviders(env.SupervisorNamespace).Get(ctx, ldapIDP.Name, metav1.GetOptions{})
					requireEventually.NoError(err)
					requireEventuallySuccessfulLDAPIdentityProviderConditions(t, requireEventually, ldapIDP, expectedMsg)
				}, time.Minute, 500*time.Millisecond)
				return ldapIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				require.Equal(t, psession.ProviderTypeLDAP, customSessionData.ProviderType)
				require.NotEmpty(t, customSessionData.LDAP.UserDN)
				customSessionData.LDAP.UserDN = "cn=not-a-user,dc=pinniped,dc=dev"
			},
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamLDAP.Host+
					"?base="+url.QueryEscape(env.SupervisorUpstreamLDAP.UserSearchBase)+
					"&sub="+base64.RawURLEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeValue)),
			) + "$",
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "^" + regexp.QuoteMeta(env.SupervisorUpstreamLDAP.TestUserMailAttributeValue) + "$"
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs,
		},
		{
			name: "ldap login still works after deleting and recreating the bind secret",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()

				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
					},
				)
				secretName := secret.Name
				ldapIDP := testlib.CreateTestLDAPIdentityProvider(t, idpv1alpha1.LDAPIdentityProviderSpec{
					Host: env.SupervisorUpstreamLDAP.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.CABundle)),
					},
					Bind: idpv1alpha1.LDAPIdentityProviderBind{
						SecretName: secretName,
					},
					UserSearch: idpv1alpha1.LDAPIdentityProviderUserSearch{
						Base:   env.SupervisorUpstreamLDAP.UserSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderUserSearchAttributes{
							Username: env.SupervisorUpstreamLDAP.TestUserMailAttributeName,
							UID:      env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeName,
						},
					},
					GroupSearch: idpv1alpha1.LDAPIdentityProviderGroupSearch{
						Base:   env.SupervisorUpstreamLDAP.GroupSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderGroupSearchAttributes{
							GroupName: "dn",
						},
					},
				}, idpv1alpha1.LDAPPhaseReady)

				// delete, then recreate that secret, which will cause the cache to recheck tls and search base values
				client := testlib.NewKubernetesClientset(t)
				deleteCtx, deleteCancel := context.WithTimeout(context.Background(), time.Minute)
				defer deleteCancel()
				err := client.CoreV1().Secrets(env.SupervisorNamespace).Delete(deleteCtx, secretName, metav1.DeleteOptions{})
				require.NoError(t, err)

				// create the secret again
				recreateCtx, recreateCancel := context.WithTimeout(context.Background(), time.Minute)
				defer recreateCancel()
				recreatedSecret, err := client.CoreV1().Secrets(env.SupervisorNamespace).Create(recreateCtx, &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: env.SupervisorNamespace,
					},
					Type: v1.SecretTypeBasicAuth,
					StringData: map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
					},
				}, metav1.CreateOptions{})
				require.NoError(t, err)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamLDAP.Host, env.SupervisorUpstreamLDAP.BindUsername,
					recreatedSecret.Name, recreatedSecret.ResourceVersion,
				)
				supervisorClient := testlib.NewSupervisorClientset(t)
				testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					ldapIDP, err = supervisorClient.IDPV1alpha1().LDAPIdentityProviders(env.SupervisorNamespace).Get(ctx, ldapIDP.Name, metav1.GetOptions{})
					requireEventually.NoError(err)
					requireEventuallySuccessfulLDAPIdentityProviderConditions(t, requireEventually, ldapIDP, expectedMsg)
				}, time.Minute, 500*time.Millisecond)
				return ldapIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				require.Equal(t, psession.ProviderTypeLDAP, customSessionData.ProviderType)
				require.NotEmpty(t, customSessionData.LDAP.UserDN)
				customSessionData.LDAP.UserDN = "cn=not-a-user,dc=pinniped,dc=dev"
			},
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamLDAP.Host+
					"?base="+url.QueryEscape(env.SupervisorUpstreamLDAP.UserSearchBase)+
					"&sub="+base64.RawURLEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeValue)),
			) + "$",
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "^" + regexp.QuoteMeta(env.SupervisorUpstreamLDAP.TestUserMailAttributeValue) + "$"
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs,
		},
		{
			name: "activedirectory with all default options",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
				if env.SupervisorUpstreamActiveDirectory.Host == "" {
					t.Skip("Active Directory hostname not specified")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ad-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
					},
				)
				adIDP := testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
					Host: env.SupervisorUpstreamActiveDirectory.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
					},
					Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
						SecretName: secret.Name,
					},
				}, idpv1alpha1.ActiveDirectoryPhaseReady)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamActiveDirectory.Host, env.SupervisorUpstreamActiveDirectory.BindUsername,
					secret.Name, secret.ResourceVersion,
				)
				requireSuccessfulActiveDirectoryIdentityProviderConditions(t, adIDP, expectedMsg)
				return adIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue, // username to present to server during login
					env.SupervisorUpstreamActiveDirectory.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				require.Equal(t, psession.ProviderTypeActiveDirectory, customSessionData.ProviderType)
				require.NotEmpty(t, customSessionData.ActiveDirectory.UserDN)
				fositeSessionData := pinnipedSession.Fosite
				fositeSessionData.Claims.Extra["username"] = "not-the-same"
			},
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamActiveDirectory.Host+
					"?base="+url.QueryEscape(env.SupervisorUpstreamActiveDirectory.DefaultNamingContextSearchBase)+
					"&sub="+env.SupervisorUpstreamActiveDirectory.TestUserUniqueIDAttributeValue,
			) + "$",
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "^" + regexp.QuoteMeta(env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue) + "$"
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamActiveDirectory.TestUserIndirectGroupsSAMAccountPlusDomainNames,
		}, {
			name: "activedirectory with custom options",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
				if env.SupervisorUpstreamActiveDirectory.Host == "" {
					t.Skip("Active Directory hostname not specified")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ad-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
					},
				)
				adIDP := testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
					Host: env.SupervisorUpstreamActiveDirectory.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
					},
					Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
						SecretName: secret.Name,
					},
					UserSearch: idpv1alpha1.ActiveDirectoryIdentityProviderUserSearch{
						Base:   env.SupervisorUpstreamActiveDirectory.UserSearchBase,
						Filter: env.SupervisorUpstreamActiveDirectory.TestUserMailAttributeName + "={}",
						Attributes: idpv1alpha1.ActiveDirectoryIdentityProviderUserSearchAttributes{
							Username: env.SupervisorUpstreamActiveDirectory.TestUserMailAttributeName,
						},
					},
					GroupSearch: idpv1alpha1.ActiveDirectoryIdentityProviderGroupSearch{
						Filter: "member={}", // excluding nested groups
						Base:   env.SupervisorUpstreamActiveDirectory.GroupSearchBase,
						Attributes: idpv1alpha1.ActiveDirectoryIdentityProviderGroupSearchAttributes{
							GroupName: "dn",
						},
					},
				}, idpv1alpha1.ActiveDirectoryPhaseReady)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamActiveDirectory.Host, env.SupervisorUpstreamActiveDirectory.BindUsername,
					secret.Name, secret.ResourceVersion,
				)
				requireSuccessfulActiveDirectoryIdentityProviderConditions(t, adIDP, expectedMsg)
				return adIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamActiveDirectory.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamActiveDirectory.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				require.Equal(t, psession.ProviderTypeActiveDirectory, customSessionData.ProviderType)
				require.NotEmpty(t, customSessionData.ActiveDirectory.UserDN)
				fositeSessionData := pinnipedSession.Fosite
				fositeSessionData.Claims.Subject = "not-right"
			},
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamActiveDirectory.Host+
					"?base="+url.QueryEscape(env.SupervisorUpstreamActiveDirectory.UserSearchBase)+
					"&sub="+env.SupervisorUpstreamActiveDirectory.TestUserUniqueIDAttributeValue,
			) + "$",
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "^" + regexp.QuoteMeta(env.SupervisorUpstreamActiveDirectory.TestUserMailAttributeValue) + "$"
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamActiveDirectory.TestUserDirectGroupsDNs,
		},
		{
			name: "active directory login still works after updating bind secret",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
				if env.SupervisorUpstreamActiveDirectory.Host == "" {
					t.Skip("Active Directory hostname not specified")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()

				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ad-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
					},
				)
				secretName := secret.Name
				adIDP := testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
					Host: env.SupervisorUpstreamActiveDirectory.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
					},
					Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
						SecretName: secretName,
					},
				}, idpv1alpha1.ActiveDirectoryPhaseReady)

				secret.Annotations = map[string]string{"pinniped.dev/test": "", "another-label": "another-key"}
				// update that secret, which will cause the cache to recheck tls and search base values
				client := testlib.NewKubernetesClientset(t)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				updatedSecret, err := client.CoreV1().Secrets(env.SupervisorNamespace).Update(ctx, secret, metav1.UpdateOptions{})
				require.NoError(t, err)

				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamActiveDirectory.Host, env.SupervisorUpstreamActiveDirectory.BindUsername,
					updatedSecret.Name, updatedSecret.ResourceVersion,
				)
				supervisorClient := testlib.NewSupervisorClientset(t)
				testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					adIDP, err = supervisorClient.IDPV1alpha1().ActiveDirectoryIdentityProviders(env.SupervisorNamespace).Get(ctx, adIDP.Name, metav1.GetOptions{})
					requireEventually.NoError(err)
					requireEventuallySuccessfulActiveDirectoryIdentityProviderConditions(t, requireEventually, adIDP, expectedMsg)
				}, time.Minute, 500*time.Millisecond)
				return adIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue, // username to present to server during login
					env.SupervisorUpstreamActiveDirectory.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				require.Equal(t, psession.ProviderTypeActiveDirectory, customSessionData.ProviderType)
				require.NotEmpty(t, customSessionData.ActiveDirectory.UserDN)
				customSessionData.ActiveDirectory.UserDN = "cn=not-a-user,dc=pinniped,dc=dev"
			},
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamActiveDirectory.Host+
					"?base="+url.QueryEscape(env.SupervisorUpstreamActiveDirectory.DefaultNamingContextSearchBase)+
					"&sub="+env.SupervisorUpstreamActiveDirectory.TestUserUniqueIDAttributeValue,
			) + "$",
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "^" + regexp.QuoteMeta(env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue) + "$"
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamActiveDirectory.TestUserIndirectGroupsSAMAccountPlusDomainNames,
		},
		{
			name: "active directory login still works after deleting and recreating bind secret",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
				if env.SupervisorUpstreamActiveDirectory.Host == "" {
					t.Skip("Active Directory hostname not specified")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()

				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ad-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
					},
				)
				secretName := secret.Name
				adIDP := testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
					Host: env.SupervisorUpstreamActiveDirectory.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
					},
					Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
						SecretName: secretName,
					},
				}, idpv1alpha1.ActiveDirectoryPhaseReady)

				// delete the secret
				client := testlib.NewKubernetesClientset(t)
				deleteCtx, deleteCancel := context.WithTimeout(context.Background(), time.Minute)
				defer deleteCancel()
				err := client.CoreV1().Secrets(env.SupervisorNamespace).Delete(deleteCtx, secretName, metav1.DeleteOptions{})
				require.NoError(t, err)

				// create the secret again
				recreateCtx, recreateCancel := context.WithTimeout(context.Background(), time.Minute)
				defer recreateCancel()
				recreatedSecret, err := client.CoreV1().Secrets(env.SupervisorNamespace).Create(recreateCtx, &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: env.SupervisorNamespace,
					},
					Type: v1.SecretTypeBasicAuth,
					StringData: map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
					},
				}, metav1.CreateOptions{})
				require.NoError(t, err)

				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamActiveDirectory.Host, env.SupervisorUpstreamActiveDirectory.BindUsername,
					recreatedSecret.Name, recreatedSecret.ResourceVersion,
				)
				supervisorClient := testlib.NewSupervisorClientset(t)
				testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					adIDP, err = supervisorClient.IDPV1alpha1().ActiveDirectoryIdentityProviders(env.SupervisorNamespace).Get(ctx, adIDP.Name, metav1.GetOptions{})
					requireEventually.NoError(err)
					requireEventuallySuccessfulActiveDirectoryIdentityProviderConditions(t, requireEventually, adIDP, expectedMsg)
				}, time.Minute, 500*time.Millisecond)
				return adIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue, // username to present to server during login
					env.SupervisorUpstreamActiveDirectory.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				require.Equal(t, psession.ProviderTypeActiveDirectory, customSessionData.ProviderType)
				require.NotEmpty(t, customSessionData.ActiveDirectory.UserDN)
				customSessionData.ActiveDirectory.UserDN = "cn=not-a-user,dc=pinniped,dc=dev"
			},
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamActiveDirectory.Host+
					"?base="+url.QueryEscape(env.SupervisorUpstreamActiveDirectory.DefaultNamingContextSearchBase)+
					"&sub="+env.SupervisorUpstreamActiveDirectory.TestUserUniqueIDAttributeValue,
			) + "$",
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "^" + regexp.QuoteMeta(env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue) + "$"
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamActiveDirectory.TestUserIndirectGroupsSAMAccountPlusDomainNames,
		},
		{
			name: "active directory login fails after the user password is changed",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
				if env.SupervisorUpstreamActiveDirectory.Host == "" {
					t.Skip("Active Directory hostname not specified")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ad-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
					},
				)
				adIDP := testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
					Host: env.SupervisorUpstreamActiveDirectory.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
					},
					Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
						SecretName: secret.Name,
					},
				}, idpv1alpha1.ActiveDirectoryPhaseReady)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamActiveDirectory.Host, env.SupervisorUpstreamActiveDirectory.BindUsername,
					secret.Name, secret.ResourceVersion,
				)
				requireSuccessfulActiveDirectoryIdentityProviderConditions(t, adIDP, expectedMsg)
				return adIDP.Name
			},
			createTestUser: func(t *testing.T) (string, string) {
				return createFreshADTestUser(t, env)
			},
			deleteTestUser: func(t *testing.T, username string) {
				deleteTestADUser(t, env, username)
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, testUserName, testUserPassword string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					testUserName,     // username to present to server during login
					testUserPassword, // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, sessionData *psession.PinnipedSession, _, username string) {
				changeADTestUserPassword(t, env, username)
			},
			// we can't know the subject ahead of time because we created a new user and don't know their uid,
			// so skip wantDownstreamIDTokenSubjectToMatch
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(username string) string {
				return "^" + regexp.QuoteMeta(username+"@"+env.SupervisorUpstreamActiveDirectory.Domain) + "$"
			},
			wantDownstreamIDTokenGroups: []string{}, // none for now.
		},
		{
			name: "active directory login fails after the user is deactivated",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
				if env.SupervisorUpstreamActiveDirectory.Host == "" {
					t.Skip("Active Directory hostname not specified")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ad-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
					},
				)
				adIDP := testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
					Host: env.SupervisorUpstreamActiveDirectory.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
					},
					Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
						SecretName: secret.Name,
					},
				}, idpv1alpha1.ActiveDirectoryPhaseReady)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamActiveDirectory.Host, env.SupervisorUpstreamActiveDirectory.BindUsername,
					secret.Name, secret.ResourceVersion,
				)
				requireSuccessfulActiveDirectoryIdentityProviderConditions(t, adIDP, expectedMsg)
				return adIDP.Name
			},
			createTestUser: func(t *testing.T) (string, string) {
				return createFreshADTestUser(t, env)
			},
			deleteTestUser: func(t *testing.T, username string) {
				deleteTestADUser(t, env, username)
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, testUserName, testUserPassword string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					testUserName,     // username to present to server during login
					testUserPassword, // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, sessionData *psession.PinnipedSession, _, username string) {
				deactivateADTestUser(t, env, username)
			},
			// we can't know the subject ahead of time because we created a new user and don't know their uid,
			// so skip wantDownstreamIDTokenSubjectToMatch
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(username string) string {
				return "^" + regexp.QuoteMeta(username+"@"+env.SupervisorUpstreamActiveDirectory.Domain) + "$"
			},
			wantDownstreamIDTokenGroups: []string{}, // none for now.
		},
		{
			name: "active directory login fails after the user is locked",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
				if env.SupervisorUpstreamActiveDirectory.Host == "" {
					t.Skip("Active Directory hostname not specified")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ad-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
					},
				)
				adIDP := testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
					Host: env.SupervisorUpstreamActiveDirectory.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
					},
					Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
						SecretName: secret.Name,
					},
				}, idpv1alpha1.ActiveDirectoryPhaseReady)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamActiveDirectory.Host, env.SupervisorUpstreamActiveDirectory.BindUsername,
					secret.Name, secret.ResourceVersion,
				)
				requireSuccessfulActiveDirectoryIdentityProviderConditions(t, adIDP, expectedMsg)
				return adIDP.Name
			},
			createTestUser: func(t *testing.T) (string, string) {
				return createFreshADTestUser(t, env)
			},
			deleteTestUser: func(t *testing.T, username string) {
				deleteTestADUser(t, env, username)
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, testUserName, testUserPassword string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					testUserName,     // username to present to server during login
					testUserPassword, // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, sessionData *psession.PinnipedSession, _, username string) {
				lockADTestUser(t, env, username)
			},
			// we can't know the subject ahead of time because we created a new user and don't know their uid,
			// so skip wantDownstreamIDTokenSubjectToMatch
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(username string) string {
				return "^" + regexp.QuoteMeta(username+"@"+env.SupervisorUpstreamActiveDirectory.Domain) + "$"
			},
			wantDownstreamIDTokenGroups: []string{},
		},
		{
			name: "logging in to activedirectory with a deactivated user fails",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
				if env.SupervisorUpstreamActiveDirectory.Host == "" {
					t.Skip("Active Directory hostname not specified")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ad-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
					},
				)
				adIDP := testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
					Host: env.SupervisorUpstreamActiveDirectory.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
					},
					Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
						SecretName: secret.Name,
					},
				}, idpv1alpha1.ActiveDirectoryPhaseReady)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamActiveDirectory.Host, env.SupervisorUpstreamActiveDirectory.BindUsername,
					secret.Name, secret.ResourceVersion,
				)
				requireSuccessfulActiveDirectoryIdentityProviderConditions(t, adIDP, expectedMsg)
				return adIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamActiveDirectory.TestDeactivatedUserSAMAccountNameValue, // username to present to server during login
					env.SupervisorUpstreamActiveDirectory.TestDeactivatedUserPassword,            // password to present to server during login
					httpClient,
					true,
				)
			},
			breakRefreshSessionData: nil,
			wantErrorDescription:    "The resource owner or authorization server denied the request. Username/password not accepted by LDAP provider.",
			wantErrorType:           "access_denied",
		},
		{
			name: "ldap refresh fails when username changes from email as username to dn as username",
			maybeSkip: func(t *testing.T) {
				t.Helper()
				if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
					t.Skip("LDAP integration test requires connectivity to an LDAP server")
				}
			},
			createIDP: func(t *testing.T) string {
				t.Helper()
				secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", v1.SecretTypeBasicAuth,
					map[string]string{
						v1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
						v1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
					},
				)
				ldapIDP := testlib.CreateTestLDAPIdentityProvider(t, idpv1alpha1.LDAPIdentityProviderSpec{
					Host: env.SupervisorUpstreamLDAP.Host,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.CABundle)),
					},
					Bind: idpv1alpha1.LDAPIdentityProviderBind{
						SecretName: secret.Name,
					},
					UserSearch: idpv1alpha1.LDAPIdentityProviderUserSearch{
						Base:   env.SupervisorUpstreamLDAP.UserSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderUserSearchAttributes{
							Username: env.SupervisorUpstreamLDAP.TestUserMailAttributeName,
							UID:      env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeName,
						},
					},
					GroupSearch: idpv1alpha1.LDAPIdentityProviderGroupSearch{
						Base:   env.SupervisorUpstreamLDAP.GroupSearchBase,
						Filter: "",
						Attributes: idpv1alpha1.LDAPIdentityProviderGroupSearchAttributes{
							GroupName: "dn",
						},
					},
				}, idpv1alpha1.LDAPPhaseReady)
				expectedMsg := fmt.Sprintf(
					`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
					env.SupervisorUpstreamLDAP.Host, env.SupervisorUpstreamLDAP.BindUsername,
					secret.Name, secret.ResourceVersion,
				)
				requireSuccessfulLDAPIdentityProviderConditions(t, ldapIDP, expectedMsg)
				return ldapIDP.Name
			},
			requestAuthorization: func(t *testing.T, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, idpName, _ string) {
				// get the idp, update the config.
				client := testlib.NewSupervisorClientset(t)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()

				// Create the LDAPIdentityProvider using GenerateName to get a random name.
				upstreams := client.IDPV1alpha1().LDAPIdentityProviders(env.SupervisorNamespace)
				ldapIDP, err := upstreams.Get(ctx, idpName, metav1.GetOptions{})
				require.NoError(t, err)
				ldapIDP.Spec.UserSearch.Attributes.Username = "dn"

				_, err = upstreams.Update(ctx, ldapIDP, metav1.UpdateOptions{})
				require.NoError(t, err)
				time.Sleep(10 * time.Second) // wait for controllers to pick up the change
			},
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamLDAP.Host+
					"?base="+url.QueryEscape(env.SupervisorUpstreamLDAP.UserSearchBase)+
					"&sub="+base64.RawURLEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeValue)),
			) + "$",
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "^" + regexp.QuoteMeta(env.SupervisorUpstreamLDAP.TestUserMailAttributeValue) + "$"
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs,
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			tt.maybeSkip(t)

			testSupervisorLogin(t,
				tt.createIDP,
				tt.requestAuthorization,
				tt.breakRefreshSessionData,
				tt.createTestUser,
				tt.deleteTestUser,
				tt.wantDownstreamIDTokenSubjectToMatch,
				tt.wantDownstreamIDTokenUsernameToMatch,
				tt.wantDownstreamIDTokenGroups,
				tt.wantErrorDescription,
				tt.wantErrorType,
			)
		})
	}
}

func requireSuccessfulLDAPIdentityProviderConditions(t *testing.T, ldapIDP *idpv1alpha1.LDAPIdentityProvider, expectedLDAPConnectionValidMessage string) {
	require.Len(t, ldapIDP.Status.Conditions, 3)

	conditionsSummary := [][]string{}
	for _, condition := range ldapIDP.Status.Conditions {
		conditionsSummary = append(conditionsSummary, []string{condition.Type, string(condition.Status), condition.Reason})
		t.Logf("Saw LDAPIdentityProvider Status.Condition Type=%s Status=%s Reason=%s Message=%s",
			condition.Type, string(condition.Status), condition.Reason, condition.Message)
		switch condition.Type {
		case "BindSecretValid":
			require.Equal(t, "loaded bind secret", condition.Message)
		case "TLSConfigurationValid":
			require.Equal(t, "loaded TLS configuration", condition.Message)
		case "LDAPConnectionValid":
			require.Equal(t, expectedLDAPConnectionValidMessage, condition.Message)
		}
	}

	require.ElementsMatch(t, [][]string{
		{"BindSecretValid", "True", "Success"},
		{"TLSConfigurationValid", "True", "Success"},
		{"LDAPConnectionValid", "True", "Success"},
	}, conditionsSummary)
}
func requireSuccessfulActiveDirectoryIdentityProviderConditions(t *testing.T, adIDP *idpv1alpha1.ActiveDirectoryIdentityProvider, expectedActiveDirectoryConnectionValidMessage string) {
	require.Len(t, adIDP.Status.Conditions, 4)

	conditionsSummary := [][]string{}
	for _, condition := range adIDP.Status.Conditions {
		conditionsSummary = append(conditionsSummary, []string{condition.Type, string(condition.Status), condition.Reason})
		t.Logf("Saw ActiveDirectoryIdentityProvider Status.Condition Type=%s Status=%s Reason=%s Message=%s",
			condition.Type, string(condition.Status), condition.Reason, condition.Message)
		switch condition.Type {
		case "BindSecretValid":
			require.Equal(t, "loaded bind secret", condition.Message)
		case "TLSConfigurationValid":
			require.Equal(t, "loaded TLS configuration", condition.Message)
		case "LDAPConnectionValid":
			require.Equal(t, expectedActiveDirectoryConnectionValidMessage, condition.Message)
		}
	}

	expectedUserSearchReason := ""
	if adIDP.Spec.UserSearch.Base == "" || adIDP.Spec.GroupSearch.Base == "" {
		expectedUserSearchReason = "Success"
	} else {
		expectedUserSearchReason = "UsingConfigurationFromSpec"
	}

	require.ElementsMatch(t, [][]string{
		{"BindSecretValid", "True", "Success"},
		{"TLSConfigurationValid", "True", "Success"},
		{"LDAPConnectionValid", "True", "Success"},
		{"SearchBaseFound", "True", expectedUserSearchReason},
	}, conditionsSummary)
}

func requireEventuallySuccessfulLDAPIdentityProviderConditions(t *testing.T, requireEventually *require.Assertions, ldapIDP *idpv1alpha1.LDAPIdentityProvider, expectedLDAPConnectionValidMessage string) {
	t.Helper()
	requireEventually.Len(ldapIDP.Status.Conditions, 3)

	conditionsSummary := [][]string{}
	for _, condition := range ldapIDP.Status.Conditions {
		conditionsSummary = append(conditionsSummary, []string{condition.Type, string(condition.Status), condition.Reason})
		t.Logf("Saw ActiveDirectoryIdentityProvider Status.Condition Type=%s Status=%s Reason=%s Message=%s",
			condition.Type, string(condition.Status), condition.Reason, condition.Message)
		switch condition.Type {
		case "BindSecretValid":
			requireEventually.Equal("loaded bind secret", condition.Message)
		case "TLSConfigurationValid":
			requireEventually.Equal("loaded TLS configuration", condition.Message)
		case "LDAPConnectionValid":
			requireEventually.Equal(expectedLDAPConnectionValidMessage, condition.Message)
		}
	}

	requireEventually.ElementsMatch([][]string{
		{"BindSecretValid", "True", "Success"},
		{"TLSConfigurationValid", "True", "Success"},
		{"LDAPConnectionValid", "True", "Success"},
	}, conditionsSummary)
}

func requireEventuallySuccessfulActiveDirectoryIdentityProviderConditions(t *testing.T, requireEventually *require.Assertions, adIDP *idpv1alpha1.ActiveDirectoryIdentityProvider, expectedActiveDirectoryConnectionValidMessage string) {
	t.Helper()
	requireEventually.Len(adIDP.Status.Conditions, 4)

	conditionsSummary := [][]string{}
	for _, condition := range adIDP.Status.Conditions {
		conditionsSummary = append(conditionsSummary, []string{condition.Type, string(condition.Status), condition.Reason})
		t.Logf("Saw ActiveDirectoryIdentityProvider Status.Condition Type=%s Status=%s Reason=%s Message=%s",
			condition.Type, string(condition.Status), condition.Reason, condition.Message)
		switch condition.Type {
		case "BindSecretValid":
			requireEventually.Equal("loaded bind secret", condition.Message)
		case "TLSConfigurationValid":
			requireEventually.Equal("loaded TLS configuration", condition.Message)
		case "LDAPConnectionValid":
			requireEventually.Equal(expectedActiveDirectoryConnectionValidMessage, condition.Message)
		}
	}

	expectedUserSearchReason := ""
	if adIDP.Spec.UserSearch.Base == "" || adIDP.Spec.GroupSearch.Base == "" {
		expectedUserSearchReason = "Success"
	} else {
		expectedUserSearchReason = "UsingConfigurationFromSpec"
	}

	requireEventually.ElementsMatch([][]string{
		{"BindSecretValid", "True", "Success"},
		{"TLSConfigurationValid", "True", "Success"},
		{"LDAPConnectionValid", "True", "Success"},
		{"SearchBaseFound", "True", expectedUserSearchReason},
	}, conditionsSummary)
}

func testSupervisorLogin(
	t *testing.T,
	createIDP func(t *testing.T) string,
	requestAuthorization func(t *testing.T, downstreamAuthorizeURL, downstreamCallbackURL, username, password string, httpClient *http.Client),
	breakRefreshSessionData func(t *testing.T, pinnipedSession *psession.PinnipedSession, idpName, username string),
	createTestUser func(t *testing.T) (string, string),
	deleteTestUser func(t *testing.T, username string),
	wantDownstreamIDTokenSubjectToMatch string,
	wantDownstreamIDTokenUsernameToMatch func(username string) string,
	wantDownstreamIDTokenGroups []string,
	wantErrorDescription string,
	wantErrorType string,
) {
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

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

	// Create an HTTP client that can reach the downstream discovery endpoint using the CA certs.
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: ca.Pool()},
			Proxy: func(req *http.Request) (*url.URL, error) {
				if strings.HasPrefix(req.URL.Host, "127.0.0.1") {
					// don't proxy requests to localhost to avoid proxying calls to our local callback listener
					return nil, nil
				}
				if env.Proxy == "" {
					t.Logf("passing request for %s with no proxy", testlib.RedactURLParams(req.URL))
					return nil, nil
				}
				proxyURL, err := url.Parse(env.Proxy)
				require.NoError(t, err)
				t.Logf("passing request for %s through proxy %s", testlib.RedactURLParams(req.URL), proxyURL.String())
				return proxyURL, nil
			},
		},
		// Don't follow redirects automatically.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	oidcHTTPClientContext := coreosoidc.ClientContext(ctx, httpClient)

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
		v1.SecretTypeTLS,
		map[string]string{"tls.crt": string(certPEM), "tls.key": string(keyPEM)},
	)

	// Create the downstream FederationDomain and expect it to go into the success status condition.
	downstream := testlib.CreateTestFederationDomain(ctx, t,
		issuerURL.String(),
		certSecret.Name,
		configv1alpha1.SuccessFederationDomainStatusCondition,
	)

	// Ensure the the JWKS data is created and ready for the new FederationDomain by waiting for
	// the `/jwks.json` endpoint to succeed, because there is no point in proceeding and eventually
	// calling the token endpoint from this test until the JWKS data has been loaded into
	// the server's in-memory JWKS cache for the token endpoint to use.
	requestJWKSEndpoint, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s/jwks.json", issuerURL.String()),
		nil,
	)
	require.NoError(t, err)
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		rsp, err := httpClient.Do(requestJWKSEndpoint)
		requireEventually.NoError(err)
		requireEventually.NoError(rsp.Body.Close())
		requireEventually.Equal(http.StatusOK, rsp.StatusCode)
	}, 30*time.Second, 200*time.Millisecond)

	// Create upstream IDP and wait for it to become ready.
	idpName := createIDP(t)

	username, password := "", ""
	if createTestUser != nil {
		username, password = createTestUser(t)
		defer deleteTestUser(t, username)
	}

	// Perform OIDC discovery for our downstream.
	var discovery *coreosoidc.Provider
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		var err error
		discovery, err = coreosoidc.NewProvider(oidcHTTPClientContext, downstream.Spec.Issuer)
		requireEventually.NoError(err)
	}, 30*time.Second, 200*time.Millisecond)

	// Start a callback server on localhost.
	localCallbackServer := startLocalCallbackServer(t)

	// Form the OAuth2 configuration corresponding to our CLI client.
	downstreamOAuth2Config := oauth2.Config{
		// This is the hardcoded public client that the supervisor supports.
		ClientID:    "pinniped-cli",
		Endpoint:    discovery.Endpoint(),
		RedirectURL: localCallbackServer.URL,
		Scopes:      []string{"openid", "pinniped:request-audience", "offline_access"},
	}

	// Build a valid downstream authorize URL for the supervisor.
	stateParam, err := state.Generate()
	require.NoError(t, err)
	nonceParam, err := nonce.Generate()
	require.NoError(t, err)
	pkceParam, err := pkce.Generate()
	require.NoError(t, err)
	downstreamAuthorizeURL := downstreamOAuth2Config.AuthCodeURL(
		stateParam.String(),
		nonceParam.Param(),
		pkceParam.Challenge(),
		pkceParam.Method(),
	)

	// Perform parameterized auth code acquisition.
	requestAuthorization(t, downstreamAuthorizeURL, localCallbackServer.URL, username, password, httpClient)

	// Expect that our callback handler was invoked.
	callback := localCallbackServer.waitForCallback(10 * time.Second)
	t.Logf("got callback request: %s", testlib.MaskTokens(callback.URL.String()))
	if wantErrorType == "" {
		require.Equal(t, stateParam.String(), callback.URL.Query().Get("state"))
		require.ElementsMatch(t, []string{"openid", "pinniped:request-audience", "offline_access"}, strings.Split(callback.URL.Query().Get("scope"), " "))
		authcode := callback.URL.Query().Get("code")
		require.NotEmpty(t, authcode)

		// Call the token endpoint to get tokens.
		tokenResponse, err := downstreamOAuth2Config.Exchange(oidcHTTPClientContext, authcode, pkceParam.Verifier())
		require.NoError(t, err)

		expectedIDTokenClaims := []string{"iss", "exp", "sub", "aud", "auth_time", "iat", "jti", "nonce", "rat", "username", "groups"}
		verifyTokenResponse(t,
			tokenResponse, discovery, downstreamOAuth2Config, nonceParam,
			expectedIDTokenClaims, wantDownstreamIDTokenSubjectToMatch, wantDownstreamIDTokenUsernameToMatch(username), wantDownstreamIDTokenGroups)

		// token exchange on the original token
		doTokenExchange(t, &downstreamOAuth2Config, tokenResponse, httpClient, discovery)

		// Use the refresh token to get new tokens
		refreshSource := downstreamOAuth2Config.TokenSource(oidcHTTPClientContext, &oauth2.Token{RefreshToken: tokenResponse.RefreshToken})
		refreshedTokenResponse, err := refreshSource.Token()
		require.NoError(t, err)

		// When refreshing, expect to get an "at_hash" claim, but no "nonce" claim.
		expectRefreshedIDTokenClaims := []string{"iss", "exp", "sub", "aud", "auth_time", "iat", "jti", "rat", "username", "groups", "at_hash"}
		verifyTokenResponse(t,
			refreshedTokenResponse, discovery, downstreamOAuth2Config, "",
			expectRefreshedIDTokenClaims, wantDownstreamIDTokenSubjectToMatch, wantDownstreamIDTokenUsernameToMatch(username), wantDownstreamIDTokenGroups)

		require.NotEqual(t, tokenResponse.AccessToken, refreshedTokenResponse.AccessToken)
		require.NotEqual(t, tokenResponse.RefreshToken, refreshedTokenResponse.RefreshToken)
		require.NotEqual(t, tokenResponse.Extra("id_token"), refreshedTokenResponse.Extra("id_token"))

		// token exchange on the refreshed token
		doTokenExchange(t, &downstreamOAuth2Config, refreshedTokenResponse, httpClient, discovery)

		// Now that we have successfully performed a refresh, let's test what happens when an
		// upstream refresh fails during the next downstream refresh.
		if breakRefreshSessionData != nil {
			latestRefreshToken := refreshedTokenResponse.RefreshToken
			signatureOfLatestRefreshToken := getFositeDataSignature(t, latestRefreshToken)

			// First use the latest downstream refresh token to look up the corresponding session in the Supervisor's storage.
			kubeClient := testlib.NewKubernetesClientset(t)
			supervisorSecretsClient := kubeClient.CoreV1().Secrets(env.SupervisorNamespace)
			oauthStore := oidc.NewKubeStorage(supervisorSecretsClient, oidc.DefaultOIDCTimeoutsConfiguration())
			storedRefreshSession, err := oauthStore.GetRefreshTokenSession(ctx, signatureOfLatestRefreshToken, nil)
			require.NoError(t, err)

			// Next mutate the part of the session that is used during upstream refresh.
			pinnipedSession, ok := storedRefreshSession.GetSession().(*psession.PinnipedSession)
			require.True(t, ok, "should have been able to cast session data to PinnipedSession")
			breakRefreshSessionData(t, pinnipedSession, idpName, username)

			// Then save the mutated Secret back to Kubernetes.
			// There is no update function, so delete and create again at the same name.
			require.NoError(t, oauthStore.DeleteRefreshTokenSession(ctx, signatureOfLatestRefreshToken))
			require.NoError(t, oauthStore.CreateRefreshTokenSession(ctx, signatureOfLatestRefreshToken, storedRefreshSession))

			// Now try to perform a downstream refresh again, knowing that the corresponding upstream refresh should fail.
			_, err = downstreamOAuth2Config.TokenSource(oidcHTTPClientContext, &oauth2.Token{RefreshToken: latestRefreshToken}).Token()
			// Should have got an error since the upstream refresh should have failed.
			require.Error(t, err)
			require.Regexp(t,
				regexp.QuoteMeta("oauth2: cannot fetch token: 401 Unauthorized\n")+
					regexp.QuoteMeta(`Response: {"error":"error","error_description":"Error during upstream refresh. Upstream refresh failed`)+
					"[^']+",
				err.Error(),
			)
		}
	} else {
		errorDescription := callback.URL.Query().Get("error_description")
		errorType := callback.URL.Query().Get("error")
		require.Equal(t, errorDescription, wantErrorDescription)
		require.Equal(t, errorType, wantErrorType)
	}
}

// getFositeDataSignature returns the signature of the provided data. The provided data could be an auth code, access
// token, etc. It is assumed that the code is of the format "data.signature", which is how Fosite generates auth codes
// and access tokens.
func getFositeDataSignature(t *testing.T, data string) string {
	split := strings.Split(data, ".")
	require.Len(t, split, 2)
	return split[1]
}

func verifyTokenResponse(
	t *testing.T,
	tokenResponse *oauth2.Token,
	discovery *coreosoidc.Provider,
	downstreamOAuth2Config oauth2.Config,
	nonceParam nonce.Nonce,
	expectedIDTokenClaims []string,
	wantDownstreamIDTokenSubjectToMatch, wantDownstreamIDTokenUsernameToMatch string, wantDownstreamIDTokenGroups []string,
) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Verify the ID Token.
	rawIDToken, ok := tokenResponse.Extra("id_token").(string)
	require.True(t, ok, "expected to get an ID token but did not")
	var verifier = discovery.Verifier(&coreosoidc.Config{ClientID: downstreamOAuth2Config.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	require.NoError(t, err)

	// Check the sub claim of the ID token.
	require.Regexp(t, wantDownstreamIDTokenSubjectToMatch, idToken.Subject)

	// Check the nonce claim of the ID token.
	require.NoError(t, nonceParam.Validate(idToken))

	// Check the exp claim of the ID token.
	expectedIDTokenLifetime := oidc.DefaultOIDCTimeoutsConfiguration().IDTokenLifespan
	testutil.RequireTimeInDelta(t, time.Now().UTC().Add(expectedIDTokenLifetime), idToken.Expiry, time.Second*30)

	// Check the full list of claim names of the ID token.
	idTokenClaims := map[string]interface{}{}
	err = idToken.Claims(&idTokenClaims)
	require.NoError(t, err)
	idTokenClaimNames := []string{}
	for k := range idTokenClaims {
		idTokenClaimNames = append(idTokenClaimNames, k)
	}
	require.ElementsMatch(t, expectedIDTokenClaims, idTokenClaimNames)

	// Check username claim of the ID token.
	require.Regexp(t, wantDownstreamIDTokenUsernameToMatch, idTokenClaims["username"].(string))

	// Check the groups claim.
	require.ElementsMatch(t, wantDownstreamIDTokenGroups, idTokenClaims["groups"])

	// Some light verification of the other tokens that were returned.
	require.NotEmpty(t, tokenResponse.AccessToken)
	require.Equal(t, "bearer", tokenResponse.TokenType)
	require.NotZero(t, tokenResponse.Expiry)
	expectedAccessTokenLifetime := oidc.DefaultOIDCTimeoutsConfiguration().AccessTokenLifespan
	testutil.RequireTimeInDelta(t, time.Now().UTC().Add(expectedAccessTokenLifetime), tokenResponse.Expiry, time.Second*30)

	require.NotEmpty(t, tokenResponse.RefreshToken)
}

func requestAuthorizationUsingBrowserAuthcodeFlow(t *testing.T, downstreamAuthorizeURL, downstreamCallbackURL, _, _ string, httpClient *http.Client) {
	t.Helper()
	env := testlib.IntegrationEnv(t)

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()

	// Make the authorize request once "manually" so we can check its response security headers.
	authorizeRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, downstreamAuthorizeURL, nil)
	require.NoError(t, err)
	authorizeResp, err := httpClient.Do(authorizeRequest)
	require.NoError(t, err)
	require.NoError(t, authorizeResp.Body.Close())
	expectSecurityHeaders(t, authorizeResp, false)

	// Open the web browser and navigate to the downstream authorize URL.
	page := browsertest.Open(t)
	t.Logf("opening browser to downstream authorize URL %s", testlib.MaskTokens(downstreamAuthorizeURL))
	require.NoError(t, page.Navigate(downstreamAuthorizeURL))

	// Expect to be redirected to the upstream provider and log in.
	browsertest.LoginToUpstream(t, page, env.SupervisorUpstreamOIDC)

	// Wait for the login to happen and us be redirected back to a localhost callback.
	t.Logf("waiting for redirect to callback")
	callbackURLPattern := regexp.MustCompile(`\A` + regexp.QuoteMeta(downstreamCallbackURL) + `\?.+\z`)
	browsertest.WaitForURL(t, page, callbackURLPattern)
}

func requestAuthorizationUsingCLIPasswordFlow(t *testing.T, downstreamAuthorizeURL, upstreamUsername, upstreamPassword string, httpClient *http.Client, wantErr bool) {
	t.Helper()

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()

	authRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, downstreamAuthorizeURL, nil)
	require.NoError(t, err)

	// Set the custom username/password headers for the LDAP authorize request.
	authRequest.Header.Set("Pinniped-Username", upstreamUsername)
	authRequest.Header.Set("Pinniped-Password", upstreamPassword)

	// At this point in the test, we've already waited for the LDAPIdentityProvider to be loaded and marked healthy by
	// at least one Supervisor pod, but we can't be sure that _all_ of them have loaded the provider, so we may need
	// to retry this request multiple times until we get the expected 302 status response.
	var authResponse *http.Response
	var responseBody []byte
	testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
		authResponse, err = httpClient.Do(authRequest)
		if err != nil {
			t.Logf("got authorization response with error %v", err)
			return false, nil
		}
		defer func() { _ = authResponse.Body.Close() }()
		responseBody, err = ioutil.ReadAll(authResponse.Body)
		if err != nil {
			return false, nil
		}
		t.Logf("got authorization response with code %d (%d byte body)", authResponse.StatusCode, len(responseBody))
		if authResponse.StatusCode != http.StatusFound {
			return false, nil
		}
		return true, nil
	}, 60*time.Second, 200*time.Millisecond)

	expectSecurityHeaders(t, authResponse, true)

	// A successful authorize request results in a redirect to our localhost callback listener with an authcode param.
	require.Equalf(t, http.StatusFound, authResponse.StatusCode, "response body was: %s", string(responseBody))
	redirectLocation := authResponse.Header.Get("Location")
	require.Contains(t, redirectLocation, "127.0.0.1")
	require.Contains(t, redirectLocation, "/callback")
	if wantErr {
		require.Contains(t, redirectLocation, "error_description")
	} else {
		require.Contains(t, redirectLocation, "code=")
	}

	// Follow the redirect.
	callbackRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, redirectLocation, nil)
	require.NoError(t, err)

	// Our localhost callback listener should have returned 200 OK.
	callbackResponse, err := httpClient.Do(callbackRequest)
	require.NoError(t, err)
	defer callbackResponse.Body.Close()
	require.Equal(t, http.StatusOK, callbackResponse.StatusCode)
}

func startLocalCallbackServer(t *testing.T) *localCallbackServer {
	// Handle the callback by sending the *http.Request object back through a channel.
	callbacks := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbacks <- r
	}))
	server.URL += "/callback"
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(callbacks) })
	return &localCallbackServer{Server: server, t: t, callbacks: callbacks}
}

type localCallbackServer struct {
	*httptest.Server
	t         *testing.T
	callbacks <-chan *http.Request
}

func (s *localCallbackServer) waitForCallback(timeout time.Duration) *http.Request {
	select {
	case callback := <-s.callbacks:
		return callback
	case <-time.After(timeout):
		require.Fail(s.t, "timed out waiting for callback request")
		return nil
	}
}

func doTokenExchange(t *testing.T, config *oauth2.Config, tokenResponse *oauth2.Token, httpClient *http.Client, provider *coreosoidc.Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Form the HTTP POST request with the parameters specified by RFC8693.
	reqBody := strings.NewReader(url.Values{
		"grant_type":           []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             []string{"cluster-1234"},
		"client_id":            []string{config.ClientID},
		"subject_token":        []string{tokenResponse.AccessToken},
		"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": []string{"urn:ietf:params:oauth:token-type:jwt"},
	}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.Endpoint.TokenURL, reqBody)
	require.NoError(t, err)
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, http.StatusOK)
	defer func() { _ = resp.Body.Close() }()
	var respBody struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))

	var clusterVerifier = provider.Verifier(&coreosoidc.Config{ClientID: "cluster-1234"})
	exchangedToken, err := clusterVerifier.Verify(ctx, respBody.AccessToken)
	require.NoError(t, err)

	var claims map[string]interface{}
	require.NoError(t, exchangedToken.Claims(&claims))
	indentedClaims, err := json.MarshalIndent(claims, "   ", "  ")
	require.NoError(t, err)
	t.Logf("exchanged token claims:\n%s", string(indentedClaims))
}

func expectSecurityHeaders(t *testing.T, response *http.Response, expectFositeToOverrideSome bool) {
	h := response.Header
	assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", h.Get("Content-Security-Policy"))
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", h.Get("X-XSS-Protection"))
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
	assert.Equal(t, "off", h.Get("X-DNS-Prefetch-Control"))
	if expectFositeToOverrideSome {
		assert.Equal(t, "no-store", h.Get("Cache-Control"))
	} else {
		assert.Equal(t, "no-cache,no-store,max-age=0,must-revalidate", h.Get("Cache-Control"))
	}
	assert.Equal(t, "no-cache", h.Get("Pragma"))
	assert.Equal(t, "0", h.Get("Expires"))
}

// create a fresh test user in AD to use for this test.
func createFreshADTestUser(t *testing.T, env *testlib.TestEnv) (string, string) {
	t.Helper()
	// dial tls
	conn := dialTLS(t, env)
	// bind
	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	testUserName := "user-" + createRandomHexString(t, 7) // sAMAccountNames are limited to 20 characters, so this is as long as we can make it.
	// create
	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	a := ldap.NewAddRequest(userDN, []ldap.Control{})
	a.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	a.Attribute("userPrincipalName", []string{fmt.Sprintf("%s@%s", testUserName, env.SupervisorUpstreamActiveDirectory.Domain)})
	a.Attribute("sAMAccountName", []string{testUserName})

	err = conn.Add(a)
	require.NoError(t, err)

	// modify password and enable account
	testUserPassword := createRandomASCIIString(t, 20)
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	encodedTestUserPassword, err := enc.String("\"" + testUserPassword + "\"")
	require.NoError(t, err)

	m := ldap.NewModifyRequest(userDN, []ldap.Control{})
	m.Replace("unicodePwd", []string{encodedTestUserPassword})
	m.Replace("userAccountControl", []string{"512"})
	err = conn.Modify(m)
	require.NoError(t, err)

	time.Sleep(20 * time.Second) // intrasite domain controller replication can take up to 15 seconds, so wait to ensure the change has propogated.
	return testUserName, testUserPassword
}

// deactivate the test user.
func deactivateADTestUser(t *testing.T, env *testlib.TestEnv, testUserName string) {
	conn := dialTLS(t, env)
	// bind
	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	m := ldap.NewModifyRequest(userDN, []ldap.Control{})
	m.Replace("userAccountControl", []string{"514"}) // normal user, account disabled
	err = conn.Modify(m)
	require.NoError(t, err)

	time.Sleep(20 * time.Second) // intrasite domain controller replication can take up to 15 seconds, so wait to ensure the change has propogated.
}

// lock the test user's account by entering the wrong password a bunch of times.
func lockADTestUser(t *testing.T, env *testlib.TestEnv, testUserName string) {
	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	conn := dialTLS(t, env)

	// our password policy allows 20 wrong attempts before locking the account, so do 21.
	// these wrong password attempts could go to different domain controllers, but account
	// lockout changes are urgently replicated, meaning that the domain controllers will be
	// synced asap rather than in the usual 15 second interval.
	// See https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961787(v=technet.10)#urgent-replication-of-account-lockout-changes
	for i := 0; i <= 21; i++ {
		err := conn.Bind(userDN, "not-the-right-password-"+fmt.Sprint(i))
		require.Error(t, err) // this should be an error
	}

	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	time.Sleep(20 * time.Second) // intrasite domain controller replication can take up to 15 seconds, so wait to ensure the change has propogated.
}

// change the user's password to a new one.
func changeADTestUserPassword(t *testing.T, env *testlib.TestEnv, testUserName string) {
	conn := dialTLS(t, env)
	// bind
	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	newTestUserPassword := createRandomASCIIString(t, 20)
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	encodedTestUserPassword, err := enc.String(`"` + newTestUserPassword + `"`)
	require.NoError(t, err)

	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	m := ldap.NewModifyRequest(userDN, []ldap.Control{})
	m.Replace("unicodePwd", []string{encodedTestUserPassword})
	err = conn.Modify(m)
	require.NoError(t, err)

	time.Sleep(20 * time.Second) // intrasite domain controller replication can take up to 15 seconds, so wait to ensure the change has propogated.
	// don't bother to return the new password... we won't be using it, just checking that it's changed.
}

// delete the test user created for this test.
func deleteTestADUser(t *testing.T, env *testlib.TestEnv, testUserName string) {
	t.Helper()
	conn := dialTLS(t, env)
	// bind
	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	d := ldap.NewDelRequest(userDN, []ldap.Control{})
	err = conn.Del(d)
	require.NoError(t, err)
}

func dialTLS(t *testing.T, env *testlib.TestEnv) *ldap.Conn {
	t.Helper()
	// dial tls
	rootCAs := x509.NewCertPool()
	success := rootCAs.AppendCertsFromPEM([]byte(env.SupervisorUpstreamActiveDirectory.CABundle))
	require.True(t, success)
	tlsConfig := ptls.DefaultLDAP(rootCAs)
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Minute}, Config: tlsConfig}
	c, err := dialer.DialContext(context.Background(), "tcp", env.SupervisorUpstreamActiveDirectory.Host)
	require.NoError(t, err)
	conn := ldap.NewConn(c, true)
	conn.Start()
	return conn
}

func createRandomHexString(t *testing.T, length int) string {
	t.Helper()
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	require.NoError(t, err)
	randomString := hex.EncodeToString(bytes)
	return randomString
}

func createRandomASCIIString(t *testing.T, length int) string {
	result := ""
	for {
		if len(result) >= length {
			return result
		}
		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		require.NoError(t, err)
		n := num.Int64()
		// Make sure that the number/byte/letter is inside
		// the range of printable ASCII characters (excluding space and DEL)
		if n > 32 && n < 127 {
			result += string(rune(n))
		}
	}
}
