// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/oidcclientvalidator"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
	"go.pinniped.dev/test/testlib"
	"go.pinniped.dev/test/testlib/browsertest"
)

func TestSupervisorLogin_Browser(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	skipNever := func(t *testing.T) {
		// never need to skip this test
	}

	skipLDAPTests := func(t *testing.T) {
		t.Helper()
		testlib.SkipTestWhenLDAPIsUnavailable(t, env)
	}

	skipActiveDirectoryTests := func(t *testing.T) {
		t.Helper()
		testlib.SkipTestWhenActiveDirectoryIsUnavailable(t, env)
	}

	basicOIDCIdentityProviderSpec := func() idpv1alpha1.OIDCIdentityProviderSpec {
		return idpv1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorUpstreamOIDC.Issuer,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
			},
			Client: idpv1alpha1.OIDCClient{
				SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}
	}

	createActiveDirectoryIdentityProvider := func(t *testing.T, edit func(spec *idpv1alpha1.ActiveDirectoryIdentityProviderSpec)) (*idpv1alpha1.ActiveDirectoryIdentityProvider, *v1.Secret) {
		t.Helper()

		secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ad-service-account", v1.SecretTypeBasicAuth,
			map[string]string{
				v1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
				v1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
			},
		)

		spec := idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
			Host: env.SupervisorUpstreamActiveDirectory.Host,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
			},
			Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
				SecretName: secret.Name,
			},
		}

		if edit != nil {
			edit(&spec)
		}

		adIDP := testlib.CreateTestActiveDirectoryIdentityProvider(t, spec, idpv1alpha1.ActiveDirectoryPhaseReady)

		expectedMsg := fmt.Sprintf(
			`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
			spec.Host, env.SupervisorUpstreamActiveDirectory.BindUsername,
			secret.Name, secret.ResourceVersion,
		)
		requireSuccessfulActiveDirectoryIdentityProviderConditions(t, adIDP, expectedMsg)

		return adIDP, secret
	}

	createLDAPIdentityProvider := func(t *testing.T, edit func(spec *idpv1alpha1.LDAPIdentityProviderSpec)) (*idpv1alpha1.LDAPIdentityProvider, *v1.Secret) {
		t.Helper()

		secret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", v1.SecretTypeBasicAuth,
			map[string]string{
				v1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
				v1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
			},
		)

		spec := idpv1alpha1.LDAPIdentityProviderSpec{
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
				Base:                   env.SupervisorUpstreamLDAP.GroupSearchBase,
				Filter:                 "",
				UserAttributeForFilter: "",
				Attributes: idpv1alpha1.LDAPIdentityProviderGroupSearchAttributes{
					GroupName: "dn",
				},
				SkipGroupRefresh: false,
			},
		}

		if edit != nil {
			edit(&spec)
		}

		ldapIDP := testlib.CreateTestLDAPIdentityProvider(t, spec, idpv1alpha1.LDAPPhaseReady)

		expectedMsg := fmt.Sprintf(
			`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
			spec.Host, env.SupervisorUpstreamLDAP.BindUsername,
			secret.Name, secret.ResourceVersion,
		)
		requireSuccessfulLDAPIdentityProviderConditions(t, ldapIDP, expectedMsg)

		return ldapIDP, secret
	}

	// These tests attempt to exercise the entire login and refresh flow of the Supervisor for various cases.
	// They do not use the Pinniped CLI as the client, which allows them to exercise the Supervisor as an
	// OIDC provider in ways that the CLI might not use. Similar tests exist using the CLI in e2e_test.go.
	//
	// Each of these tests perform the following flow:
	// 1. Create a FederationDomain with TLS configured and wait for its JWKS endpoint to be available.
	// 2. Configure an IDP CR.
	// 3. Call the authorization endpoint and log in as a specific user.
	//    Note that these tests do not use form_post response type (which is tested by e2e_test.go).
	// 4. Listen on a local callback server for the authorization redirect, and assert that it was success or failure.
	// 5. Call the token endpoint to exchange the authcode.
	// 6. Call the token endpoint to perform the RFC8693 token exchange for the cluster-scoped ID token.
	// 7. Potentially edit the refresh session data or IDP settings before the refresh.
	// 8. Call the token endpoint to perform a refresh, and expect it to succeed.
	// 9. Call the token endpoint again to perform another RFC8693 token exchange for the cluster-scoped ID token,
	//    this time using the recently refreshed tokens when submitting the request.
	// 10. Potentially edit the refresh session data or IDP settings again, this time in such a way that the next
	//     refresh should fail. If done, then perform one more refresh and expect failure.
	tests := []struct {
		name string

		// This required function might choose to skip the test case, for example if the LDAP server is not
		// available for an LDAP test.
		maybeSkip func(t *testing.T)

		// This required function should configure an IDP CR. It should also wait for it to be ready and schedule
		// its cleanup. Return the name of the IDP CR.
		createIDP func(t *testing.T) string

		// Optionally create an OIDCClient CR for the test to use. Return the client ID and client secret for the
		// test to use. When not set, the test will default to using the "pinniped-cli" static client with no secret.
		// When a client secret is returned, it will be used for authcode exchange, refresh requests, and RFC8693
		// token exchanges for cluster-scoped tokens (client secrets are not needed in authorization requests).
		createOIDCClient func(t *testing.T, callbackURL string) (string, string)

		// Optionally return the username and password for the test to use when logging in. This username/password
		// will be passed to requestAuthorization(), or empty strings will be passed to indicate that the defaults
		// should be used. If there is any cleanup required, then this function should also schedule that cleanup.
		testUser func(t *testing.T) (string, string)

		// This required function should call the authorization endpoint using the given URL and also perform whatever
		// interactions are needed to log in as the user.
		requestAuthorization func(t *testing.T, downstreamIssuer, downstreamAuthorizeURL, downstreamCallbackURL, username, password string, httpClient *http.Client)

		// This string will be used as the requested audience in the RFC8693 token exchange for
		// the cluster-scoped ID token. When it is not specified, a default string will be used.
		requestTokenExchangeAud string

		// The scopes to request from the authorization endpoint. Defaults will be used when not specified.
		downstreamScopes []string
		// The scopes to want granted from the authorization endpoint. Defaults to the downstreamScopes value when not,
		// specified, i.e. by default it expects that all requested scopes were granted.
		wantDownstreamScopes []string

		// When we want the localhost callback to have never happened, then the flow will stop there. The login was
		// unable to finish so there is nothing to assert about what should have happened with the callback, and there
		// won't be any error sent to the callback either. This would happen, for example, when the user fails to log
		// in at the LDAP/AD login page, because then they would be redirected back to that page again, instead of
		// getting a callback success/error redirect.
		wantLocalhostCallbackToNeverHappen bool

		// The expected ID token subject claim value as a regexp, for the original ID token and the refreshed ID token.
		wantDownstreamIDTokenSubjectToMatch string
		// The expected ID token username claim value as a regexp, for the original ID token and the refreshed ID token.
		// This function should return an empty string when there should be no username claim in the ID tokens.
		wantDownstreamIDTokenUsernameToMatch func(username string) string
		// The expected ID token groups claim value, for the original ID token and the refreshed ID token.
		wantDownstreamIDTokenGroups []string
		// The expected ID token additional claims, which will be nested under claim "additionalClaims",
		// for the original ID token and the refreshed ID token.
		wantDownstreamIDTokenAdditionalClaims map[string]interface{}

		// Want the authorization endpoint to redirect to the callback with this error type.
		// The rest of the flow will be skipped since the initial authorization failed.
		wantAuthorizationErrorType string
		// Want the authorization endpoint to redirect to the callback with this error description.
		// Should be used with wantAuthorizationErrorType.
		wantAuthorizationErrorDescription string

		// Optionally want to the authcode exchange at the token endpoint to fail. The rest of the flow will be
		// skipped since the authcode exchange failed.
		wantAuthcodeExchangeError string

		// Optionally make all required assertions about the response of the RFC8693 token exchange for
		// the cluster-scoped ID token, given the http response status and response body from the token endpoint.
		// When this is not specified then the appropriate default assertions for a successful exchange are made.
		// Even if this expects failures, the rest of the flow will continue.
		wantTokenExchangeResponse func(t *testing.T, status int, body string)

		// Optionally edit the refresh session data between the initial login and the first refresh,
		// which is still expected to succeed after these edits. Returns the group memberships expected after the
		// refresh is performed.
		editRefreshSessionDataWithoutBreaking func(t *testing.T, sessionData *psession.PinnipedSession, idpName, username string) []string
		// Optionally either revoke the user's session on the upstream provider, or manipulate the user's session
		// data in such a way that it should cause the next upstream refresh attempt to fail.
		breakRefreshSessionData func(t *testing.T, sessionData *psession.PinnipedSession, idpName, username string)
	}{
		{
			name:      "oidc with default username and groups claim settings",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				return testlib.CreateTestOIDCIdentityProvider(t, basicOIDCIdentityProviderSpec(), idpv1alpha1.PhaseReady).Name
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowOIDC,
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
			name:      "oidc with custom username and groups claim settings",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				spec := basicOIDCIdentityProviderSpec()
				spec.Claims = idpv1alpha1.OIDCClaims{
					Username: env.SupervisorUpstreamOIDC.UsernameClaim,
					Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
				}
				spec.AuthorizationConfig = idpv1alpha1.OIDCAuthorizationConfig{
					AdditionalScopes: env.SupervisorUpstreamOIDC.AdditionalScopes,
				}
				return testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseReady).Name
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowOIDC,
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				customSessionData.Username = "some-incorrect-username"
			},
			wantDownstreamIDTokenSubjectToMatch:  "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Username) + "$" },
			wantDownstreamIDTokenGroups:          env.SupervisorUpstreamOIDC.ExpectedGroups,
			editRefreshSessionDataWithoutBreaking: func(t *testing.T, sessionData *psession.PinnipedSession, _, _ string) []string {
				// even if we update this group to the wrong thing, we expect that it will return to the correct
				// value after we refresh.
				// However if there are no expected groups then they will not update, so we should skip this.
				if len(env.SupervisorUpstreamOIDC.ExpectedGroups) > 0 {
					sessionData.Fosite.Claims.Extra["groups"] = []string{"some-wrong-group", "some-other-group"}
				}
				return env.SupervisorUpstreamOIDC.ExpectedGroups
			},
		},
		{
			name:      "oidc without refresh token",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				var additionalScopes []string
				// keep all the scopes except for offline access so we can test the access token based refresh flow.
				if len(env.ToolsNamespace) == 0 || !strings.Contains(env.SupervisorUpstreamLDAP.Host, "tools.svc.cluster.local") {
					// Not using Dex.
					additionalScopes = env.SupervisorUpstreamOIDC.AdditionalScopes
				} else {
					// Using Dex in the tools namespace.
					for _, additionalScope := range env.SupervisorUpstreamOIDC.AdditionalScopes {
						if additionalScope != "offline_access" {
							additionalScopes = append(additionalScopes, additionalScope)
						}
					}
				}
				spec := basicOIDCIdentityProviderSpec()
				spec.Claims = idpv1alpha1.OIDCClaims{
					Username: env.SupervisorUpstreamOIDC.UsernameClaim,
					Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
				}
				spec.AuthorizationConfig = idpv1alpha1.OIDCAuthorizationConfig{
					AdditionalScopes: additionalScopes,
				}
				return testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseReady).Name
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowOIDC,
			breakRefreshSessionData: func(t *testing.T, pinnipedSession *psession.PinnipedSession, _, _ string) {
				customSessionData := pinnipedSession.Custom
				customSessionData.Username = "some-incorrect-username"
			},
			wantDownstreamIDTokenSubjectToMatch:  "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Username) + "$" },
			wantDownstreamIDTokenGroups:          env.SupervisorUpstreamOIDC.ExpectedGroups,
		},
		{
			name:      "oidc with CLI password flow",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				spec := basicOIDCIdentityProviderSpec()
				spec.AuthorizationConfig = idpv1alpha1.OIDCAuthorizationConfig{
					AllowPasswordGrant: true, // allow the CLI password flow for this OIDCIdentityProvider
				}
				return testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseReady).Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
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
			name:      "oidc with CLI password flow with additional claim mappings",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				spec := basicOIDCIdentityProviderSpec()
				spec.AuthorizationConfig = idpv1alpha1.OIDCAuthorizationConfig{
					AllowPasswordGrant: true,                                        // allow the CLI password flow for this OIDCIdentityProvider
					AdditionalScopes:   env.SupervisorUpstreamOIDC.AdditionalScopes, // ask for the groups claim so we can use it in additionalClaimMappings below
				}
				spec.Claims.AdditionalClaimMappings = map[string]string{
					"upstream_issuer✅":  "iss",
					"upstream_username": env.SupervisorUpstreamOIDC.UsernameClaim,
					"not_existing":      "not_existing_upstream_claim",
					"upstream_groups":   env.SupervisorUpstreamOIDC.GroupsClaim,
				}
				return testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseReady).Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamOIDC.Username, // username to present to server during login
					env.SupervisorUpstreamOIDC.Password, // password to present to server during login
					httpClient,
					false,
				)
			},
			// the ID token Subject should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			// the ID token Username should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+" },
			wantDownstreamIDTokenAdditionalClaims: wantGroupsInAdditionalClaimsIfGroupsExist(map[string]interface{}{
				"upstream_issuer✅":  env.SupervisorUpstreamOIDC.Issuer,
				"upstream_username": env.SupervisorUpstreamOIDC.Username,
			}, "upstream_groups", env.SupervisorUpstreamOIDC.ExpectedGroups),
		},
		{
			name:      "oidc with default username and groups claim settings with additional claim mappings",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				spec := basicOIDCIdentityProviderSpec()
				spec.AuthorizationConfig = idpv1alpha1.OIDCAuthorizationConfig{
					AdditionalScopes: env.SupervisorUpstreamOIDC.AdditionalScopes, // ask for the groups claim so we can use it in additionalClaimMappings below
				}
				spec.Claims.AdditionalClaimMappings = map[string]string{
					"upstream_issuer✅":  "iss",
					"upstream_username": env.SupervisorUpstreamOIDC.UsernameClaim,
					"not_existing":      "not_existing_upstream_claim",
					"upstream_groups":   env.SupervisorUpstreamOIDC.GroupsClaim,
				}
				return testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseReady).Name
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowOIDC,
			// the ID token Subject should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			// the ID token Username should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+" },
			wantDownstreamIDTokenAdditionalClaims: wantGroupsInAdditionalClaimsIfGroupsExist(map[string]interface{}{
				"upstream_issuer✅":  env.SupervisorUpstreamOIDC.Issuer,
				"upstream_username": env.SupervisorUpstreamOIDC.Username,
			}, "upstream_groups", env.SupervisorUpstreamOIDC.ExpectedGroups),
		},
		{
			name:      "ldap with email as username and groups names as DNs and using an LDAP provider which supports TLS",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			editRefreshSessionDataWithoutBreaking: func(t *testing.T, sessionData *psession.PinnipedSession, _, _ string) []string {
				// even if we update this group to the wrong thing, we expect that it will return to the correct
				// value after we refresh.
				sessionData.Fosite.Claims.Extra["groups"] = []string{"some-wrong-group", "some-other-group"}
				return env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs
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
			name:      "ldap using posix groups by using the UserAttributeForFilter option to adjust the group search filter behavior",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, func(spec *idpv1alpha1.LDAPIdentityProviderSpec) {
					spec.GroupSearch.Filter = "&(objectClass=posixGroup)(memberUid={})"
					spec.GroupSearch.UserAttributeForFilter = "uid"
					spec.GroupSearch.Attributes.GroupName = "cn"
				})
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
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
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamLDAP.TestUserDirectPosixGroupsCNs,
		},
		{
			name:      "ldap without requesting username and groups scope gets them anyway for pinniped-cli for backwards compatibility with old CLIs",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			downstreamScopes:     []string{"openid", "pinniped:request-audience", "offline_access"},
			wantDownstreamScopes: []string{"openid", "pinniped:request-audience", "offline_access", "username", "groups"},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
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
			name:      "oidc without requesting username and groups scope gets them anyway for pinniped-cli for backwards compatibility with old CLIs",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				spec := basicOIDCIdentityProviderSpec()
				spec.Claims = idpv1alpha1.OIDCClaims{
					Username: env.SupervisorUpstreamOIDC.UsernameClaim,
					Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
				}
				spec.AuthorizationConfig = idpv1alpha1.OIDCAuthorizationConfig{
					AdditionalScopes: env.SupervisorUpstreamOIDC.AdditionalScopes,
				}
				return testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseReady).Name
			},
			downstreamScopes:                     []string{"openid", "pinniped:request-audience", "offline_access"},
			wantDownstreamScopes:                 []string{"openid", "pinniped:request-audience", "offline_access", "username", "groups"},
			requestAuthorization:                 requestAuthorizationUsingBrowserAuthcodeFlowOIDC,
			wantDownstreamIDTokenSubjectToMatch:  "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Username) + "$" },
			wantDownstreamIDTokenGroups:          env.SupervisorUpstreamOIDC.ExpectedGroups,
		},
		{
			name:      "ldap with browser flow",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowLDAP,
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
			name:      "ldap with browser flow with wrong password",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					"this is the wrong password" // password to present to server during login
			},
			requestAuthorization:               requestAuthorizationUsingBrowserAuthcodeFlowLDAPWithBadCredentials,
			wantLocalhostCallbackToNeverHappen: true, // we should have been sent back to the login page to retry login
		},
		{
			name:      "ldap with browser flow with wrong username",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return "this is the wrong username", // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			requestAuthorization:               requestAuthorizationUsingBrowserAuthcodeFlowLDAPWithBadCredentials,
			wantLocalhostCallbackToNeverHappen: true, // we should have been sent back to the login page to retry login
		},
		{
			name:      "ldap with browser flow with wrong password and then correct password",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowLDAPWithBadCredentialsAndThenGoodCredentials,
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
			name:      "ldap skip group refresh",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, func(spec *idpv1alpha1.LDAPIdentityProviderSpec) {
					spec.GroupSearch.SkipGroupRefresh = true
				})
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			editRefreshSessionDataWithoutBreaking: func(t *testing.T, sessionData *psession.PinnipedSession, _, _ string) []string {
				// update the list of groups to the wrong thing and see that they do not get updated because
				// skip group refresh is set
				wrongGroups := []string{"some-wrong-group", "some-other-group"}
				sessionData.Fosite.Claims.Extra["groups"] = wrongGroups
				return wrongGroups
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
			name: "ldap with email as username and group search base that doesn't return anything, and using an LDAP provider which supports TLS",
			maybeSkip: func(t *testing.T) {
				skipLDAPTests(t)
				if env.SupervisorUpstreamLDAP.UserSearchBase == env.SupervisorUpstreamLDAP.GroupSearchBase {
					// This test relies on using the user search base as the group search base, to simulate
					// searching for groups and not finding any.
					// If the users and groups are stored in the same place, then we will get groups
					// back, so this test wouldn't make sense.
					t.Skip("must have a different user search base than group search base")
				}
			},
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, func(spec *idpv1alpha1.LDAPIdentityProviderSpec) {
					spec.GroupSearch.Base = env.SupervisorUpstreamLDAP.UserSearchBase // groups not stored at the user search base
				})
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			editRefreshSessionDataWithoutBreaking: func(t *testing.T, sessionData *psession.PinnipedSession, _, _ string) []string {
				// even if we update this group to the wrong thing, we expect that it will return to the correct
				// value (no groups) after we refresh.
				sessionData.Fosite.Claims.Extra["groups"] = []string{"some-wrong-group", "some-other-group"}
				return []string{}
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
			wantDownstreamIDTokenGroups: []string{},
		},
		{
			name:      "ldap with CN as username and group names as CNs and using an LDAP provider which only supports StartTLS", // try another variation of configuration options
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, func(spec *idpv1alpha1.LDAPIdentityProviderSpec) {
					spec.Host = env.SupervisorUpstreamLDAP.StartTLSOnlyHost
					spec.UserSearch.Filter = "cn={}"           // try using a non-default search filter
					spec.UserSearch.Attributes.Username = "dn" // try using the user's DN as the downstream username
					spec.GroupSearch.Attributes.GroupName = "cn"
				})
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
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
				customSessionData.Username = "not-the-same"
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
			name:      "logging in to ldap with the wrong password fails",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					"incorrect", // password to present to server during login
					httpClient,
					true,
				)
			},
			wantAuthorizationErrorDescription: "The resource owner or authorization server denied the request. Username/password not accepted by LDAP provider.",
			wantAuthorizationErrorType:        "access_denied",
		},
		{
			name:      "ldap login still works after updating bind secret",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				t.Helper()
				idp, secret := createLDAPIdentityProvider(t, nil)

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
					idp, err = supervisorClient.IDPV1alpha1().LDAPIdentityProviders(env.SupervisorNamespace).Get(ctx, idp.Name, metav1.GetOptions{})
					requireEventually.NoError(err)
					requireEventuallySuccessfulLDAPIdentityProviderConditions(t, requireEventually, idp, expectedMsg)
				}, time.Minute, 500*time.Millisecond)
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
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
			name:      "ldap login still works after deleting and recreating the bind secret",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				t.Helper()
				idp, secret := createLDAPIdentityProvider(t, nil)

				// delete, then recreate that secret, which will cause the cache to recheck tls and search base values
				client := testlib.NewKubernetesClientset(t)
				deleteCtx, deleteCancel := context.WithTimeout(context.Background(), time.Minute)
				defer deleteCancel()
				err := client.CoreV1().Secrets(env.SupervisorNamespace).Delete(deleteCtx, secret.Name, metav1.DeleteOptions{})
				require.NoError(t, err)

				// create the secret again
				recreateCtx, recreateCancel := context.WithTimeout(context.Background(), time.Minute)
				defer recreateCancel()
				recreatedSecret, err := client.CoreV1().Secrets(env.SupervisorNamespace).Create(recreateCtx, &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secret.Name,
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
					idp, err = supervisorClient.IDPV1alpha1().LDAPIdentityProviders(env.SupervisorNamespace).Get(ctx, idp.Name, metav1.GetOptions{})
					requireEventually.NoError(err)
					requireEventuallySuccessfulLDAPIdentityProviderConditions(t, requireEventually, idp, expectedMsg)
				}, time.Minute, 500*time.Millisecond)
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
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
			name:      "active directory with all default options",
			maybeSkip: skipActiveDirectoryTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createActiveDirectoryIdentityProvider(t, nil)
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
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
				customSessionData.Username = "not-the-same"
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
			name:      "active directory with custom options",
			maybeSkip: skipActiveDirectoryTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createActiveDirectoryIdentityProvider(t, func(spec *idpv1alpha1.ActiveDirectoryIdentityProviderSpec) {
					spec.UserSearch = idpv1alpha1.ActiveDirectoryIdentityProviderUserSearch{
						Base:   env.SupervisorUpstreamActiveDirectory.UserSearchBase,
						Filter: env.SupervisorUpstreamActiveDirectory.TestUserMailAttributeName + "={}",
						Attributes: idpv1alpha1.ActiveDirectoryIdentityProviderUserSearchAttributes{
							Username: env.SupervisorUpstreamActiveDirectory.TestUserMailAttributeName,
						},
					}
					spec.GroupSearch = idpv1alpha1.ActiveDirectoryIdentityProviderGroupSearch{
						Filter: "member={}", // excluding nested groups
						Base:   env.SupervisorUpstreamActiveDirectory.GroupSearchBase,
						Attributes: idpv1alpha1.ActiveDirectoryIdentityProviderGroupSearchAttributes{
							GroupName: "dn",
						},
					}
				})
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
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
			name:      "active directory login still works after updating bind secret",
			maybeSkip: skipActiveDirectoryTests,
			createIDP: func(t *testing.T) string {
				t.Helper()
				idp, secret := createActiveDirectoryIdentityProvider(t, nil)

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
					idp, err = supervisorClient.IDPV1alpha1().ActiveDirectoryIdentityProviders(env.SupervisorNamespace).Get(ctx, idp.Name, metav1.GetOptions{})
					requireEventually.NoError(err)
					requireEventuallySuccessfulActiveDirectoryIdentityProviderConditions(t, requireEventually, idp, expectedMsg)
				}, time.Minute, 500*time.Millisecond)
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
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
			name:      "active directory login still works after deleting and recreating bind secret",
			maybeSkip: skipActiveDirectoryTests,
			createIDP: func(t *testing.T) string {
				t.Helper()
				idp, secret := createActiveDirectoryIdentityProvider(t, nil)

				// delete the secret
				client := testlib.NewKubernetesClientset(t)
				deleteCtx, deleteCancel := context.WithTimeout(context.Background(), time.Minute)
				defer deleteCancel()
				err := client.CoreV1().Secrets(env.SupervisorNamespace).Delete(deleteCtx, secret.Name, metav1.DeleteOptions{})
				require.NoError(t, err)

				// create the secret again
				recreateCtx, recreateCancel := context.WithTimeout(context.Background(), time.Minute)
				defer recreateCancel()
				recreatedSecret, err := client.CoreV1().Secrets(env.SupervisorNamespace).Create(recreateCtx, &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secret.Name,
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
					idp, err = supervisorClient.IDPV1alpha1().ActiveDirectoryIdentityProviders(env.SupervisorNamespace).Get(ctx, idp.Name, metav1.GetOptions{})
					requireEventually.NoError(err)
					requireEventuallySuccessfulActiveDirectoryIdentityProviderConditions(t, requireEventually, idp, expectedMsg)
				}, time.Minute, 500*time.Millisecond)
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
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
			name:      "active directory login fails after the user password is changed",
			maybeSkip: skipActiveDirectoryTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createActiveDirectoryIdentityProvider(t, nil)
				return idp.Name
			},
			testUser: func(t *testing.T) (string, string) {
				return testlib.CreateFreshADTestUser(t, env)
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, testUserName, testUserPassword string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					testUserName,     // username to present to server during login
					testUserPassword, // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, sessionData *psession.PinnipedSession, _, username string) {
				testlib.ChangeADTestUserPassword(t, env, username)
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
			name:      "active directory login fails after the user is deactivated",
			maybeSkip: skipActiveDirectoryTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createActiveDirectoryIdentityProvider(t, nil)
				return idp.Name
			},
			testUser: func(t *testing.T) (string, string) {
				return testlib.CreateFreshADTestUser(t, env)
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, testUserName, testUserPassword string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					testUserName,     // username to present to server during login
					testUserPassword, // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, sessionData *psession.PinnipedSession, _, username string) {
				testlib.DeactivateADTestUser(t, env, username)
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
			name:      "active directory login fails after the user is locked",
			maybeSkip: skipActiveDirectoryTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createActiveDirectoryIdentityProvider(t, nil)
				return idp.Name
			},
			testUser: func(t *testing.T) (string, string) {
				return testlib.CreateFreshADTestUser(t, env)
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, testUserName, testUserPassword string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					testUserName,     // username to present to server during login
					testUserPassword, // password to present to server during login
					httpClient,
					false,
				)
			},
			breakRefreshSessionData: func(t *testing.T, sessionData *psession.PinnipedSession, _, username string) {
				testlib.LockADTestUser(t, env, username)
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
			name:      "logging in to active directory with a deactivated user fails",
			maybeSkip: skipActiveDirectoryTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createActiveDirectoryIdentityProvider(t, nil)
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamActiveDirectory.TestDeactivatedUserSAMAccountNameValue, // username to present to server during login
					env.SupervisorUpstreamActiveDirectory.TestDeactivatedUserPassword,            // password to present to server during login
					httpClient,
					true,
				)
			},
			breakRefreshSessionData:           nil,
			wantAuthorizationErrorDescription: "The resource owner or authorization server denied the request. Username/password not accepted by LDAP provider.",
			wantAuthorizationErrorType:        "access_denied",
		},
		{
			name:      "ldap refresh fails when username changes from email as username to dn as username",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
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
		{
			name:      "ldap refresh updates groups to be empty after deleting the group search base",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			requestAuthorization: func(t *testing.T, _, downstreamAuthorizeURL, _, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingCLIPasswordFlow(t,
					downstreamAuthorizeURL,
					env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword,           // password to present to server during login
					httpClient,
					false,
				)
			},
			editRefreshSessionDataWithoutBreaking: func(t *testing.T, pinnipedSession *psession.PinnipedSession, idpName, _ string) []string {
				// get the idp, update the config.
				client := testlib.NewSupervisorClientset(t)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()

				upstreams := client.IDPV1alpha1().LDAPIdentityProviders(env.SupervisorNamespace)
				ldapIDP, err := upstreams.Get(ctx, idpName, metav1.GetOptions{})
				require.NoError(t, err)
				ldapIDP.Spec.GroupSearch.Base = ""

				_, err = upstreams.Update(ctx, ldapIDP, metav1.UpdateOptions{})
				require.NoError(t, err)
				time.Sleep(10 * time.Second) // wait for controllers to pick up the change
				return []string{}
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
			name:      "disallowed requested audience using reserved substring on token exchange results in token exchange error",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				return testlib.CreateTestOIDCIdentityProvider(t, basicOIDCIdentityProviderSpec(), idpv1alpha1.PhaseReady).Name
			},
			requestAuthorization:    requestAuthorizationUsingBrowserAuthcodeFlowOIDC,
			requestTokenExchangeAud: "contains-disallowed-substring.pinniped.dev-something", // .pinniped.dev substring is not allowed
			// the ID token Subject should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			// the ID token Username should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+" },
			wantTokenExchangeResponse: func(t *testing.T, status int, body string) {
				require.Equal(t, http.StatusBadRequest, status)
				require.Equal(t,
					`{"error":"invalid_request","error_description":"The request is missing a required parameter, `+
						`includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. `+
						`requested audience cannot contain '.pinniped.dev'"}`,
					body)
			},
		},
		{
			name:      "disallowed requested audience using specific reserved name of a dynamic client on token exchange results in token exchange error",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				return testlib.CreateTestOIDCIdentityProvider(t, basicOIDCIdentityProviderSpec(), idpv1alpha1.PhaseReady).Name
			},
			requestAuthorization:    requestAuthorizationUsingBrowserAuthcodeFlowOIDC,
			requestTokenExchangeAud: "client.oauth.pinniped.dev-client-name", // OIDC dynamic client name is not allowed
			// the ID token Subject should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			// the ID token Username should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+" },
			wantTokenExchangeResponse: func(t *testing.T, status int, body string) {
				require.Equal(t, http.StatusBadRequest, status)
				require.Equal(t,
					`{"error":"invalid_request","error_description":"The request is missing a required parameter, `+
						`includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. `+
						`requested audience cannot contain '.pinniped.dev'"}`,
					body)
			},
		},
		{
			name:      "disallowed requested audience pinniped-cli on token exchange results in token exchange error",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				return testlib.CreateTestOIDCIdentityProvider(t, basicOIDCIdentityProviderSpec(), idpv1alpha1.PhaseReady).Name
			},
			requestAuthorization:    requestAuthorizationUsingBrowserAuthcodeFlowOIDC,
			requestTokenExchangeAud: "pinniped-cli", // pinniped-cli is not allowed
			// the ID token Subject should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			// the ID token Username should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+" },
			wantTokenExchangeResponse: func(t *testing.T, status int, body string) {
				require.Equal(t, http.StatusBadRequest, status)
				require.Equal(t,
					`{"error":"invalid_request","error_description":"The request is missing a required parameter, `+
						`includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. `+
						`requested audience cannot equal 'pinniped-cli'"}`,
					body)
			},
		},
		{
			name:      "oidc upstream with downstream dynamic client happy path, requesting all scopes",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				spec := basicOIDCIdentityProviderSpec()
				spec.Claims = idpv1alpha1.OIDCClaims{
					Username: env.SupervisorUpstreamOIDC.UsernameClaim,
					Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
				}
				spec.AuthorizationConfig = idpv1alpha1.OIDCAuthorizationConfig{
					AdditionalScopes: env.SupervisorUpstreamOIDC.AdditionalScopes,
				}
				return testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseReady).Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
				}, configv1alpha1.PhaseReady)
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowOIDC,
			// the ID token Subject should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenSubjectToMatch:  "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Username) + "$" },
			wantDownstreamIDTokenGroups:          env.SupervisorUpstreamOIDC.ExpectedGroups,
		},
		{
			name:      "oidc upstream with downstream dynamic client happy path, requesting all scopes, with additional claims",
			maybeSkip: skipNever,
			createIDP: func(t *testing.T) string {
				spec := basicOIDCIdentityProviderSpec()
				spec.Claims = idpv1alpha1.OIDCClaims{
					Username: env.SupervisorUpstreamOIDC.UsernameClaim,
					Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
					AdditionalClaimMappings: map[string]string{
						"upstream_issuer✅":  "iss",
						"upstream_username": env.SupervisorUpstreamOIDC.UsernameClaim,
						"not_existing":      "not_existing_upstream_claim",
						"upstream_groups":   env.SupervisorUpstreamOIDC.GroupsClaim,
					},
				}
				spec.AuthorizationConfig = idpv1alpha1.OIDCAuthorizationConfig{
					AdditionalScopes: env.SupervisorUpstreamOIDC.AdditionalScopes,
				}
				return testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseReady).Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
				}, configv1alpha1.PhaseReady)
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowOIDC,
			// the ID token Subject should include the upstream user ID after the upstream issuer name
			wantDownstreamIDTokenSubjectToMatch:  "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Issuer+"?sub=") + ".+",
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string { return "^" + regexp.QuoteMeta(env.SupervisorUpstreamOIDC.Username) + "$" },
			wantDownstreamIDTokenGroups:          env.SupervisorUpstreamOIDC.ExpectedGroups,
			wantDownstreamIDTokenAdditionalClaims: wantGroupsInAdditionalClaimsIfGroupsExist(map[string]interface{}{
				"upstream_issuer✅":  env.SupervisorUpstreamOIDC.Issuer,
				"upstream_username": env.SupervisorUpstreamOIDC.Username,
			}, "upstream_groups", env.SupervisorUpstreamOIDC.ExpectedGroups),
		},
		{
			name:      "ldap upstream with downstream dynamic client happy path, requesting all scopes",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
				}, configv1alpha1.PhaseReady)
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowLDAP,
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
			name:      "ldap upstream with downstream dynamic client when dynamic client is not allowed to use the token exchange grant type, causes token exchange error",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "refresh_token"},        // token exchange grant type not allowed
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "username", "groups"}, // a validation requires that we also disallow the pinniped:request-audience scope
				}, configv1alpha1.PhaseReady)
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			downstreamScopes:     []string{"openid", "offline_access", "username", "groups"}, // does not request (or expect) pinniped:request-audience token exchange scope
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowLDAP,
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "^" + regexp.QuoteMeta(env.SupervisorUpstreamLDAP.TestUserMailAttributeValue) + "$"
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs,
			wantTokenExchangeResponse: func(t *testing.T, status int, body string) { // can't do token exchanges without the token exchange grant type
				require.Equal(t, http.StatusBadRequest, status)
				require.Equal(t,
					`{"error":"unauthorized_client","error_description":"The client is not authorized to request a token using this method. `+
						`The OAuth 2.0 Client is not allowed to use token exchange grant 'urn:ietf:params:oauth:grant-type:token-exchange'."}`,
					body)
			},
		},
		{
			name:      "ldap upstream with downstream dynamic client when dynamic client that does not request the pinniped:request-audience scope, causes token exchange error",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
				}, configv1alpha1.PhaseReady)
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			downstreamScopes:     []string{"openid", "offline_access", "username", "groups"}, // does not request (or expect) pinniped:request-audience token exchange scope
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowLDAP,
			// the ID token Username should have been pulled from the requested UserSearch.Attributes.Username attribute
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "^" + regexp.QuoteMeta(env.SupervisorUpstreamLDAP.TestUserMailAttributeValue) + "$"
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs,
			wantTokenExchangeResponse: func(t *testing.T, status int, body string) { // can't do token exchanges without the pinniped:request-audience token exchange scope
				require.Equal(t, http.StatusForbidden, status)
				require.Equal(t,
					`{"error":"access_denied","error_description":"The resource owner or authorization server denied the request. `+
						`Missing the 'pinniped:request-audience' scope."}`,
					body)
			},
		},
		{
			name:      "ldap upstream with downstream dynamic client when dynamic client is not allowed to request username but requests username anyway, causes authorization error",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude groups scope)
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "groups"},      // username not allowed
				}, configv1alpha1.PhaseReady)
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			downstreamScopes: []string{"openid", "offline_access", "username"}, // request username, even though the client is not allowed to request it
			// Should have been immediately redirected back to the local callback server with an error in this case,
			// since we requested a scope that the client is not allowed to request. The login UI page is never shown.
			requestAuthorization:              requestAuthorizationAndExpectImmediateRedirectToCallback,
			wantAuthorizationErrorDescription: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'username'.",
			wantAuthorizationErrorType:        "invalid_scope",
		},
		{
			name:      "ldap upstream with downstream dynamic client when dynamic client is not allowed to request groups but requests groups anyway, causes authorization error",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude groups scope)
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "username"},    // groups not allowed
				}, configv1alpha1.PhaseReady)
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			downstreamScopes: []string{"openid", "offline_access", "groups"}, // request groups, even though the client is not allowed to request it
			// Should have been immediately redirected back to the local callback server with an error in this case,
			// since we requested a scope that the client is not allowed to request. The login UI page is never shown.
			requestAuthorization:              requestAuthorizationAndExpectImmediateRedirectToCallback,
			wantAuthorizationErrorDescription: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'groups'.",
			wantAuthorizationErrorType:        "invalid_scope",
		},
		{
			name:      "ldap upstream with downstream dynamic client when dynamic client does not request groups happy path",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
				}, configv1alpha1.PhaseReady)
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			downstreamScopes:     []string{"openid", "pinniped:request-audience", "offline_access", "username"}, // do not request (or expect) groups
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowLDAP,
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
			wantDownstreamIDTokenGroups: nil, // did not request groups, so should not have got any groups
		},
		{
			name:      "ldap upstream with downstream dynamic client when dynamic client does not request username, is allowed to auth but cannot do token exchange",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
				}, configv1alpha1.PhaseReady)
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			downstreamScopes:     []string{"openid", "pinniped:request-audience", "offline_access", "groups"}, // do not request (or expect) username
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowLDAP,
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamLDAP.Host+
					"?base="+url.QueryEscape(env.SupervisorUpstreamLDAP.UserSearchBase)+
					"&sub="+base64.RawURLEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeValue)),
			) + "$",
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "" // username should not exist as a claim since we did not request it
			},
			wantDownstreamIDTokenGroups: env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs,
			wantTokenExchangeResponse: func(t *testing.T, status int, body string) { // can't do token exchanges without a username
				require.Equal(t, http.StatusForbidden, status)
				require.Equal(t,
					`{"error":"access_denied","error_description":"The resource owner or authorization server denied the request. `+
						`No username found in session. Ensure that the 'username' scope was requested and granted at the authorization endpoint."}`,
					body)
			},
		},
		{
			name:      "ldap upstream with downstream dynamic client when dynamic client is not allowed to request username or groups and does not request them, is allowed to auth but cannot do token exchange",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "refresh_token"},
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access"}, // validations require that when username/groups are excluded, then token exchange must also not be allowed
				}, configv1alpha1.PhaseReady)
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			downstreamScopes:     []string{"openid", "offline_access"}, // do not request (or expect) pinniped:request-audience or username or groups
			requestAuthorization: requestAuthorizationUsingBrowserAuthcodeFlowLDAP,
			// the ID token Subject should be the Host URL plus the value pulled from the requested UserSearch.Attributes.UID attribute
			wantDownstreamIDTokenSubjectToMatch: "^" + regexp.QuoteMeta(
				"ldaps://"+env.SupervisorUpstreamLDAP.Host+
					"?base="+url.QueryEscape(env.SupervisorUpstreamLDAP.UserSearchBase)+
					"&sub="+base64.RawURLEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeValue)),
			) + "$",
			wantDownstreamIDTokenUsernameToMatch: func(_ string) string {
				return "" // username should not exist as a claim since we did not request it
			},
			wantDownstreamIDTokenGroups: nil, // did not request groups, so should not have got any groups
			wantTokenExchangeResponse: func(t *testing.T, status int, body string) { // can't do token exchanges without the token exchange grant type
				require.Equal(t, http.StatusBadRequest, status)
				require.Equal(t,
					`{"error":"unauthorized_client","error_description":"The client is not authorized to request a token using this method. `+
						`The OAuth 2.0 Client is not allowed to use token exchange grant 'urn:ietf:params:oauth:grant-type:token-exchange'."}`,
					body)
			},
		},
		{
			name:      "active directory with all default options with downstream dynamic client happy path",
			maybeSkip: skipActiveDirectoryTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createActiveDirectoryIdentityProvider(t, nil)
				return idp.Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				return testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
				}, configv1alpha1.PhaseReady)
			},
			requestAuthorization: func(t *testing.T, downstreamIssuer, downstreamAuthorizeURL, downstreamCallbackURL, _, _ string, httpClient *http.Client) {
				requestAuthorizationUsingBrowserAuthcodeFlowLDAP(t,
					downstreamIssuer,
					downstreamAuthorizeURL,
					downstreamCallbackURL,
					env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue, // username to present to server during login
					env.SupervisorUpstreamActiveDirectory.TestUserPassword,           // password to present to server during login
					httpClient,
				)
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
			name:      "ldap upstream with downstream dynamic client, failed client authentication",
			maybeSkip: skipLDAPTests,
			createIDP: func(t *testing.T) string {
				idp, _ := createLDAPIdentityProvider(t, nil)
				return idp.Name
			},
			createOIDCClient: func(t *testing.T, callbackURL string) (string, string) {
				clientID, _ := testlib.CreateOIDCClient(t, configv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(callbackURL)},
					AllowedGrantTypes:   []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					AllowedScopes:       []configv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
				}, configv1alpha1.PhaseReady)
				return clientID, "wrong-client-secret"
			},
			testUser: func(t *testing.T) (string, string) {
				// return the username and password of the existing user that we want to use for this test
				return env.SupervisorUpstreamLDAP.TestUserMailAttributeValue, // username to present to server during login
					env.SupervisorUpstreamLDAP.TestUserPassword // password to present to server during login
			},
			requestAuthorization:      requestAuthorizationUsingBrowserAuthcodeFlowLDAP,
			wantAuthcodeExchangeError: `oauth2: "invalid_client" "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."`,
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			tt.maybeSkip(t)

			testSupervisorLogin(
				t,
				tt.createIDP,
				tt.requestAuthorization,
				tt.editRefreshSessionDataWithoutBreaking,
				tt.breakRefreshSessionData,
				tt.testUser,
				tt.createOIDCClient,
				tt.downstreamScopes,
				tt.requestTokenExchangeAud,
				tt.wantDownstreamScopes,
				tt.wantLocalhostCallbackToNeverHappen,
				tt.wantDownstreamIDTokenSubjectToMatch,
				tt.wantDownstreamIDTokenUsernameToMatch,
				tt.wantDownstreamIDTokenGroups,
				tt.wantDownstreamIDTokenAdditionalClaims,
				tt.wantAuthorizationErrorType,
				tt.wantAuthorizationErrorDescription,
				tt.wantAuthcodeExchangeError,
				tt.wantTokenExchangeResponse,
			)
		})
	}
}

func wantGroupsInAdditionalClaimsIfGroupsExist(additionalClaims map[string]interface{}, wantGroupsAdditionalClaimName string, wantGroups []string) map[string]interface{} {
	if len(wantGroups) > 0 {
		var wantGroupsAnyType []interface{}
		for _, group := range wantGroups {
			wantGroupsAnyType = append(wantGroupsAnyType, group)
		}
		additionalClaims[wantGroupsAdditionalClaimName] = wantGroupsAnyType
	}
	return additionalClaims
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
	requestAuthorization func(t *testing.T, downstreamIssuer string, downstreamAuthorizeURL string, downstreamCallbackURL string, username string, password string, httpClient *http.Client),
	editRefreshSessionDataWithoutBreaking func(t *testing.T, pinnipedSession *psession.PinnipedSession, idpName string, username string) []string,
	breakRefreshSessionData func(t *testing.T, pinnipedSession *psession.PinnipedSession, idpName string, username string),
	testUser func(t *testing.T) (string, string),
	createOIDCClient func(t *testing.T, callbackURL string) (string, string),
	downstreamScopes []string,
	requestTokenExchangeAud string,
	wantDownstreamScopes []string,
	wantLocalhostCallbackToNeverHappen bool,
	wantDownstreamIDTokenSubjectToMatch string,
	wantDownstreamIDTokenUsernameToMatch func(username string) string,
	wantDownstreamIDTokenGroups []string,
	wantDownstreamIDTokenAdditionalClaims map[string]interface{},
	wantAuthorizationErrorType string,
	wantAuthorizationErrorDescription string,
	wantAuthcodeExchangeError string,
	wantTokenExchangeResponse func(t *testing.T, status int, body string),
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
			TLSClientConfig: &tls.Config{RootCAs: ca.Pool()}, //nolint:gosec // not concerned with TLS MinVersion here
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

	// Start a callback server on localhost.
	localCallbackServer := startLocalCallbackServer(t)

	// Optionally create an OIDCClient. Default to using the hardcoded public client that the Supervisor supports.
	clientID, clientSecret := "pinniped-cli", "" //nolint:gosec // empty credential is not a hardcoded credential
	if createOIDCClient != nil {
		clientID, clientSecret = createOIDCClient(t, localCallbackServer.URL)
	}

	// Optionally override which user to use for the test, or choose zero values to mean use the default for
	// the test's IDP.
	username, password := "", ""
	if testUser != nil {
		username, password = testUser(t)
	}

	// Perform OIDC discovery for our downstream.
	var discovery *coreosoidc.Provider
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		var err error
		discovery, err = coreosoidc.NewProvider(oidcHTTPClientContext, downstream.Spec.Issuer)
		requireEventually.NoError(err)
	}, 30*time.Second, 200*time.Millisecond)

	if downstreamScopes == nil {
		// By default, tests will request all the relevant scopes.
		downstreamScopes = []string{"openid", "pinniped:request-audience", "offline_access", "username", "groups"}
	}
	if wantDownstreamScopes == nil {
		// By default, tests will want that all requested scopes were granted.
		wantDownstreamScopes = make([]string, len(downstreamScopes))
		copy(wantDownstreamScopes, downstreamScopes)
	}

	// Create the OAuth2 configuration.
	// Note that this is not using response_type=form_post, so the Supervisor will redirect to the callback endpoint
	// directly, without using the Javascript form_post HTML page to POST back to the callback endpoint. The e2e
	// tests which use the Pinniped CLI are testing the form_post part of the flow, so that is covered elsewhere.
	// When ClientSecret is set here, it will be used for all token endpoint requests, but not for the authorization
	// request, where it is not needed.
	endpoint := discovery.Endpoint()
	if clientSecret != "" {
		// We only support basic auth for dynamic clients, so use basic auth in these tests.
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	}
	downstreamOAuth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     endpoint,
		RedirectURL:  localCallbackServer.URL,
		Scopes:       downstreamScopes,
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
	requestAuthorization(t, downstream.Spec.Issuer, downstreamAuthorizeURL, localCallbackServer.URL, username, password, httpClient)

	// Expect that our callback handler was invoked.
	callback, err := localCallbackServer.waitForCallback(10 * time.Second)
	if wantLocalhostCallbackToNeverHappen {
		require.Error(t, err)
		// When we want the localhost callback to have never happened, then this is the end of the test. The login was
		// unable to finish so there is nothing to assert about what should have happened with the callback, and there
		// won't be any error sent to the callback either.
		return
	}
	// Else, no error.
	require.NoError(t, err)

	t.Logf("got callback request: %s", testlib.MaskTokens(callback.URL.String()))

	if wantAuthorizationErrorType != "" {
		errorDescription := callback.URL.Query().Get("error_description")
		errorType := callback.URL.Query().Get("error")
		require.Equal(t, wantAuthorizationErrorDescription, errorDescription)
		require.Equal(t, wantAuthorizationErrorType, errorType)
		// The authorization has failed, so can't continue the login flow, making this the end of the test case.
		return
	}

	require.Equal(t, stateParam.String(), callback.URL.Query().Get("state"))
	require.ElementsMatch(t, wantDownstreamScopes, strings.Split(callback.URL.Query().Get("scope"), " "))
	authcode := callback.URL.Query().Get("code")
	require.NotEmpty(t, authcode)

	// Authcodes should start with the custom prefix "pin_ac_" to make them identifiable as authcodes when seen by a user out of context.
	require.True(t, strings.HasPrefix(authcode, "pin_ac_"), "token %q did not have expected prefix 'pin_ac_'", authcode)

	// Call the token endpoint to get tokens.
	tokenResponse, err := downstreamOAuth2Config.Exchange(oidcHTTPClientContext, authcode, pkceParam.Verifier())
	if wantAuthcodeExchangeError != "" {
		require.EqualError(t, err, wantAuthcodeExchangeError)
		// The authcode exchange has failed, so can't continue the login flow, making this the end of the test case.
		return
	}
	require.NoError(t, err)

	expectedIDTokenClaims := []string{"iss", "exp", "sub", "aud", "auth_time", "iat", "jti", "nonce", "rat", "azp", "at_hash"}
	if slices.Contains(wantDownstreamScopes, "username") {
		// If the test wants the username scope to have been granted, then also expect the claim in the ID token.
		expectedIDTokenClaims = append(expectedIDTokenClaims, "username")
	}
	if slices.Contains(wantDownstreamScopes, "groups") {
		// If the test wants the groups scope to have been granted, then also expect the claim in the ID token.
		expectedIDTokenClaims = append(expectedIDTokenClaims, "groups")
	}
	if len(wantDownstreamIDTokenAdditionalClaims) > 0 {
		expectedIDTokenClaims = append(expectedIDTokenClaims, "additionalClaims")
	}
	initialIDTokenClaims := verifyTokenResponse(
		t,
		tokenResponse,
		discovery,
		downstreamOAuth2Config,
		nonceParam,
		expectedIDTokenClaims,
		wantDownstreamIDTokenSubjectToMatch,
		wantDownstreamIDTokenUsernameToMatch(username),
		wantDownstreamIDTokenGroups,
		wantDownstreamIDTokenAdditionalClaims,
	)

	// token exchange on the original token
	if requestTokenExchangeAud == "" {
		requestTokenExchangeAud = "some-cluster-123" // use a default test value
	}
	doTokenExchange(t, requestTokenExchangeAud, &downstreamOAuth2Config, tokenResponse, httpClient, discovery, wantTokenExchangeResponse, initialIDTokenClaims)

	wantRefreshedGroups := wantDownstreamIDTokenGroups
	if editRefreshSessionDataWithoutBreaking != nil {
		latestRefreshToken := tokenResponse.RefreshToken
		signatureOfLatestRefreshToken := getFositeDataSignature(t, latestRefreshToken)

		// First use the latest downstream refresh token to look up the corresponding session in the Supervisor's storage.
		supervisorSecretsClient := testlib.NewKubernetesClientset(t).CoreV1().Secrets(env.SupervisorNamespace)
		supervisorOIDCClientsClient := testlib.NewSupervisorClientset(t).ConfigV1alpha1().OIDCClients(env.SupervisorNamespace)
		oauthStore := oidc.NewKubeStorage(supervisorSecretsClient, supervisorOIDCClientsClient, oidc.DefaultOIDCTimeoutsConfiguration(), oidcclientvalidator.DefaultMinBcryptCost)
		storedRefreshSession, err := oauthStore.GetRefreshTokenSession(ctx, signatureOfLatestRefreshToken, nil)
		require.NoError(t, err)

		// Next mutate the part of the session that is used during upstream refresh.
		pinnipedSession, ok := storedRefreshSession.GetSession().(*psession.PinnipedSession)
		require.True(t, ok, "should have been able to cast session data to PinnipedSession")

		wantRefreshedGroups = editRefreshSessionDataWithoutBreaking(t, pinnipedSession, idpName, username)

		// Then save the mutated Secret back to Kubernetes.
		// There is no update function, so delete and create again at the same name.
		require.NoError(t, oauthStore.DeleteRefreshTokenSession(ctx, signatureOfLatestRefreshToken))
		require.NoError(t, oauthStore.CreateRefreshTokenSession(ctx, signatureOfLatestRefreshToken, storedRefreshSession))
	}
	// Use the refresh token to get new tokens
	refreshSource := downstreamOAuth2Config.TokenSource(oidcHTTPClientContext, &oauth2.Token{RefreshToken: tokenResponse.RefreshToken})
	refreshedTokenResponse, err := refreshSource.Token()
	require.NoError(t, err)

	// When refreshing, do not expect a "nonce" claim.
	expectRefreshedIDTokenClaims := []string{"iss", "exp", "sub", "aud", "auth_time", "iat", "jti", "rat", "azp", "at_hash"}
	if slices.Contains(wantDownstreamScopes, "username") {
		// If the test wants the username scope to have been granted, then also expect the claim in the refreshed ID token.
		expectRefreshedIDTokenClaims = append(expectRefreshedIDTokenClaims, "username")
	}
	if slices.Contains(wantDownstreamScopes, "groups") {
		// If the test wants the groups scope to have been granted, then also expect the claim in the refreshed ID token.
		expectRefreshedIDTokenClaims = append(expectRefreshedIDTokenClaims, "groups")
	}
	if len(wantDownstreamIDTokenAdditionalClaims) > 0 {
		expectRefreshedIDTokenClaims = append(expectRefreshedIDTokenClaims, "additionalClaims")
	}
	refreshedIDTokenClaims := verifyTokenResponse(
		t,
		refreshedTokenResponse,
		discovery,
		downstreamOAuth2Config,
		"",
		expectRefreshedIDTokenClaims,
		wantDownstreamIDTokenSubjectToMatch,
		wantDownstreamIDTokenUsernameToMatch(username),
		wantRefreshedGroups,
		wantDownstreamIDTokenAdditionalClaims,
	)

	require.NotEqual(t, tokenResponse.AccessToken, refreshedTokenResponse.AccessToken)
	require.NotEqual(t, tokenResponse.RefreshToken, refreshedTokenResponse.RefreshToken)
	require.NotEqual(t, tokenResponse.Extra("id_token"), refreshedTokenResponse.Extra("id_token"))

	// token exchange on the refreshed token
	doTokenExchange(t, requestTokenExchangeAud, &downstreamOAuth2Config, refreshedTokenResponse, httpClient, discovery, wantTokenExchangeResponse, refreshedIDTokenClaims)

	// Now that we have successfully performed a refresh, let's test what happens when an
	// upstream refresh fails during the next downstream refresh.
	if breakRefreshSessionData != nil {
		latestRefreshToken := refreshedTokenResponse.RefreshToken
		signatureOfLatestRefreshToken := getFositeDataSignature(t, latestRefreshToken)

		// First use the latest downstream refresh token to look up the corresponding session in the Supervisor's storage.
		supervisorSecretsClient := testlib.NewKubernetesClientset(t).CoreV1().Secrets(env.SupervisorNamespace)
		supervisorOIDCClientsClient := testlib.NewSupervisorClientset(t).ConfigV1alpha1().OIDCClients(env.SupervisorNamespace)
		oauthStore := oidc.NewKubeStorage(supervisorSecretsClient, supervisorOIDCClientsClient, oidc.DefaultOIDCTimeoutsConfiguration(), oidcclientvalidator.DefaultMinBcryptCost)
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
		require.EqualError(t, err, `oauth2: "error" "Error during upstream refresh. Upstream refresh failed."`)
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
	wantDownstreamIDTokenSubjectToMatch, wantDownstreamIDTokenUsernameToMatch string,
	wantDownstreamIDTokenGroups []string,
	wantDownstreamIDTokenAdditionalClaims map[string]interface{},
) map[string]interface{} {
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

	// There should always be an "azp" claim, and the value should be the client ID of the client which made
	// the authorization request.
	require.Equal(t, downstreamOAuth2Config.ClientID, idTokenClaims["azp"])

	// Check username claim of the ID token, if one is expected. Asserting on the lack of a username claim is
	// handled above where the full list of claims are asserted.
	if wantDownstreamIDTokenUsernameToMatch != "" {
		require.Regexp(t, wantDownstreamIDTokenUsernameToMatch, idTokenClaims["username"].(string))
	}

	// Check the groups claim.
	require.ElementsMatch(t, wantDownstreamIDTokenGroups, idTokenClaims["groups"])

	// Check the "additionalClaims" claim.
	if len(wantDownstreamIDTokenAdditionalClaims) > 0 {
		require.Equal(t, wantDownstreamIDTokenAdditionalClaims, idTokenClaims["additionalClaims"])
	} else {
		require.NotContains(t, idTokenClaims, "additionalClaims", "additionalClaims claim should not be present when no sub claims are expected")
	}

	// Some light verification of the other tokens that were returned.
	require.NotEmpty(t, tokenResponse.AccessToken)
	require.Equal(t, "bearer", tokenResponse.TokenType)
	require.NotZero(t, tokenResponse.Expiry)
	expectedAccessTokenLifetime := oidc.DefaultOIDCTimeoutsConfiguration().AccessTokenLifespan
	testutil.RequireTimeInDelta(t, time.Now().UTC().Add(expectedAccessTokenLifetime), tokenResponse.Expiry, time.Second*30)
	// Access tokens should start with the custom prefix "pin_at_" to make them identifiable as access tokens when seen by a user out of context.
	require.True(t, strings.HasPrefix(tokenResponse.AccessToken, "pin_at_"), "token %q did not have expected prefix 'pin_at_'", tokenResponse.AccessToken)

	require.NotEmpty(t, tokenResponse.RefreshToken)
	// Refresh tokens should start with the custom prefix "pin_rt_" to make them identifiable as refresh tokens when seen by a user out of context.
	require.True(t, strings.HasPrefix(tokenResponse.RefreshToken, "pin_rt_"), "token %q did not have expected prefix 'pin_rt_'", tokenResponse.RefreshToken)

	// The at_hash claim should be present and should be equal to the hash of the access token.
	actualAccessTokenHashClaimValue := idTokenClaims["at_hash"]
	require.NotEmpty(t, actualAccessTokenHashClaimValue)
	require.Equal(t, hashAccessToken(tokenResponse.AccessToken), actualAccessTokenHashClaimValue)

	return idTokenClaims
}

func hashAccessToken(accessToken string) string {
	// See https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken.
	// "Access Token hash value. Its value is the base64url encoding of the left-most half of
	// the hash of the octets of the ASCII representation of the access_token value, where the
	// hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID
	// Token's JOSE Header."
	b := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(b[:len(b)/2])
}

func requestAuthorizationAndExpectImmediateRedirectToCallback(t *testing.T, _, downstreamAuthorizeURL, downstreamCallbackURL, _, _ string, _ *http.Client) {
	t.Helper()

	// Open the web browser and navigate to the downstream authorize URL.
	page := browsertest.Open(t)
	t.Logf("opening browser to downstream authorize URL %s", testlib.MaskTokens(downstreamAuthorizeURL))
	require.NoError(t, page.Navigate(downstreamAuthorizeURL))

	// Expect that it immediately redirects back to the callback, which is what happens for certain types of errors
	// where it is not worth redirecting to the login UI page.
	t.Logf("waiting for redirect to callback")
	callbackURLPattern := regexp.MustCompile(`\A` + regexp.QuoteMeta(downstreamCallbackURL) + `\?.+\z`)
	browsertest.WaitForURL(t, page, callbackURLPattern)
}

func requestAuthorizationUsingBrowserAuthcodeFlowOIDC(t *testing.T, _, downstreamAuthorizeURL, downstreamCallbackURL, _, _ string, httpClient *http.Client) {
	t.Helper()
	env := testlib.IntegrationEnv(t)

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()

	// Make the authorize request once "manually" so we can check its response security headers.
	makeAuthorizationRequestAndRequireSecurityHeaders(ctx, t, downstreamAuthorizeURL, httpClient)

	// Open the web browser and navigate to the downstream authorize URL.
	page := browsertest.Open(t)
	t.Logf("opening browser to downstream authorize URL %s", testlib.MaskTokens(downstreamAuthorizeURL))
	require.NoError(t, page.Navigate(downstreamAuthorizeURL))

	// Expect to be redirected to the upstream provider and log in.
	browsertest.LoginToUpstreamOIDC(t, page, env.SupervisorUpstreamOIDC)

	// Wait for the login to happen and us be redirected back to a localhost callback.
	t.Logf("waiting for redirect to callback")
	callbackURLPattern := regexp.MustCompile(`\A` + regexp.QuoteMeta(downstreamCallbackURL) + `\?.+\z`)
	browsertest.WaitForURL(t, page, callbackURLPattern)
}

func requestAuthorizationUsingBrowserAuthcodeFlowLDAP(t *testing.T, downstreamIssuer, downstreamAuthorizeURL, downstreamCallbackURL, username, password string, httpClient *http.Client) {
	t.Helper()

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()

	// Make the authorize request once "manually" so we can check its response security headers.
	makeAuthorizationRequestAndRequireSecurityHeaders(ctx, t, downstreamAuthorizeURL, httpClient)

	// Open the web browser and navigate to the downstream authorize URL.
	page := browsertest.Open(t)
	t.Logf("opening browser to downstream authorize URL %s", testlib.MaskTokens(downstreamAuthorizeURL))
	require.NoError(t, page.Navigate(downstreamAuthorizeURL))

	// Expect to be redirected to the upstream provider and log in.
	browsertest.LoginToUpstreamLDAP(t, page, downstreamIssuer, username, password)

	// Wait for the login to happen and us be redirected back to a localhost callback.
	t.Logf("waiting for redirect to callback")
	callbackURLPattern := regexp.MustCompile(`\A` + regexp.QuoteMeta(downstreamCallbackURL) + `\?.+\z`)
	browsertest.WaitForURL(t, page, callbackURLPattern)
}

func requestAuthorizationUsingBrowserAuthcodeFlowLDAPWithBadCredentials(t *testing.T, downstreamIssuer, downstreamAuthorizeURL, _, username, password string, _ *http.Client) {
	t.Helper()

	// Open the web browser and navigate to the downstream authorize URL.
	page := browsertest.Open(t)
	t.Logf("opening browser to downstream authorize URL %s", testlib.MaskTokens(downstreamAuthorizeURL))
	require.NoError(t, page.Navigate(downstreamAuthorizeURL))

	// This functions assumes that it has been passed either a bad username or a bad password, and submits the
	// provided credentials. Expect to be redirected to the upstream provider and attempt to log in.
	browsertest.LoginToUpstreamLDAP(t, page, downstreamIssuer, username, password)

	// After failing login expect to land back on the login page again with an error message.
	browsertest.WaitForUpstreamLDAPLoginPageWithError(t, page, downstreamIssuer)
}

func requestAuthorizationUsingBrowserAuthcodeFlowLDAPWithBadCredentialsAndThenGoodCredentials(t *testing.T, downstreamIssuer, downstreamAuthorizeURL, _, username, password string, _ *http.Client) {
	t.Helper()

	// Open the web browser and navigate to the downstream authorize URL.
	page := browsertest.Open(t)
	t.Logf("opening browser to downstream authorize URL %s", testlib.MaskTokens(downstreamAuthorizeURL))
	require.NoError(t, page.Navigate(downstreamAuthorizeURL))

	// Expect to be redirected to the upstream provider and attempt to log in.
	browsertest.LoginToUpstreamLDAP(t, page, downstreamIssuer, username, "this is the wrong password!")

	// After failing login expect to land back on the login page again with an error message.
	browsertest.WaitForUpstreamLDAPLoginPageWithError(t, page, downstreamIssuer)

	// Already at the login page, so this time can directly submit it using the provided username and password.
	browsertest.SubmitUpstreamLDAPLoginForm(t, page, username, password)
}

func makeAuthorizationRequestAndRequireSecurityHeaders(ctx context.Context, t *testing.T, downstreamAuthorizeURL string, httpClient *http.Client) {
	authorizeRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, downstreamAuthorizeURL, nil)
	require.NoError(t, err)
	authorizeResp, err := httpClient.Do(authorizeRequest)
	require.NoError(t, err)
	require.NoError(t, authorizeResp.Body.Close())
	expectSecurityHeaders(t, authorizeResp, false)
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
		responseBody, err = io.ReadAll(authResponse.Body)
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

func (s *localCallbackServer) waitForCallback(timeout time.Duration) (*http.Request, error) {
	select {
	case callback := <-s.callbacks:
		return callback, nil
	case <-time.After(timeout):
		return nil, errors.New("timed out waiting for callback request")
	}
}

func doTokenExchange(
	t *testing.T,
	requestTokenExchangeAud string,
	config *oauth2.Config,
	tokenResponse *oauth2.Token,
	httpClient *http.Client,
	provider *coreosoidc.Provider,
	wantTokenExchangeResponse func(t *testing.T, status int, body string),
	previousIDTokenClaims map[string]interface{},
) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Form the HTTP POST request with the parameters specified by RFC8693.
	reqBody := strings.NewReader(url.Values{
		"grant_type":           []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             []string{requestTokenExchangeAud},
		"client_id":            []string{config.ClientID},
		"subject_token":        []string{tokenResponse.AccessToken},
		"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": []string{"urn:ietf:params:oauth:token-type:jwt"},
	}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.Endpoint.TokenURL, reqBody)
	require.NoError(t, err)
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	if config.ClientSecret != "" {
		// We only support basic auth for dynamic clients, so use basic auth in these tests.
		req.SetBasicAuth(config.ClientID, config.ClientSecret)
	}

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// If a function was passed, call it, so it can make the desired assertions.
	if wantTokenExchangeResponse != nil {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		wantTokenExchangeResponse(t, resp.StatusCode, string(body))
		return // the above call should have made all desired assertions about the response, so return
	}

	// Else, want a successful response.
	require.Equal(t, resp.StatusCode, http.StatusOK)

	var respBody struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))

	// Note that this validates the "aud" claim, among other things.
	var clusterVerifier = provider.Verifier(&coreosoidc.Config{ClientID: requestTokenExchangeAud})
	exchangedToken, err := clusterVerifier.Verify(ctx, respBody.AccessToken)
	require.NoError(t, err)

	var claims map[string]interface{}
	require.NoError(t, exchangedToken.Claims(&claims))
	indentedClaims, err := json.MarshalIndent(claims, "   ", "  ")
	require.NoError(t, err)
	t.Logf("exchanged token claims:\n%s", string(indentedClaims))

	// Some claims should be identical to the previously issued ID token.
	require.Equal(t, previousIDTokenClaims["iss"], claims["iss"])
	require.Equal(t, previousIDTokenClaims["sub"], claims["sub"])
	require.Equal(t, previousIDTokenClaims["username"], claims["username"])
	require.Equal(t, previousIDTokenClaims["groups"], claims["groups"])                     // may be nil in some test cases
	require.Equal(t, previousIDTokenClaims["additionalClaims"], claims["additionalClaims"]) // may be nil in some test cases
	require.Equal(t, previousIDTokenClaims["auth_time"], claims["auth_time"])
	require.Contains(t, claims, "rat") // requested at
	require.Contains(t, claims, "iat") // issued at
	require.Contains(t, claims, "exp") // expires at
	require.Contains(t, claims, "jti") // JWT ID

	// The original client ID should be preserved in the azp claim, therefore preserving this information
	// about the original source of the authorization for tracing/auditing purposes, since the "aud" claim
	// has been updated to have a new value.
	require.Equal(t, config.ClientID, claims["azp"])
}

func expectSecurityHeaders(t *testing.T, response *http.Response, expectFositeToOverrideSome bool) {
	h := response.Header

	cspHeader := h.Get("Content-Security-Policy")
	require.Contains(t, cspHeader, "script-src '") // loose assertion
	require.Contains(t, cspHeader, "style-src '")  // loose assertion
	require.Contains(t, cspHeader, "img-src data:")
	require.Contains(t, cspHeader, "connect-src *")
	require.Contains(t, cspHeader, "default-src 'none'")
	require.Contains(t, cspHeader, "frame-ancestors 'none'")

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
