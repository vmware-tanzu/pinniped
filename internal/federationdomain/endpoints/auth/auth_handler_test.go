// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/ptr"

	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	"go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/config/v1alpha1"
	"go.pinniped.dev/internal/authenticators"
	"go.pinniped.dev/internal/federationdomain/csrftoken"
	"go.pinniped.dev/internal/federationdomain/endpoints/jwks"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/oidcclientvalidator"
	"go.pinniped.dev/internal/federationdomain/requestlogger"
	"go.pinniped.dev/internal/federationdomain/stateparam"
	"go.pinniped.dev/internal/federationdomain/storage"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/testidplister"
	"go.pinniped.dev/internal/testutil/transformtestutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

func TestAuthorizationEndpoint(t *testing.T) { //nolint:gocyclo
	const (
		oidcUpstreamName                     = "some-oidc-idp"
		oidcUpstreamResourceUID              = "oidc-resource-uid"
		oidcPasswordGrantUpstreamName        = "some-password-granting-oidc-idp"
		oidcPasswordGrantUpstreamResourceUID = "some-password-granting-resource-uid"
		ldapUpstreamName                     = "some-ldap-idp"
		ldapUpstreamResourceUID              = "ldap-resource-uid"
		activeDirectoryUpstreamName          = "some-active-directory-idp"
		activeDirectoryUpstreamResourceUID   = "active-directory-resource-uid"
		githubUpstreamName                   = "some-github-idp"
		githubUpstreamResourceUID            = "github-resource-uid"

		oidcUpstreamIssuer                    = "https://my-upstream-issuer.com"
		oidcUpstreamSubject                   = "abc123-some guid" // has a space character which should get escaped in URL
		oidcUpstreamSubjectQueryEscaped       = "abc123-some+guid"
		oidcUpstreamUsername                  = "test-oidc-pinniped-username"
		oidcUpstreamPassword                  = "test-oidc-pinniped-password" //nolint:gosec
		oidcUpstreamUsernameClaim             = "the-user-claim"
		oidcUpstreamGroupsClaim               = "the-groups-claim"
		oidcPasswordGrantUpstreamRefreshToken = "some-opaque-token" //nolint:gosec
		oidcUpstreamAccessToken               = "some-access-token"

		downstreamIssuer                       = "https://my-downstream-issuer.com/some-path"
		downstreamRedirectURI                  = "http://127.0.0.1/callback"
		downstreamRedirectURIWithDifferentPort = "http://127.0.0.1:42/callback"
		downstreamNonce                        = "some-nonce-value"
		downstreamPKCEChallenge                = "some-challenge"
		downstreamPKCEChallengeMethod          = "S256"
		happyState                             = "8b-state"
		upstreamLDAPURL                        = "ldaps://some-ldap-host:123?base=ou%3Dusers%2Cdc%3Dpinniped%2Cdc%3Ddev"
		plainContentType                       = "text/plain; charset=utf-8"
		htmlContentType                        = "text/html; charset=utf-8"
		jsonContentType                        = "application/json; charset=utf-8"
		formContentType                        = "application/x-www-form-urlencoded"

		pinnipedCLIClientID = "pinniped-cli"
		dynamicClientID     = "client.oauth.pinniped.dev-test-name"
		dynamicClientUID    = "fake-client-uid"

		transformationUsernamePrefix = "username_prefix:"
		transformationGroupsPrefix   = "groups_prefix:"
	)

	require.Len(t, happyState, 8, "we expect fosite to allow 8 byte state params, so we want to test that boundary case")

	var (
		oidcUpstreamGroupMembership = []string{"test-pinniped-group-0", "test-pinniped-group-1"}

		fositeInvalidClientErrorBody = here.Doc(`
			{
				"error":             "invalid_client",
				"error_description": "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
			 }
		`)

		fositeInvalidRedirectURIErrorBody = here.Doc(`
			{
				"error":             "invalid_request",
				"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls."
			}
		`)

		fositePromptHasNoneAndOtherValueErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Parameter 'prompt' was set to 'none', but contains other values as well which is not allowed.",
			"state":             happyState,
		}

		fositeMissingCodeChallengeErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a code_challenge when performing the authorize code flow, but it is missing.",
			"state":             happyState,
		}

		fositeMissingCodeChallengeMethodErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must use code_challenge_method=S256, plain is not allowed.",
			"state":             happyState,
		}

		fositeInvalidCodeChallengeErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The code_challenge_method is not supported, use S256 instead.",
			"state":             happyState,
		}

		fositeUnsupportedResponseTypeErrorQuery = map[string]string{
			"error":             "unsupported_response_type",
			"error_description": "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'unsupported'.",
			"state":             happyState,
		}

		fositeInvalidScopeErrorQuery = map[string]string{
			"error":             "invalid_scope",
			"error_description": "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'tuna'.",
			"state":             happyState,
		}

		fositeInvalidStateErrorQuery = map[string]string{
			"error":             "invalid_state",
			"error_description": "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy.",
			"state":             "short",
		}

		fositeMissingResponseTypeErrorQuery = map[string]string{
			"error":             "unsupported_response_type",
			"error_description": "The authorization server does not support obtaining a token using this method. `The request is missing the 'response_type' parameter.",
			"state":             happyState,
		}

		fositeAccessDeniedErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Make sure that the request you are making is valid. Maybe the credential or request parameters you are using are limited in scope or otherwise restricted.",
			"state":             happyState,
		}

		fositeAccessDeniedWithBadUsernamePasswordHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Username/password not accepted by LDAP provider.",
			"state":             happyState,
		}

		fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Missing or blank username or password.",
			"state":             happyState,
		}

		fositeAccessDeniedWithMissingAccessTokenErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Reason: neither access token nor refresh token returned by upstream provider.",
			"state":             happyState,
		}

		fositeAccessDeniedWithMissingUserInfoEndpointErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Reason: access token was returned by upstream provider but there was no userinfo endpoint.",
			"state":             happyState,
		}

		fositeAccessDeniedWithPasswordGrantDisallowedHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Resource owner password credentials grant is not allowed for this upstream provider according to its configuration.",
			"state":             happyState,
		}

		fositeAccessDeniedWithUsernamePasswordHeadersDisallowedHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. This client is not allowed to submit username or password headers to this endpoint.",
			"state":             happyState,
		}

		fositeAccessDeniedWithInvalidEmailVerifiedHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Reason: email_verified claim in upstream ID token has invalid format.",
			"state":             happyState,
		}

		fositeAccessDeniedWithFalseEmailVerifiedHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Reason: email_verified claim in upstream ID token has false value.",
			"state":             happyState,
		}

		fositeAccessDeniedWithRequiredClaimMissingHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Reason: required claim in upstream ID token missing.",
			"state":             happyState,
		}

		fositeAccessDeniedWithRequiredClaimEmptyHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Reason: required claim in upstream ID token is empty.",
			"state":             happyState,
		}

		fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Reason: required claim in upstream ID token has invalid format.",
			"state":             happyState,
		}

		fositeAccessDeniedWithConfiguredPolicyRejectionHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Reason: configured identity policy rejected this authentication: authentication was rejected by a configured policy.",
			"state":             happyState,
		}

		fositeLoginRequiredErrorQuery = map[string]string{
			"error":             "login_required",
			"error_description": "The Authorization Server requires End-User authentication.",
			"state":             happyState,
		}

		fositeUpstreamAuthErrorQuery = map[string]string{
			"error":             "error",
			"error_description": "Unexpected error during upstream LDAP authentication.",
			"state":             happyState,
		}

		fositeInternalServerErrorQueryWithHint = func(hint string) map[string]string {
			return map[string]string{
				"error": "server_error",
				"error_description": fmt.Sprintf(
					"The authorization server encountered an unexpected condition that prevented it from fulfilling the request. %s",
					hint,
				),
				"state": happyState,
			}
		}
	)

	hmacSecretFunc := func() []byte { return []byte("some secret - must have at least 32 bytes") }
	require.GreaterOrEqual(t, len(hmacSecretFunc()), 32, "fosite requires that hmac secrets have at least 32 bytes")
	jwksProviderIsUnused := jwks.NewDynamicJWKSProvider()
	timeoutsConfiguration := oidc.DefaultOIDCTimeoutsConfiguration()

	createOauthHelperWithRealStorage := func(secretsClient v1.SecretInterface, oidcClientsClient v1alpha1.OIDCClientInterface) (fosite.OAuth2Provider, *storage.KubeStorage) {
		// Configure fosite the same way that the production code would when using Kube storage.
		// Inject this into our test subject at the last second so we get a fresh storage for every test.
		// Use lower minimum required bcrypt cost than we would use in production to keep unit the tests fast.
		kubeOauthStore := storage.NewKubeStorage(secretsClient, oidcClientsClient, timeoutsConfiguration, bcrypt.MinCost)
		return oidc.FositeOauth2Helper(kubeOauthStore, downstreamIssuer, hmacSecretFunc, jwksProviderIsUnused, timeoutsConfiguration), kubeOauthStore
	}

	createOauthHelperWithNullStorage := func(secretsClient v1.SecretInterface, oidcClientsClient v1alpha1.OIDCClientInterface) (fosite.OAuth2Provider, *storage.NullStorage) {
		// Configure fosite the same way that the production code would, using NullStorage to turn off storage.
		// Use lower minimum required bcrypt cost than we would use in production to keep unit the tests fast.
		nullOauthStore := storage.NewNullStorage(secretsClient, oidcClientsClient, bcrypt.MinCost)
		return oidc.FositeOauth2Helper(nullOauthStore, downstreamIssuer, hmacSecretFunc, jwksProviderIsUnused, timeoutsConfiguration), nullOauthStore
	}

	upstreamAuthURL, err := url.Parse("https://some-upstream-idp:8443/auth")
	require.NoError(t, err)

	upstreamOIDCIdentityProviderBuilder := func() *oidctestutil.TestUpstreamOIDCIdentityProviderBuilder {
		return oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
			WithName(oidcUpstreamName).
			WithResourceUID(oidcUpstreamResourceUID).
			WithClientID("some-client-id").
			WithAuthorizationURL(*upstreamAuthURL).
			WithScopes([]string{"scope1", "scope2"}). // the scopes to request when starting the upstream authorization flow
			WithAllowPasswordGrant(false).
			WithAdditionalAuthcodeParams(map[string]string{}).
			WithPasswordGrantError(errors.New("should not have used password grant on this instance"))
	}

	upstreamGitHubIdentityProviderBuilder := func() *oidctestutil.TestUpstreamGitHubIdentityProviderBuilder {
		return oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
			WithName(githubUpstreamName).
			WithResourceUID(githubUpstreamResourceUID).
			WithClientID("some-github-client-id").
			WithAuthorizationURL(upstreamAuthURL.String()).
			WithScopes([]string{"scope1", "scope2"}) // the scopes to request when starting the upstream authorization flow
	}

	passwordGrantUpstreamOIDCIdentityProviderBuilder := func() *oidctestutil.TestUpstreamOIDCIdentityProviderBuilder {
		return oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
			WithName(oidcPasswordGrantUpstreamName).
			WithResourceUID(oidcPasswordGrantUpstreamResourceUID).
			WithClientID("some-client-id").
			WithAuthorizationURL(*upstreamAuthURL).
			WithScopes([]string{"scope1", "scope2"}). // the scopes to request when starting the upstream authorization flow
			WithAllowPasswordGrant(false).
			WithUsernameClaim(oidcUpstreamUsernameClaim).
			WithGroupsClaim(oidcUpstreamGroupsClaim).
			WithIDTokenClaim("iss", oidcUpstreamIssuer).
			WithIDTokenClaim("sub", oidcUpstreamSubject).
			WithIDTokenClaim(oidcUpstreamUsernameClaim, oidcUpstreamUsername).
			WithIDTokenClaim(oidcUpstreamGroupsClaim, oidcUpstreamGroupMembership).
			WithIDTokenClaim("other-claim", "should be ignored").
			WithAllowPasswordGrant(true).
			WithRefreshToken(oidcPasswordGrantUpstreamRefreshToken).
			WithAdditionalAuthcodeParams(map[string]string{"should-be-ignored": "doesn't apply to password grant"}).
			WithUpstreamAuthcodeExchangeError(errors.New("should not have tried to exchange upstream authcode on this instance"))
	}

	happyUpstreamPasswordGrantMockExpectation := &expectedPasswordGrant{
		performedByUpstreamName: oidcPasswordGrantUpstreamName,
		args: &oidctestutil.PasswordCredentialsGrantAndValidateTokensArgs{
			Username: oidcUpstreamUsername,
			Password: oidcUpstreamPassword,
		},
	}

	happyLDAPUsername := "some-ldap-user"
	happyLDAPUsernameFromAuthenticator := "some-ldap-username-from-authenticator"
	happyLDAPPassword := "some-ldap-password" //nolint:gosec
	happyLDAPUID := "some-ldap-uid"
	happyLDAPUserDN := "cn=foo,dn=bar"
	happyLDAPGroups := []string{"group1", "group2", "group3"}
	happyLDAPExtraRefreshAttribute := "some-refresh-attribute"
	happyLDAPExtraRefreshValue := "some-refresh-attribute-value"

	parsedUpstreamLDAPURL, err := url.Parse(upstreamLDAPURL)
	require.NoError(t, err)

	ldapAuthenticateFunc := func(ctx context.Context, username, password string) (*authenticators.Response, bool, error) {
		if username == "" || password == "" {
			return nil, false, fmt.Errorf("should not have passed empty username or password to the authenticator")
		}
		if username == happyLDAPUsername && password == happyLDAPPassword {
			return &authenticators.Response{
				User: &user.DefaultInfo{
					Name:   happyLDAPUsernameFromAuthenticator,
					UID:    happyLDAPUID,
					Groups: happyLDAPGroups,
				},
				DN: happyLDAPUserDN,
				ExtraRefreshAttributes: map[string]string{
					happyLDAPExtraRefreshAttribute: happyLDAPExtraRefreshValue,
				},
			}, true, nil
		}
		return nil, false, nil
	}

	upstreamLDAPIdentityProviderBuilder := func() *oidctestutil.TestUpstreamLDAPIdentityProviderBuilder {
		return oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
			WithName(ldapUpstreamName).
			WithResourceUID(ldapUpstreamResourceUID).
			WithURL(parsedUpstreamLDAPURL).
			WithAuthenticateFunc(ldapAuthenticateFunc)
	}

	upstreamActiveDirectoryIdentityProviderBuilder := func() *oidctestutil.TestUpstreamLDAPIdentityProviderBuilder {
		return oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
			WithName(activeDirectoryUpstreamName).
			WithResourceUID(activeDirectoryUpstreamResourceUID).
			WithURL(parsedUpstreamLDAPURL).
			WithAuthenticateFunc(ldapAuthenticateFunc)
	}

	erroringUpstreamLDAPIdentityProvider := oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
		WithName(ldapUpstreamName).
		WithResourceUID(ldapUpstreamResourceUID).
		WithAuthenticateFunc(func(ctx context.Context, username, password string) (*authenticators.Response, bool, error) {
			return nil, false, fmt.Errorf("some ldap upstream auth error")
		}).Build()

	happyCSRF := "test-csrf"
	happyPKCE := "test-pkce"
	happyNonce := "test-nonce"
	happyCSRFGenerator := func() (csrftoken.CSRFToken, error) { return csrftoken.CSRFToken(happyCSRF), nil }
	happyPKCEGenerator := func() (pkce.Code, error) { return pkce.Code(happyPKCE), nil }
	happyNonceGenerator := func() (nonce.Nonce, error) { return nonce.Nonce(happyNonce), nil }
	sadCSRFGenerator := func() (csrftoken.CSRFToken, error) { return "", fmt.Errorf("some csrf generator error") }
	sadPKCEGenerator := func() (pkce.Code, error) { return "", fmt.Errorf("some PKCE generator error") }
	sadNonceGenerator := func() (nonce.Nonce, error) { return "", fmt.Errorf("some nonce generator error") }
	expectedUpstreamCodeChallenge := testutil.SHA256("test-pkce")

	var stateEncoderHashKey = []byte("fake-hash-secret")
	var stateEncoderBlockKey = []byte("0123456789ABCDEF") // block encryption requires 16/24/32 bytes for AES
	var cookieEncoderHashKey = []byte("fake-hash-secret2")
	var cookieEncoderBlockKey = []byte("0123456789ABCDE2") // block encryption requires 16/24/32 bytes for AES
	require.NotEqual(t, stateEncoderHashKey, cookieEncoderHashKey)
	require.NotEqual(t, stateEncoderBlockKey, cookieEncoderBlockKey)

	var happyStateEncoder = securecookie.New(stateEncoderHashKey, stateEncoderBlockKey)
	happyStateEncoder.SetSerializer(securecookie.JSONEncoder{})
	var happyCookieEncoder = securecookie.New(cookieEncoderHashKey, cookieEncoderBlockKey)
	happyCookieEncoder.SetSerializer(securecookie.JSONEncoder{})

	encodeQuery := func(query map[string]string) string {
		values := url.Values{}
		for k, v := range query {
			values[k] = []string{v}
		}
		return values.Encode()
	}

	pathWithQuery := func(path string, query map[string]string) string {
		pathToReturn := fmt.Sprintf("%s?%s", path, encodeQuery(query))
		require.NotRegexp(t, "^http", pathToReturn, "pathWithQuery helper was used to create a URL")
		return pathToReturn
	}

	urlWithQuery := func(baseURL string, query map[string]string) string {
		urlToReturn := fmt.Sprintf("%s?%s", baseURL, encodeQuery(query))
		_, err := url.Parse(urlToReturn)
		require.NoError(t, err, "urlWithQuery helper was used to create an illegal URL")
		return urlToReturn
	}

	happyDownstreamScopesRequested := []string{"openid", "profile", "email", "username", "groups"}
	happyDownstreamScopesGranted := []string{"openid", "username", "groups"}

	happyGetRequestQueryMap := map[string]string{
		"response_type":         "code",
		"scope":                 strings.Join(happyDownstreamScopesRequested, " "),
		"client_id":             pinnipedCLIClientID,
		"state":                 happyState,
		"nonce":                 downstreamNonce,
		"code_challenge":        downstreamPKCEChallenge,
		"code_challenge_method": downstreamPKCEChallengeMethod,
		"redirect_uri":          downstreamRedirectURI,
	}

	happyGetRequestPath := pathWithQuery("/some/path", happyGetRequestQueryMap)

	modifiedQueryMap := func(modifyThisMap map[string]string, queryOverrides map[string]string) map[string]string {
		copyModifyThisMap := map[string]string{}
		for k, v := range modifyThisMap {
			copyModifyThisMap[k] = v
		}
		for k, v := range queryOverrides {
			_, hasKey := copyModifyThisMap[k]
			if v == "" && hasKey {
				delete(copyModifyThisMap, k)
			} else {
				copyModifyThisMap[k] = v
			}
		}
		return copyModifyThisMap
	}

	modifiedHappyGetRequestQueryMap := func(queryOverrides map[string]string) map[string]string {
		return modifiedQueryMap(happyGetRequestQueryMap, queryOverrides)
	}

	modifiedHappyGetRequestPath := func(queryOverrides map[string]string) string {
		return pathWithQuery("/some/path", modifiedHappyGetRequestQueryMap(queryOverrides))
	}

	happyGetRequestPathForOIDCUpstream := modifiedHappyGetRequestPath(map[string]string{"pinniped_idp_name": oidcUpstreamName})
	happyGetRequestPathForOIDCPasswordGrantUpstream := modifiedHappyGetRequestPath(map[string]string{"pinniped_idp_name": oidcPasswordGrantUpstreamName})
	happyGetRequestPathForLDAPUpstream := modifiedHappyGetRequestPath(map[string]string{"pinniped_idp_name": ldapUpstreamName})
	happyGetRequestPathForADUpstream := modifiedHappyGetRequestPath(map[string]string{"pinniped_idp_name": activeDirectoryUpstreamName})
	happyGetRequestPathForGithubUpstream := modifiedHappyGetRequestPath(map[string]string{"pinniped_idp_name": githubUpstreamName})

	modifiedHappyGetRequestPathForOIDCUpstream := func(queryOverrides map[string]string) string {
		queryOverrides["pinniped_idp_name"] = oidcUpstreamName
		return modifiedHappyGetRequestPath(queryOverrides)
	}
	modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream := func(queryOverrides map[string]string) string {
		queryOverrides["pinniped_idp_name"] = oidcPasswordGrantUpstreamName
		return modifiedHappyGetRequestPath(queryOverrides)
	}
	modifiedHappyGetRequestPathForLDAPUpstream := func(queryOverrides map[string]string) string {
		queryOverrides["pinniped_idp_name"] = ldapUpstreamName
		return modifiedHappyGetRequestPath(queryOverrides)
	}
	modifiedHappyGetRequestPathForADUpstream := func(queryOverrides map[string]string) string {
		queryOverrides["pinniped_idp_name"] = activeDirectoryUpstreamName
		return modifiedHappyGetRequestPath(queryOverrides)
	}
	modifiedHappyGetRequestPathForGithubUpstream := func(queryOverrides map[string]string) string {
		queryOverrides["pinniped_idp_name"] = githubUpstreamName
		return modifiedHappyGetRequestPath(queryOverrides)
	}

	happyGetRequestQueryMapForOIDCUpstream := modifiedQueryMap(happyGetRequestQueryMap, map[string]string{"pinniped_idp_name": oidcUpstreamName})
	happyGetRequestQueryMapForOIDCPasswordGrantUpstream := modifiedQueryMap(happyGetRequestQueryMap, map[string]string{"pinniped_idp_name": oidcPasswordGrantUpstreamName})
	happyGetRequestQueryMapForLDAPUpstream := modifiedQueryMap(happyGetRequestQueryMap, map[string]string{"pinniped_idp_name": ldapUpstreamName})
	happyGetRequestQueryMapForADUpstream := modifiedQueryMap(happyGetRequestQueryMap, map[string]string{"pinniped_idp_name": activeDirectoryUpstreamName})

	modifiedHappyGetRequestQueryMapForOIDCUpstream := func(queryOverrides map[string]string) map[string]string {
		return modifiedQueryMap(happyGetRequestQueryMapForOIDCUpstream, queryOverrides)
	}
	modifiedHappyGetRequestQueryMapForLDAPUpstream := func(queryOverrides map[string]string) map[string]string {
		return modifiedQueryMap(happyGetRequestQueryMapForLDAPUpstream, queryOverrides)
	}
	modifiedHappyGetRequestQueryMapForADUpstream := func(queryOverrides map[string]string) map[string]string {
		return modifiedQueryMap(happyGetRequestQueryMapForADUpstream, queryOverrides)
	}

	expectedUpstreamStateParam := func(queryOverrides map[string]string, csrfValueOverride, upstreamName, upstreamType string) string {
		csrf := happyCSRF
		if csrfValueOverride != "" {
			csrf = csrfValueOverride
		}
		encoded, err := happyStateEncoder.Encode("s",
			oidctestutil.ExpectedUpstreamStateParamFormat{
				P: encodeQuery(modifiedHappyGetRequestQueryMap(queryOverrides)),
				U: upstreamName,
				T: upstreamType,
				N: happyNonce,
				C: csrf,
				K: happyPKCE,
				V: "2",
			},
		)
		require.NoError(t, err)
		return encoded
	}

	expectedRedirectLocationForUpstreamOIDC := func(expectedUpstreamState string, expectedAdditionalParams map[string]string) string {
		query := map[string]string{
			"response_type":         "code",
			"scope":                 "scope1 scope2",
			"client_id":             "some-client-id",
			"state":                 expectedUpstreamState,
			"nonce":                 happyNonce,
			"code_challenge":        expectedUpstreamCodeChallenge,
			"code_challenge_method": downstreamPKCEChallengeMethod,
			"redirect_uri":          downstreamIssuer + "/callback",
		}
		for key, val := range expectedAdditionalParams {
			query[key] = val
		}
		return urlWithQuery(upstreamAuthURL.String(), query)
	}

	expectedRedirectLocationForUpstreamGithub := func(expectedUpstreamState string) string {
		query := map[string]string{
			"response_type": "code",
			"scope":         "scope1 scope2",
			"client_id":     "some-github-client-id",
			"state":         expectedUpstreamState,
			"redirect_uri":  downstreamIssuer + "/callback",
		}
		return urlWithQuery(upstreamAuthURL.String(), query)
	}

	expectedHappyActiveDirectoryUpstreamCustomSession := &psession.CustomSessionData{
		Username:         happyLDAPUsernameFromAuthenticator,
		UpstreamUsername: happyLDAPUsernameFromAuthenticator,
		UpstreamGroups:   happyLDAPGroups,
		ProviderUID:      activeDirectoryUpstreamResourceUID,
		ProviderName:     activeDirectoryUpstreamName,
		ProviderType:     psession.ProviderTypeActiveDirectory,
		OIDC:             nil,
		LDAP:             nil,
		ActiveDirectory: &psession.ActiveDirectorySessionData{
			UserDN:                 happyLDAPUserDN,
			ExtraRefreshAttributes: map[string]string{happyLDAPExtraRefreshAttribute: happyLDAPExtraRefreshValue},
		},
	}

	expectedHappyLDAPUpstreamCustomSession := &psession.CustomSessionData{
		Username:         happyLDAPUsernameFromAuthenticator,
		UpstreamUsername: happyLDAPUsernameFromAuthenticator,
		UpstreamGroups:   happyLDAPGroups,
		ProviderUID:      ldapUpstreamResourceUID,
		ProviderName:     ldapUpstreamName,
		ProviderType:     psession.ProviderTypeLDAP,
		OIDC:             nil,
		LDAP: &psession.LDAPSessionData{
			UserDN:                 happyLDAPUserDN,
			ExtraRefreshAttributes: map[string]string{happyLDAPExtraRefreshAttribute: happyLDAPExtraRefreshValue},
		},
		ActiveDirectory: nil,
	}

	expectedHappyOIDCPasswordGrantCustomSession := &psession.CustomSessionData{
		Username:         oidcUpstreamUsername,
		UpstreamUsername: oidcUpstreamUsername,
		UpstreamGroups:   oidcUpstreamGroupMembership,
		ProviderUID:      oidcPasswordGrantUpstreamResourceUID,
		ProviderName:     oidcPasswordGrantUpstreamName,
		ProviderType:     psession.ProviderTypeOIDC,
		OIDC: &psession.OIDCSessionData{
			UpstreamRefreshToken: oidcPasswordGrantUpstreamRefreshToken,
			UpstreamSubject:      oidcUpstreamSubject,
			UpstreamIssuer:       oidcUpstreamIssuer,
		},
	}

	expectedHappyOIDCPasswordGrantCustomSessionWithAccessToken := &psession.CustomSessionData{
		Username:         oidcUpstreamUsername,
		UpstreamUsername: oidcUpstreamUsername,
		UpstreamGroups:   oidcUpstreamGroupMembership,
		ProviderUID:      oidcPasswordGrantUpstreamResourceUID,
		ProviderName:     oidcPasswordGrantUpstreamName,
		ProviderType:     psession.ProviderTypeOIDC,
		OIDC: &psession.OIDCSessionData{
			UpstreamAccessToken: oidcUpstreamAccessToken,
			UpstreamSubject:     oidcUpstreamSubject,
			UpstreamIssuer:      oidcUpstreamIssuer,
		},
	}

	withUsernameAndGroupsInCustomSession := func(expectedCustomSessionData *psession.CustomSessionData, wantDownstreamUsername string, wantUpstreamUsername string, wantUpstreamGroups []string) *psession.CustomSessionData {
		copyOfCustomSession := *expectedCustomSessionData
		if expectedCustomSessionData.LDAP != nil {
			copyOfLDAP := *(expectedCustomSessionData.LDAP)
			copyOfCustomSession.LDAP = &copyOfLDAP
		}
		if expectedCustomSessionData.OIDC != nil {
			copyOfOIDC := *(expectedCustomSessionData.OIDC)
			copyOfCustomSession.OIDC = &copyOfOIDC
		}
		if expectedCustomSessionData.ActiveDirectory != nil {
			copyOfActiveDirectory := *(expectedCustomSessionData.ActiveDirectory)
			copyOfCustomSession.ActiveDirectory = &copyOfActiveDirectory
		}
		copyOfCustomSession.Username = wantDownstreamUsername
		copyOfCustomSession.UpstreamUsername = wantUpstreamUsername
		copyOfCustomSession.UpstreamGroups = wantUpstreamGroups
		return &copyOfCustomSession
	}

	addFullyCapableDynamicClientAndSecretToKubeResources := func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
		oidcClient, secret := testutil.FullyCapableOIDCClientAndStorageSecret(t,
			"some-namespace", dynamicClientID, dynamicClientUID, downstreamRedirectURI, nil,
			[]string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
		require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
		require.NoError(t, kubeClient.Tracker().Add(secret))
	}

	// Note that fosite puts the granted scopes as a param in the redirect URI even though the spec doesn't seem to require it
	happyAuthcodeDownstreamRedirectLocationRegexp := downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+username\+groups&state=` + happyState

	incomingCookieCSRFValue := "csrf-value-from-cookie"
	encodedIncomingCookieCSRFValue, err := happyCookieEncoder.Encode("csrf", incomingCookieCSRFValue)
	require.NoError(t, err)

	prefixUsernameAndGroupsPipeline := transformtestutil.NewPrefixingPipeline(t, transformationUsernamePrefix, transformationGroupsPrefix)
	rejectAuthPipeline := transformtestutil.NewRejectAllAuthPipeline(t)

	type testCase struct {
		name string

		idps                 *testidplister.UpstreamIDPListerBuilder
		kubeResources        func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset)
		generateCSRF         func() (csrftoken.CSRFToken, error)
		generatePKCE         func() (pkce.Code, error)
		generateNonce        func() (nonce.Nonce, error)
		stateEncoder         oidc.Codec
		cookieEncoder        oidc.Codec
		method               string
		path                 string
		contentType          string
		body                 string
		csrfCookie           string
		customUsernameHeader *string // nil means do not send header, empty means send header with empty value
		customPasswordHeader *string // nil means do not send header, empty means send header with empty value

		wantStatus                             int
		wantContentType                        string
		wantBodyString                         string
		wantBodyRegex                          string
		wantBodyJSON                           string
		wantCSRFValueInCookieHeader            string
		wantBodyStringWithLocationInHref       bool
		wantLocationHeader                     string
		wantUpstreamStateParamInLocationHeader bool
		wantAuditLogs                          func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog

		// Assertions for when an authcode should be returned, i.e. the request was authenticated by an
		// upstream LDAP provider or an upstream OIDC password grant flow.
		wantRedirectLocationRegexp        string
		wantDownstreamRedirectURI         string
		wantDownstreamGrantedScopes       []string
		wantDownstreamIDTokenSubject      string
		wantDownstreamIDTokenUsername     string
		wantDownstreamIDTokenGroups       []string
		wantDownstreamRequestedScopes     []string
		wantDownstreamPKCEChallenge       string
		wantDownstreamPKCEChallengeMethod string
		wantDownstreamNonce               string
		wantDownstreamClientID            string // defaults to wanting "pinniped-cli" when not set
		wantUnnecessaryStoredRecords      int
		wantPasswordGrantCall             *expectedPasswordGrant
		wantDownstreamCustomSessionData   *psession.CustomSessionData
		wantDownstreamAdditionalClaims    map[string]any
	}
	tests := []testCase{
		{
			name:                                   "OIDC upstream browser flow happy path using GET without a CSRF cookie",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPathForOIDCUpstream,
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": false,
						"Pinniped-Password": false,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": "client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-oidc-idp&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted",
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-oidc-idp",
						"resourceName": "some-oidc-idp",
						"resourceUID":  "oidc-resource-uid",
						"type":         "oidc",
					}),
					testutil.WantAuditLog("Upstream Authorize Redirect", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name:                                   "OIDC upstream browser flow happy path using GET without a CSRF cookie using a dynamic client",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:                          addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": false,
						"Pinniped-Password": false,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=` + dynamicClientID + `&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-oidc-idp&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+offline_access+pinniped%3Arequest-audience+username+groups&state=redacted`,
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-oidc-idp",
						"resourceName": "some-oidc-idp",
						"resourceUID":  "oidc-resource-uid",
						"type":         "oidc",
					}),
					testutil.WantAuditLog("Upstream Authorize Redirect", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name:                                   "GitHub upstream browser flow happy path using GET without a CSRF cookie",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithGitHub(upstreamGitHubIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPathForGithubUpstream,
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamGithub(expectedUpstreamStateParam(nil, "", githubUpstreamName, "github")),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": false,
						"Pinniped-Password": false,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": "client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-github-idp&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted",
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-github-idp",
						"resourceName": "some-github-idp",
						"resourceUID":  "github-resource-uid",
						"type":         "github",
					}),
					testutil.WantAuditLog("Upstream Authorize Redirect", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name:                                   "GitHub upstream browser flow happy path using GET without a CSRF cookie using a dynamic client",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithGitHub(upstreamGitHubIdentityProviderBuilder().Build()),
			kubeResources:                          addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   modifiedHappyGetRequestPathForGithubUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamGithub(expectedUpstreamStateParam(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}, "", githubUpstreamName, "github")),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": false,
						"Pinniped-Password": false,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=` + dynamicClientID + `&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-github-idp&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+offline_access+pinniped%3Arequest-audience+username+groups&state=redacted`,
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-github-idp",
						"resourceName": "some-github-idp",
						"resourceUID":  "github-resource-uid",
						"type":         "github",
					}),
					testutil.WantAuditLog("Upstream Authorize Redirect", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name:                                   "LDAP upstream browser flow happy path using GET without a CSRF cookie",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPathForLDAPUpstream,
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(nil, "", ldapUpstreamName, "ldap")}),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": false,
						"Pinniped-Password": false,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-ldap-idp&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted`,
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-ldap-idp",
						"resourceName": "some-ldap-idp",
						"resourceUID":  "ldap-resource-uid",
						"type":         "ldap",
					}),
					testutil.WantAuditLog("Upstream Authorize Redirect", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name: "OIDC upstream browser flow happy path using GET without a CSRF cookie using backwards compatibility mode to have a default IDP (display name does not need to be sent as query param)",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()).
				WithDefaultIDPDisplayName(oidcUpstreamName), // specify which IDP is the backwards-compatibility mode IDP
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPath, // does not include IDP display name as query param
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": false,
						"Pinniped-Password": false,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted`,
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-oidc-idp",
						"resourceName": "some-oidc-idp",
						"resourceUID":  "oidc-resource-uid",
						"type":         "oidc",
					}),
					testutil.WantAuditLog("Upstream Authorize Redirect", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name: "with multiple IDPs available, request does not choose which IDP to use",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()).
				WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPath, // does not include pinniped_idp_name param
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            "", // there should not be a CSRF cookie set on the response
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/choose_identity_provider", happyGetRequestQueryMap),
			wantUpstreamStateParamInLocationHeader: false, // it should copy the params of the original request, not add a new state param
			wantBodyStringWithLocationInHref:       true,
			wantAuditLogs: func(_ stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": false,
						"Pinniped-Password": false,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted`,
					}),
				}
			},
		},
		{
			name: "with multiple IDPs available, request chooses to use OIDC browser flow",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()).
				WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPathForOIDCUpstream, // includes IDP display name of OIDC upstream
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": false,
						"Pinniped-Password": false,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-oidc-idp&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted`,
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-oidc-idp",
						"resourceName": "some-oidc-idp",
						"resourceUID":  "oidc-resource-uid",
						"type":         "oidc",
					}),
					testutil.WantAuditLog("Upstream Authorize Redirect", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name: "with multiple IDPs available, request chooses to use LDAP browser flow",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()).
				WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPathForLDAPUpstream, // includes IDP display name of LDAP upstream
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(nil, "", ldapUpstreamName, "ldap")}),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                                   "LDAP upstream browser flow happy path using GET without a CSRF cookie using a dynamic client",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			kubeResources:                          addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}, "", ldapUpstreamName, "ldap")}),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                                   "Active Directory upstream browser flow happy path using GET without a CSRF cookie",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPathForADUpstream,
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(nil, "", activeDirectoryUpstreamName, "activedirectory")}),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                                   "Active Directory upstream browser flow happy path using GET without a CSRF cookie using a dynamic client",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			kubeResources:                          addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   modifiedHappyGetRequestPathForADUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}, "", activeDirectoryUpstreamName, "activedirectory")}),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                              "OIDC upstream password grant happy path using GET",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
			wantAuditLogs: func(_ stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": true,
						"Pinniped-Password": true,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-password-granting-oidc-idp&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted`,
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-password-granting-oidc-idp",
						"resourceName": "some-password-granting-oidc-idp",
						"resourceUID":  "some-password-granting-resource-uid",
						"type":         "oidc",
					}),
					testutil.WantAuditLog("Identity From Upstream IDP", map[string]any{
						"upstreamIDPDisplayName":  "some-password-granting-oidc-idp",
						"upstreamIDPResourceName": "some-password-granting-oidc-idp",
						"upstreamIDPResourceUID":  "some-password-granting-resource-uid",
						"upstreamIDPType":         "oidc",
						"upstreamUsername":        "test-oidc-pinniped-username",
						"upstreamGroups":          []any{"test-pinniped-group-0", "test-pinniped-group-1"},
					}),
					testutil.WantAuditLog("Session Started", map[string]any{
						"sessionID":        sessionID,
						"username":         "test-oidc-pinniped-username",
						"groups":           []any{"test-pinniped-group-0", "test-pinniped-group-1"},
						"subject":          "https://my-upstream-issuer.com?idpName=some-password-granting-oidc-idp&sub=abc123-some+guid",
						"additionalClaims": map[string]any{}, // json: {}
						"warnings":         []any{},          // json: []
					}),
				}
			},
		},
		{
			name: "OIDC upstream password grant happy path using GET with identity transformations which change username and groups",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     transformationUsernamePrefix + oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       testutil.AddPrefixToEach(transformationGroupsPrefix, oidcUpstreamGroupMembership),
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyOIDCPasswordGrantCustomSession,
				transformationUsernamePrefix+oidcUpstreamUsername,
				oidcUpstreamUsername,
				oidcUpstreamGroupMembership,
			),
		},
		{
			name: "OIDC upstream password grant with identity transformations which rejects auth",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithTransformsForFederationDomain(rejectAuthPipeline).Build()),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithConfiguredPolicyRejectionHintErrorQuery),
			wantBodyString:        "",
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": true,
						"Pinniped-Password": true,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-password-granting-oidc-idp&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted`,
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-password-granting-oidc-idp",
						"resourceName": "some-password-granting-oidc-idp",
						"resourceUID":  "some-password-granting-resource-uid",
						"type":         "oidc",
					}),
					testutil.WantAuditLog("Identity From Upstream IDP", map[string]any{
						"upstreamIDPDisplayName":  "some-password-granting-oidc-idp",
						"upstreamIDPResourceName": "some-password-granting-oidc-idp",
						"upstreamIDPResourceUID":  "some-password-granting-resource-uid",
						"upstreamIDPType":         "oidc",
						"upstreamUsername":        "test-oidc-pinniped-username",
						"upstreamGroups":          []any{"test-pinniped-group-0", "test-pinniped-group-1"},
					}),
					testutil.WantAuditLog("Authentication Rejected By Transforms", map[string]any{
						"reason": "configured identity policy rejected this authentication: authentication was rejected by a configured policy",
					}),
				}
			},
		},
		{
			name: "OIDC upstream password grant happy path using GET with additional claim mappings",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().
				WithAdditionalClaimMappings(map[string]string{
					"downstreamCustomClaim":  "upstreamCustomClaim",
					"downstreamOtherClaim":   "upstreamOtherClaim",
					"downstreamMissingClaim": "upstreamMissingClaim",
				}).
				WithIDTokenClaim("upstreamCustomClaim", "i am a claim value").
				WithIDTokenClaim("upstreamOtherClaim", []any{"hello", true}).
				Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
			wantDownstreamAdditionalClaims: map[string]any{
				"downstreamCustomClaim": "i am a claim value",
				"downstreamOtherClaim":  []any{"hello", true},
			},
		},
		{
			name: "OIDC upstream password grant happy path using GET with additional claim mappings, when upstream claims are not available",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().
				WithAdditionalClaimMappings(map[string]string{
					"downstream": "upstream",
				}).
				WithIDTokenClaim("not-upstream", "value").
				Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
			wantDownstreamAdditionalClaims:    nil, // downstream claims are empty
		},
		{
			name:                              "LDAP upstream cli_password flow happy path using GET",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForLDAPUpstream,
			customUsernameHeader:              ptr.To(happyLDAPUsername),
			customPasswordHeader:              ptr.To(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
			wantAuditLogs: func(_ stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": true,
						"Pinniped-Password": true,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-ldap-idp&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted`,
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-ldap-idp",
						"resourceName": "some-ldap-idp",
						"resourceUID":  "ldap-resource-uid",
						"type":         "ldap",
					}),
					testutil.WantAuditLog("Identity From Upstream IDP", map[string]any{
						"upstreamIDPDisplayName":  "some-ldap-idp",
						"upstreamIDPResourceName": "some-ldap-idp",
						"upstreamIDPResourceUID":  "ldap-resource-uid",
						"upstreamIDPType":         "ldap",
						"upstreamUsername":        "some-ldap-username-from-authenticator",
						"upstreamGroups":          []any{"group1", "group2", "group3"},
					}),
					testutil.WantAuditLog("Session Started", map[string]any{
						"sessionID":        sessionID,
						"username":         "some-ldap-username-from-authenticator",
						"groups":           []any{"group1", "group2", "group3"},
						"subject":          "ldaps://some-ldap-host:123?base=ou%3Dusers%2Cdc%3Dpinniped%2Cdc%3Ddev&idpName=some-ldap-idp&sub=some-ldap-uid",
						"additionalClaims": nil,     // json: null
						"warnings":         []any{}, // json: []
					}),
				}
			},
		},
		{
			name: "LDAP cli upstream happy path using GET with identity transformations which change username and groups",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(upstreamLDAPIdentityProviderBuilder().WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForLDAPUpstream,
			customUsernameHeader:              ptr.To(happyLDAPUsername),
			customPasswordHeader:              ptr.To(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     transformationUsernamePrefix + happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       testutil.AddPrefixToEach(transformationGroupsPrefix, happyLDAPGroups),
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyLDAPUpstreamCustomSession,
				transformationUsernamePrefix+happyLDAPUsernameFromAuthenticator,
				happyLDAPUsernameFromAuthenticator,
				happyLDAPGroups,
			),
			wantAuditLogs: func(_ stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": true,
						"Pinniped-Password": true,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-ldap-idp&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted`,
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-ldap-idp",
						"resourceName": "some-ldap-idp",
						"resourceUID":  "ldap-resource-uid",
						"type":         "ldap",
					}),
					testutil.WantAuditLog("Identity From Upstream IDP", map[string]any{
						"upstreamIDPDisplayName":  "some-ldap-idp",
						"upstreamIDPResourceName": "some-ldap-idp",
						"upstreamIDPResourceUID":  "ldap-resource-uid",
						"upstreamIDPType":         "ldap",
						"upstreamUsername":        "some-ldap-username-from-authenticator",
						"upstreamGroups":          []any{"group1", "group2", "group3"},
					}),
					testutil.WantAuditLog("Session Started", map[string]any{
						"sessionID":        sessionID,
						"username":         "username_prefix:some-ldap-username-from-authenticator",
						"groups":           []any{"groups_prefix:group1", "groups_prefix:group2", "groups_prefix:group3"},
						"subject":          "ldaps://some-ldap-host:123?base=ou%3Dusers%2Cdc%3Dpinniped%2Cdc%3Ddev&idpName=some-ldap-idp&sub=some-ldap-uid",
						"additionalClaims": nil,     // json: null
						"warnings":         []any{}, // json: []
					}),
				}
			},
		},
		{
			name: "LDAP cli upstream with identity transformations which reject auth",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(upstreamLDAPIdentityProviderBuilder().WithTransformsForFederationDomain(rejectAuthPipeline).Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForLDAPUpstream,
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithConfiguredPolicyRejectionHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                              "ActiveDirectory cli upstream happy path using GET",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForADUpstream,
			customUsernameHeader:              ptr.To(happyLDAPUsername),
			customPasswordHeader:              ptr.To(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + activeDirectoryUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyActiveDirectoryUpstreamCustomSession,
		},
		{
			name:                                   "OIDC upstream browser flow happy path using GET with a CSRF cookie",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPathForOIDCUpstream,
			csrfCookie:                             "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue + " ",
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, incomingCookieCSRFValue, oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                                   "LDAP upstream browser flow happy path using GET with a CSRF cookie",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPathForLDAPUpstream,
			csrfCookie:                             "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue + " ",
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(nil, incomingCookieCSRFValue, ldapUpstreamName, "ldap")}),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                                   "Active Directory upstream browser flow happy path using GET with a CSRF cookie",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPathForADUpstream,
			csrfCookie:                             "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue + " ",
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(nil, incomingCookieCSRFValue, activeDirectoryUpstreamName, "activedirectory")}),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                                   "OIDC upstream browser flow happy path using POST",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodPost,
			path:                                   "/some/path",
			contentType:                            formContentType,
			body:                                   encodeQuery(happyGetRequestQueryMapForOIDCUpstream),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        "",
			wantBodyString:                         "",
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:                                   "OIDC upstream browser flow happy path using POST with a dynamic client",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:                          addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodPost,
			path:                                   "/some/path",
			contentType:                            formContentType,
			body:                                   encodeQuery(modifiedHappyGetRequestQueryMapForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep})),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        "",
			wantBodyString:                         "",
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:                                   "LDAP upstream browser flow happy path using POST",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodPost,
			path:                                   "/some/path",
			contentType:                            formContentType,
			body:                                   encodeQuery(happyGetRequestQueryMapForLDAPUpstream),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        "",
			wantBodyString:                         "",
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(nil, "", ldapUpstreamName, "ldap")}),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:                                   "LDAP upstream browser flow happy path using POST with a dynamic client",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			kubeResources:                          addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodPost,
			path:                                   "/some/path",
			contentType:                            formContentType,
			body:                                   encodeQuery(modifiedHappyGetRequestQueryMapForLDAPUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep})),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        "",
			wantBodyString:                         "",
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}, "", ldapUpstreamName, "ldap")}),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:                                   "Active Directory upstream browser flow happy path using POST",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodPost,
			path:                                   "/some/path",
			contentType:                            formContentType,
			body:                                   encodeQuery(happyGetRequestQueryMapForADUpstream),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        "",
			wantBodyString:                         "",
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(nil, "", activeDirectoryUpstreamName, "activedirectory")}),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:                                   "Active Directory upstream browser flow happy path using POST with a dynamic client",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			kubeResources:                          addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodPost,
			path:                                   "/some/path",
			contentType:                            formContentType,
			body:                                   encodeQuery(modifiedHappyGetRequestQueryMapForADUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep})),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        "",
			wantBodyString:                         "",
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     urlWithQuery(downstreamIssuer+"/login", map[string]string{"state": expectedUpstreamStateParam(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}, "", activeDirectoryUpstreamName, "activedirectory")}),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:                              "OIDC upstream password grant happy path using POST",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                            http.MethodPost,
			path:                              "/some/path",
			contentType:                       formContentType,
			body:                              encodeQuery(happyGetRequestQueryMapForOIDCPasswordGrantUpstream),
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
		},
		{
			name:                              "LDAP cli upstream happy path using POST",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:                            http.MethodPost,
			path:                              "/some/path",
			contentType:                       formContentType,
			body:                              encodeQuery(happyGetRequestQueryMapForLDAPUpstream),
			customUsernameHeader:              ptr.To(happyLDAPUsername),
			customPasswordHeader:              ptr.To(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name:                              "Active Directory cli upstream happy path using POST",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:                            http.MethodPost,
			path:                              "/some/path",
			contentType:                       formContentType,
			body:                              encodeQuery(happyGetRequestQueryMapForADUpstream),
			customUsernameHeader:              ptr.To(happyLDAPUsername),
			customPasswordHeader:              ptr.To(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + activeDirectoryUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyActiveDirectoryUpstreamCustomSession,
		},
		{
			name:                                   "OIDC upstream browser flow happy path with prompt param other than none that gets ignored",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"prompt": "login"}),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantBodyStringWithLocationInHref:       true,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{"prompt": "login"}, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:                                   "OIDC upstream browser flow happy path with custom IDP name and type query params, which are excluded from the query params in the upstream state",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"pinniped_idp_type": "oidc"}),
			contentType:                            formContentType,
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantBodyStringWithLocationInHref:       true,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:                                   "OIDC upstream browser flow happy path with extra params that get passed through",
			idps:                                   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().WithAdditionalAuthcodeParams(map[string]string{"prompt": "consent", "abc": "123", "def": "456"}).Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"prompt": "login"}),
			wantStatus:                             http.StatusSeeOther,
			wantContentType:                        htmlContentType,
			wantBodyStringWithLocationInHref:       true,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{"prompt": "login"}, "", oidcUpstreamName, "oidc"), map[string]string{"prompt": "consent", "abc": "123", "def": "456"}),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:               "OIDC upstream browser flow with prompt param none throws an error because we want to independently decide the upstream prompt param",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"prompt": "none"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeLoginRequiredErrorQuery),
			wantBodyString:     "",
			wantAuditLogs: func(_ stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Custom Headers Used", map[string]any{
						"Pinniped-Username": false,
						"Pinniped-Password": false,
					}),
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": `client_id=pinniped-cli&code_challenge=redacted&code_challenge_method=S256&nonce=redacted&pinniped_idp_name=some-oidc-idp&prompt=none&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code&scope=openid+profile+email+username+groups&state=redacted`,
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "some-oidc-idp",
						"resourceName": "some-oidc-idp",
						"resourceUID":  "oidc-resource-uid",
						"type":         "oidc",
					}),
				}
			},
		},
		{
			name:            "OIDC upstream browser flow with error while decoding CSRF cookie just generates a new cookie and succeeds as usual",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPathForOIDCUpstream,
			csrfCookie:      "__Host-pinniped-csrf=this-value-was-not-signed-by-pinniped",
			wantStatus:      http.StatusSeeOther,
			wantContentType: htmlContentType,
			// Generated a new CSRF cookie and set it in the response.
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:          "OIDC upstream browser flow happy path when downstream redirect uri matches what is configured for client except for the port number",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
			}),
			wantStatus:                  http.StatusSeeOther,
			wantContentType:             htmlContentType,
			wantCSRFValueInCookieHeader: happyCSRF,
			wantLocationHeader: expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
			}, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:          "OIDC upstream browser flow happy path using dynamic client when downstream redirect uri matches what is configured for client except for the port number",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
				"client_id":    dynamicClientID,
				"scope":        testutil.AllDynamicClientScopesSpaceSep,
			}),
			wantStatus:                  http.StatusSeeOther,
			wantContentType:             htmlContentType,
			wantCSRFValueInCookieHeader: happyCSRF,
			wantLocationHeader: expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
				"client_id":    dynamicClientID,
				"scope":        testutil.AllDynamicClientScopesSpaceSep,
			}, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:   "OIDC upstream password grant happy path when downstream redirect uri matches what is configured for client except for the port number",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method: http.MethodGet,
			path: modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
			}),
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        downstreamRedirectURIWithDifferentPort + `\?code=([^&]+)&scope=openid\+username\+groups&state=` + happyState,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURIWithDifferentPort,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
		},
		{
			name:   "LDAP upstream happy path when downstream redirect uri matches what is configured for client except for the port number",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method: http.MethodGet,
			path: modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
			}),
			customUsernameHeader:              ptr.To(happyLDAPUsername),
			customPasswordHeader:              ptr.To(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        downstreamRedirectURIWithDifferentPort + `\?code=([^&]+)&scope=openid\+username\+groups&state=` + happyState,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURIWithDifferentPort,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name:                        "OIDC upstream browser flow happy path when downstream requested scopes include offline_access",
			idps:                        testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                happyCSRFGenerator,
			generatePKCE:                happyPKCEGenerator,
			generateNonce:               happyNonceGenerator,
			stateEncoder:                happyStateEncoder,
			cookieEncoder:               happyCookieEncoder,
			method:                      http.MethodGet,
			path:                        modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"scope": "openid offline_access"}),
			wantStatus:                  http.StatusSeeOther,
			wantContentType:             htmlContentType,
			wantCSRFValueInCookieHeader: happyCSRF,
			wantLocationHeader: expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{
				"scope": "openid offline_access",
			}, "", oidcUpstreamName, "oidc"), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                              "OIDC password grant happy path when upstream IDP returned empty refresh token but it did return an access token and has a userinfo endpoint",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithEmptyRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(9*time.Hour))).WithUserInfoURL().Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSessionWithAccessToken,
		},
		{
			name:                              "OIDC password grant happy path when upstream IDP returned empty refresh token and an access token that has a short lifetime",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithEmptyRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(1*time.Hour))).WithUserInfoURL().Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: &psession.CustomSessionData{
				Username:         oidcUpstreamUsername,
				UpstreamUsername: oidcUpstreamUsername,
				UpstreamGroups:   oidcUpstreamGroupMembership,
				ProviderUID:      oidcPasswordGrantUpstreamResourceUID,
				ProviderName:     oidcPasswordGrantUpstreamName,
				ProviderType:     psession.ProviderTypeOIDC,
				Warnings:         []string{"Access token from identity provider has lifetime of less than 3 hours. Expect frequent prompts to log in."},
				OIDC: &psession.OIDCSessionData{
					UpstreamAccessToken: oidcUpstreamAccessToken,
					UpstreamSubject:     oidcUpstreamSubject,
					UpstreamIssuer:      oidcUpstreamIssuer,
				},
			},
		},
		{
			name:                              "OIDC password grant happy path when upstream IDP did not return a refresh token but it did return an access token and has a userinfo endpoint",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(9*time.Hour))).WithUserInfoURL().Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSessionWithAccessToken,
		},
		{
			name:                 "error during upstream LDAP authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithLDAP(erroringUpstreamLDAPIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForLDAPUpstream,
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeUpstreamAuthErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "error during upstream Active Directory authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(erroringUpstreamLDAPIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForLDAPUpstream,
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeUpstreamAuthErrorQuery),
			wantBodyString:       "",
		},
		{
			name: "wrong upstream credentials for OIDC password grant authentication",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					// This is similar to the error that would be returned by the underlying call to oauth2.PasswordCredentialsToken()
					WithPasswordGrantError(&oauth2.RetrieveError{Response: &http.Response{Status: "fake status"}, Body: []byte("fake body")}).
					Build(),
			),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To("wrong-password"),
			wantPasswordGrantCall: &expectedPasswordGrant{
				performedByUpstreamName: oidcPasswordGrantUpstreamName,
				args: &oidctestutil.PasswordCredentialsGrantAndValidateTokensArgs{
					Username: oidcUpstreamUsername,
					Password: "wrong-password",
				}},
			wantStatus:         http.StatusFound,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeAccessDeniedErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "wrong upstream password for LDAP authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForLDAPUpstream,
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To("wrong-password"),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithBadUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "wrong upstream password for Active Directory authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForADUpstream,
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To("wrong-password"),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithBadUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "wrong upstream username for LDAP authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForLDAPUpstream,
			customUsernameHeader: ptr.To("wrong-username"),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithBadUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "wrong upstream username for Active Directory authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForADUpstream,
			customUsernameHeader: ptr.To("wrong-username"),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithBadUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "missing upstream username but has password on request for OIDC password grant",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader: nil, // do not send header
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "missing upstream username but has password on request for LDAP authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForLDAPUpstream,
			customUsernameHeader: nil, // do not send header
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "missing upstream username on request for Active Directory authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForADUpstream,
			customUsernameHeader: nil, // do not send header
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "missing upstream password on request for LDAP authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForLDAPUpstream,
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: nil, // do not send header
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "missing upstream password on request for Active Directory authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForADUpstream,
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: nil, // do not send header
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                  "password grant returns an error when upstream IDP returns no refresh token with an access token but has no userinfo endpoint",
			idps:                  testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(9*time.Hour))).WithoutUserInfoURL().Build()),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUserInfoEndpointErrorQuery),
			wantBodyString:        "",
		},
		{
			name:                  "password grant returns an error when upstream IDP returns empty refresh token with an access token but has no userinfo endpoint",
			idps:                  testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithEmptyRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(9*time.Hour))).WithoutUserInfoURL().Build()),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUserInfoEndpointErrorQuery),
			wantBodyString:        "",
		},
		{
			name:                  "password grant returns an error when upstream IDP returns empty refresh token and empty access token",
			idps:                  testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithEmptyRefreshToken().WithEmptyAccessToken().Build()),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingAccessTokenErrorQuery),
			wantBodyString:        "",
		},
		{
			name:                  "password grant returns an error when upstream IDP returns no refresh and no access token",
			idps:                  testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutRefreshToken().WithoutAccessToken().Build()),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingAccessTokenErrorQuery),
			wantBodyString:        "",
		},
		{
			name:                  "password grant returns an error when upstream IDP returns no refresh token and empty access token",
			idps:                  testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutRefreshToken().WithEmptyAccessToken().Build()),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingAccessTokenErrorQuery),
			wantBodyString:        "",
		},
		{
			name:                  "password grant returns an error when upstream IDP returns empty refresh token and no access token",
			idps:                  testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithEmptyRefreshToken().WithoutAccessToken().Build()),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingAccessTokenErrorQuery),
			wantBodyString:        "",
		},
		{
			name:                 "missing upstream password on request for OIDC password grant authentication",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: nil, // do not send header
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "using the custom username header on request for OIDC password grant authentication when OIDCIdentityProvider does not allow password grants",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPathForOIDCUpstream,
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithPasswordGrantDisallowedHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "dynamic clients are not allowed to use OIDC password grant because we don't want them to handle user credentials",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:        addFullyCapableDynamicClientAndSecretToKubeResources,
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithUsernamePasswordHeadersDisallowedHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "dynamic clients are not allowed to use LDAP CLI-flow authentication because we don't want them to handle user credentials",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			kubeResources:        addFullyCapableDynamicClientAndSecretToKubeResources,
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}),
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithUsernamePasswordHeadersDisallowedHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "dynamic clients are not allowed to use Active Directory CLI-flow authentication because we don't want them to handle user credentials",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			kubeResources:        addFullyCapableDynamicClientAndSecretToKubeResources,
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForADUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}),
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithUsernamePasswordHeadersDisallowedHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:          "downstream redirect uri does not match what is configured for client when using OIDC upstream browser flow",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client",
			}),
			wantStatus:      http.StatusBadRequest,
			wantContentType: jsonContentType,
			wantBodyJSON:    fositeInvalidRedirectURIErrorBody,
		},
		{
			name:          "downstream redirect uri does not match what is configured for client when using OIDC upstream browser flow with a dynamic client",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-dynamic-client",
				"client_id":    dynamicClientID,
				"scope":        testutil.AllDynamicClientScopesSpaceSep,
			}),
			wantStatus:      http.StatusBadRequest,
			wantContentType: jsonContentType,
			wantBodyJSON:    fositeInvalidRedirectURIErrorBody,
		},
		{
			name:   "downstream redirect uri does not match what is configured for client when using OIDC upstream password grant",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method: http.MethodGet,
			path: modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client",
			}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusBadRequest,
			wantContentType:      jsonContentType,
			wantBodyJSON:         fositeInvalidRedirectURIErrorBody,
		},
		{
			name:   "downstream redirect uri does not match what is configured for client when using LDAP upstream",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method: http.MethodGet,
			path: modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client",
			}),
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusBadRequest,
			wantContentType:      jsonContentType,
			wantBodyJSON:         fositeInvalidRedirectURIErrorBody,
		},
		{
			name:   "downstream redirect uri does not match what is configured for client when using active directory upstream",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method: http.MethodGet,
			path: modifiedHappyGetRequestPathForADUpstream(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client",
			}),
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusBadRequest,
			wantContentType:      jsonContentType,
			wantBodyJSON:         fositeInvalidRedirectURIErrorBody,
		},
		{
			name:            "downstream client does not exist when using OIDC upstream browser flow",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": "invalid-client"}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: jsonContentType,
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:                 "downstream client does not exist when using OIDC upstream password grant",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"client_id": "invalid-client"}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusUnauthorized,
			wantContentType:      jsonContentType,
			wantBodyJSON:         fositeInvalidClientErrorBody,
		},
		{
			name:            "downstream client does not exist when using LDAP upstream",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"client_id": "invalid-client"}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: jsonContentType,
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:            "downstream client does not exist when using active directory upstream",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPathForADUpstream(map[string]string{"client_id": "invalid-client"}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: jsonContentType,
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:               "response type is unsupported when using OIDC upstream browser flow",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"response_type": "unsupported"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:          "response type is unsupported when using OIDC upstream browser flow with dynamic client",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{
				"response_type": "unsupported",
				"client_id":     dynamicClientID,
				"scope":         testutil.AllDynamicClientScopesSpaceSep,
			}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "response type is unsupported when using OIDC upstream password grant",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"response_type": "unsupported"}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "response type is unsupported when using LDAP cli upstream",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"response_type": "unsupported"}),
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:               "response type is unsupported when using LDAP browser upstream",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"response_type": "unsupported"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:          "response type is unsupported when using LDAP browser upstream with dynamic client",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{
				"response_type": "unsupported",
				"client_id":     dynamicClientID,
				"scope":         testutil.AllDynamicClientScopesSpaceSep,
			}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "response type is unsupported when using active directory cli upstream",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForADUpstream(map[string]string{"response_type": "unsupported"}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:               "response type is unsupported when using active directory browser upstream",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForADUpstream(map[string]string{"response_type": "unsupported"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:          "response type is unsupported when using active directory browser upstream with dynamic client",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPathForADUpstream(map[string]string{
				"response_type": "unsupported",
				"client_id":     dynamicClientID,
				"scope":         testutil.AllDynamicClientScopesSpaceSep,
			}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "downstream scopes do not match what is configured for client using OIDC upstream browser flow",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"scope": "openid profile email tuna"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "downstream scopes do not match what is configured for client using OIDC upstream browser flow with dynamic client",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:      addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": "openid tuna"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "downstream scopes do not match what is configured for client using OIDC upstream password grant",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"scope": "openid profile email tuna"}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:            "form_post page is used to send errors to client using OIDC upstream browser flow with response_mode=form_post",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"response_mode": "form_post", "scope": "openid profile email tuna"}),
			wantStatus:      http.StatusOK,
			wantContentType: htmlContentType,
			wantBodyRegex:   `<input type="hidden" name="encoded_params" value="error=invalid_scope&amp;error_description=The&#43;requested&#43;scope&#43;is&#43;invalid`,
		},
		{
			name:            "response_mode form_post is not allowed for dynamic clients",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:   addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"response_mode": "form_post", "client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep}),
			wantStatus:      http.StatusOK, // this is weird, but fosite uses a form_post response to tell the client that it is not allowed to use form_post responses
			wantContentType: htmlContentType,
			wantBodyRegex:   `<input type="hidden" name="encoded_params" value="error=unsupported_response_mode&amp;error_description=The&#43;authorization&#43;server&#43;does&#43;not&#43;support&#43;obtaining&#43;a&#43;response&#43;using&#43;this&#43;response&#43;mode.`,
		},
		{
			name:                 "downstream scopes do not match what is configured for client using LDAP upstream",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"scope": "openid tuna"}),
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "downstream scopes do not match what is configured for client using Active Directory upstream",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForADUpstream(map[string]string{"scope": "openid tuna"}),
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:               "missing response type in request using OIDC upstream browser flow",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"response_type": ""}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "missing response type in request using OIDC upstream browser flow with dynamic client",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:      addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep, "response_type": ""}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "missing response type in request using OIDC upstream password grant",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"response_type": ""}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "missing response type in request using LDAP cli upstream",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"response_type": ""}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:               "missing response type in request using LDAP browser upstream",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"response_type": ""}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "missing response type in request using LDAP browser upstream with dynamic client",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			kubeResources:      addFullyCapableDynamicClientAndSecretToKubeResources,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep, "response_type": ""}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "missing response type in request using Active Directory cli upstream",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForADUpstream(map[string]string{"response_type": ""}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:               "missing response type in request using Active Directory browser upstream",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForADUpstream(map[string]string{"response_type": ""}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "missing response type in request using Active Directory browser upstream with dynamic client",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder().Build()),
			kubeResources:      addFullyCapableDynamicClientAndSecretToKubeResources,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForADUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep, "response_type": ""}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:            "missing client id in request using OIDC upstream browser flow",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": ""}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: jsonContentType,
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:                 "missing client id in request using OIDC upstream password grant",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"client_id": ""}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusUnauthorized,
			wantContentType:      jsonContentType,
			wantBodyJSON:         fositeInvalidClientErrorBody,
		},
		{
			name:            "missing client id in request using LDAP upstream",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"client_id": ""}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: jsonContentType,
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:               "missing PKCE code_challenge in request using OIDC upstream browser flow", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"code_challenge": ""}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "missing PKCE code_challenge in request using OIDC upstream browser flow with dynamic client", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:      addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep, "code_challenge": ""}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                         "missing PKCE code_challenge in request using OIDC upstream password grant", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"code_challenge": ""}),
			customUsernameHeader:         ptr.To(oidcUpstreamUsername),
			customPasswordHeader:         ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:        happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                   http.StatusFound,
			wantContentType:              jsonContentType,
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:                         "missing PKCE code_challenge in request using LDAP upstream", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"code_challenge": ""}),
			customUsernameHeader:         ptr.To(happyLDAPUsername),
			customPasswordHeader:         ptr.To(happyLDAPPassword),
			wantStatus:                   http.StatusFound,
			wantContentType:              jsonContentType,
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:               "invalid value for PKCE code_challenge_method in request using OIDC upstream browser flow", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"code_challenge_method": "this-is-not-a-valid-pkce-alg"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidCodeChallengeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "invalid value for PKCE code_challenge_method in request using OIDC upstream browser flow with dynamic client", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:      addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep, "code_challenge_method": "this-is-not-a-valid-pkce-alg"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidCodeChallengeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                         "invalid value for PKCE code_challenge_method in request using OIDC upstream password grant", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"code_challenge_method": "this-is-not-a-valid-pkce-alg"}),
			customUsernameHeader:         ptr.To(oidcUpstreamUsername),
			customPasswordHeader:         ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:        happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                   http.StatusFound,
			wantContentType:              jsonContentType,
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeInvalidCodeChallengeErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:                         "invalid value for PKCE code_challenge_method in request using LDAP upstream", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"code_challenge_method": "this-is-not-a-valid-pkce-alg"}),
			customUsernameHeader:         ptr.To(happyLDAPUsername),
			customPasswordHeader:         ptr.To(happyLDAPPassword),
			wantStatus:                   http.StatusFound,
			wantContentType:              jsonContentType,
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeInvalidCodeChallengeErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:               "when PKCE code_challenge_method in request is `plain` using OIDC upstream browser flow", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"code_challenge_method": "plain"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "when PKCE code_challenge_method in request is `plain` using OIDC upstream browser flow with dynamic client", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:      addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep, "code_challenge_method": "plain"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                         "when PKCE code_challenge_method in request is `plain` using OIDC upstream password grant", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"code_challenge_method": "plain"}),
			customUsernameHeader:         ptr.To(oidcUpstreamUsername),
			customPasswordHeader:         ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:        happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                   http.StatusFound,
			wantContentType:              jsonContentType,
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:                         "when PKCE code_challenge_method in request is `plain` using LDAP upstream", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"code_challenge_method": "plain"}),
			customUsernameHeader:         ptr.To(happyLDAPUsername),
			customPasswordHeader:         ptr.To(happyLDAPPassword),
			wantStatus:                   http.StatusFound,
			wantContentType:              jsonContentType,
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:               "missing PKCE code_challenge_method in request using OIDC upstream browser flow", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"code_challenge_method": ""}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "missing PKCE code_challenge_method in request using OIDC upstream browser flow with dynamic client", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:      addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep, "code_challenge_method": ""}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                         "missing PKCE code_challenge_method in request using OIDC upstream password grant", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"code_challenge_method": ""}),
			customUsernameHeader:         ptr.To(oidcUpstreamUsername),
			customPasswordHeader:         ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:        happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                   http.StatusFound,
			wantContentType:              jsonContentType,
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:                         "missing PKCE code_challenge_method in request using LDAP upstream", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"code_challenge_method": ""}),
			customUsernameHeader:         ptr.To(happyLDAPUsername),
			customPasswordHeader:         ptr.To(happyLDAPPassword),
			wantStatus:                   http.StatusFound,
			wantContentType:              jsonContentType,
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			// This is just one of the many OIDC validations run by fosite. This test is to ensure that we are running
			// through that part of the fosite library when using an OIDC upstream browser flow.
			name:               "prompt param is not allowed to have none and another legal value at the same time using OIDC upstream browser flow",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"prompt": "none login"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositePromptHasNoneAndOtherValueErrorQuery),
			wantBodyString:     "",
		},
		{
			// This is just one of the many OIDC validations run by fosite. This test is to ensure that we are running
			// through that part of the fosite library when using an OIDC upstream browser flow with a dynamic client.
			name:               "prompt param is not allowed to have none and another legal value at the same time using OIDC upstream browser flow with dynamic client",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:      addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep, "prompt": "none login"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositePromptHasNoneAndOtherValueErrorQuery),
			wantBodyString:     "",
		},
		{
			// This is just one of the many OIDC validations run by fosite. This test is to ensure that we are running
			// through that part of the fosite library when using an OIDC upstream password grant.
			name:                         "prompt param is not allowed to have none and another legal value at the same time using OIDC upstream password grant",
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"prompt": "none login"}),
			customUsernameHeader:         ptr.To(oidcUpstreamUsername),
			customPasswordHeader:         ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:        happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                   http.StatusFound,
			wantContentType:              jsonContentType,
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositePromptHasNoneAndOtherValueErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 1, // fosite already stored the authcode before it noticed the error
		},
		{
			// This is just one of the many OIDC validations run by fosite. This test is to ensure that we are running
			// through that part of the fosite library when using an LDAP upstream.
			name:                         "prompt param is not allowed to have none and another legal value at the same time using LDAP upstream",
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"prompt": "none login"}),
			customUsernameHeader:         ptr.To(happyLDAPUsername),
			customPasswordHeader:         ptr.To(happyLDAPPassword),
			wantStatus:                   http.StatusFound,
			wantContentType:              jsonContentType,
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositePromptHasNoneAndOtherValueErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 1, // fosite already stored the authcode before it noticed the error
		},
		{
			name:          "happy path: downstream OIDC validations are skipped when the openid scope was not requested using OIDC upstream browser flow",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			// The following prompt value is illegal when openid is requested, but note that openid is not requested.
			path:                        modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"prompt": "none login", "scope": "email"}),
			wantStatus:                  http.StatusSeeOther,
			wantContentType:             htmlContentType,
			wantCSRFValueInCookieHeader: happyCSRF,
			wantLocationHeader: expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(
				map[string]string{"prompt": "none login", "scope": "email"}, "", oidcUpstreamName, "oidc",
			), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:          "happy path: downstream OIDC validations are skipped when the openid scope was not requested using OIDC upstream browser flow with dynamic client",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			// The following prompt value is illegal when openid is requested, but note that openid is not requested.
			path:                        modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": "groups", "prompt": "none login"}),
			wantStatus:                  http.StatusSeeOther,
			wantContentType:             htmlContentType,
			wantCSRFValueInCookieHeader: happyCSRF,
			wantLocationHeader: expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(
				map[string]string{"client_id": dynamicClientID, "scope": "groups", "prompt": "none login"}, "", oidcUpstreamName, "oidc",
			), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:   "happy path: downstream OIDC validations are skipped when the openid scope was not requested using OIDC upstream password grant",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method: http.MethodGet,
			// The following prompt value is illegal when openid is requested, but note that openid is not requested.
			path:                              modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"prompt": "none login", "scope": "email"}),
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=username\+groups&state=` + happyState, // username and groups scopes were not requested, but are granted anyway for backwards compatibility
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,        // username scope was not requested, but is granted anyway for backwards compatibility
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership, // groups scope was not requested, but is granted anyway for backwards compatibility
			wantDownstreamRequestedScopes:     []string{"email"},           // only email was requested
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       []string{"username", "groups"}, // username and groups scopes were not requested, but are granted anyway for backwards compatibility
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
		},
		{
			name:   "happy path: downstream OIDC validations are skipped when the openid scope was not requested using LDAP upstream",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method: http.MethodGet,
			// The following prompt value is illegal when openid is requested, but note that openid is not requested.
			path:                              modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"prompt": "none login", "scope": "email"}),
			customUsernameHeader:              ptr.To(happyLDAPUsername),
			customPasswordHeader:              ptr.To(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=username\+groups&state=` + happyState, // username and groups scopes were not requested, but are granted anyway for backwards compatibility
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator, // username scope was not requested, but is granted anyway for backwards compatibility
			wantDownstreamIDTokenGroups:       happyLDAPGroups,                    // groups scope was not requested, but is granted anyway for backwards compatibility
			wantDownstreamRequestedScopes:     []string{"email"},                  // only email was requested
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       []string{"username", "groups"}, // username and groups scopes were not requested, but are granted anyway for backwards compatibility
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name: "OIDC upstream password grant: upstream IDP provides no username or group claim configuration, so we use default username claim and skip groups",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutUsernameClaim().WithoutGroupsClaim().Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenGroups:       []string{},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyOIDCPasswordGrantCustomSession,
				oidcUpstreamIssuer+"?sub="+oidcUpstreamSubjectQueryEscaped,
				oidcUpstreamIssuer+"?sub="+oidcUpstreamSubjectQueryEscaped,
				nil,
			),
		},
		{
			name: "OIDC upstream password grant: upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is missing",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe@whitehouse.gov",
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyOIDCPasswordGrantCustomSession,
				"joe@whitehouse.gov",
				"joe@whitehouse.gov",
				oidcUpstreamGroupMembership,
			),
		},
		{
			name: "OIDC upstream password grant: upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with true value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", true).Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe@whitehouse.gov",
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyOIDCPasswordGrantCustomSession,
				"joe@whitehouse.gov",
				"joe@whitehouse.gov",
				oidcUpstreamGroupMembership,
			),
		},
		{
			name: "OIDC upstream password grant: upstream IDP configures username claim as anything other than special claim `email` and `email_verified` upstream claim is present with false value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithUsernameClaim("some-claim").
					WithIDTokenClaim("some-claim", "joe").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", false).Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe",
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyOIDCPasswordGrantCustomSession,
				"joe",
				"joe",
				oidcUpstreamGroupMembership,
			),
		},
		{
			name: "OIDC upstream password grant: upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with illegal value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", "supposed to be boolean").Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithInvalidEmailVerifiedHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with false value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", false).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithFalseEmailVerifiedHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream IDP provides username claim configuration as `sub`, so the downstream token subject should be exactly what they asked for",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithUsernameClaim("sub").Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamSubject,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyOIDCPasswordGrantCustomSession,
				oidcUpstreamSubject,
				oidcUpstreamSubject,
				oidcUpstreamGroupMembership,
			),
		},
		{
			name: "OIDC upstream password grant: upstream IDP's configured groups claim in the ID token has a non-array value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithIDTokenClaim(oidcUpstreamGroupsClaim, "notAnArrayGroup1 notAnArrayGroup2").Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       []string{"notAnArrayGroup1 notAnArrayGroup2"},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyOIDCPasswordGrantCustomSession,
				oidcUpstreamUsername,
				oidcUpstreamUsername,
				[]string{"notAnArrayGroup1 notAnArrayGroup2"},
			),
		},
		{
			name: "OIDC upstream password grant: upstream IDP's configured groups claim in the ID token is a slice of interfaces",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithIDTokenClaim(oidcUpstreamGroupsClaim, []any{"group1", "group2"}).Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       []string{"group1", "group2"},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyOIDCPasswordGrantCustomSession,
				oidcUpstreamUsername,
				oidcUpstreamUsername,
				[]string{"group1", "group2"},
			),
		},
		{
			name: "OIDC upstream password grant: upstream ID token does not contain requested username claim",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutIDTokenClaim(oidcUpstreamUsernameClaim).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimMissingHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token does not contain requested groups claim",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutIDTokenClaim(oidcUpstreamGroupsClaim).Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:              ptr.To(oidcUpstreamUsername),
			customPasswordHeader:              ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + oidcPasswordGrantUpstreamName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       []string{},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyOIDCPasswordGrantCustomSession,
				oidcUpstreamUsername,
				oidcUpstreamUsername,
				nil,
			),
		},
		{
			name: "OIDC upstream password grant: upstream ID token contains username claim with weird format",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim(oidcUpstreamUsernameClaim, 42).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token contains username claim with empty string value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim(oidcUpstreamUsernameClaim, "").Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimEmptyHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token does not contain iss claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutIDTokenClaim("iss").WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimMissingHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token does has an empty string value for iss claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim("iss", "").WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimEmptyHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token has an non-string iss claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim("iss", 42).WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token does not contain sub claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutIDTokenClaim("sub").WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimMissingHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token does has an empty string value for sub claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim("sub", "").WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimEmptyHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token has an non-string sub claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim("sub", 42).WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token contains groups claim with weird format",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim(oidcUpstreamGroupsClaim, 42).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token contains groups claim where one element is invalid",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim(oidcUpstreamGroupsClaim, []any{"foo", 7}).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token contains groups claim with invalid null type",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim(oidcUpstreamGroupsClaim, nil).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPathForOIDCPasswordGrantUpstream,
			customUsernameHeader:  ptr.To(oidcUpstreamUsername),
			customPasswordHeader:  ptr.To(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       jsonContentType,
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name:               "downstream state does not have enough entropy using OIDC upstream browser flow",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"state": "short"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidStateErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "downstream state does not have enough entropy using OIDC upstream browser flow with dynamic client",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			kubeResources:      addFullyCapableDynamicClientAndSecretToKubeResources,
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPathForOIDCUpstream(map[string]string{"client_id": dynamicClientID, "scope": testutil.AllDynamicClientScopesSpaceSep, "state": "short"}),
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidStateErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "downstream state does not have enough entropy using OIDC upstream password grant",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForOIDCPasswordGrantUpstream(map[string]string{"state": "short"}),
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeInvalidStateErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "downstream state does not have enough entropy using LDAP upstream",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPathForLDAPUpstream(map[string]string{"state": "short"}),
			customUsernameHeader: ptr.To(happyLDAPUsername),
			customPasswordHeader: ptr.To(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      jsonContentType,
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeInvalidStateErrorQuery),
			wantBodyString:       "",
		},
		{
			name:               "error while encoding upstream state param using OIDC upstream browser flow",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       &errorReturningEncoder{},
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               happyGetRequestPathForOIDCUpstream,
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInternalServerErrorQueryWithHint("Error encoding upstream state param.")),
			wantBodyString:     "",
		},
		{
			name:               "error while encoding CSRF cookie value for new cookie using OIDC upstream browser flow",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      &errorReturningEncoder{},
			method:             http.MethodGet,
			path:               happyGetRequestPathForOIDCUpstream,
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInternalServerErrorQueryWithHint("Error encoding CSRF cookie.")),
			wantBodyString:     "",
		},
		{
			name:               "error while generating CSRF token using OIDC upstream browser flow",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       sadCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               happyGetRequestPathForOIDCUpstream,
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInternalServerErrorQueryWithHint("Server could not generate necessary values.")),
			wantBodyString:     "",
		},
		{
			name:               "error while generating nonce using OIDC upstream browser flow",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      sadNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               happyGetRequestPathForOIDCUpstream,
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInternalServerErrorQueryWithHint("Server could not generate necessary values.")),
			wantBodyString:     "",
		},
		{
			name:               "error while generating PKCE using OIDC upstream browser flow",
			idps:               testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       sadPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               happyGetRequestPathForOIDCUpstream,
			wantStatus:         http.StatusSeeOther,
			wantContentType:    jsonContentType,
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInternalServerErrorQueryWithHint("Server could not generate necessary values.")),
			wantBodyString:     "",
		},
		{
			name:            "no default upstream provider is configured and no specific IDP was requested in the request params",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(), // empty
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusBadRequest,
			wantContentType: plainContentType,
			wantBodyString:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. 'pinniped_idp_name' param error: identity provider not found: this federation domain does not have a default identity provider"}`,
		},
		{
			name:            "could not find requested IDP display name",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:          http.MethodGet,
			path:            happyGetRequestPathForLDAPUpstream, // includes param to request a different IDP display name than what is available
			wantStatus:      http.StatusBadRequest,
			wantContentType: plainContentType,
			wantBodyString:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. 'pinniped_idp_name' param error: did not find IDP with name 'some-ldap-idp'"}`,
		},
		{
			name:                 "with multiple IDPs, when using browserless flow, when pinniped_idp_name param is not specified, should be an error (browerless flows do not use IDP chooser page)",
			idps:                 testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().WithAllowPasswordGrant(true).Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: ptr.To(oidcUpstreamUsername),
			customPasswordHeader: ptr.To(oidcUpstreamPassword),
			wantStatus:           http.StatusBadRequest,
			wantContentType:      plainContentType,
			wantBodyString:       `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. 'pinniped_idp_name' param error: identity provider not found: this federation domain does not have a default identity provider"}`,
		},
		{
			name:            "post with invalid form in the body",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:          http.MethodPost,
			path:            "/some/path",
			contentType:     formContentType,
			body:            "this is not a valid form because of the semi-colons;;;;",
			wantStatus:      http.StatusBadRequest,
			wantContentType: plainContentType,
			wantBodyString:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse form params, make sure to send a properly formatted query params or form request body."}`,
		},
		{
			name:            "post with invalid multipart form in the body",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:          http.MethodPost,
			path:            "/some/path",
			contentType:     "multipart/form-data",
			body:            "this is not a valid multipart form",
			wantStatus:      http.StatusBadRequest,
			wantContentType: plainContentType,
			wantBodyString:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse multipart HTTP body, make sure to send a properly formatted form request body."}`,
		},
		{
			name:            "get with invalid query",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:          http.MethodGet,
			path:            "/some/path?param=this-is-not-a-valid-query-due-to-the-semicolons;;;;",
			contentType:     formContentType,
			wantStatus:      http.StatusBadRequest,
			wantContentType: plainContentType,
			wantBodyString:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse form params, make sure to send a properly formatted query params or form request body."}`,
		},
		{
			name:            "PUT is a bad method",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:          http.MethodPut,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: plainContentType,
			wantBodyString:  "Method Not Allowed: PUT (try GET or POST)\n",
		},
		{
			name:            "PATCH is a bad method",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:          http.MethodPatch,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: plainContentType,
			wantBodyString:  "Method Not Allowed: PATCH (try GET or POST)\n",
		},
		{
			name:            "DELETE is a bad method",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:          http.MethodDelete,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: plainContentType,
			wantBodyString:  "Method Not Allowed: DELETE (try GET or POST)\n",
		},
	}

	runOneTestCase := func(
		t *testing.T,
		test testCase,
		subject http.Handler,
		kubeOauthStore *storage.KubeStorage,
		supervisorClient *supervisorfake.Clientset,
		kubeClient *fake.Clientset,
		secretsClient v1.SecretInterface,
		auditLog *bytes.Buffer,
	) {
		if test.kubeResources != nil {
			test.kubeResources(t, supervisorClient, kubeClient)
		}

		reqContext := context.WithValue(context.Background(), struct{ name string }{name: "test"}, "request-context")
		req := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body)).WithContext(reqContext)
		req.Header.Set("Content-Type", test.contentType)
		if test.csrfCookie != "" {
			req.Header.Set("Cookie", test.csrfCookie)
		}
		if test.customUsernameHeader != nil {
			req.Header.Set("Pinniped-Username", *test.customUsernameHeader)
		}
		if test.customPasswordHeader != nil {
			req.Header.Set("Pinniped-Password", *test.customPasswordHeader)
		}
		req, _ = requestlogger.NewRequestWithAuditID(req, func() string { return "fake-audit-id" })
		rsp := httptest.NewRecorder()

		subject.ServeHTTP(rsp, req)
		t.Logf("response: %#v", rsp)
		t.Logf("response body: %q", rsp.Body.String())

		require.Equal(t, test.wantStatus, rsp.Code)
		testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), test.wantContentType)

		// Use form_post page's CSPs because sometimes errors are sent to the client via the form_post page.
		testutil.RequireSecurityHeadersWithFormPostPageCSPs(t, rsp)

		if test.wantPasswordGrantCall != nil {
			test.wantPasswordGrantCall.args.Ctx = req.Context()
			test.idps.RequireExactlyOneCallToPasswordCredentialsGrantAndValidateTokens(t,
				test.wantPasswordGrantCall.performedByUpstreamName, test.wantPasswordGrantCall.args,
			)
		} else {
			test.idps.RequireExactlyZeroCallsToPasswordCredentialsGrantAndValidateTokens(t)
		}

		actualLocation := rsp.Header().Get("Location")
		actualQueryStateParam := ""
		sessionID := ""
		switch {
		case test.wantLocationHeader != "":
			if test.wantUpstreamStateParamInLocationHeader {
				actualQueryStateParam = requireEqualDecodedStateParams(t, actualLocation, test.wantLocationHeader, test.stateEncoder)
				// Ignore the state, since it was encoded with a randomly-generated initialization vector that cannot be reproduced.
				requireEqualURLsIgnoringState(t, actualLocation, test.wantLocationHeader)
			} else {
				require.Equal(t, test.wantLocationHeader, actualLocation)
			}

			// Authorization requests for either a successful OIDC upstream or for an error with any upstream
			// should never use Kube storage. There is only one exception to this rule, which is that certain
			// OIDC validations are checked in fosite after the OAuth authcode (and sometimes the OIDC session)
			// is stored, so it is possible with an LDAP upstream to store objects and then return an error to
			// the client anyway (which makes the stored objects useless, but oh well).
			require.Len(t, oidctestutil.FilterClientSecretCreateActions(kubeClient.Actions()), test.wantUnnecessaryStoredRecords)
		case test.wantRedirectLocationRegexp != "":
			if test.wantDownstreamClientID == "" {
				test.wantDownstreamClientID = pinnipedCLIClientID // default assertion value when not provided by test case
			}
			require.Len(t, rsp.Header().Values("Location"), 1)
			sessionID = oidctestutil.RequireAuthCodeRegexpMatch(
				t,
				rsp.Header().Get("Location"),
				test.wantRedirectLocationRegexp,
				kubeClient,
				secretsClient,
				kubeOauthStore,
				test.wantDownstreamGrantedScopes,
				test.wantDownstreamIDTokenSubject,
				test.wantDownstreamIDTokenUsername,
				test.wantDownstreamIDTokenGroups,
				test.wantDownstreamRequestedScopes,
				test.wantDownstreamPKCEChallenge,
				test.wantDownstreamPKCEChallengeMethod,
				test.wantDownstreamNonce,
				test.wantDownstreamClientID,
				test.wantDownstreamRedirectURI,
				test.wantDownstreamCustomSessionData,
				test.wantDownstreamAdditionalClaims,
			)
		default:
			require.Empty(t, rsp.Header().Values("Location"))
		}

		if test.wantAuditLogs != nil {
			wantAuditLogs := test.wantAuditLogs(stateparam.Encoded(actualQueryStateParam), sessionID)
			testutil.WantAuditIDOnEveryAuditLog(wantAuditLogs, "fake-audit-id")
			testutil.CompareAuditLogs(t, wantAuditLogs, auditLog.String())
		}

		switch {
		case test.wantBodyJSON != "":
			require.JSONEq(t, test.wantBodyJSON, rsp.Body.String())
		case test.wantBodyStringWithLocationInHref:
			switch code := rsp.Code; code {
			case http.StatusFound:
				anchorTagWithLocationHref := fmt.Sprintf("<a href=\"%s\">Found</a>.\n\n", html.EscapeString(actualLocation))
				require.Equal(t, anchorTagWithLocationHref, rsp.Body.String())
			case http.StatusSeeOther:
				anchorTagWithLocationHref := fmt.Sprintf("<a href=\"%s\">See Other</a>.\n\n", html.EscapeString(actualLocation))
				require.Equal(t, anchorTagWithLocationHref, rsp.Body.String())
			default:
				t.Errorf("unexpected response code: %v", code)
			}
		case test.wantBodyRegex != "":
			require.Regexp(t, test.wantBodyRegex, rsp.Body.String())
		default:
			require.Equal(t, test.wantBodyString, rsp.Body.String())
		}

		if test.wantCSRFValueInCookieHeader != "" {
			require.Len(t, rsp.Header().Values("Set-Cookie"), 1)
			actualCookie := rsp.Header().Get("Set-Cookie")
			regex := regexp.MustCompile("__Host-pinniped-csrf=([^;]+); Path=/; HttpOnly; Secure; SameSite=Lax")
			submatches := regex.FindStringSubmatch(actualCookie)
			require.Len(t, submatches, 2)
			captured := submatches[1]
			var decodedCSRFCookieValue string
			err := test.cookieEncoder.Decode("csrf", captured, &decodedCSRFCookieValue)
			require.NoError(t, err)
			require.Equal(t, test.wantCSRFValueInCookieHeader, decodedCSRFCookieValue)
		} else {
			require.Empty(t, rsp.Header().Values("Set-Cookie"))
		}
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset()
			supervisorClient := supervisorfake.NewSimpleClientset()
			secretsClient := kubeClient.CoreV1().Secrets("some-namespace")
			oidcClientsClient := supervisorClient.ConfigV1alpha1().OIDCClients("some-namespace")
			oauthHelperWithRealStorage, kubeOauthStore := createOauthHelperWithRealStorage(secretsClient, oidcClientsClient)
			oauthHelperWithNullStorage, _ := createOauthHelperWithNullStorage(secretsClient, oidcClientsClient)

			idps := test.idps.BuildFederationDomainIdentityProvidersListerFinder()

			oidcIDPsCount := 0
			for _, p := range idps.GetIdentityProviders() {
				if p.GetSessionProviderType() == psession.ProviderTypeOIDC {
					oidcIDPsCount++
				}
			}
			if len(test.wantDownstreamAdditionalClaims) > 0 {
				require.True(t, oidcIDPsCount > 0, "wantDownstreamAdditionalClaims requires at least one OIDC IDP")
			}
			auditLogger, auditLog := plog.TestLogger(t)
			subject := NewHandler(
				downstreamIssuer,
				idps,
				oauthHelperWithNullStorage, oauthHelperWithRealStorage,
				test.generateCSRF, test.generatePKCE, test.generateNonce,
				test.stateEncoder, test.cookieEncoder,
				auditLogger,
			)
			runOneTestCase(t, test, subject, kubeOauthStore, supervisorClient, kubeClient, secretsClient, auditLog)
		})
	}

	t.Run("allows upstream provider configuration to change between requests", func(t *testing.T) {
		test := tests[0]
		// TODO: check to see if it's easy to verify audit logs
		test.wantAuditLogs = nil
		// Double-check that we are re-using the happy path test case here as we intend.
		require.Equal(t, "OIDC upstream browser flow happy path using GET without a CSRF cookie", test.name)

		kubeClient := fake.NewSimpleClientset()
		supervisorClient := supervisorfake.NewSimpleClientset()
		secretsClient := kubeClient.CoreV1().Secrets("some-namespace")
		oidcClientsClient := supervisorClient.ConfigV1alpha1().OIDCClients("some-namespace")
		oauthHelperWithRealStorage, kubeOauthStore := createOauthHelperWithRealStorage(secretsClient, oidcClientsClient)
		oauthHelperWithNullStorage, _ := createOauthHelperWithNullStorage(secretsClient, oidcClientsClient)
		idpLister := test.idps.BuildFederationDomainIdentityProvidersListerFinder()
		auditLogger, auditLog := plog.TestLogger(t)
		subject := NewHandler(
			downstreamIssuer,
			idpLister,
			oauthHelperWithNullStorage, oauthHelperWithRealStorage,
			test.generateCSRF, test.generatePKCE, test.generateNonce,
			test.stateEncoder, test.cookieEncoder,
			auditLogger,
		)

		runOneTestCase(t, test, subject, kubeOauthStore, supervisorClient, kubeClient, secretsClient, auditLog)

		// Call the idpLister's setter to change the upstream IDP settings.
		newProviderSettings := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
			WithName("some-other-new-idp-name").
			WithClientID("some-other-new-client-id").
			WithAuthorizationURL(*upstreamAuthURL).
			WithScopes([]string{"some-other-new-scope1", "some-other-new-scope2"}).
			WithAdditionalAuthcodeParams(map[string]string{"prompt": "consent", "abc": "123"}).
			Build()
		idpLister.SetOIDCIdentityProviders([]*oidctestutil.TestUpstreamOIDCIdentityProvider{newProviderSettings})

		test.path = modifiedHappyGetRequestPath(map[string]string{
			// update the IDP name in the request to match the name of the new IDP
			"pinniped_idp_name": "some-other-new-idp-name",
		})

		// Update the expectations of the test case to match the new upstream IDP settings.
		test.wantLocationHeader = urlWithQuery(upstreamAuthURL.String(),
			map[string]string{
				"response_type": "code",
				"prompt":        "consent",
				"abc":           "123",
				"scope":         "some-other-new-scope1 some-other-new-scope2", // updated expectation
				"client_id":     "some-other-new-client-id",                    // updated expectation
				"state": expectedUpstreamStateParam(
					nil, "", "some-other-new-idp-name", "oidc",
				), // updated expectation
				"nonce":                 happyNonce,
				"code_challenge":        expectedUpstreamCodeChallenge,
				"code_challenge_method": downstreamPKCEChallengeMethod,
				"redirect_uri":          downstreamIssuer + "/callback",
			},
		)
		test.wantBodyString = fmt.Sprintf(`<a href="%s">Found</a>.%s`,
			html.EscapeString(test.wantLocationHeader),
			"\n\n",
		)

		// Run again on the same instance of the subject with the modified upstream IDP settings and the
		// modified expectations. This should ensure that the implementation is using the in-memory cache
		// of upstream IDP settings appropriately in terms of always getting the values from the cache
		// on every request.
		runOneTestCase(t, test, subject, kubeOauthStore, supervisorClient, kubeClient, secretsClient, auditLog)
	})
}

type errorReturningEncoder struct {
	oidc.Codec
}

func (*errorReturningEncoder) Encode(_ string, _ any) (string, error) {
	return "", fmt.Errorf("some encoding error")
}

type expectedPasswordGrant struct {
	performedByUpstreamName string
	args                    *oidctestutil.PasswordCredentialsGrantAndValidateTokensArgs
}

func requireEqualDecodedStateParams(t *testing.T, actualURL string, expectedURL string, stateParamDecoder oidc.Codec) string {
	t.Helper()
	actualLocationURL, err := url.Parse(actualURL)
	require.NoError(t, err)
	expectedLocationURL, err := url.Parse(expectedURL)
	require.NoError(t, err)

	expectedQueryStateParam := expectedLocationURL.Query().Get("state")
	require.NotEmpty(t, expectedQueryStateParam)
	var expectedDecodedStateParam oidctestutil.ExpectedUpstreamStateParamFormat
	err = stateParamDecoder.Decode("s", expectedQueryStateParam, &expectedDecodedStateParam)
	require.NoError(t, err)

	actualQueryStateParam := actualLocationURL.Query().Get("state")
	require.NotEmpty(t, actualQueryStateParam)
	var actualDecodedStateParam oidctestutil.ExpectedUpstreamStateParamFormat
	err = stateParamDecoder.Decode("s", actualQueryStateParam, &actualDecodedStateParam)
	require.NoError(t, err)

	require.Equal(t, expectedDecodedStateParam, actualDecodedStateParam)

	return actualQueryStateParam
}

func requireEqualURLsIgnoringState(t *testing.T, actualURL string, expectedURL string) {
	t.Helper()
	actualLocationURL, err := url.Parse(actualURL)
	require.NoError(t, err)
	expectedLocationURL, err := url.Parse(expectedURL)
	require.NoError(t, err)
	require.Equal(t, expectedLocationURL.Scheme, actualLocationURL.Scheme,
		"schemes were not equal: expected %s but got %s", expectedURL, actualURL,
	)
	require.Equal(t, expectedLocationURL.User, actualLocationURL.User,
		"users were not equal: expected %s but got %s", expectedURL, actualURL,
	)

	require.Equal(t, expectedLocationURL.Host, actualLocationURL.Host,
		"hosts were not equal: expected %s but got %s", expectedURL, actualURL,
	)

	require.Equal(t, expectedLocationURL.Path, actualLocationURL.Path,
		"paths were not equal: expected %s but got %s", expectedURL, actualURL,
	)

	expectedLocationQuery := expectedLocationURL.Query()
	actualLocationQuery := actualLocationURL.Query()
	// Ignore the state, since it was encoded with a randomly-generated initialization vector that cannot be reproduced.
	expectedLocationQuery.Del("state")
	actualLocationQuery.Del("state")

	require.Equal(t, expectedLocationQuery, actualLocationQuery)
}
