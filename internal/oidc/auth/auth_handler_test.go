// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
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

	"github.com/gorilla/securecookie"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/pointer"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

func TestAuthorizationEndpoint(t *testing.T) {
	const (
		oidcUpstreamName                     = "some-oidc-idp"
		oidcUpstreamResourceUID              = "oidc-resource-uid"
		oidcPasswordGrantUpstreamName        = "some-password-granting-oidc-idp"
		oidcPasswordGrantUpstreamResourceUID = "some-password-granting-resource-uid"
		ldapUpstreamName                     = "some-ldap-idp"
		ldapUpstreamResourceUID              = "ldap-resource-uid"
		activeDirectoryUpstreamName          = "some-active-directory-idp"
		activeDirectoryUpstreamResourceUID   = "active-directory-resource-uid"

		oidcUpstreamIssuer                    = "https://my-upstream-issuer.com"
		oidcUpstreamSubject                   = "abc123-some guid" // has a space character which should get escaped in URL
		oidcUpstreamSubjectQueryEscaped       = "abc123-some+guid"
		oidcUpstreamUsername                  = "test-oidc-pinniped-username"
		oidcUpstreamPassword                  = "test-oidc-pinniped-password" //nolint: gosec
		oidcUpstreamUsernameClaim             = "the-user-claim"
		oidcUpstreamGroupsClaim               = "the-groups-claim"
		oidcPasswordGrantUpstreamRefreshToken = "some-opaque-token" //nolint: gosec

		downstreamIssuer                       = "https://my-downstream-issuer.com/some-path"
		downstreamRedirectURI                  = "http://127.0.0.1/callback"
		downstreamRedirectURIWithDifferentPort = "http://127.0.0.1:42/callback"
		downstreamNonce                        = "some-nonce-value"
		downstreamPKCEChallenge                = "some-challenge"
		downstreamPKCEChallengeMethod          = "S256"
		happyState                             = "8b-state"
		downstreamClientID                     = "pinniped-cli"
		upstreamLDAPURL                        = "ldaps://some-ldap-host:123?base=ou%3Dusers%2Cdc%3Dpinniped%2Cdc%3Ddev"
		htmlContentType                        = "text/html; charset=utf-8"
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

		fositeAccessDeniedWithMissingRefreshTokenErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Refresh token not returned by upstream provider during password grant.",
			"state":             happyState,
		}

		fositeAccessDeniedWithPasswordGrantDisallowedHintErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Resource owner password credentials grant is not allowed for this upstream provider according to its configuration.",
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

		fositeLoginRequiredErrorQuery = map[string]string{
			"error":             "login_required",
			"error_description": "The Authorization Server requires End-User authentication.",
			"state":             happyState,
		}
	)

	hmacSecretFunc := func() []byte { return []byte("some secret - must have at least 32 bytes") }
	require.GreaterOrEqual(t, len(hmacSecretFunc()), 32, "fosite requires that hmac secrets have at least 32 bytes")
	jwksProviderIsUnused := jwks.NewDynamicJWKSProvider()
	timeoutsConfiguration := oidc.DefaultOIDCTimeoutsConfiguration()

	createOauthHelperWithRealStorage := func(secretsClient v1.SecretInterface) (fosite.OAuth2Provider, *oidc.KubeStorage) {
		// Configure fosite the same way that the production code would when using Kube storage.
		// Inject this into our test subject at the last second so we get a fresh storage for every test.
		kubeOauthStore := oidc.NewKubeStorage(secretsClient, timeoutsConfiguration)
		return oidc.FositeOauth2Helper(kubeOauthStore, downstreamIssuer, hmacSecretFunc, jwksProviderIsUnused, timeoutsConfiguration), kubeOauthStore
	}

	// Configure fosite the same way that the production code would, using NullStorage to turn off storage.
	nullOauthStore := oidc.NullStorage{}
	oauthHelperWithNullStorage := oidc.FositeOauth2Helper(nullOauthStore, downstreamIssuer, hmacSecretFunc, jwksProviderIsUnused, timeoutsConfiguration)

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
	happyLDAPUsernameFromAuthenticator := "some-mapped-ldap-username"
	happyLDAPPassword := "some-ldap-password" //nolint:gosec
	happyLDAPUID := "some-ldap-uid"
	happyLDAPUserDN := "cn=foo,dn=bar"
	happyLDAPGroups := []string{"group1", "group2", "group3"}

	parsedUpstreamLDAPURL, err := url.Parse(upstreamLDAPURL)
	require.NoError(t, err)

	ldapAuthenticateFunc := func(ctx context.Context, username, password string) (*authenticator.Response, bool, error) {
		if username == "" || password == "" {
			return nil, false, fmt.Errorf("should not have passed empty username or password to the authenticator")
		}
		if username == happyLDAPUsername && password == happyLDAPPassword {
			return &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   happyLDAPUsernameFromAuthenticator,
					UID:    happyLDAPUID,
					Groups: happyLDAPGroups,
					Extra:  map[string][]string{"userDN": {happyLDAPUserDN}},
				},
			}, true, nil
		}
		return nil, false, nil
	}

	upstreamLDAPIdentityProvider := oidctestutil.TestUpstreamLDAPIdentityProvider{
		Name:             ldapUpstreamName,
		ResourceUID:      ldapUpstreamResourceUID,
		URL:              parsedUpstreamLDAPURL,
		AuthenticateFunc: ldapAuthenticateFunc,
	}

	upstreamActiveDirectoryIdentityProvider := oidctestutil.TestUpstreamLDAPIdentityProvider{
		Name:             activeDirectoryUpstreamName,
		ResourceUID:      activeDirectoryUpstreamResourceUID,
		URL:              parsedUpstreamLDAPURL,
		AuthenticateFunc: ldapAuthenticateFunc,
	}

	erroringUpstreamLDAPIdentityProvider := oidctestutil.TestUpstreamLDAPIdentityProvider{
		Name:        ldapUpstreamName,
		ResourceUID: ldapUpstreamResourceUID,
		AuthenticateFunc: func(ctx context.Context, username, password string) (*authenticator.Response, bool, error) {
			return nil, false, fmt.Errorf("some ldap upstream auth error")
		},
	}

	happyCSRF := "test-csrf"
	happyPKCE := "test-pkce"
	happyNonce := "test-nonce"
	happyCSRFGenerator := func() (csrftoken.CSRFToken, error) { return csrftoken.CSRFToken(happyCSRF), nil }
	happyPKCEGenerator := func() (pkce.Code, error) { return pkce.Code(happyPKCE), nil }
	happyNonceGenerator := func() (nonce.Nonce, error) { return nonce.Nonce(happyNonce), nil }
	sadCSRFGenerator := func() (csrftoken.CSRFToken, error) { return "", fmt.Errorf("some csrf generator error") }
	sadPKCEGenerator := func() (pkce.Code, error) { return "", fmt.Errorf("some PKCE generator error") }
	sadNonceGenerator := func() (nonce.Nonce, error) { return "", fmt.Errorf("some nonce generator error") }

	// This is the PKCE challenge which is calculated as base64(sha256("test-pkce")). For example:
	// $ echo -n test-pkce | shasum -a 256 | cut -d" " -f1 | xxd -r -p | base64 | cut -d"=" -f1
	expectedUpstreamCodeChallenge := "VVaezYqum7reIhoavCHD1n2d-piN3r_mywoYj7fCR7g"

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

	happyDownstreamScopesRequested := []string{"openid", "profile", "email"}
	happyDownstreamScopesGranted := []string{"openid"}

	happyGetRequestQueryMap := map[string]string{
		"response_type":         "code",
		"scope":                 strings.Join(happyDownstreamScopesRequested, " "),
		"client_id":             downstreamClientID,
		"state":                 happyState,
		"nonce":                 downstreamNonce,
		"code_challenge":        downstreamPKCEChallenge,
		"code_challenge_method": downstreamPKCEChallengeMethod,
		"redirect_uri":          downstreamRedirectURI,
	}

	happyGetRequestPath := pathWithQuery("/some/path", happyGetRequestQueryMap)

	modifiedHappyGetRequestQueryMap := func(queryOverrides map[string]string) map[string]string {
		copyOfHappyGetRequestQueryMap := map[string]string{}
		for k, v := range happyGetRequestQueryMap {
			copyOfHappyGetRequestQueryMap[k] = v
		}
		for k, v := range queryOverrides {
			_, hasKey := copyOfHappyGetRequestQueryMap[k]
			if v == "" && hasKey {
				delete(copyOfHappyGetRequestQueryMap, k)
			} else {
				copyOfHappyGetRequestQueryMap[k] = v
			}
		}
		return copyOfHappyGetRequestQueryMap
	}

	modifiedHappyGetRequestPath := func(queryOverrides map[string]string) string {
		return pathWithQuery("/some/path", modifiedHappyGetRequestQueryMap(queryOverrides))
	}

	expectedUpstreamStateParam := func(queryOverrides map[string]string, csrfValueOverride, upstreamNameOverride string) string {
		csrf := happyCSRF
		if csrfValueOverride != "" {
			csrf = csrfValueOverride
		}
		upstreamName := oidcUpstreamName
		if upstreamNameOverride != "" {
			upstreamName = upstreamNameOverride
		}
		encoded, err := happyStateEncoder.Encode("s",
			oidctestutil.ExpectedUpstreamStateParamFormat{
				P: encodeQuery(modifiedHappyGetRequestQueryMap(queryOverrides)),
				U: upstreamName,
				N: happyNonce,
				C: csrf,
				K: happyPKCE,
				V: "1",
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

	expectedHappyActiveDirectoryUpstreamCustomSession := &psession.CustomSessionData{
		ProviderUID:  activeDirectoryUpstreamResourceUID,
		ProviderName: activeDirectoryUpstreamName,
		ProviderType: psession.ProviderTypeActiveDirectory,
		OIDC:         nil,
		LDAP:         nil,
		ActiveDirectory: &psession.ActiveDirectorySessionData{
			UserDN: happyLDAPUserDN,
		},
	}

	expectedHappyLDAPUpstreamCustomSession := &psession.CustomSessionData{
		ProviderUID:  ldapUpstreamResourceUID,
		ProviderName: ldapUpstreamName,
		ProviderType: psession.ProviderTypeLDAP,
		OIDC:         nil,
		LDAP: &psession.LDAPSessionData{
			UserDN: happyLDAPUserDN,
		},
		ActiveDirectory: nil,
	}

	expectedHappyOIDCPasswordGrantCustomSession := &psession.CustomSessionData{
		ProviderUID:  oidcPasswordGrantUpstreamResourceUID,
		ProviderName: oidcPasswordGrantUpstreamName,
		ProviderType: psession.ProviderTypeOIDC,
		OIDC: &psession.OIDCSessionData{
			UpstreamRefreshToken: oidcPasswordGrantUpstreamRefreshToken,
		},
	}

	// Note that fosite puts the granted scopes as a param in the redirect URI even though the spec doesn't seem to require it
	happyAuthcodeDownstreamRedirectLocationRegexp := downstreamRedirectURI + `\?code=([^&]+)&scope=openid&state=` + happyState

	incomingCookieCSRFValue := "csrf-value-from-cookie"
	encodedIncomingCookieCSRFValue, err := happyCookieEncoder.Encode("csrf", incomingCookieCSRFValue)
	require.NoError(t, err)

	type testCase struct {
		name string

		idps                 *oidctestutil.UpstreamIDPListerBuilder
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
		wantBodyJSON                           string
		wantCSRFValueInCookieHeader            string
		wantBodyStringWithLocationInHref       bool
		wantLocationHeader                     string
		wantUpstreamStateParamInLocationHeader bool

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
		wantUnnecessaryStoredRecords      int
		wantPasswordGrantCall             *expectedPasswordGrant
		wantDownstreamCustomSessionData   *psession.CustomSessionData
	}
	tests := []testCase{
		{
			name:                                   "OIDC upstream browser flow happy path using GET without a CSRF cookie",
			idps:                                   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPath,
			wantStatus:                             http.StatusFound,
			wantContentType:                        htmlContentType,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, "", ""), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                              "OIDC upstream password grant happy path using GET",
			idps:                              oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
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
			name:                              "LDAP upstream happy path using GET",
			idps:                              oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:              pointer.StringPtr(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&sub=" + happyLDAPUID,
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
			name:                              "ActiveDirectory upstream happy path using GET",
			idps:                              oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:              pointer.StringPtr(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&sub=" + happyLDAPUID,
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
			idps:                                   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPath,
			csrfCookie:                             "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue + " ",
			wantStatus:                             http.StatusFound,
			wantContentType:                        htmlContentType,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, incomingCookieCSRFValue, ""), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                                   "OIDC upstream browser flow happy path using POST",
			idps:                                   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodPost,
			path:                                   "/some/path",
			contentType:                            "application/x-www-form-urlencoded",
			body:                                   encodeQuery(happyGetRequestQueryMap),
			wantStatus:                             http.StatusFound,
			wantContentType:                        "",
			wantBodyString:                         "",
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, "", ""), nil),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:                              "OIDC upstream password grant happy path using POST",
			idps:                              oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                            http.MethodPost,
			path:                              "/some/path",
			contentType:                       "application/x-www-form-urlencoded",
			body:                              encodeQuery(happyGetRequestQueryMap),
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
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
			name:                              "LDAP upstream happy path using POST",
			idps:                              oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:                            http.MethodPost,
			path:                              "/some/path",
			contentType:                       "application/x-www-form-urlencoded",
			body:                              encodeQuery(happyGetRequestQueryMap),
			customUsernameHeader:              pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:              pointer.StringPtr(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&sub=" + happyLDAPUID,
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
			name:                              "Active Directory upstream happy path using POST",
			idps:                              oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method:                            http.MethodPost,
			path:                              "/some/path",
			contentType:                       "application/x-www-form-urlencoded",
			body:                              encodeQuery(happyGetRequestQueryMap),
			customUsernameHeader:              pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:              pointer.StringPtr(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&sub=" + happyLDAPUID,
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
			idps:                                   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   modifiedHappyGetRequestPath(map[string]string{"prompt": "login"}),
			contentType:                            "application/x-www-form-urlencoded",
			body:                                   encodeQuery(happyGetRequestQueryMap),
			wantStatus:                             http.StatusFound,
			wantContentType:                        htmlContentType,
			wantBodyStringWithLocationInHref:       true,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{"prompt": "login"}, "", ""), nil),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:                                   "OIDC upstream browser flow happy path with extra params that get passed through",
			idps:                                   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().WithAdditionalAuthcodeParams(map[string]string{"prompt": "consent", "abc": "123", "def": "456"}).Build()),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   modifiedHappyGetRequestPath(map[string]string{"prompt": "login"}),
			contentType:                            "application/x-www-form-urlencoded",
			body:                                   encodeQuery(happyGetRequestQueryMap),
			wantStatus:                             http.StatusFound,
			wantContentType:                        htmlContentType,
			wantBodyStringWithLocationInHref:       true,
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{"prompt": "login"}, "", ""), map[string]string{"prompt": "consent", "abc": "123", "def": "456"}),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:               "OIDC upstream browser flow with prompt param none throws an error because we want to independently decide the upstream prompt param",
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"prompt": "none"}),
			contentType:        "application/x-www-form-urlencoded",
			body:               encodeQuery(happyGetRequestQueryMap),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeLoginRequiredErrorQuery),
			wantBodyString:     "",
		},
		{
			name:            "OIDC upstream browser flow with error while decoding CSRF cookie just generates a new cookie and succeeds as usual",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			csrfCookie:      "__Host-pinniped-csrf=this-value-was-not-signed-by-pinniped",
			wantStatus:      http.StatusFound,
			wantContentType: htmlContentType,
			// Generated a new CSRF cookie and set it in the response.
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(nil, "", ""), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:          "OIDC upstream browser flow happy path when downstream redirect uri matches what is configured for client except for the port number",
			idps:          oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPath(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
			}),
			wantStatus:                  http.StatusFound,
			wantContentType:             htmlContentType,
			wantCSRFValueInCookieHeader: happyCSRF,
			wantLocationHeader: expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
			}, "", ""), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:   "OIDC upstream password grant happy path when downstream redirect uri matches what is configured for client except for the port number",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method: http.MethodGet,
			path: modifiedHappyGetRequestPath(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
			}),
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        downstreamRedirectURIWithDifferentPort + `\?code=([^&]+)&scope=openid&state=` + happyState,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
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
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method: http.MethodGet,
			path: modifiedHappyGetRequestPath(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
			}),
			customUsernameHeader:              pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:              pointer.StringPtr(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        downstreamRedirectURIWithDifferentPort + `\?code=([^&]+)&scope=openid&state=` + happyState,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&sub=" + happyLDAPUID,
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
			idps:                        oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:                happyCSRFGenerator,
			generatePKCE:                happyPKCEGenerator,
			generateNonce:               happyNonceGenerator,
			stateEncoder:                happyStateEncoder,
			cookieEncoder:               happyCookieEncoder,
			method:                      http.MethodGet,
			path:                        modifiedHappyGetRequestPath(map[string]string{"scope": "openid offline_access"}),
			wantStatus:                  http.StatusFound,
			wantContentType:             htmlContentType,
			wantCSRFValueInCookieHeader: happyCSRF,
			wantLocationHeader: expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(map[string]string{
				"scope": "openid offline_access",
			}, "", ""), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                 "error during upstream LDAP authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&erroringUpstreamLDAPIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusBadGateway,
			wantContentType:      htmlContentType,
			wantBodyString:       "Bad Gateway: unexpected error during upstream authentication\n",
		},
		{
			name:                 "error during upstream Active Directory authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&erroringUpstreamLDAPIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusBadGateway,
			wantContentType:      htmlContentType,
			wantBodyString:       "Bad Gateway: unexpected error during upstream authentication\n",
		},
		{
			name: "wrong upstream credentials for OIDC password grant authentication",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					// This is similar to the error that would be returned by the underlying call to oauth2.PasswordCredentialsToken()
					WithPasswordGrantError(&oauth2.RetrieveError{Response: &http.Response{Status: "fake status"}, Body: []byte("fake body")}).
					Build(),
			),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader: pointer.StringPtr("wrong-password"),
			wantPasswordGrantCall: &expectedPasswordGrant{
				performedByUpstreamName: oidcPasswordGrantUpstreamName,
				args: &oidctestutil.PasswordCredentialsGrantAndValidateTokensArgs{
					Username: oidcUpstreamUsername,
					Password: "wrong-password",
				}},
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeAccessDeniedErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "wrong upstream password for LDAP authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: pointer.StringPtr("wrong-password"),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithBadUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "wrong upstream password for Active Directory authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: pointer.StringPtr("wrong-password"),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithBadUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "wrong upstream username for LDAP authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr("wrong-username"),
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithBadUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "wrong upstream username for Active Directory authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr("wrong-username"),
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithBadUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "missing upstream username on request for LDAP authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: nil, // do not send header
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "missing upstream username on request for Active Directory authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: nil, // do not send header
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "missing upstream password on request for LDAP authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: nil, // do not send header
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "missing upstream password on request for Active Directory authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: nil, // do not send header
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                  "return an error when upstream IDP did not return a refresh token",
			idps:                  oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutRefreshToken().Build()),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingRefreshTokenErrorQuery),
			wantBodyString:        "",
		},
		{
			name:                  "return an error when upstream IDP did not return a refresh token",
			idps:                  oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().WithEmptyRefreshToken().Build()),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingRefreshTokenErrorQuery),
			wantBodyString:        "",
		},
		{
			name:                 "missing upstream password on request for OIDC password grant authentication",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader: nil, // do not send header
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithMissingUsernamePasswordHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "using the custom username header on request for OIDC password grant authentication when OIDCIdentityProvider does not allow password grants",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 happyGetRequestPath,
			customUsernameHeader: pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader: pointer.StringPtr(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithPasswordGrantDisallowedHintErrorQuery),
			wantBodyString:       "",
		},
		{
			name:          "downstream redirect uri does not match what is configured for client when using OIDC upstream browser flow",
			idps:          oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPath(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client",
			}),
			wantStatus:      http.StatusBadRequest,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidRedirectURIErrorBody,
		},
		{
			name:   "downstream redirect uri does not match what is configured for client when using OIDC upstream password grant",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method: http.MethodGet,
			path: modifiedHappyGetRequestPath(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client",
			}),
			customUsernameHeader: pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader: pointer.StringPtr(oidcUpstreamPassword),
			wantStatus:           http.StatusBadRequest,
			wantContentType:      "application/json; charset=utf-8",
			wantBodyJSON:         fositeInvalidRedirectURIErrorBody,
		},
		{
			name:   "downstream redirect uri does not match what is configured for client when using LDAP upstream",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method: http.MethodGet,
			path: modifiedHappyGetRequestPath(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client",
			}),
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusBadRequest,
			wantContentType:      "application/json; charset=utf-8",
			wantBodyJSON:         fositeInvalidRedirectURIErrorBody,
		},
		{
			name:   "downstream redirect uri does not match what is configured for client when using active directory upstream",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method: http.MethodGet,
			path: modifiedHappyGetRequestPath(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client",
			}),
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusBadRequest,
			wantContentType:      "application/json; charset=utf-8",
			wantBodyJSON:         fositeInvalidRedirectURIErrorBody,
		},
		{
			name:            "downstream client does not exist when using OIDC upstream browser flow",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPath(map[string]string{"client_id": "invalid-client"}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:                 "downstream client does not exist when using OIDC upstream password grant",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPath(map[string]string{"client_id": "invalid-client"}),
			customUsernameHeader: pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader: pointer.StringPtr(oidcUpstreamPassword),
			wantStatus:           http.StatusUnauthorized,
			wantContentType:      "application/json; charset=utf-8",
			wantBodyJSON:         fositeInvalidClientErrorBody,
		},
		{
			name:            "downstream client does not exist when using LDAP upstream",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPath(map[string]string{"client_id": "invalid-client"}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:            "downstream client does not exist when using active directory upstream",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPath(map[string]string{"client_id": "invalid-client"}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:               "response type is unsupported when using OIDC upstream browser flow",
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"response_type": "unsupported"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "response type is unsupported when using OIDC upstream password grant",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPath(map[string]string{"response_type": "unsupported"}),
			customUsernameHeader: pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader: pointer.StringPtr(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:               "response type is unsupported when using LDAP upstream",
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"response_type": "unsupported"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "response type is unsupported when using active directory upstream",
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"response_type": "unsupported"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "downstream scopes do not match what is configured for client using OIDC upstream browser flow",
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"scope": "openid profile email tuna"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "downstream scopes do not match what is configured for client using OIDC upstream password grant",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPath(map[string]string{"scope": "openid profile email tuna"}),
			customUsernameHeader: pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader: pointer.StringPtr(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "downstream scopes do not match what is configured for client using LDAP upstream",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPath(map[string]string{"scope": "openid tuna"}),
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "downstream scopes do not match what is configured for client using Active Directory upstream",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPath(map[string]string{"scope": "openid tuna"}),
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:               "missing response type in request using OIDC upstream browser flow",
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"response_type": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "missing response type in request using OIDC upstream password grant",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPath(map[string]string{"response_type": ""}),
			customUsernameHeader: pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader: pointer.StringPtr(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:       "",
		},
		{
			name:               "missing response type in request using LDAP upstream",
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"response_type": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "missing response type in request using Active Directory upstream",
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider),
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"response_type": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:            "missing client id in request using OIDC upstream browser flow",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPath(map[string]string{"client_id": ""}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:                 "missing client id in request using OIDC upstream password grant",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPath(map[string]string{"client_id": ""}),
			customUsernameHeader: pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader: pointer.StringPtr(oidcUpstreamPassword),
			wantStatus:           http.StatusUnauthorized,
			wantContentType:      "application/json; charset=utf-8",
			wantBodyJSON:         fositeInvalidClientErrorBody,
		},
		{
			name:            "missing client id in request using LDAP upstream",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPath(map[string]string{"client_id": ""}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:               "missing PKCE code_challenge in request using OIDC upstream browser flow", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                         "missing PKCE code_challenge in request using OIDC upstream password grant", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:                         oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPath(map[string]string{"code_challenge": ""}),
			customUsernameHeader:         pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:         pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:        happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                   http.StatusFound,
			wantContentType:              "application/json; charset=utf-8",
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:                         "missing PKCE code_challenge in request using LDAP upstream", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:                         oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPath(map[string]string{"code_challenge": ""}),
			customUsernameHeader:         pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:         pointer.StringPtr(happyLDAPPassword),
			wantStatus:                   http.StatusFound,
			wantContentType:              "application/json; charset=utf-8",
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:               "invalid value for PKCE code_challenge_method in request using OIDC upstream browser flow", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": "this-is-not-a-valid-pkce-alg"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidCodeChallengeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                         "invalid value for PKCE code_challenge_method in request using OIDC upstream password grant", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:                         oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": "this-is-not-a-valid-pkce-alg"}),
			customUsernameHeader:         pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:         pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:        happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                   http.StatusFound,
			wantContentType:              "application/json; charset=utf-8",
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeInvalidCodeChallengeErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:                         "invalid value for PKCE code_challenge_method in request using LDAP upstream", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:                         oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": "this-is-not-a-valid-pkce-alg"}),
			customUsernameHeader:         pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:         pointer.StringPtr(happyLDAPPassword),
			wantStatus:                   http.StatusFound,
			wantContentType:              "application/json; charset=utf-8",
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeInvalidCodeChallengeErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:               "when PKCE code_challenge_method in request is `plain` using OIDC upstream browser flow", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": "plain"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                         "when PKCE code_challenge_method in request is `plain` using OIDC upstream password grant", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:                         oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": "plain"}),
			customUsernameHeader:         pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:         pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:        happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                   http.StatusFound,
			wantContentType:              "application/json; charset=utf-8",
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:                         "when PKCE code_challenge_method in request is `plain` using LDAP upstream", // https://tools.ietf.org/html/rfc7636#section-4.3
			idps:                         oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": "plain"}),
			customUsernameHeader:         pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:         pointer.StringPtr(happyLDAPPassword),
			wantStatus:                   http.StatusFound,
			wantContentType:              "application/json; charset=utf-8",
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:               "missing PKCE code_challenge_method in request using OIDC upstream browser flow", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                         "missing PKCE code_challenge_method in request using OIDC upstream password grant", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:                         oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": ""}),
			customUsernameHeader:         pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:         pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:        happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                   http.StatusFound,
			wantContentType:              "application/json; charset=utf-8",
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:                         "missing PKCE code_challenge_method in request using LDAP upstream", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			idps:                         oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": ""}),
			customUsernameHeader:         pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:         pointer.StringPtr(happyLDAPPassword),
			wantStatus:                   http.StatusFound,
			wantContentType:              "application/json; charset=utf-8",
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			// This is just one of the many OIDC validations run by fosite. This test is to ensure that we are running
			// through that part of the fosite library when using an OIDC upstream browser flow.
			name:               "prompt param is not allowed to have none and another legal value at the same time using OIDC upstream browser flow",
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"prompt": "none login"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositePromptHasNoneAndOtherValueErrorQuery),
			wantBodyString:     "",
		},
		{
			// This is just one of the many OIDC validations run by fosite. This test is to ensure that we are running
			// through that part of the fosite library when using an OIDC upstream password grant.
			name:                         "prompt param is not allowed to have none and another legal value at the same time using OIDC upstream password grant",
			idps:                         oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPath(map[string]string{"prompt": "none login"}),
			customUsernameHeader:         pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:         pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:        happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                   http.StatusFound,
			wantContentType:              "application/json; charset=utf-8",
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositePromptHasNoneAndOtherValueErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 1, // fosite already stored the authcode before it noticed the error
		},
		{
			// This is just one of the many OIDC validations run by fosite. This test is to ensure that we are running
			// through that part of the fosite library when using an LDAP upstream.
			name:                         "prompt param is not allowed to have none and another legal value at the same time using LDAP upstream",
			idps:                         oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:                       http.MethodGet,
			path:                         modifiedHappyGetRequestPath(map[string]string{"prompt": "none login"}),
			customUsernameHeader:         pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:         pointer.StringPtr(happyLDAPPassword),
			wantStatus:                   http.StatusFound,
			wantContentType:              "application/json; charset=utf-8",
			wantLocationHeader:           urlWithQuery(downstreamRedirectURI, fositePromptHasNoneAndOtherValueErrorQuery),
			wantBodyString:               "",
			wantUnnecessaryStoredRecords: 1, // fosite already stored the authcode before it noticed the error
		},
		{
			name:          "happy path: downstream OIDC validations are skipped when the openid scope was not requested using OIDC upstream browser flow",
			idps:          oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			// The following prompt value is illegal when openid is requested, but note that openid is not requested.
			path:                        modifiedHappyGetRequestPath(map[string]string{"prompt": "none login", "scope": "email"}),
			wantStatus:                  http.StatusFound,
			wantContentType:             htmlContentType,
			wantCSRFValueInCookieHeader: happyCSRF,
			wantLocationHeader: expectedRedirectLocationForUpstreamOIDC(expectedUpstreamStateParam(
				map[string]string{"prompt": "none login", "scope": "email"}, "", "",
			), nil),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:   "happy path: downstream OIDC validations are skipped when the openid scope was not requested using OIDC upstream password grant",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method: http.MethodGet,
			// The following prompt value is illegal when openid is requested, but note that openid is not requested.
			path:                              modifiedHappyGetRequestPath(map[string]string{"prompt": "none login", "scope": "email"}),
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=&state=` + happyState, // no scopes granted
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     []string{"email"}, // only email was requested
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       []string{}, // no scopes granted
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
		},
		{
			name:   "happy path: downstream OIDC validations are skipped when the openid scope was not requested using LDAP upstream",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method: http.MethodGet,
			// The following prompt value is illegal when openid is requested, but note that openid is not requested.
			path:                              modifiedHappyGetRequestPath(map[string]string{"prompt": "none login", "scope": "email"}),
			customUsernameHeader:              pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader:              pointer.StringPtr(happyLDAPPassword),
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=&state=` + happyState, // no scopes granted
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     []string{"email"}, // only email was requested
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       []string{}, // no scopes granted
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name: "OIDC upstream password grant: upstream IDP provides no username or group claim configuration, so we use default username claim and skip groups",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutUsernameClaim().WithoutGroupsClaim().Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenGroups:       []string{},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
		},
		{
			name: "OIDC upstream password grant: upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is missing",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe@whitehouse.gov",
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
			name: "OIDC upstream password grant: upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with true value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", true).Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe@whitehouse.gov",
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
			name: "OIDC upstream password grant: upstream IDP configures username claim as anything other than special claim `email` and `email_verified` upstream claim is present with false value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithUsernameClaim("some-claim").
					WithIDTokenClaim("some-claim", "joe").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", false).Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe",
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
			name: "OIDC upstream password grant: upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with illegal value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", "supposed to be boolean").Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithInvalidEmailVerifiedHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with false value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", false).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithFalseEmailVerifiedHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream IDP provides username claim configuration as `sub`, so the downstream token subject should be exactly what they asked for",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithUsernameClaim("sub").Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamSubject,
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
			name: "OIDC upstream password grant: upstream IDP's configured groups claim in the ID token has a non-array value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithIDTokenClaim(oidcUpstreamGroupsClaim, "notAnArrayGroup1 notAnArrayGroup2").Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       []string{"notAnArrayGroup1 notAnArrayGroup2"},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
		},
		{
			name: "OIDC upstream password grant: upstream IDP's configured groups claim in the ID token is a slice of interfaces",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().
					WithIDTokenClaim(oidcUpstreamGroupsClaim, []interface{}{"group1", "group2"}).Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       []string{"group1", "group2"},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
		},
		{
			name: "OIDC upstream password grant: upstream ID token does not contain requested username claim",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutIDTokenClaim(oidcUpstreamUsernameClaim).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimMissingHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token does not contain requested groups claim",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutIDTokenClaim(oidcUpstreamGroupsClaim).Build(),
			),
			method:                            http.MethodGet,
			path:                              happyGetRequestPath,
			customUsernameHeader:              pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:              pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall:             happyUpstreamPasswordGrantMockExpectation,
			wantStatus:                        http.StatusFound,
			wantContentType:                   htmlContentType,
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       []string{},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyOIDCPasswordGrantCustomSession,
		},
		{
			name: "OIDC upstream password grant: upstream ID token contains username claim with weird format",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim(oidcUpstreamUsernameClaim, 42).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token contains username claim with empty string value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim(oidcUpstreamUsernameClaim, "").Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimEmptyHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token does not contain iss claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutIDTokenClaim("iss").WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimMissingHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token does has an empty string value for iss claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim("iss", "").WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimEmptyHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token has an non-string iss claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim("iss", 42).WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token does not contain sub claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithoutIDTokenClaim("sub").WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimMissingHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token does has an empty string value for sub claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim("sub", "").WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimEmptyHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token has an non-string sub claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim("sub", 42).WithoutUsernameClaim().Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token contains groups claim with weird format",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim(oidcUpstreamGroupsClaim, 42).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token contains groups claim where one element is invalid",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim(oidcUpstreamGroupsClaim, []interface{}{"foo", 7}).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name: "OIDC upstream password grant: upstream ID token contains groups claim with invalid null type",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				passwordGrantUpstreamOIDCIdentityProviderBuilder().WithIDTokenClaim(oidcUpstreamGroupsClaim, nil).Build(),
			),
			method:                http.MethodGet,
			path:                  happyGetRequestPath,
			customUsernameHeader:  pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader:  pointer.StringPtr(oidcUpstreamPassword),
			wantPasswordGrantCall: happyUpstreamPasswordGrantMockExpectation,
			wantStatus:            http.StatusFound,
			wantContentType:       "application/json; charset=utf-8",
			wantLocationHeader:    urlWithQuery(downstreamRedirectURI, fositeAccessDeniedWithRequiredClaimInvalidFormatHintErrorQuery),
			wantBodyString:        "",
		},
		{
			name:               "downstream state does not have enough entropy using OIDC upstream browser flow",
			idps:               oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"state": "short"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidStateErrorQuery),
			wantBodyString:     "",
		},
		{
			name:                 "downstream state does not have enough entropy using OIDC upstream password grant",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(passwordGrantUpstreamOIDCIdentityProviderBuilder().Build()),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPath(map[string]string{"state": "short"}),
			customUsernameHeader: pointer.StringPtr(oidcUpstreamUsername),
			customPasswordHeader: pointer.StringPtr(oidcUpstreamPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeInvalidStateErrorQuery),
			wantBodyString:       "",
		},
		{
			name:                 "downstream state does not have enough entropy using LDAP upstream",
			idps:                 oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider),
			method:               http.MethodGet,
			path:                 modifiedHappyGetRequestPath(map[string]string{"state": "short"}),
			customUsernameHeader: pointer.StringPtr(happyLDAPUsername),
			customPasswordHeader: pointer.StringPtr(happyLDAPPassword),
			wantStatus:           http.StatusFound,
			wantContentType:      "application/json; charset=utf-8",
			wantLocationHeader:   urlWithQuery(downstreamRedirectURI, fositeInvalidStateErrorQuery),
			wantBodyString:       "",
		},
		{
			name:            "error while encoding upstream state param using OIDC upstream browser flow",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    &errorReturningEncoder{},
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error encoding upstream state param\n",
		},
		{
			name:            "error while encoding CSRF cookie value for new cookie using OIDC upstream browser flow",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   &errorReturningEncoder{},
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error encoding CSRF cookie\n",
		},
		{
			name:            "error while generating CSRF token using OIDC upstream browser flow",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    sadCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error generating CSRF token\n",
		},
		{
			name:            "error while generating nonce using OIDC upstream browser flow",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   sadNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error generating nonce param\n",
		},
		{
			name:            "error while generating PKCE using OIDC upstream browser flow",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    sadPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error generating PKCE param\n",
		},
		{
			name:            "no upstream providers are configured",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(), // empty
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: No upstream providers are configured\n",
		},
		{
			name:            "too many upstream providers are configured: multiple OIDC",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build(), upstreamOIDCIdentityProviderBuilder().Build()), // more than one not allowed
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: Too many upstream providers are configured (support for multiple upstreams is not yet implemented)\n",
		},
		{
			name:            "too many upstream providers are configured: multiple LDAP",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&upstreamLDAPIdentityProvider, &upstreamLDAPIdentityProvider), // more than one not allowed
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: Too many upstream providers are configured (support for multiple upstreams is not yet implemented)\n",
		},
		{
			name:            "too many upstream providers are configured: multiple Active Directory",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&upstreamLDAPIdentityProvider, &upstreamLDAPIdentityProvider), // more than one not allowed
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: Too many upstream providers are configured (support for multiple upstreams is not yet implemented)\n",
		},
		{
			name:            "too many upstream providers are configured: both OIDC and LDAP",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()).WithLDAP(&upstreamLDAPIdentityProvider), // more than one not allowed
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: Too many upstream providers are configured (support for multiple upstreams is not yet implemented)\n",
		},
		{
			name:            "too many upstream providers are configured: OIDC, LDAP and AD",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()).WithLDAP(&upstreamLDAPIdentityProvider).WithActiveDirectory(&upstreamActiveDirectoryIdentityProvider), // more than one not allowed
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: Too many upstream providers are configured (support for multiple upstreams is not yet implemented)\n",
		},
		{
			name:            "PUT is a bad method",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:          http.MethodPut,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method Not Allowed: PUT (try GET or POST)\n",
		},
		{
			name:            "PATCH is a bad method",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:          http.MethodPatch,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method Not Allowed: PATCH (try GET or POST)\n",
		},
		{
			name:            "DELETE is a bad method",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			method:          http.MethodDelete,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method Not Allowed: DELETE (try GET or POST)\n",
		},
	}

	runOneTestCase := func(t *testing.T, test testCase, subject http.Handler, kubeOauthStore *oidc.KubeStorage, kubeClient *fake.Clientset, secretsClient v1.SecretInterface) {
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
		rsp := httptest.NewRecorder()
		subject.ServeHTTP(rsp, req)
		t.Logf("response: %#v", rsp)
		t.Logf("response body: %q", rsp.Body.String())

		require.Equal(t, test.wantStatus, rsp.Code)
		testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), test.wantContentType)
		testutil.RequireSecurityHeaders(t, rsp)

		if test.wantPasswordGrantCall != nil {
			test.wantPasswordGrantCall.args.Ctx = reqContext
			test.idps.RequireExactlyOneCallToPasswordCredentialsGrantAndValidateTokens(t,
				test.wantPasswordGrantCall.performedByUpstreamName, test.wantPasswordGrantCall.args,
			)
		} else {
			test.idps.RequireExactlyZeroCallsToPasswordCredentialsGrantAndValidateTokens(t)
		}

		actualLocation := rsp.Header().Get("Location")
		switch {
		case test.wantLocationHeader != "":
			if test.wantUpstreamStateParamInLocationHeader {
				requireEqualDecodedStateParams(t, actualLocation, test.wantLocationHeader, test.stateEncoder)
			}
			// The upstream state param is encoded using a timestamp at the beginning so we don't want to
			// compare those states since they may be different, but we do want to compare the downstream
			// state param that should be exactly the same.
			requireEqualURLs(t, actualLocation, test.wantLocationHeader, test.wantUpstreamStateParamInLocationHeader)

			// Authorization requests for either a successful OIDC upstream or for an error with any upstream
			// should never use Kube storage. There is only one exception to this rule, which is that certain
			// OIDC validations are checked in fosite after the OAuth authcode (and sometimes the OIDC session)
			// is stored, so it is possible with an LDAP upstream to store objects and then return an error to
			// the client anyway (which makes the stored objects useless, but oh well).
			require.Len(t, kubeClient.Actions(), test.wantUnnecessaryStoredRecords)
		case test.wantRedirectLocationRegexp != "":
			require.Len(t, rsp.Header().Values("Location"), 1)
			oidctestutil.RequireAuthCodeRegexpMatch(
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
				downstreamClientID,
				test.wantDownstreamRedirectURI,
				test.wantDownstreamCustomSessionData,
			)
		default:
			require.Empty(t, rsp.Header().Values("Location"))
		}

		switch {
		case test.wantBodyJSON != "":
			require.JSONEq(t, test.wantBodyJSON, rsp.Body.String())
		case test.wantBodyStringWithLocationInHref:
			anchorTagWithLocationHref := fmt.Sprintf("<a href=\"%s\">Found</a>.\n\n", html.EscapeString(actualLocation))
			require.Equal(t, anchorTagWithLocationHref, rsp.Body.String())
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
		test := test
		t.Run(test.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset()
			secretsClient := kubeClient.CoreV1().Secrets("some-namespace")
			oauthHelperWithRealStorage, kubeOauthStore := createOauthHelperWithRealStorage(secretsClient)
			subject := NewHandler(
				downstreamIssuer,
				test.idps.Build(),
				oauthHelperWithNullStorage, oauthHelperWithRealStorage,
				test.generateCSRF, test.generatePKCE, test.generateNonce,
				test.stateEncoder, test.cookieEncoder,
			)
			runOneTestCase(t, test, subject, kubeOauthStore, kubeClient, secretsClient)
		})
	}

	t.Run("allows upstream provider configuration to change between requests", func(t *testing.T) {
		test := tests[0]
		// Double-check that we are re-using the happy path test case here as we intend.
		require.Equal(t, "OIDC upstream browser flow happy path using GET without a CSRF cookie", test.name)

		kubeClient := fake.NewSimpleClientset()
		secretsClient := kubeClient.CoreV1().Secrets("some-namespace")
		oauthHelperWithRealStorage, kubeOauthStore := createOauthHelperWithRealStorage(secretsClient)
		idpLister := test.idps.Build()
		subject := NewHandler(
			downstreamIssuer,
			idpLister,
			oauthHelperWithNullStorage, oauthHelperWithRealStorage,
			test.generateCSRF, test.generatePKCE, test.generateNonce,
			test.stateEncoder, test.cookieEncoder,
		)

		runOneTestCase(t, test, subject, kubeOauthStore, kubeClient, secretsClient)

		// Call the idpLister's setter to change the upstream IDP settings.
		newProviderSettings := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
			WithName("some-other-new-idp-name").
			WithClientID("some-other-new-client-id").
			WithAuthorizationURL(*upstreamAuthURL).
			WithScopes([]string{"some-other-new-scope1", "some-other-new-scope2"}).
			WithAdditionalAuthcodeParams(map[string]string{"prompt": "consent", "abc": "123"}).
			Build()
		idpLister.SetOIDCIdentityProviders([]provider.UpstreamOIDCIdentityProviderI{provider.UpstreamOIDCIdentityProviderI(newProviderSettings)})

		// Update the expectations of the test case to match the new upstream IDP settings.
		test.wantLocationHeader = urlWithQuery(upstreamAuthURL.String(),
			map[string]string{
				"response_type": "code",
				"prompt":        "consent",
				"abc":           "123",
				"scope":         "some-other-new-scope1 some-other-new-scope2", // updated expectation
				"client_id":     "some-other-new-client-id",                    // updated expectation
				"state": expectedUpstreamStateParam(
					nil, "", "some-other-new-idp-name",
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
		runOneTestCase(t, test, subject, kubeOauthStore, kubeClient, secretsClient)
	})
}

type errorReturningEncoder struct {
	oidc.Codec
}

func (*errorReturningEncoder) Encode(_ string, _ interface{}) (string, error) {
	return "", fmt.Errorf("some encoding error")
}

type expectedPasswordGrant struct {
	performedByUpstreamName string
	args                    *oidctestutil.PasswordCredentialsGrantAndValidateTokensArgs
}

func requireEqualDecodedStateParams(t *testing.T, actualURL string, expectedURL string, stateParamDecoder oidc.Codec) {
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
}

func requireEqualURLs(t *testing.T, actualURL string, expectedURL string, ignoreState bool) {
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
	// Let the caller ignore the state, since it may contain a digest at the end that is difficult to
	// predict because it depends on a time.Now() timestamp.
	if ignoreState {
		expectedLocationQuery.Del("state")
		actualLocationQuery.Del("state")
	}
	require.Equal(t, expectedLocationQuery, actualLocationQuery)
}
