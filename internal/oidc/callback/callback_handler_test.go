// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package callback

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/oidcclientvalidator"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	oidcpkce "go.pinniped.dev/pkg/oidcclient/pkce"
)

const (
	happyUpstreamIDPName        = "upstream-idp-name"
	happyUpstreamIDPResourceUID = "upstream-uid"

	oidcUpstreamIssuer              = "https://my-upstream-issuer.com"
	oidcUpstreamRefreshToken        = "test-refresh-token"
	oidcUpstreamAccessToken         = "test-access-token"
	oidcUpstreamSubject             = "abc123-some guid" // has a space character which should get escaped in URL
	oidcUpstreamSubjectQueryEscaped = "abc123-some+guid"
	oidcUpstreamUsername            = "test-pinniped-username"

	oidcUpstreamUsernameClaim = "the-user-claim"
	oidcUpstreamGroupsClaim   = "the-groups-claim"

	happyUpstreamAuthcode    = "upstream-auth-code"
	happyUpstreamRedirectURI = "https://example.com/callback"

	happyDownstreamState        = "8b-state"
	happyDownstreamCSRF         = "test-csrf"
	happyDownstreamPKCE         = "test-pkce"
	happyDownstreamNonce        = "test-nonce"
	happyDownstreamStateVersion = "2"

	downstreamIssuer              = "https://my-downstream-issuer.com/path"
	downstreamRedirectURI         = "http://127.0.0.1/callback"
	downstreamPinnipedClientID    = "pinniped-cli"
	downstreamDynamicClientID     = "client.oauth.pinniped.dev-test-name"
	downstreamDynamicClientUID    = "fake-client-uid"
	downstreamNonce               = "some-nonce-value"
	downstreamPKCEChallenge       = "some-challenge"
	downstreamPKCEChallengeMethod = "S256"

	htmlContentType = "text/html; charset=utf-8"
)

var (
	oidcUpstreamGroupMembership    = []string{"test-pinniped-group-0", "test-pinniped-group-1"}
	happyDownstreamScopesRequested = []string{"openid", "username", "groups"}
	happyDownstreamScopesGranted   = []string{"openid", "username", "groups"}

	happyDownstreamRequestParamsQuery = url.Values{
		"response_type":         []string{"code"},
		"scope":                 []string{strings.Join(happyDownstreamScopesRequested, " ")},
		"client_id":             []string{downstreamPinnipedClientID},
		"state":                 []string{happyDownstreamState},
		"nonce":                 []string{downstreamNonce},
		"code_challenge":        []string{downstreamPKCEChallenge},
		"code_challenge_method": []string{downstreamPKCEChallengeMethod},
		"redirect_uri":          []string{downstreamRedirectURI},
	}
	happyDownstreamRequestParams = happyDownstreamRequestParamsQuery.Encode()

	happyDownstreamRequestParamsQueryForDynamicClient = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
		map[string]string{"client_id": downstreamDynamicClientID},
	)
	happyDownstreamRequestParamsForDynamicClient = happyDownstreamRequestParamsQueryForDynamicClient.Encode()

	happyDownstreamCustomSessionData = &psession.CustomSessionData{
		Username:     oidcUpstreamUsername,
		ProviderUID:  happyUpstreamIDPResourceUID,
		ProviderName: happyUpstreamIDPName,
		ProviderType: psession.ProviderTypeOIDC,
		OIDC: &psession.OIDCSessionData{
			UpstreamRefreshToken: oidcUpstreamRefreshToken,
			UpstreamIssuer:       oidcUpstreamIssuer,
			UpstreamSubject:      oidcUpstreamSubject,
		},
	}
	happyDownstreamCustomSessionDataWithUsername = func(wantUsername string) *psession.CustomSessionData {
		copyOfCustomSession := *happyDownstreamCustomSessionData
		copyOfOIDC := *(happyDownstreamCustomSessionData.OIDC)
		copyOfCustomSession.OIDC = &copyOfOIDC
		copyOfCustomSession.Username = wantUsername
		return &copyOfCustomSession
	}
	happyDownstreamAccessTokenCustomSessionData = &psession.CustomSessionData{
		Username:     oidcUpstreamUsername,
		ProviderUID:  happyUpstreamIDPResourceUID,
		ProviderName: happyUpstreamIDPName,
		ProviderType: psession.ProviderTypeOIDC,
		OIDC: &psession.OIDCSessionData{
			UpstreamAccessToken: oidcUpstreamAccessToken,
			UpstreamIssuer:      oidcUpstreamIssuer,
			UpstreamSubject:     oidcUpstreamSubject,
		},
	}
)

func TestCallbackEndpoint(t *testing.T) {
	require.Len(t, happyDownstreamState, 8, "we expect fosite to allow 8 byte state params, so we want to test that boundary case")

	otherUpstreamOIDCIdentityProvider := oidctestutil.TestUpstreamOIDCIdentityProvider{
		Name:     "other-upstream-idp-name",
		ClientID: "other-some-client-id",
		Scopes:   []string{"other-scope1", "other-scope2"},
	}

	var stateEncoderHashKey = []byte("fake-hash-secret")
	var stateEncoderBlockKey = []byte("0123456789ABCDEF") // block encryption requires 16/24/32 bytes for AES
	var cookieEncoderHashKey = []byte("fake-hash-secret2")
	var cookieEncoderBlockKey = []byte("0123456789ABCDE2") // block encryption requires 16/24/32 bytes for AES
	require.NotEqual(t, stateEncoderHashKey, cookieEncoderHashKey)
	require.NotEqual(t, stateEncoderBlockKey, cookieEncoderBlockKey)

	var happyStateCodec = securecookie.New(stateEncoderHashKey, stateEncoderBlockKey)
	happyStateCodec.SetSerializer(securecookie.JSONEncoder{})
	var happyCookieCodec = securecookie.New(cookieEncoderHashKey, cookieEncoderBlockKey)
	happyCookieCodec.SetSerializer(securecookie.JSONEncoder{})

	happyState := happyUpstreamStateParam().Build(t, happyStateCodec)
	happyStateForDynamicClient := happyUpstreamStateParamForDynamicClient().Build(t, happyStateCodec)

	encodedIncomingCookieCSRFValue, err := happyCookieCodec.Encode("csrf", happyDownstreamCSRF)
	require.NoError(t, err)
	happyCSRFCookie := "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue

	happyExchangeAndValidateTokensArgs := &oidctestutil.ExchangeAuthcodeAndValidateTokenArgs{
		Authcode:             happyUpstreamAuthcode,
		PKCECodeVerifier:     oidcpkce.Code(happyDownstreamPKCE),
		ExpectedIDTokenNonce: nonce.Nonce(happyDownstreamNonce),
		RedirectURI:          happyUpstreamRedirectURI,
	}

	// Note that fosite puts the granted scopes as a param in the redirect URI even though the spec doesn't seem to require it
	happyDownstreamRedirectLocationRegexp := downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+username\+groups&state=` + happyDownstreamState

	addFullyCapableDynamicClientAndSecretToKubeResources := func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
		oidcClient, secret := testutil.FullyCapableOIDCClientAndStorageSecret(t,
			"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID, downstreamRedirectURI,
			[]string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
		require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
		require.NoError(t, kubeClient.Tracker().Add(secret))
	}

	tests := []struct {
		name string

		idps          *oidctestutil.UpstreamIDPListerBuilder
		kubeResources func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset)
		method        string
		path          string
		csrfCookie    string

		wantStatus                        int
		wantContentType                   string
		wantBody                          string
		wantRedirectLocationRegexp        string
		wantBodyFormResponseRegexp        string
		wantDownstreamGrantedScopes       []string
		wantDownstreamIDTokenSubject      string
		wantDownstreamIDTokenUsername     string
		wantDownstreamIDTokenGroups       []string
		wantDownstreamRequestedScopes     []string
		wantDownstreamNonce               string
		wantDownstreamClientID            string
		wantDownstreamPKCEChallenge       string
		wantDownstreamPKCEChallengeMethod string
		wantDownstreamCustomSessionData   *psession.CustomSessionData
		wantAdditionalClaims              map[string]interface{}

		wantAuthcodeExchangeCall *expectedAuthcodeExchange
	}{
		{
			name:   "GET with good state and cookie and successful upstream token exchange with response_mode=form_post returns 200 with HTML+JS form",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithAuthorizeRequestParams(
					shallowCopyAndModifyQuery(
						happyDownstreamRequestParamsQuery,
						map[string]string{"response_mode": "form_post"},
					).Encode(),
				).Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusOK,
			wantContentType:                   "text/html;charset=UTF-8",
			wantBodyFormResponseRegexp:        `<code id="manual-auth-code">(.+)</code>`,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "GET with good state and cookie with additional params",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().
				WithAdditionalClaimMappings(map[string]string{
					"downstreamCustomClaim":  "upstreamCustomClaim",
					"downstreamOtherClaim":   "upstreamOtherClaim",
					"downstreamMissingClaim": "upstreamMissingClaim",
				}).
				WithIDTokenClaim("upstreamCustomClaim", "i am a claim value").
				WithIDTokenClaim("upstreamOtherClaim", "other claim value").
				Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithAuthorizeRequestParams(
					shallowCopyAndModifyQuery(
						happyDownstreamRequestParamsQuery,
						map[string]string{"response_mode": "form_post"},
					).Encode(),
				).Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusOK,
			wantContentType:                   "text/html;charset=UTF-8",
			wantBodyFormResponseRegexp:        `<code id="manual-auth-code">(.+)</code>`,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
			wantAdditionalClaims: map[string]interface{}{
				"downstreamCustomClaim": "i am a claim value",
				"downstreamOtherClaim":  "other claim value",
			},
		},
		{
			name:                              "GET with good state and cookie and successful upstream token exchange returns 303 to downstream client callback with its state and code",
			idps:                              oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:                              "GET with good state and cookie and successful upstream token exchange returns 303 to downstream client callback with its state and code when using dynamic client",
			idps:                              oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			kubeResources:                     addFullyCapableDynamicClientAndSecretToKubeResources,
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyStateForDynamicClient).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:                              "GET with authcode exchange that returns an access token but no refresh token when there is a userinfo endpoint returns 303 to downstream client callback with its state and code",
			idps:                              oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().WithEmptyRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(9*time.Hour))).WithUserInfoURL().Build()),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamAccessTokenCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:   "form_post happy path without username or groups scopes requested",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithAuthorizeRequestParams(
					shallowCopyAndModifyQuery(
						happyDownstreamRequestParamsQuery,
						map[string]string{
							"response_mode": "form_post",
							"scope":         "openid",
						},
					).Encode(),
				).Build(t, happyStateCodec),
			).String(),
			csrfCookie:                    happyCSRFCookie,
			wantStatus:                    http.StatusOK,
			wantContentType:               "text/html;charset=UTF-8",
			wantBodyFormResponseRegexp:    `<code id="manual-auth-code">(.+)</code>`,
			wantDownstreamIDTokenSubject:  oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername: oidcUpstreamUsername,
			wantDownstreamRequestedScopes: []string{"openid"},
			wantDownstreamIDTokenGroups:   oidcUpstreamGroupMembership,
			// username and groups scopes were not requested but are granted anyway for the pinniped-cli client for backwards compatibility
			wantDownstreamGrantedScopes:       []string{"openid", "username", "groups"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:                              "GET with authcode exchange that returns an access token but no refresh token but has a short token lifetime which is stored as a warning in the session",
			idps:                              oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().WithEmptyRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(1*time.Hour))).WithUserInfoURL().Build()),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: &psession.CustomSessionData{
				Username:     oidcUpstreamUsername,
				ProviderUID:  happyUpstreamIDPResourceUID,
				ProviderName: happyUpstreamIDPName,
				ProviderType: psession.ProviderTypeOIDC,
				Warnings:     []string{"Access token from identity provider has lifetime of less than 3 hours. Expect frequent prompts to log in."},
				OIDC: &psession.OIDCSessionData{
					UpstreamAccessToken: oidcUpstreamAccessToken,
					UpstreamIssuer:      oidcUpstreamIssuer,
					UpstreamSubject:     oidcUpstreamSubject,
				},
			},
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream IDP provides no username or group claim configuration, so we use default username claim and skip groups",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithoutUsernameClaim().WithoutGroupsClaim().Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenGroups:       []string{},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataWithUsername(oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped),
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is missing",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithUsernameClaim("email").WithIDTokenClaim("email", "joe@whitehouse.gov").Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe@whitehouse.gov",
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataWithUsername("joe@whitehouse.gov"),
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with true value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", true).Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe@whitehouse.gov",
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataWithUsername("joe@whitehouse.gov"),
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream IDP configures username claim as anything other than special claim `email` and `email_verified` upstream claim is present with false value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithUsernameClaim("some-claim").
					WithIDTokenClaim("some-claim", "joe").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", false).Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther, // succeed despite `email_verified=false` because we're not using the email claim for anything
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe",
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataWithUsername("joe"),
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with illegal value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().WithUsernameClaim("email").
				WithIDTokenClaim("email", "joe@whitehouse.gov").
				WithIDTokenClaim("email_verified", "supposed to be boolean").Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: email_verified claim in upstream ID token has invalid format\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:            "return an error when upstream IDP returned no refresh token with an access token when there is no userinfo endpoint",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().WithoutRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(9*time.Hour))).WithoutUserInfoURL().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: access token was returned by upstream provider but there was no userinfo endpoint\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:            "return an error when upstream IDP returned no refresh token and no access token",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().WithoutRefreshToken().WithoutAccessToken().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: neither access token nor refresh token returned by upstream provider\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:            "return an error when upstream IDP returned an empty refresh token and empty access token",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().WithEmptyRefreshToken().WithEmptyAccessToken().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: neither access token nor refresh token returned by upstream provider\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:            "return an error when upstream IDP returned no refresh token and empty access token",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().WithoutRefreshToken().WithEmptyAccessToken().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: neither access token nor refresh token returned by upstream provider\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:            "return an error when upstream IDP returned an empty refresh token and no access token",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().WithEmptyRefreshToken().WithoutAccessToken().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: neither access token nor refresh token returned by upstream provider\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with false value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", false).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: email_verified claim in upstream ID token has false value\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream IDP provides username claim configuration as `sub`, so the downstream token subject should be exactly what they asked for",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithUsernameClaim("sub").Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamSubject,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataWithUsername(oidcUpstreamSubject),
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream IDP's configured groups claim in the ID token has a non-array value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim(oidcUpstreamGroupsClaim, "notAnArrayGroup1 notAnArrayGroup2").Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       []string{"notAnArrayGroup1 notAnArrayGroup2"},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream IDP's configured groups claim in the ID token is a slice of interfaces",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim(oidcUpstreamGroupsClaim, []interface{}{"group1", "group2"}).Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       []string{"group1", "group2"},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:          "using dynamic client which is allowed to request username scope, but does not actually request username scope in authorize request, does not get username in ID token",
			idps:          oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			method:        http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParamForDynamicClient().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
						map[string]string{"scope": "openid groups offline_access"}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+groups&state=` + happyDownstreamState,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "", // username scope was not requested
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     []string{"openid", "groups", "offline_access"},
			wantDownstreamGrantedScopes:       []string{"openid", "groups", "offline_access"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:          "using dynamic client which is allowed to request groups scope, but does not actually request groups scope in authorize request, does not get groups in ID token",
			idps:          oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			method:        http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParamForDynamicClient().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
						map[string]string{"scope": "openid username offline_access"}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+username&state=` + happyDownstreamState,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       nil, // groups scope was not requested
			wantDownstreamRequestedScopes:     []string{"openid", "username", "offline_access"},
			wantDownstreamGrantedScopes:       []string{"openid", "username", "offline_access"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "using dynamic client which is not allowed to request username scope, and does not actually request username scope in authorize request, does not get username in ID token",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]configv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude username scope)
					[]configv1alpha1.Scope{"openid", "offline_access", "groups"},      // username not allowed
					downstreamRedirectURI, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithAuthorizeRequestParams(
					shallowCopyAndModifyQuery(
						happyDownstreamRequestParamsQuery,
						map[string]string{
							"client_id": downstreamDynamicClientID,
							"scope":     "openid offline_access groups",
						},
					).Encode(),
				).Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+groups&state=` + happyDownstreamState,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "", // username scope was not requested
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     []string{"openid", "groups", "offline_access"},
			wantDownstreamGrantedScopes:       []string{"openid", "groups", "offline_access"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "using dynamic client which is not allowed to request groups scope, and does not actually request groups scope in authorize request, does not get groups in ID token",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]configv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude groups scope)
					[]configv1alpha1.Scope{"openid", "offline_access", "username"},    // groups not allowed
					downstreamRedirectURI, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithAuthorizeRequestParams(
					shallowCopyAndModifyQuery(
						happyDownstreamRequestParamsQuery,
						map[string]string{
							"client_id": downstreamDynamicClientID,
							"scope":     "openid offline_access username",
						},
					).Encode(),
				).Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+username&state=` + happyDownstreamState,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       nil, // groups scope was not requested
			wantDownstreamRequestedScopes:     []string{"openid", "username", "offline_access"},
			wantDownstreamGrantedScopes:       []string{"openid", "username", "offline_access"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},

		// Pre-upstream-exchange verification
		{
			name:            "PUT method is invalid",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodPut,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: PUT (try GET)\n",
		},
		{
			name:            "POST method is invalid",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodPost,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: POST (try GET)\n",
		},
		{
			name:            "PATCH method is invalid",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodPatch,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: PATCH (try GET)\n",
		},
		{
			name:            "DELETE method is invalid",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodDelete,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: DELETE (try GET)\n",
		},
		{
			name:            "code param was not included on request",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).WithoutCode().String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: code param not found\n",
		},
		{
			name:            "state param was not included on request",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithoutState().String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: state param not found\n",
		},
		{
			name:            "state param was not signed correctly, has expired, or otherwise cannot be decoded for any reason",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState("this-will-not-decode").String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error reading state\n",
		},
		{
			// This shouldn't happen in practice because the authorize endpoint should have already run the same
			// validations, but we would like to test the error handling in this endpoint anyway.
			name:   "state param contains authorization request params which fail validation",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
						map[string]string{"prompt": "none login"}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie: happyCSRFCookie,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},

			wantStatus:      http.StatusInternalServerError,
			wantContentType: htmlContentType,
			wantBody:        "Internal Server Error: error while generating and saving authcode\n",
		},
		{
			name:            "state's internal version does not match what we want",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyUpstreamStateParam().WithStateVersion("wrong-state-version").Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: state format version is invalid\n",
		},
		{
			name:   "state's downstream auth params element is invalid",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(happyUpstreamStateParam().
				WithAuthorizeRequestParams("the following is an invalid url encoding token, and therefore this is an invalid param: %z").
				Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error reading state downstream auth params\n",
		},
		{
			name:   "state's downstream auth params are missing required value (e.g., client_id)",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
						map[string]string{"client_id": ""}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error using state downstream auth params\n",
		},
		{
			name:   "state's downstream auth params have invalid client_id",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
						map[string]string{"client_id": "bogus"}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error using state downstream auth params\n",
		},
		{
			name:          "dynamic clients do not allow response_mode=form_post",
			idps:          oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			method:        http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithAuthorizeRequestParams(
					shallowCopyAndModifyQuery(
						happyDownstreamRequestParamsQuery,
						map[string]string{
							"client_id":     downstreamDynamicClientID,
							"response_mode": "form_post",
							"scope":         "openid",
						},
					).Encode(),
				).Build(t, happyStateCodec),
			).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error using state downstream auth params\n",
		},
		{
			name: "using dynamic client which is not allowed to request username scope in authorize request but requests it anyway",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]configv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude username scope)
					[]configv1alpha1.Scope{"openid", "offline_access", "groups"},      // username not allowed
					downstreamRedirectURI, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithAuthorizeRequestParams(
					shallowCopyAndModifyQuery(
						happyDownstreamRequestParamsQuery,
						map[string]string{
							"client_id": downstreamDynamicClientID,
							"scope":     "openid username",
						},
					).Encode(),
				).Build(t, happyStateCodec),
			).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error using state downstream auth params\n",
		},
		{
			name: "using dynamic client which is not allowed to request groups scope in authorize request but requests it anyway",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]configv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude groups scope)
					[]configv1alpha1.Scope{"openid", "offline_access", "username"},    // groups not allowed
					downstreamRedirectURI, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithAuthorizeRequestParams(
					shallowCopyAndModifyQuery(
						happyDownstreamRequestParamsQuery,
						map[string]string{
							"client_id": downstreamDynamicClientID,
							"scope":     "openid groups",
						},
					).Encode(),
				).Build(t, happyStateCodec),
			).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error using state downstream auth params\n",
		},
		{
			name:   "state's downstream auth params does not contain openid scope",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().
				WithState(
					happyUpstreamStateParam().
						WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
							map[string]string{"scope": "profile username email groups"}).Encode()).
						Build(t, happyStateCodec),
				).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamRequestedScopes:     []string{"profile", "email", "username", "groups"},
			wantDownstreamGrantedScopes:       []string{"username", "groups"},
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:   "state's downstream auth params does not contain openid, username, or groups scope",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().
				WithState(
					happyUpstreamStateParam().
						WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
							map[string]string{"scope": "profile email"}).Encode()).
						Build(t, happyStateCodec),
				).String(),
			csrfCookie:                    happyCSRFCookie,
			wantStatus:                    http.StatusSeeOther,
			wantRedirectLocationRegexp:    downstreamRedirectURI + `\?code=([^&]+)&scope=username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenUsername: oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:   oidcUpstreamGroupMembership,
			wantDownstreamIDTokenSubject:  oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamRequestedScopes: []string{"profile", "email"},
			// username and groups scopes were not requested but are granted anyway for the pinniped-cli client for backwards compatibility
			wantDownstreamGrantedScopes:       []string{"username", "groups"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:   "state's downstream auth params also included offline_access scope",
			idps:   oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().
				WithState(
					happyUpstreamStateParam().
						WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
							map[string]string{"scope": "openid offline_access username groups"}).Encode()).
						Build(t, happyStateCodec),
				).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamRequestedScopes:     []string{"openid", "offline_access", "username", "groups"},
			wantDownstreamGrantedScopes:       []string{"openid", "offline_access", "username", "groups"},
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name:            "the OIDCIdentityProvider CRD has been deleted",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(&otherUpstreamOIDCIdentityProvider),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: upstream provider not found\n",
		},
		{
			name:            "the CSRF cookie does not exist on request",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: CSRF cookie is missing\n",
		},
		{
			name:            "cookie was not signed correctly, has expired, or otherwise cannot be decoded for any reason",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      "__Host-pinniped-csrf=this-value-was-not-signed-by-pinniped",
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: error reading CSRF cookie\n",
		},
		{
			name:            "cookie csrf value does not match state csrf value",
			idps:            oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(happyUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyUpstreamStateParam().WithCSRF("wrong-csrf-value").Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: CSRF value does not match\n",
		},

		// Upstream exchange
		{
			name: "upstream auth code exchange fails",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithUpstreamAuthcodeExchangeError(errors.New("some error")).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadGateway,
			wantBody:        "Bad Gateway: error exchanging and validating upstream tokens\n",
			wantContentType: htmlContentType,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token does not contain requested username claim",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithoutIDTokenClaim(oidcUpstreamUsernameClaim).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token missing\n",
			wantContentType: htmlContentType,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token does not contain requested groups claim",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithoutIDTokenClaim(oidcUpstreamGroupsClaim).Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamIDTokenGroups:       []string{},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionData,
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token contains username claim with weird format",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim(oidcUpstreamUsernameClaim, 42).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token contains username claim with empty string value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim(oidcUpstreamUsernameClaim, "").Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token is empty\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token does not contain iss claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithoutIDTokenClaim("iss").WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token missing\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token does has an empty string value for iss claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim("iss", "").WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token is empty\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token has an non-string iss claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim("iss", 42).WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token does not contain sub claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithoutIDTokenClaim("sub").WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token missing\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token does has an empty string value for sub claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim("sub", "").WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token is empty\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token has an non-string sub claim when using default username claim config",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim("sub", 42).WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token contains groups claim with weird format",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim(oidcUpstreamGroupsClaim, 42).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token contains groups claim where one element is invalid",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim(oidcUpstreamGroupsClaim, []interface{}{"foo", 7}).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "upstream ID token contains groups claim with invalid null type",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				happyUpstream().WithIDTokenClaim(oidcUpstreamGroupsClaim, nil).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantAuthcodeExchangeCall: &expectedAuthcodeExchange{
				performedByUpstreamName: happyUpstreamIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
	}
	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset()
			supervisorClient := supervisorfake.NewSimpleClientset()
			secrets := kubeClient.CoreV1().Secrets("some-namespace")
			oidcClientsClient := supervisorClient.ConfigV1alpha1().OIDCClients("some-namespace")

			if test.kubeResources != nil {
				test.kubeResources(t, supervisorClient, kubeClient)
			}

			// Configure fosite the same way that the production code would.
			// Inject this into our test subject at the last second so we get a fresh storage for every test.
			timeoutsConfiguration := oidc.DefaultOIDCTimeoutsConfiguration()
			// Use lower minimum required bcrypt cost than we would use in production to keep unit the tests fast.
			oauthStore := oidc.NewKubeStorage(secrets, oidcClientsClient, timeoutsConfiguration, bcrypt.MinCost)
			hmacSecretFunc := func() []byte { return []byte("some secret - must have at least 32 bytes") }
			require.GreaterOrEqual(t, len(hmacSecretFunc()), 32, "fosite requires that hmac secrets have at least 32 bytes")
			jwksProviderIsUnused := jwks.NewDynamicJWKSProvider()
			oauthHelper := oidc.FositeOauth2Helper(oauthStore, downstreamIssuer, hmacSecretFunc, jwksProviderIsUnused, timeoutsConfiguration)

			subject := NewHandler(test.idps.Build(), oauthHelper, happyStateCodec, happyCookieCodec, happyUpstreamRedirectURI)
			reqContext := context.WithValue(context.Background(), struct{ name string }{name: "test"}, "request-context")
			req := httptest.NewRequest(test.method, test.path, nil).WithContext(reqContext)
			if test.csrfCookie != "" {
				req.Header.Set("Cookie", test.csrfCookie)
			}
			rsp := httptest.NewRecorder()
			subject.ServeHTTP(rsp, req)
			t.Logf("response: %#v", rsp)
			t.Logf("response body: %q", rsp.Body.String())

			testutil.RequireSecurityHeadersWithFormPostPageCSPs(t, rsp)

			if test.wantAuthcodeExchangeCall != nil {
				test.wantAuthcodeExchangeCall.args.Ctx = reqContext
				test.idps.RequireExactlyOneCallToExchangeAuthcodeAndValidateTokens(t,
					test.wantAuthcodeExchangeCall.performedByUpstreamName, test.wantAuthcodeExchangeCall.args,
				)
			} else {
				test.idps.RequireExactlyZeroCallsToExchangeAuthcodeAndValidateTokens(t)
			}

			require.Equal(t, test.wantStatus, rsp.Code)
			testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), test.wantContentType)

			switch {
			// If we want a specific static response body, assert that.
			case test.wantBody != "":
				require.Equal(t, test.wantBody, rsp.Body.String())

			// Else if we want a body that contains a regex-matched auth code, assert that (for "response_mode=form_post").
			case test.wantBodyFormResponseRegexp != "":
				oidctestutil.RequireAuthCodeRegexpMatch(
					t,
					rsp.Body.String(),
					test.wantBodyFormResponseRegexp,
					kubeClient,
					secrets,
					oauthStore,
					test.wantDownstreamGrantedScopes,
					test.wantDownstreamIDTokenSubject,
					test.wantDownstreamIDTokenUsername,
					test.wantDownstreamIDTokenGroups,
					test.wantDownstreamRequestedScopes,
					test.wantDownstreamPKCEChallenge,
					test.wantDownstreamPKCEChallengeMethod,
					test.wantDownstreamNonce,
					test.wantDownstreamClientID,
					downstreamRedirectURI,
					test.wantDownstreamCustomSessionData,
					test.wantAdditionalClaims,
				)

			// Otherwise, expect an empty response body.
			default:
				require.Empty(t, rsp.Body.String())
			}

			if test.wantRedirectLocationRegexp != "" {
				require.Len(t, rsp.Header().Values("Location"), 1)
				oidctestutil.RequireAuthCodeRegexpMatch(
					t,
					rsp.Header().Get("Location"),
					test.wantRedirectLocationRegexp,
					kubeClient,
					secrets,
					oauthStore,
					test.wantDownstreamGrantedScopes,
					test.wantDownstreamIDTokenSubject,
					test.wantDownstreamIDTokenUsername,
					test.wantDownstreamIDTokenGroups,
					test.wantDownstreamRequestedScopes,
					test.wantDownstreamPKCEChallenge,
					test.wantDownstreamPKCEChallengeMethod,
					test.wantDownstreamNonce,
					test.wantDownstreamClientID,
					downstreamRedirectURI,
					test.wantDownstreamCustomSessionData,
					test.wantAdditionalClaims,
				)
			}
		})
	}
}

type expectedAuthcodeExchange struct {
	performedByUpstreamName string
	args                    *oidctestutil.ExchangeAuthcodeAndValidateTokenArgs
}

type requestPath struct {
	code, state *string
}

func newRequestPath() *requestPath {
	c := happyUpstreamAuthcode
	s := "4321"
	return &requestPath{
		code:  &c,
		state: &s,
	}
}

func (r *requestPath) WithCode(code string) *requestPath {
	r.code = &code
	return r
}

func (r *requestPath) WithoutCode() *requestPath {
	r.code = nil
	return r
}

func (r *requestPath) WithState(state string) *requestPath {
	r.state = &state
	return r
}

func (r *requestPath) WithoutState() *requestPath {
	r.state = nil
	return r
}

func (r *requestPath) String() string {
	path := "/downstream-provider-name/callback?"
	params := url.Values{}
	if r.code != nil {
		params.Add("code", *r.code)
	}
	if r.state != nil {
		params.Add("state", *r.state)
	}
	return path + params.Encode()
}

func happyUpstreamStateParam() *oidctestutil.UpstreamStateParamBuilder {
	return &oidctestutil.UpstreamStateParamBuilder{
		U: happyUpstreamIDPName,
		P: happyDownstreamRequestParams,
		T: "oidc",
		N: happyDownstreamNonce,
		C: happyDownstreamCSRF,
		K: happyDownstreamPKCE,
		V: happyDownstreamStateVersion,
	}
}

func happyUpstreamStateParamForDynamicClient() *oidctestutil.UpstreamStateParamBuilder {
	p := happyUpstreamStateParam()
	p.P = happyDownstreamRequestParamsForDynamicClient
	return p
}

func happyUpstream() *oidctestutil.TestUpstreamOIDCIdentityProviderBuilder {
	return oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
		WithName(happyUpstreamIDPName).
		WithResourceUID(happyUpstreamIDPResourceUID).
		WithClientID("some-client-id").
		WithScopes([]string{"scope1", "scope2"}).
		WithUsernameClaim(oidcUpstreamUsernameClaim).
		WithGroupsClaim(oidcUpstreamGroupsClaim).
		WithIDTokenClaim("iss", oidcUpstreamIssuer).
		WithIDTokenClaim("sub", oidcUpstreamSubject).
		WithIDTokenClaim(oidcUpstreamUsernameClaim, oidcUpstreamUsername).
		WithIDTokenClaim(oidcUpstreamGroupsClaim, oidcUpstreamGroupMembership).
		WithIDTokenClaim("other-claim", "should be ignored").
		WithAllowPasswordGrant(false).
		WithRefreshToken(oidcUpstreamRefreshToken).
		WithPasswordGrantError(errors.New("the callback endpoint should not use password grants"))
}

func shallowCopyAndModifyQuery(query url.Values, modifications map[string]string) url.Values {
	copied := url.Values{}
	for key, value := range query {
		copied[key] = value
	}
	for key, value := range modifications {
		if value == "" {
			copied.Del(key)
		} else {
			copied[key] = []string{value}
		}
	}
	return copied
}
