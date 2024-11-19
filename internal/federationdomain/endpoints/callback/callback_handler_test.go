// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package callback

import (
	"context"
	"errors"
	"fmt"
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

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	"go.pinniped.dev/internal/auditid"
	"go.pinniped.dev/internal/federationdomain/endpoints/jwks"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/oidcclientvalidator"
	"go.pinniped.dev/internal/federationdomain/stateparam"
	"go.pinniped.dev/internal/federationdomain/storage"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/testidplister"
	"go.pinniped.dev/internal/testutil/transformtestutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	oidcpkce "go.pinniped.dev/pkg/oidcclient/pkce"
)

const (
	// Upstream OIDC.
	happyOIDCUpstreamIDPName        = "upstream-oidc-idp-name"
	happyOIDCUpstreamIDPResourceUID = "upstream-oidc-resource-uid"

	oidcUpstreamIssuer              = "https://my-upstream-issuer.com"
	oidcUpstreamRefreshToken        = "test-refresh-token"
	oidcUpstreamAccessToken         = "test-access-token"
	oidcUpstreamSubject             = "abc123-some guid" // has a space character which should get escaped in URL
	oidcUpstreamSubjectQueryEscaped = "abc123-some+guid"
	oidcUpstreamUsername            = "test-pinniped-username"

	oidcUpstreamUsernameClaim = "the-user-claim"
	oidcUpstreamGroupsClaim   = "the-groups-claim"

	// Upstream GitHub.
	happyGithubIDPName        = "upstream-github-idp-name"
	happyGithubIDPResourceUID = "upstream-github-idp-resource-uid"

	// Upstream OAuth2 (OIDC or GitHub).
	happyUpstreamAuthcode    = "upstream-auth-code"
	happyUpstreamRedirectURI = "https://example.com/callback"

	// Downstream parameters.
	happyDownstreamState        = "8b-state"
	happyDownstreamCSRF         = "test-csrf"
	happyDownstreamPKCEVerifier = "test-pkce"
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

	transformationUsernamePrefix = "username_prefix:"
	transformationGroupsPrefix   = "groups_prefix:"
)

var (
	githubUpstreamUsername        = "some-github-login"
	githubUpstreamGroupMembership = []string{"org1/team1", "org2/team2"}
	githubDownstreamSubject       = fmt.Sprintf("https://github.com?idpName=%s&sub=%s", happyGithubIDPName, githubUpstreamUsername)
	githubUpstreamAccessToken     = "some-opaque-access-token-from-github" //nolint:gosec // this is not a credential

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

	happyDownstreamCustomSessionDataForOIDCUpstream = &psession.CustomSessionData{
		Username:         oidcUpstreamUsername,
		UpstreamUsername: oidcUpstreamUsername,
		UpstreamGroups:   oidcUpstreamGroupMembership,
		ProviderUID:      happyOIDCUpstreamIDPResourceUID,
		ProviderName:     happyOIDCUpstreamIDPName,
		ProviderType:     psession.ProviderTypeOIDC,
		OIDC: &psession.OIDCSessionData{
			UpstreamRefreshToken: oidcUpstreamRefreshToken,
			UpstreamIssuer:       oidcUpstreamIssuer,
			UpstreamSubject:      oidcUpstreamSubject,
		},
	}
	happyDownstreamCustomSessionDataWithUsernameAndGroups = func(startingSessionData *psession.CustomSessionData, wantDownstreamUsername, wantUpstreamUsername string, wantUpstreamGroups []string) *psession.CustomSessionData {
		copyOfCustomSession := *startingSessionData
		if startingSessionData.OIDC != nil {
			copyOfOIDC := *(startingSessionData.OIDC)
			copyOfCustomSession.OIDC = &copyOfOIDC
		}
		if startingSessionData.GitHub != nil {
			copyOfGitHub := *(startingSessionData.GitHub)
			copyOfCustomSession.GitHub = &copyOfGitHub
		}
		copyOfCustomSession.Username = wantDownstreamUsername
		copyOfCustomSession.UpstreamUsername = wantUpstreamUsername
		copyOfCustomSession.UpstreamGroups = wantUpstreamGroups
		return &copyOfCustomSession
	}
	happyDownstreamAccessTokenCustomSessionData = &psession.CustomSessionData{
		Username:         oidcUpstreamUsername,
		UpstreamUsername: oidcUpstreamUsername,
		UpstreamGroups:   oidcUpstreamGroupMembership,
		ProviderUID:      happyOIDCUpstreamIDPResourceUID,
		ProviderName:     happyOIDCUpstreamIDPName,
		ProviderType:     psession.ProviderTypeOIDC,
		OIDC: &psession.OIDCSessionData{
			UpstreamAccessToken: oidcUpstreamAccessToken,
			UpstreamIssuer:      oidcUpstreamIssuer,
			UpstreamSubject:     oidcUpstreamSubject,
		},
	}
	happyDownstreamCustomSessionDataForGitHubUpstream = &psession.CustomSessionData{
		Username:         githubUpstreamUsername,
		UpstreamUsername: githubUpstreamUsername,
		UpstreamGroups:   githubUpstreamGroupMembership,
		ProviderUID:      happyGithubIDPResourceUID,
		ProviderName:     happyGithubIDPName,
		ProviderType:     psession.ProviderTypeGitHub,
		GitHub: &psession.GitHubSessionData{
			UpstreamAccessToken: githubUpstreamAccessToken,
		},
	}
)

func TestCallbackEndpoint(t *testing.T) {
	require.Len(t, happyDownstreamState, 8, "we expect fosite to allow 8 byte state params, so we want to test that boundary case")

	otherUpstreamOIDCIdentityProvider := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
		WithName("other-upstream-idp-name").
		WithClientID("other-some-client-id").
		WithScopes([]string{"other-scope1", "other-scope2"}).
		Build()

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

	happyOIDCState := happyOIDCUpstreamStateParam().Build(t, happyStateCodec)
	happyOIDCStateForDynamicClient := happyOIDCUpstreamStateParamForDynamicClient().Build(t, happyStateCodec)

	happyGitHubPath := newRequestPath().WithState(happyGitHubUpstreamStateParam().Build(t, happyStateCodec)).String()

	encodedIncomingCookieCSRFValue, err := happyCookieCodec.Encode("csrf", happyDownstreamCSRF)
	require.NoError(t, err)
	happyCSRFCookie := "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue

	happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs := &oidctestutil.ExchangeAuthcodeAndValidateTokenArgs{
		Authcode:             happyUpstreamAuthcode,
		RedirectURI:          happyUpstreamRedirectURI,
		PKCECodeVerifier:     oidcpkce.Code(happyDownstreamPKCEVerifier),
		ExpectedIDTokenNonce: nonce.Nonce(happyDownstreamNonce),
	}

	happyGitHubUpstreamExchangeAuthcodeArgs := &oidctestutil.ExchangeAuthcodeArgs{
		Authcode:    happyUpstreamAuthcode,
		RedirectURI: happyUpstreamRedirectURI,
	}

	// Note that fosite puts the granted scopes as a param in the redirect URI even though the spec doesn't seem to require it
	happyDownstreamRedirectLocationRegexp := downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+username\+groups&state=` + happyDownstreamState

	addFullyCapableDynamicClientAndSecretToKubeResources := func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
		oidcClient, secret := testutil.FullyCapableOIDCClientAndStorageSecret(t,
			"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID, downstreamRedirectURI, nil,
			[]string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
		require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
		require.NoError(t, kubeClient.Tracker().Add(secret))
	}

	prefixUsernameAndGroupsPipeline := transformtestutil.NewPrefixingPipeline(t, transformationUsernamePrefix, transformationGroupsPrefix)
	rejectAuthPipeline := transformtestutil.NewRejectAllAuthPipeline(t)

	tests := []struct {
		name string

		idps          *testidplister.UpstreamIDPListerBuilder
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
		wantDownstreamAdditionalClaims    map[string]any
		wantOIDCAuthcodeExchangeCall      *expectedOIDCAuthcodeExchange
		wantGitHubAuthcodeExchangeCall    *expectedGitHubAuthcodeExchange
		wantAuditLogs                     func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog
	}{
		{
			name:   "OIDC: GET with good state and cookie and successful upstream token exchange with response_mode=form_post returns 200 with HTML+JS form",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParam().WithAuthorizeRequestParams(
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
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"code": "redacted", "state": "redacted"},
					}),
					testutil.WantAuditLog("AuthorizeID From Parameters", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "upstream-oidc-idp-name",
						"resourceName": "upstream-oidc-idp-name",
						"resourceUID":  "upstream-oidc-resource-uid",
						"type":         "oidc",
					}),
					testutil.WantAuditLog("Identity From Upstream IDP", map[string]any{
						"upstreamIDPDisplayName":  "upstream-oidc-idp-name",
						"upstreamIDPType":         "oidc",
						"upstreamIDPResourceName": "upstream-oidc-idp-name",
						"upstreamIDPResourceUID":  "upstream-oidc-resource-uid",
						"personalInfo": map[string]any{
							"upstreamUsername": "test-pinniped-username",
							"upstreamGroups":   []any{"test-pinniped-group-0", "test-pinniped-group-1"},
						},
					}),
					testutil.WantAuditLog("Session Started", map[string]any{
						"sessionID": sessionID,
						"warnings":  []any{}, // json: []
						"personalInfo": map[string]any{
							"username":         "test-pinniped-username",
							"groups":           []any{"test-pinniped-group-0", "test-pinniped-group-1"},
							"subject":          "https://my-upstream-issuer.com?idpName=upstream-oidc-idp-name&sub=abc123-some+guid",
							"additionalClaims": map[string]any{}, // json: {}
						},
					}),
				}
			},
		},
		{
			name:   "GitHub: GET with good state and cookie and successful upstream token exchange with response_mode=form_post returns 200 with HTML+JS form",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithGitHub(happyGitHubUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyGitHubUpstreamStateParam().WithAuthorizeRequestParams(
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
			wantDownstreamIDTokenSubject:      githubDownstreamSubject,
			wantDownstreamIDTokenUsername:     githubUpstreamUsername,
			wantDownstreamIDTokenGroups:       githubUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForGitHubUpstream,
			wantGitHubAuthcodeExchangeCall: &expectedGitHubAuthcodeExchange{
				performedByUpstreamName: happyGithubIDPName,
				args:                    happyGitHubUpstreamExchangeAuthcodeArgs,
			},
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"code": "redacted", "state": "redacted"},
					}),
					testutil.WantAuditLog("AuthorizeID From Parameters", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "upstream-github-idp-name",
						"resourceName": "upstream-github-idp-name",
						"resourceUID":  "upstream-github-idp-resource-uid",
						"type":         "github",
					}),
					testutil.WantAuditLog("Identity From Upstream IDP", map[string]any{
						"upstreamIDPDisplayName":  "upstream-github-idp-name",
						"upstreamIDPType":         "github",
						"upstreamIDPResourceName": "upstream-github-idp-name",
						"upstreamIDPResourceUID":  "upstream-github-idp-resource-uid",
						"personalInfo": map[string]any{
							"upstreamUsername": "some-github-login",
							"upstreamGroups":   []any{"org1/team1", "org2/team2"},
						},
					}),
					testutil.WantAuditLog("Session Started", map[string]any{
						"sessionID": sessionID,
						"warnings":  []any{}, // json: []
						"personalInfo": map[string]any{
							"username":         "some-github-login",
							"groups":           []any{"org1/team1", "org2/team2"},
							"subject":          "https://github.com?idpName=upstream-github-idp-name&sub=some-github-login",
							"additionalClaims": map[string]any{}, // json: {}
						},
					}),
				}
			},
		},
		{
			name: "GET with good state and cookie with additional params",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().
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
				happyOIDCUpstreamStateParam().WithAuthorizeRequestParams(
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
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
			wantDownstreamAdditionalClaims: map[string]any{
				"downstreamCustomClaim": "i am a claim value",
				"downstreamOtherClaim":  "other claim value",
			},
		},
		{
			name:                              "GET with good state and cookie and successful upstream token exchange returns 303 to downstream client callback with its state and code",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:                              "GET with good state and cookie and successful upstream token exchange returns 303 to downstream client callback with its state and code when using dynamic client",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			kubeResources:                     addFullyCapableDynamicClientAndSecretToKubeResources,
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCStateForDynamicClient).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:                              "GET with authcode exchange that returns an access token but no refresh token when there is a userinfo endpoint returns 303 to downstream client callback with its state and code",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().WithEmptyRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(9*time.Hour))).WithUserInfoURL().Build()),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamAccessTokenCustomSessionData,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:   "form_post happy path without username or groups scopes requested",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParam().WithAuthorizeRequestParams(
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
			wantDownstreamIDTokenSubject:  oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername: oidcUpstreamUsername,
			wantDownstreamRequestedScopes: []string{"openid"},
			wantDownstreamIDTokenGroups:   oidcUpstreamGroupMembership,
			// username and groups scopes were not requested but are granted anyway for the pinniped-cli client for backwards compatibility
			wantDownstreamGrantedScopes:       []string{"openid", "username", "groups"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:                              "GET with authcode exchange that returns an access token but no refresh token but has a short token lifetime which is stored as a warning in the session",
			idps:                              testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().WithEmptyRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(1*time.Hour))).WithUserInfoURL().Build()),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: &psession.CustomSessionData{
				Username:         oidcUpstreamUsername,
				UpstreamUsername: oidcUpstreamUsername,
				UpstreamGroups:   oidcUpstreamGroupMembership,
				ProviderUID:      happyOIDCUpstreamIDPResourceUID,
				ProviderName:     happyOIDCUpstreamIDPName,
				ProviderType:     psession.ProviderTypeOIDC,
				Warnings:         []string{"Access token from identity provider has lifetime of less than 3 hours. Expect frequent prompts to log in."},
				OIDC: &psession.OIDCSessionData{
					UpstreamAccessToken: oidcUpstreamAccessToken,
					UpstreamIssuer:      oidcUpstreamIssuer,
					UpstreamSubject:     oidcUpstreamSubject,
				},
			},
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream IDP provides no username or group claim configuration, so we use default username claim and skip groups",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithoutUsernameClaim().WithoutGroupsClaim().Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamIssuer + "?sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenGroups:       []string{},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: happyDownstreamCustomSessionDataWithUsernameAndGroups(
				happyDownstreamCustomSessionDataForOIDCUpstream,
				oidcUpstreamIssuer+"?sub="+oidcUpstreamSubjectQueryEscaped,
				oidcUpstreamIssuer+"?sub="+oidcUpstreamSubjectQueryEscaped,
				nil,
			),
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is missing",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithUsernameClaim("email").WithIDTokenClaim("email", "joe@whitehouse.gov").Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe@whitehouse.gov",
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: happyDownstreamCustomSessionDataWithUsernameAndGroups(
				happyDownstreamCustomSessionDataForOIDCUpstream,
				"joe@whitehouse.gov",
				"joe@whitehouse.gov",
				oidcUpstreamGroupMembership,
			),
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with true value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", true).Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe@whitehouse.gov",
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: happyDownstreamCustomSessionDataWithUsernameAndGroups(
				happyDownstreamCustomSessionDataForOIDCUpstream,
				"joe@whitehouse.gov",
				"joe@whitehouse.gov",
				oidcUpstreamGroupMembership,
			),
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream IDP configures username claim as anything other than special claim `email` and `email_verified` upstream claim is present with false value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithUsernameClaim("some-claim").
					WithIDTokenClaim("some-claim", "joe").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", false).Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther, // succeed despite `email_verified=false` because we're not using the email claim for anything
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "joe",
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: happyDownstreamCustomSessionDataWithUsernameAndGroups(
				happyDownstreamCustomSessionDataForOIDCUpstream,
				"joe",
				"joe",
				oidcUpstreamGroupMembership,
			),
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with illegal value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().WithUsernameClaim("email").
				WithIDTokenClaim("email", "joe@whitehouse.gov").
				WithIDTokenClaim("email_verified", "supposed to be boolean").Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: email_verified claim in upstream ID token has invalid format\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:            "return an error when upstream IDP returned no refresh token with an access token when there is no userinfo endpoint",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().WithoutRefreshToken().WithAccessToken(oidcUpstreamAccessToken, metav1.NewTime(time.Now().Add(9*time.Hour))).WithoutUserInfoURL().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: access token was returned by upstream provider but there was no userinfo endpoint\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, _ string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"code": "redacted", "state": "redacted"},
					}),
					testutil.WantAuditLog("AuthorizeID From Parameters", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "upstream-oidc-idp-name",
						"resourceName": "upstream-oidc-idp-name",
						"resourceUID":  "upstream-oidc-resource-uid",
						"type":         "oidc",
					}),
				}
			},
		},
		{
			name:            "return an error when upstream IDP returned no refresh token and no access token",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().WithoutRefreshToken().WithoutAccessToken().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: neither access token nor refresh token returned by upstream provider\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:            "return an error when upstream IDP returned an empty refresh token and empty access token",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().WithEmptyRefreshToken().WithEmptyAccessToken().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: neither access token nor refresh token returned by upstream provider\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:            "return an error when upstream IDP returned no refresh token and empty access token",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().WithoutRefreshToken().WithEmptyAccessToken().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: neither access token nor refresh token returned by upstream provider\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:            "return an error when upstream IDP returned an empty refresh token and no access token",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().WithEmptyRefreshToken().WithoutAccessToken().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: neither access token nor refresh token returned by upstream provider\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with false value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithUsernameClaim("email").
					WithIDTokenClaim("email", "joe@whitehouse.gov").
					WithIDTokenClaim("email_verified", false).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: email_verified claim in upstream ID token has false value\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream IDP provides username claim configuration as `sub`, so the downstream token subject should be exactly what they asked for",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithUsernameClaim("sub").Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamSubject,
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: happyDownstreamCustomSessionDataWithUsernameAndGroups(
				happyDownstreamCustomSessionDataForOIDCUpstream,
				oidcUpstreamSubject,
				oidcUpstreamSubject,
				oidcUpstreamGroupMembership,
			),
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream IDP's configured groups claim in the ID token has a non-array value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim(oidcUpstreamGroupsClaim, "notAnArrayGroup1 notAnArrayGroup2").Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       []string{"notAnArrayGroup1 notAnArrayGroup2"},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: happyDownstreamCustomSessionDataWithUsernameAndGroups(
				happyDownstreamCustomSessionDataForOIDCUpstream,
				oidcUpstreamUsername,
				oidcUpstreamUsername,
				[]string{"notAnArrayGroup1 notAnArrayGroup2"},
			),
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream IDP's configured groups claim in the ID token is a slice of interfaces",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim(oidcUpstreamGroupsClaim, []any{"group1", "group2"}).Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       []string{"group1", "group2"},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: happyDownstreamCustomSessionDataWithUsernameAndGroups(
				happyDownstreamCustomSessionDataForOIDCUpstream,
				oidcUpstreamUsername,
				oidcUpstreamUsername,
				[]string{"group1", "group2"},
			),
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:          "using dynamic client which is allowed to request username scope, but does not actually request username scope in authorize request, does not get username in ID token",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			method:        http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParamForDynamicClient().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
						map[string]string{"scope": "openid groups offline_access"}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+groups&state=` + happyDownstreamState,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "", // username scope was not requested
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     []string{"openid", "groups", "offline_access"},
			wantDownstreamGrantedScopes:       []string{"openid", "groups", "offline_access"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:          "using dynamic client which is allowed to request groups scope, but does not actually request groups scope in authorize request, does not get groups in ID token",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			method:        http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParamForDynamicClient().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
						map[string]string{"scope": "openid username offline_access"}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+username&state=` + happyDownstreamState,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       nil, // groups scope was not requested
			wantDownstreamRequestedScopes:     []string{"openid", "username", "offline_access"},
			wantDownstreamGrantedScopes:       []string{"openid", "username", "offline_access"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "using dynamic client which is not allowed to request username scope, and does not actually request username scope in authorize request, does not get username in ID token",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude username scope)
					[]supervisorconfigv1alpha1.Scope{"openid", "offline_access", "groups"},      // username not allowed
					downstreamRedirectURI, nil, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParam().WithAuthorizeRequestParams(
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
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     "", // username scope was not requested
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     []string{"openid", "groups", "offline_access"},
			wantDownstreamGrantedScopes:       []string{"openid", "groups", "offline_access"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "using dynamic client which is not allowed to request groups scope, and does not actually request groups scope in authorize request, does not get groups in ID token",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude groups scope)
					[]supervisorconfigv1alpha1.Scope{"openid", "offline_access", "username"},    // groups not allowed
					downstreamRedirectURI, nil, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParam().WithAuthorizeRequestParams(
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
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       nil, // groups scope was not requested
			wantDownstreamRequestedScopes:     []string{"openid", "username", "offline_access"},
			wantDownstreamGrantedScopes:       []string{"openid", "username", "offline_access"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "OIDC: using identity transformations which modify the username and group names",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(happyOIDCUpstream().WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).Build()),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     transformationUsernamePrefix + oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:       testutil.AddPrefixToEach(transformationGroupsPrefix, oidcUpstreamGroupMembership),
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: happyDownstreamCustomSessionDataWithUsernameAndGroups(
				happyDownstreamCustomSessionDataForOIDCUpstream,
				transformationUsernamePrefix+oidcUpstreamUsername,
				oidcUpstreamUsername,
				oidcUpstreamGroupMembership,
			),
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "GitHub: using identity transformations which modify the username and group names",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithGitHub(happyGitHubUpstream().WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).Build()),
			method:                            http.MethodGet,
			path:                              happyGitHubPath,
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      githubDownstreamSubject,
			wantDownstreamIDTokenUsername:     transformationUsernamePrefix + githubUpstreamUsername,
			wantDownstreamIDTokenGroups:       testutil.AddPrefixToEach(transformationGroupsPrefix, githubUpstreamGroupMembership),
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: happyDownstreamCustomSessionDataWithUsernameAndGroups(
				happyDownstreamCustomSessionDataForGitHubUpstream,
				transformationUsernamePrefix+githubUpstreamUsername,
				githubUpstreamUsername,
				githubUpstreamGroupMembership,
			),
			wantGitHubAuthcodeExchangeCall: &expectedGitHubAuthcodeExchange{
				performedByUpstreamName: happyGithubIDPName,
				args:                    happyGitHubUpstreamExchangeAuthcodeArgs,
			},
		},

		// Pre-upstream-exchange verification
		{
			name:            "PUT method is invalid",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodPut,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: PUT (try GET)\n",
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"code": "redacted", "state": "redacted"},
					}),
				}
			},
		},
		{
			name:            "POST method is invalid",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodPost,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: POST (try GET)\n",
		},
		{
			name:            "PATCH method is invalid",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodPatch,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: PATCH (try GET)\n",
		},
		{
			name:            "DELETE method is invalid",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodDelete,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: DELETE (try GET)\n",
		},
		{
			name:            "params cannot be parsed",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().String() + "&invalid;;param",
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error parsing request params\n",
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{}
			},
		},
		{
			name:            "error redirect from upstream IDP audit logs the error params from the OAuth2 spec",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).WithoutCode().String() + "&error=some_error&error_description=some_description&error_uri=some_uri",
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: code param not found: check URL in browser's address bar for error parameters from upstream identity provider\n",
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{
							"state":             "redacted",
							"error":             "some_error",
							"error_description": "some_description",
							"error_uri":         "some_uri",
						},
					}),
				}
			},
		},
		{
			name:            "code param was not included on request",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).WithoutCode().String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: code param not found: check URL in browser's address bar for error parameters from upstream identity provider\n",
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"state": "redacted"},
					}),
				}
			},
		},
		{
			name:            "state param was not included on request",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithoutState().String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: state param not found\n",
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"code": "redacted"},
					}),
				}
			},
		},
		{
			name:            "state param was not signed correctly, has expired, or otherwise cannot be decoded for any reason",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
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
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParam().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
						map[string]string{"prompt": "none login"}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie: happyCSRFCookie,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},

			wantStatus:      http.StatusInternalServerError,
			wantContentType: htmlContentType,
			wantBody:        "Internal Server Error: error while generating and saving authcode\n",
		},
		{
			name:            "state's internal version does not match what we want",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCUpstreamStateParam().WithStateVersion("wrong-state-version").Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: state format version is invalid\n",
		},
		{
			name:   "state's downstream auth params element is invalid",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(happyOIDCUpstreamStateParam().
				WithAuthorizeRequestParams("the following is an invalid url encoding token, and therefore this is an invalid param: %z").
				Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error reading state downstream auth params\n",
		},
		{
			name:   "state's downstream auth params are missing required value (e.g., client_id)",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParam().
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
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParam().
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
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			method:        http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParam().WithAuthorizeRequestParams(
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude username scope)
					[]supervisorconfigv1alpha1.Scope{"openid", "offline_access", "groups"},      // username not allowed
					downstreamRedirectURI, nil, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParam().WithAuthorizeRequestParams(
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude groups scope)
					[]supervisorconfigv1alpha1.Scope{"openid", "offline_access", "username"},    // groups not allowed
					downstreamRedirectURI, nil, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyOIDCUpstreamStateParam().WithAuthorizeRequestParams(
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
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().
				WithState(
					happyOIDCUpstreamStateParam().
						WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
							map[string]string{"scope": "profile username email groups"}).Encode()).
						Build(t, happyStateCodec),
				).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamRequestedScopes:     []string{"profile", "email", "username", "groups"},
			wantDownstreamGrantedScopes:       []string{"username", "groups"},
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:   "state's downstream auth params does not contain openid, username, or groups scope",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().
				WithState(
					happyOIDCUpstreamStateParam().
						WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
							map[string]string{"scope": "profile email"}).Encode()).
						Build(t, happyStateCodec),
				).String(),
			csrfCookie:                    happyCSRFCookie,
			wantStatus:                    http.StatusSeeOther,
			wantRedirectLocationRegexp:    downstreamRedirectURI + `\?code=([^&]+)&scope=username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenUsername: oidcUpstreamUsername,
			wantDownstreamIDTokenGroups:   oidcUpstreamGroupMembership,
			wantDownstreamIDTokenSubject:  oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamRequestedScopes: []string{"profile", "email"},
			// username and groups scopes were not requested but are granted anyway for the pinniped-cli client for backwards compatibility
			wantDownstreamGrantedScopes:       []string{"username", "groups"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:   "state's downstream auth params also included offline_access scope",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().
				WithState(
					happyOIDCUpstreamStateParam().
						WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
							map[string]string{"scope": "openid offline_access username groups"}).Encode()).
						Build(t, happyStateCodec),
				).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamRequestedScopes:     []string{"openid", "offline_access", "username", "groups"},
			wantDownstreamGrantedScopes:       []string{"openid", "offline_access", "username", "groups"},
			wantDownstreamIDTokenGroups:       oidcUpstreamGroupMembership,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForOIDCUpstream,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name:   "GitHub: GET with good state and cookie and successful upstream token exchange returns 303 to downstream client callback",
			idps:   testidplister.NewUpstreamIDPListerBuilder().WithGitHub(happyGitHubUpstream().Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyGitHubUpstreamStateParam().
					WithAuthorizeRequestParams(
						happyDownstreamRequestParamsQuery.Encode(),
					).Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      githubDownstreamSubject,
			wantDownstreamIDTokenUsername:     githubUpstreamUsername,
			wantDownstreamIDTokenGroups:       githubUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForGitHubUpstream,
			wantGitHubAuthcodeExchangeCall: &expectedGitHubAuthcodeExchange{
				performedByUpstreamName: happyGithubIDPName,
				args:                    happyGitHubUpstreamExchangeAuthcodeArgs,
			},
		},
		{
			name:          "GitHub: GET with good state and cookie and successful upstream token exchange with dynamic client returns 303 to downstream client callback, with dynamic client",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithGitHub(happyGitHubUpstream().Build()),
			method:        http.MethodGet,
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			path: newRequestPath().WithState(
				happyGitHubUpstreamStateParam().
					WithAuthorizeRequestParams(
						shallowCopyAndModifyQuery(
							happyDownstreamRequestParamsQuery,
							map[string]string{
								"client_id": downstreamDynamicClientID,
							},
						).Encode(),
					).Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      githubDownstreamSubject,
			wantDownstreamIDTokenUsername:     githubUpstreamUsername,
			wantDownstreamIDTokenGroups:       githubUpstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamCustomSessionDataForGitHubUpstream,
			wantGitHubAuthcodeExchangeCall: &expectedGitHubAuthcodeExchange{
				performedByUpstreamName: happyGithubIDPName,
				args:                    happyGitHubUpstreamExchangeAuthcodeArgs,
			},
		},
		{
			name:            "the OIDCIdentityProvider resource has been deleted",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(otherUpstreamOIDCIdentityProvider),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: upstream provider not found\n",
		},
		{
			name:            "the CSRF cookie does not exist on request",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: CSRF cookie is missing\n",
		},
		{
			name:            "cookie was not signed correctly, has expired, or otherwise cannot be decoded for any reason",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      "__Host-pinniped-csrf=this-value-was-not-signed-by-pinniped",
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: error reading CSRF cookie\n",
		},
		{
			name:            "cookie csrf value does not match state csrf value",
			idps:            testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream().Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCUpstreamStateParam().WithCSRF("wrong-csrf-value").Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: CSRF value does not match\n",
		},

		// Upstream exchange
		{
			name: "OIDC: upstream auth code exchange fails",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithUpstreamAuthcodeExchangeError(errors.New("some error")).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadGateway,
			wantBody:        "Bad Gateway: error exchanging and validating upstream tokens\n",
			wantContentType: htmlContentType,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "GitHub: upstream auth code exchange fails",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithGitHub(
				happyGitHubUpstream().WithAuthcodeExchangeError(errors.New("some error")).Build(),
			),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyGitHubUpstreamStateParam().
					WithAuthorizeRequestParams(
						happyDownstreamRequestParamsQuery.Encode(),
					).Build(t, happyStateCodec),
			).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadGateway,
			wantBody:        "Bad Gateway: failed to exchange authcode using GitHub API\n",
			wantContentType: htmlContentType,
			wantGitHubAuthcodeExchangeCall: &expectedGitHubAuthcodeExchange{
				performedByUpstreamName: happyGithubIDPName,
				args:                    happyGitHubUpstreamExchangeAuthcodeArgs,
			},
		},
		{
			name: "upstream ID token does not contain requested username claim",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithoutIDTokenClaim(oidcUpstreamUsernameClaim).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token missing\n",
			wantContentType: htmlContentType,
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token does not contain requested groups claim",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithoutIDTokenClaim(oidcUpstreamGroupsClaim).Build(),
			),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusSeeOther,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      oidcUpstreamIssuer + "?idpName=" + happyOIDCUpstreamIDPName + "&sub=" + oidcUpstreamSubjectQueryEscaped,
			wantDownstreamIDTokenUsername:     oidcUpstreamUsername,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamIDTokenGroups:       []string{},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: happyDownstreamCustomSessionDataWithUsernameAndGroups(
				happyDownstreamCustomSessionDataForOIDCUpstream,
				oidcUpstreamUsername,
				oidcUpstreamUsername,
				nil,
			),
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token contains username claim with weird format",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim(oidcUpstreamUsernameClaim, 42).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token contains username claim with empty string value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim(oidcUpstreamUsernameClaim, "").Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token is empty\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token does not contain iss claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithoutIDTokenClaim("iss").WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token missing\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token does has an empty string value for iss claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim("iss", "").WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token is empty\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token has an non-string iss claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim("iss", 42).WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token does not contain sub claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithoutIDTokenClaim("sub").WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token missing\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token does has an empty string value for sub claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim("sub", "").WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token is empty\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token has an non-string sub claim when using default username claim config",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim("sub", 42).WithoutUsernameClaim().Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token contains groups claim with weird format",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim(oidcUpstreamGroupsClaim, 42).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token contains groups claim where one element is invalid",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim(oidcUpstreamGroupsClaim, []any{"foo", 7}).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "upstream ID token contains groups claim with invalid null type",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				happyOIDCUpstream().WithIDTokenClaim(oidcUpstreamGroupsClaim, nil).Build(),
			),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: required claim in upstream ID token has invalid format\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
		},
		{
			name: "OIDC: using identity transformations which reject the authentication",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(happyOIDCUpstream().WithTransformsForFederationDomain(rejectAuthPipeline).Build()),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyOIDCState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: configured identity policy rejected this authentication: authentication was rejected by a configured policy\n",
			wantOIDCAuthcodeExchangeCall: &expectedOIDCAuthcodeExchange{
				performedByUpstreamName: happyOIDCUpstreamIDPName,
				args:                    happyOIDCUpstreamExchangeAuthcodeAndValidateTokenArgs,
			},
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"code": "redacted", "state": "redacted"},
					}),
					testutil.WantAuditLog("AuthorizeID From Parameters", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "upstream-oidc-idp-name",
						"resourceName": "upstream-oidc-idp-name",
						"resourceUID":  "upstream-oidc-resource-uid",
						"type":         "oidc",
					}),
					testutil.WantAuditLog("Identity From Upstream IDP", map[string]any{
						"upstreamIDPDisplayName":  "upstream-oidc-idp-name",
						"upstreamIDPType":         "oidc",
						"upstreamIDPResourceName": "upstream-oidc-idp-name",
						"upstreamIDPResourceUID":  "upstream-oidc-resource-uid",
						"personalInfo": map[string]any{
							"upstreamUsername": "test-pinniped-username",
							"upstreamGroups":   []any{"test-pinniped-group-0", "test-pinniped-group-1"},
						},
					}),
					testutil.WantAuditLog("Authentication Rejected By Transforms", map[string]any{
						"reason": "configured identity policy rejected this authentication: authentication was rejected by a configured policy",
					}),
				}
			},
		},
		{
			name: "GitHub: using identity transformations which reject the authentication",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithGitHub(happyGitHubUpstream().WithTransformsForFederationDomain(rejectAuthPipeline).Build()),
			method:          http.MethodGet,
			path:            happyGitHubPath,
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: configured identity policy rejected this authentication: authentication was rejected by a configured policy\n",
			wantGitHubAuthcodeExchangeCall: &expectedGitHubAuthcodeExchange{
				performedByUpstreamName: happyGithubIDPName,
				args:                    happyGitHubUpstreamExchangeAuthcodeArgs,
			},
			wantAuditLogs: func(encodedStateParam stateparam.Encoded, sessionID string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"code": "redacted", "state": "redacted"},
					}),
					testutil.WantAuditLog("AuthorizeID From Parameters", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
					testutil.WantAuditLog("Using Upstream IDP", map[string]any{
						"displayName":  "upstream-github-idp-name",
						"resourceName": "upstream-github-idp-name",
						"resourceUID":  "upstream-github-idp-resource-uid",
						"type":         "github",
					}),
					testutil.WantAuditLog("Identity From Upstream IDP", map[string]any{
						"upstreamIDPDisplayName":  "upstream-github-idp-name",
						"upstreamIDPType":         "github",
						"upstreamIDPResourceName": "upstream-github-idp-name",
						"upstreamIDPResourceUID":  "upstream-github-idp-resource-uid",
						"personalInfo": map[string]any{
							"upstreamUsername": "some-github-login",
							"upstreamGroups":   []any{"org1/team1", "org2/team2"},
						},
					}),
					testutil.WantAuditLog("Authentication Rejected By Transforms", map[string]any{
						"reason": "configured identity policy rejected this authentication: authentication was rejected by a configured policy",
					}),
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset()
			supervisorClient := supervisorfake.NewSimpleClientset()
			secrets := kubeClient.CoreV1().Secrets("some-namespace")
			oidcClientsClient := supervisorClient.ConfigV1alpha1().OIDCClients("some-namespace")

			if test.kubeResources != nil {
				test.kubeResources(t, supervisorClient, kubeClient)
			}

			// Configure fosite the same way that the production code would.
			// Inject this into our test subject at the last second, so we get a fresh storage for every test.
			timeoutsConfiguration := oidc.DefaultOIDCTimeoutsConfiguration()
			// Use lower minimum required bcrypt cost than we would use in production to keep unit the tests fast.
			oauthStore := storage.NewKubeStorage(secrets, oidcClientsClient, timeoutsConfiguration, bcrypt.MinCost)
			hmacSecretFunc := func() []byte { return []byte("some secret - must have at least 32 bytes") }
			require.GreaterOrEqual(t, len(hmacSecretFunc()), 32, "fosite requires that hmac secrets have at least 32 bytes")
			jwksProviderIsUnused := jwks.NewDynamicJWKSProvider()
			oauthHelper := oidc.FositeOauth2Helper(oauthStore, downstreamIssuer, hmacSecretFunc, jwksProviderIsUnused, timeoutsConfiguration)

			auditLogger, actualAuditLog := plog.TestAuditLogger(t)

			subject := NewHandler(
				test.idps.BuildFederationDomainIdentityProvidersListerFinder(),
				oauthHelper,
				happyStateCodec,
				happyCookieCodec,
				happyUpstreamRedirectURI,
				auditLogger,
			)

			reqContext := context.WithValue(context.Background(), struct{ name string }{name: "test"}, "request-context")
			req := httptest.NewRequest(test.method, test.path, nil).WithContext(reqContext)
			if test.csrfCookie != "" {
				req.Header.Set("Cookie", test.csrfCookie)
			}
			req, _ = auditid.NewRequestWithAuditID(req, func() string { return "fake-audit-id" })
			rsp := httptest.NewRecorder()
			subject.ServeHTTP(rsp, req)
			t.Logf("response: %#v", rsp)
			t.Logf("response body: %q", rsp.Body.String())

			testutil.RequireSecurityHeadersWithFormPostPageCSPs(t, rsp)

			switch {
			case test.wantOIDCAuthcodeExchangeCall != nil:
				test.wantOIDCAuthcodeExchangeCall.args.Ctx = req.Context()
				test.idps.RequireExactlyOneOIDCAuthcodeExchange(t,
					test.wantOIDCAuthcodeExchangeCall.performedByUpstreamName,
					test.wantOIDCAuthcodeExchangeCall.args,
				)
			case test.wantGitHubAuthcodeExchangeCall != nil:
				test.wantGitHubAuthcodeExchangeCall.args.Ctx = req.Context()
				test.idps.RequireExactlyOneGitHubAuthcodeExchange(t,
					test.wantGitHubAuthcodeExchangeCall.performedByUpstreamName,
					test.wantGitHubAuthcodeExchangeCall.args,
				)
			default:
				test.idps.RequireExactlyZeroAuthcodeExchanges(t)
			}

			require.Equal(t, test.wantStatus, rsp.Code)
			testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), test.wantContentType)

			sessionID := ""

			switch {
			// If we want a specific static response body, assert that.
			case test.wantBody != "":
				require.Equal(t, test.wantBody, rsp.Body.String())

			// Else if we want a body that contains a regex-matched auth code, assert that (for "response_mode=form_post").
			case test.wantBodyFormResponseRegexp != "":
				sessionID = oidctestutil.RequireAuthCodeRegexpMatch(
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
					test.wantDownstreamAdditionalClaims,
				)

			// Otherwise, expect an empty response body.
			default:
				require.Empty(t, rsp.Body.String())
			}

			if test.wantRedirectLocationRegexp != "" {
				require.Len(t, rsp.Header().Values("Location"), 1)
				sessionID = oidctestutil.RequireAuthCodeRegexpMatch(
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
					test.wantDownstreamAdditionalClaims,
				)
			}

			if test.wantAuditLogs != nil {
				wantAuditLogs := test.wantAuditLogs(testutil.GetStateParam(t, test.path), sessionID)
				testutil.WantAuditIDOnEveryAuditLog(wantAuditLogs, "fake-audit-id")
				testutil.CompareAuditLogs(t, wantAuditLogs, actualAuditLog.String())
			}
		})
	}
}

type expectedOIDCAuthcodeExchange struct {
	performedByUpstreamName string
	args                    *oidctestutil.ExchangeAuthcodeAndValidateTokenArgs
}

type expectedGitHubAuthcodeExchange struct {
	performedByUpstreamName string
	args                    *oidctestutil.ExchangeAuthcodeArgs
}

type requestPath struct {
	code  *string
	state *stateparam.Encoded
}

func newRequestPath() *requestPath {
	c := happyUpstreamAuthcode
	s := stateparam.Encoded("4321")
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

func (r *requestPath) WithState(state stateparam.Encoded) *requestPath {
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
		params.Add("state", r.state.String())
	}
	return path + params.Encode()
}

func happyOIDCUpstreamStateParam() *oidctestutil.UpstreamStateParamBuilder {
	return &oidctestutil.UpstreamStateParamBuilder{
		U: happyOIDCUpstreamIDPName,
		P: happyDownstreamRequestParams,
		T: "oidc",
		N: happyDownstreamNonce,
		C: happyDownstreamCSRF,
		K: happyDownstreamPKCEVerifier,
		V: happyDownstreamStateVersion,
	}
}

func happyGitHubUpstreamStateParam() *oidctestutil.UpstreamStateParamBuilder {
	return &oidctestutil.UpstreamStateParamBuilder{
		U: happyGithubIDPName,
		P: happyDownstreamRequestParams,
		T: "github",
		N: happyDownstreamNonce,
		C: happyDownstreamCSRF,
		K: happyDownstreamPKCEVerifier,
		V: happyDownstreamStateVersion,
	}
}

func happyOIDCUpstreamStateParamForDynamicClient() *oidctestutil.UpstreamStateParamBuilder {
	p := happyOIDCUpstreamStateParam()
	p.P = happyDownstreamRequestParamsForDynamicClient
	return p
}

func happyOIDCUpstream() *oidctestutil.TestUpstreamOIDCIdentityProviderBuilder {
	return oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
		WithName(happyOIDCUpstreamIDPName).
		WithResourceUID(happyOIDCUpstreamIDPResourceUID).
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

func happyGitHubUpstream() *oidctestutil.TestUpstreamGitHubIdentityProviderBuilder {
	return oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
		WithName(happyGithubIDPName).
		WithResourceUID(happyGithubIDPResourceUID).
		WithClientID("some-client-id").
		WithAccessToken(githubUpstreamAccessToken).
		WithUser(&upstreamprovider.GitHubUser{
			Username:          githubUpstreamUsername,
			Groups:            githubUpstreamGroupMembership,
			DownstreamSubject: githubDownstreamSubject,
		})
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

// TestParamsSafeToLog only exists to ensure that paramsSafeToLog will not be accidentally updated.
func TestParamsSafeToLog(t *testing.T) {
	wantParams := []string{
		"error",
		"error_description",
		"error_uri",
	}

	require.ElementsMatch(t, wantParams, paramsSafeToLog().UnsortedList())
}
