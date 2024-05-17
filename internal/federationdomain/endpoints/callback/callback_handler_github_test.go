// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package callback

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	idpdiscoveryv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	"go.pinniped.dev/internal/federationdomain/endpoints/jwks"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/oidcclientvalidator"
	"go.pinniped.dev/internal/federationdomain/storage"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/testidplister"
)

var (
	githubIDPName             = "upstream-github-idp-name"
	githubIDPResourceUID      = types.UID("upstream-github-idp-resource-uid")
	githubUpstreamUsername    = "some-github-login"
	githubUpstreamGroups      = []string{"org1/team1", "org2/team2"}
	githubDownstreamSubject   = fmt.Sprintf("https://github.com?idpName=%s&sub=%s", githubIDPName, githubUpstreamUsername)
	githubUpstreamAccessToken = "some-opaque-access-token-from-github" //nolint:gosec // this is not a credential

	happyDownstreamGitHubCustomSessionData = &psession.CustomSessionData{
		Username:         githubUpstreamUsername,
		UpstreamUsername: githubUpstreamUsername,
		UpstreamGroups:   githubUpstreamGroups,
		ProviderUID:      githubIDPResourceUID,
		ProviderName:     githubIDPName,
		ProviderType:     psession.ProviderTypeGitHub,
		GitHub: &psession.GitHubSessionData{
			UpstreamAccessToken: githubUpstreamAccessToken,
		},
	}
)

func TestCallbackEndpointWithGitHubIdentityProviders(t *testing.T) {
	require.Len(t, happyDownstreamState, 8, "we expect fosite to allow 8 byte state params, so we want to test that boundary case")

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

	encodedIncomingCookieCSRFValue, err := happyCookieCodec.Encode("csrf", happyDownstreamCSRF)
	require.NoError(t, err)
	happyCSRFCookie := "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue

	happyExchangeAndValidateTokensArgs := &oidctestutil.ExchangeAuthcodeArgs{
		Authcode:    happyUpstreamAuthcode,
		RedirectURI: happyUpstreamRedirectURI,
	}

	// TODO: when we merge this file back into callback_handler_test.go, we do not need to copy this function
	//  because it is already in callback_handler_test.go
	addFullyCapableDynamicClientAndSecretToKubeResources := func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
		oidcClient, secret := testutil.FullyCapableOIDCClientAndStorageSecret(t,
			"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID, downstreamRedirectURI, nil,
			[]string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
		require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
		require.NoError(t, kubeClient.Tracker().Add(secret))
	}

	tests := []struct {
		name string

		idps          *testidplister.UpstreamIDPListerBuilder
		kubeResources func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset)
		method        string
		path          string
		csrfCookie    string

		wantRedirectLocationRegexp        string
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
		wantDownstreamAdditionalClaims    map[string]interface{}
		wantGitHubAuthcodeExchangeCall    *expectedGitHubAuthcodeExchange
	}{
		{
			name: "GitHub IDP: GET with good state and cookie and successful upstream token exchange returns 303 to downstream client callback",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithGitHub(
				happyGitHubUpstream().
					WithAccessToken(githubUpstreamAccessToken).
					WithUser(&upstreamprovider.GitHubUser{
						Username:          githubUpstreamUsername,
						Groups:            githubUpstreamGroups,
						DownstreamSubject: githubDownstreamSubject,
					}).
					Build()),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().
					WithUpstreamIDPName(githubIDPName).
					WithUpstreamIDPType(idpdiscoveryv1alpha1.IDPTypeGitHub).
					WithAuthorizeRequestParams(
						happyDownstreamRequestParamsQuery.Encode(),
					).Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=` + regexp.QuoteMeta(strings.Join(happyDownstreamScopesGranted, "+")) + `&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      githubDownstreamSubject,
			wantDownstreamIDTokenUsername:     githubUpstreamUsername,
			wantDownstreamIDTokenGroups:       githubUpstreamGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamPinnipedClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamGitHubCustomSessionData,
			wantGitHubAuthcodeExchangeCall: &expectedGitHubAuthcodeExchange{
				performedByUpstreamName: githubIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
			},
		},
		{
			name: "GitHub IDP: GET with good state and cookie and successful upstream token exchange with dynamic client returns 303 to downstream client callback, with dynamic client",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithGitHub(
				happyGitHubUpstream().
					WithAccessToken(githubUpstreamAccessToken).
					WithUser(&upstreamprovider.GitHubUser{
						Username:          githubUpstreamUsername,
						Groups:            githubUpstreamGroups,
						DownstreamSubject: githubDownstreamSubject,
					}).
					Build()),
			method:        http.MethodGet,
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().
					WithUpstreamIDPName(githubIDPName).
					WithUpstreamIDPType(idpdiscoveryv1alpha1.IDPTypeGitHub).
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
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=` + regexp.QuoteMeta(strings.Join(happyDownstreamScopesGranted, "+")) + `&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      githubDownstreamSubject,
			wantDownstreamIDTokenUsername:     githubUpstreamUsername,
			wantDownstreamIDTokenGroups:       githubUpstreamGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClientID:            downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   happyDownstreamGitHubCustomSessionData,
			wantGitHubAuthcodeExchangeCall: &expectedGitHubAuthcodeExchange{
				performedByUpstreamName: githubIDPName,
				args:                    happyExchangeAndValidateTokensArgs,
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

			subject := NewHandler(test.idps.BuildFederationDomainIdentityProvidersListerFinder(), oauthHelper, happyStateCodec, happyCookieCodec, happyUpstreamRedirectURI)
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

			require.NotNil(t, test.wantGitHubAuthcodeExchangeCall, "wantOIDCAuthcodeExchangeCall is required for testing purposes")

			test.wantGitHubAuthcodeExchangeCall.args.Ctx = reqContext
			test.idps.RequireExactlyOneGitHubAuthcodeExchange(t,
				test.wantGitHubAuthcodeExchangeCall.performedByUpstreamName,
				test.wantGitHubAuthcodeExchangeCall.args,
			)

			require.Equal(t, http.StatusSeeOther, rsp.Code)
			testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), "")
			require.Empty(t, rsp.Body.String())

			require.Len(t, rsp.Header().Values("Location"), 1)
			require.NotEmpty(t, test.wantRedirectLocationRegexp, "wantRedirectLocationRegexp is required for testing purposes")
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
				test.wantDownstreamAdditionalClaims,
			)
		})
	}
}

func happyGitHubUpstream() *oidctestutil.TestUpstreamGitHubIdentityProviderBuilder {
	return oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
		WithName(githubIDPName).
		WithResourceUID(githubIDPResourceUID).
		WithClientID("some-client-id").
		WithScopes([]string{"these", "scopes", "appear", "unused"})
}
