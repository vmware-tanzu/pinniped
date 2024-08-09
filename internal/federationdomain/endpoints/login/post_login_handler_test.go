// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/fake"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	"go.pinniped.dev/internal/authenticators"
	"go.pinniped.dev/internal/celtransformer"
	"go.pinniped.dev/internal/federationdomain/endpoints/jwks"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/oidcclientvalidator"
	"go.pinniped.dev/internal/federationdomain/storage"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/testidplister"
	"go.pinniped.dev/internal/testutil/transformtestutil"
)

func TestPostLoginEndpoint(t *testing.T) {
	const (
		htmlContentType = "text/html; charset=utf-8"

		happyDownstreamCSRF         = "test-csrf"
		happyDownstreamPKCE         = "test-pkce"
		happyDownstreamNonce        = "test-nonce"
		happyDownstreamStateVersion = "2"
		happyEncodedUpstreamState   = "fake-encoded-state-param-value"

		downstreamIssuer              = "https://my-downstream-issuer.com/path"
		downstreamRedirectURI         = "http://127.0.0.1/callback"
		downstreamPinnipedCLIClientID = "pinniped-cli"
		downstreamDynamicClientID     = "client.oauth.pinniped.dev-test-name"
		downstreamDynamicClientUID    = "fake-client-uid"
		happyDownstreamState          = "8b-state"
		downstreamNonce               = "some-nonce-value"
		downstreamPKCEChallenge       = "some-challenge"
		downstreamPKCEChallengeMethod = "S256"

		ldapUpstreamName                   = "some-ldap-idp"
		ldapUpstreamType                   = "ldap"
		ldapUpstreamResourceUID            = "ldap-resource-uid"
		activeDirectoryUpstreamName        = "some-active-directory-idp"
		activeDirectoryUpstreamType        = "activedirectory"
		activeDirectoryUpstreamResourceUID = "active-directory-resource-uid"
		upstreamLDAPURL                    = "ldaps://some-ldap-host:123?base=ou%3Dusers%2Cdc%3Dpinniped%2Cdc%3Ddev"

		userParam                = "username"
		passParam                = "password"
		badUserPassErrParamValue = "login_error"
		internalErrParamValue    = "internal_error"

		transformationUsernamePrefix = "username_prefix:"
		transformationGroupsPrefix   = "groups_prefix:"
	)

	var (
		fositeMissingCodeChallengeErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a code_challenge when performing the authorize code flow, but it is missing.",
			"state":             happyDownstreamState,
		}

		fositeInvalidCodeChallengeErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The code_challenge_method is not supported, use S256 instead.",
			"state":             happyDownstreamState,
		}

		fositeMissingCodeChallengeMethodErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must use code_challenge_method=S256, plain is not allowed.",
			"state":             happyDownstreamState,
		}

		fositePromptHasNoneAndOtherValueErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Parameter 'prompt' was set to 'none', but contains other values as well which is not allowed.",
			"state":             happyDownstreamState,
		}

		fositeConfiguredPolicyRejectedAuthErrorQuery = map[string]string{
			"error":             "access_denied",
			"error_description": "The resource owner or authorization server denied the request. Reason: configured identity policy rejected this authentication: authentication was rejected by a configured policy.",
			"state":             happyDownstreamState,
		}
	)

	happyDownstreamScopesRequested := []string{"openid", "username", "groups"}
	happyDownstreamScopesGranted := []string{"openid", "username", "groups"}

	happyDownstreamRequestParamsQuery := url.Values{
		"response_type":         []string{"code"},
		"scope":                 []string{strings.Join(happyDownstreamScopesRequested, " ")},
		"client_id":             []string{downstreamPinnipedCLIClientID},
		"state":                 []string{happyDownstreamState},
		"nonce":                 []string{downstreamNonce},
		"code_challenge":        []string{downstreamPKCEChallenge},
		"code_challenge_method": []string{downstreamPKCEChallengeMethod},
		"redirect_uri":          []string{downstreamRedirectURI},
	}
	happyDownstreamRequestParams := happyDownstreamRequestParamsQuery.Encode()

	happyDownstreamRequestParamsQueryForDynamicClient := shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
		map[string]string{"client_id": downstreamDynamicClientID},
	)
	happyDownstreamRequestParamsForDynamicClient := happyDownstreamRequestParamsQueryForDynamicClient.Encode()

	happyLDAPDecodedState := &oidc.UpstreamStateParamData{
		AuthParams:    happyDownstreamRequestParams,
		UpstreamName:  ldapUpstreamName,
		UpstreamType:  ldapUpstreamType,
		Nonce:         happyDownstreamNonce,
		CSRFToken:     happyDownstreamCSRF,
		PKCECode:      happyDownstreamPKCE,
		FormatVersion: happyDownstreamStateVersion,
	}

	modifyHappyLDAPDecodedState := func(edit func(*oidc.UpstreamStateParamData)) *oidc.UpstreamStateParamData {
		copyOfHappyLDAPDecodedState := *happyLDAPDecodedState
		edit(&copyOfHappyLDAPDecodedState)
		return &copyOfHappyLDAPDecodedState
	}

	happyLDAPDecodedStateForDynamicClient := modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
		data.AuthParams = happyDownstreamRequestParamsForDynamicClient
	})

	happyActiveDirectoryDecodedState := modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
		data.UpstreamName = activeDirectoryUpstreamName
		data.UpstreamType = activeDirectoryUpstreamType
	})

	happyActiveDirectoryDecodedStateForDynamicClient := modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
		data.AuthParams = happyDownstreamRequestParamsForDynamicClient
		data.UpstreamName = activeDirectoryUpstreamName
		data.UpstreamType = activeDirectoryUpstreamType
	})

	happyLDAPUsername := "some-ldap-user"
	happyLDAPUsernameFromAuthenticator := "some-mapped-ldap-username"
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

	upstreamLDAPIdentityProviderBuilder := oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
		WithName(ldapUpstreamName).
		WithResourceUID(ldapUpstreamResourceUID).
		WithURL(parsedUpstreamLDAPURL).
		WithAuthenticateFunc(ldapAuthenticateFunc)

	upstreamLDAPIdentityProvider := upstreamLDAPIdentityProviderBuilder.Build()

	upstreamActiveDirectoryIdentityProviderBuilder := oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
		WithName(activeDirectoryUpstreamName).
		WithResourceUID(activeDirectoryUpstreamResourceUID).
		WithURL(parsedUpstreamLDAPURL).
		WithAuthenticateFunc(ldapAuthenticateFunc)

	upstreamActiveDirectoryIdentityProvider := upstreamActiveDirectoryIdentityProviderBuilder.Build()

	erroringUpstreamLDAPIdentityProvider := oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
		WithName(ldapUpstreamName).
		WithResourceUID(ldapUpstreamResourceUID).
		WithAuthenticateFunc(func(ctx context.Context, username, password string) (*authenticators.Response, bool, error) {
			return nil, false, fmt.Errorf("some ldap upstream auth error")
		}).
		Build()

	expectedHappyActiveDirectoryUpstreamCustomSession := &psession.CustomSessionData{
		Username:         happyLDAPUsernameFromAuthenticator,
		ProviderUID:      activeDirectoryUpstreamResourceUID,
		ProviderName:     activeDirectoryUpstreamName,
		ProviderType:     psession.ProviderTypeActiveDirectory,
		UpstreamUsername: happyLDAPUsernameFromAuthenticator,
		UpstreamGroups:   happyLDAPGroups,
		OIDC:             nil,
		LDAP:             nil,
		ActiveDirectory: &psession.ActiveDirectorySessionData{
			UserDN:                 happyLDAPUserDN,
			ExtraRefreshAttributes: map[string]string{happyLDAPExtraRefreshAttribute: happyLDAPExtraRefreshValue},
		},
	}

	expectedHappyLDAPUpstreamCustomSession := &psession.CustomSessionData{
		Username:         happyLDAPUsernameFromAuthenticator,
		ProviderUID:      ldapUpstreamResourceUID,
		ProviderName:     ldapUpstreamName,
		ProviderType:     psession.ProviderTypeLDAP,
		UpstreamUsername: happyLDAPUsernameFromAuthenticator,
		UpstreamGroups:   happyLDAPGroups,
		OIDC:             nil,
		LDAP: &psession.LDAPSessionData{
			UserDN:                 happyLDAPUserDN,
			ExtraRefreshAttributes: map[string]string{happyLDAPExtraRefreshAttribute: happyLDAPExtraRefreshValue},
		},
		ActiveDirectory: nil,
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

	// Note that fosite puts the granted scopes as a param in the redirect URI even though the spec doesn't seem to require it
	happyAuthcodeDownstreamRedirectLocationRegexp := downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+username\+groups&state=` + happyDownstreamState

	happyUsernamePasswordFormParams := url.Values{userParam: []string{happyLDAPUsername}, passParam: []string{happyLDAPPassword}}

	encodeQuery := func(query map[string]string) string {
		values := url.Values{}
		for k, v := range query {
			values[k] = []string{v}
		}
		return values.Encode()
	}

	urlWithQuery := func(baseURL string, query map[string]string) string {
		urlToReturn := fmt.Sprintf("%s?%s", baseURL, encodeQuery(query))
		_, err := url.Parse(urlToReturn)
		require.NoError(t, err, "urlWithQuery helper was used to create an illegal URL")
		return urlToReturn
	}

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
		name          string
		idps          *testidplister.UpstreamIDPListerBuilder
		kubeResources func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset)
		decodedState  *oidc.UpstreamStateParamData
		formParams    url.Values
		reqURIQuery   url.Values

		wantStatus      int
		wantContentType string
		wantBodyString  string
		wantErr         string

		// Assertion that the response should be a redirect to the login page with an error param.
		wantRedirectToLoginPageError string

		// Assertions for when an authcode should be returned, i.e. the request was authenticated by an
		// upstream LDAP or AD provider.
		wantRedirectLocationRegexp        string // for loose matching
		wantRedirectLocationString        string // for exact matching instead
		wantBodyFormResponseRegexp        string // for form_post html page matching instead
		wantDownstreamRedirectURI         string
		wantDownstreamGrantedScopes       []string
		wantDownstreamIDTokenSubject      string
		wantDownstreamIDTokenUsername     string
		wantDownstreamIDTokenGroups       []string
		wantDownstreamRequestedScopes     []string
		wantDownstreamPKCEChallenge       string
		wantDownstreamPKCEChallengeMethod string
		wantDownstreamNonce               string
		wantDownstreamClient              string
		wantDownstreamCustomSessionData   *psession.CustomSessionData

		// Authorization requests for either a successful OIDC upstream or for an error with any upstream
		// should never use Kube storage. There is only one exception to this rule, which is that certain
		// OIDC validations are checked in fosite after the OAuth authcode (and sometimes the OIDC session)
		// is stored, so it is possible with an LDAP upstream to store objects and then return an error to
		// the client anyway (which makes the stored objects useless, but oh well).
		wantUnnecessaryStoredRecords int
	}{
		{
			name: "happy LDAP login",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(upstreamLDAPIdentityProvider). // should pick this one
				WithActiveDirectory(erroringUpstreamLDAPIdentityProvider),
			decodedState:                      happyLDAPDecodedState,
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamPinnipedCLIClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name: "happy LDAP login with identity transformations which modify the username and group names",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(upstreamLDAPIdentityProviderBuilder.WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).Build()). // should pick this one
				WithActiveDirectory(erroringUpstreamLDAPIdentityProvider),
			decodedState:                      happyLDAPDecodedState,
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     transformationUsernamePrefix + happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       testutil.AddPrefixToEach(transformationGroupsPrefix, happyLDAPGroups),
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamPinnipedCLIClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyLDAPUpstreamCustomSession,
				transformationUsernamePrefix+happyLDAPUsernameFromAuthenticator,
				happyLDAPUsernameFromAuthenticator,
				happyLDAPGroups,
			),
		},
		{
			name: "happy LDAP login with dynamic client",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(upstreamLDAPIdentityProvider). // should pick this one
				WithActiveDirectory(erroringUpstreamLDAPIdentityProvider),
			kubeResources:                     addFullyCapableDynamicClientAndSecretToKubeResources,
			decodedState:                      happyLDAPDecodedStateForDynamicClient,
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name: "happy AD login",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(erroringUpstreamLDAPIdentityProvider).
				WithActiveDirectory(upstreamActiveDirectoryIdentityProvider), // should pick this one
			decodedState:                      happyActiveDirectoryDecodedState,
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + activeDirectoryUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamPinnipedCLIClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyActiveDirectoryUpstreamCustomSession,
		},
		{
			name: "happy AD login with identity transformations which modify the username and group names",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(erroringUpstreamLDAPIdentityProvider).
				WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder.WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).Build()), // should pick this one
			decodedState:                      happyActiveDirectoryDecodedState,
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + activeDirectoryUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     transformationUsernamePrefix + happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       testutil.AddPrefixToEach(transformationGroupsPrefix, happyLDAPGroups),
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamPinnipedCLIClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData: withUsernameAndGroupsInCustomSession(
				expectedHappyActiveDirectoryUpstreamCustomSession,
				transformationUsernamePrefix+happyLDAPUsernameFromAuthenticator,
				happyLDAPUsernameFromAuthenticator,
				happyLDAPGroups,
			),
		},
		{
			name: "happy AD login with dynamic client",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(erroringUpstreamLDAPIdentityProvider).
				WithActiveDirectory(upstreamActiveDirectoryIdentityProvider), // should pick this one
			kubeResources:                     addFullyCapableDynamicClientAndSecretToKubeResources,
			decodedState:                      happyActiveDirectoryDecodedStateForDynamicClient,
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        happyAuthcodeDownstreamRedirectLocationRegexp,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + activeDirectoryUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyActiveDirectoryUpstreamCustomSession,
		},
		{
			name: "happy LDAP login when downstream response_mode=form_post returns 200 with HTML+JS form",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"response_mode": "form_post"},
				).Encode()
			}),
			formParams:      happyUsernamePasswordFormParams,
			wantStatus:      http.StatusOK,
			wantContentType: htmlContentType,
			wantBodyFormResponseRegexp: `(?s)<html.*<script>.*To finish logging in, paste this authorization code` +
				`.*<form>.*<code id="manual-auth-code">(.+)</code>.*</html>`, // "(?s)" means match "." across newlines
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamPinnipedCLIClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name: "happy LDAP login when downstream redirect uri matches what is configured for client except for the port number",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"redirect_uri": "http://127.0.0.1:4242/callback"},
				).Encode()
			}),
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        "http://127.0.0.1:4242/callback" + `\?code=([^&]+)&scope=openid\+username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         "http://127.0.0.1:4242/callback",
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamPinnipedCLIClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name:          "happy LDAP login when downstream redirect uri matches what is configured for client except for the port number with dynamic client",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"redirect_uri": "http://127.0.0.1:4242/callback"},
				).Encode()
			}),
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        "http://127.0.0.1:4242/callback" + `\?code=([^&]+)&scope=openid\+username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamRedirectURI:         "http://127.0.0.1:4242/callback",
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name: "happy LDAP login when there are additional allowed downstream requested scopes",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"scope": "openid offline_access pinniped:request-audience"},
				).Encode()
			}),
			formParams:      happyUsernamePasswordFormParams,
			wantStatus:      http.StatusSeeOther,
			wantContentType: htmlContentType,
			wantBodyString:  "",
			// username and groups scopes were not requested but are granted anyway for the pinniped-cli client for backwards compatibility
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+pinniped%3Arequest-audience\+username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     []string{"openid", "offline_access", "pinniped:request-audience"},
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       []string{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamPinnipedCLIClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name:          "happy LDAP login when there are additional allowed downstream requested scopes with dynamic client, when dynamic client is allowed to request username and groups but does not request them",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"scope": "openid offline_access pinniped:request-audience"},
				).Encode()
			}),
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+pinniped%3Arequest-audience&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     "",         // username scope was not requested, so there should be no username in the ID token
			wantDownstreamIDTokenGroups:       []string{}, // groups scope was not requested, so there should be no groups in the ID token
			wantDownstreamRequestedScopes:     []string{"openid", "offline_access", "pinniped:request-audience"},
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       []string{"openid", "offline_access", "pinniped:request-audience"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name: "happy LDAP login when there are additional allowed downstream requested scopes with dynamic client, when dynamic client is not allowed to request username and does not request username",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude username scope)
					[]supervisorconfigv1alpha1.Scope{"openid", "offline_access", "groups"},      // username not allowed
					downstreamRedirectURI, nil, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"scope": "openid groups offline_access"},
				).Encode()
			}),
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     "", // username scope was not requested, so there should be no username in the ID token
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     []string{"openid", "offline_access", "groups"},
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       []string{"openid", "offline_access", "groups"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name: "happy LDAP login when there are additional allowed downstream requested scopes with dynamic client, when dynamic client is not allowed to request groups and does not request groups",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude groups scope)
					[]supervisorconfigv1alpha1.Scope{"openid", "offline_access", "username"},    // groups not allowed
					downstreamRedirectURI, nil, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"scope": "openid username offline_access"},
				).Encode()
			}),
			formParams:                        happyUsernamePasswordFormParams,
			wantStatus:                        http.StatusSeeOther,
			wantContentType:                   htmlContentType,
			wantBodyString:                    "",
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access\+username&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       []string{}, // groups scope was not requested, so there should be no groups in the ID token
			wantDownstreamRequestedScopes:     []string{"openid", "offline_access", "username"},
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       []string{"openid", "offline_access", "username"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamDynamicClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name: "login with dynamic client which is not allowed to request groups still runs identity transformations with upstream groups " +
				"in case transforms want to reject auth based on groups, even though groups would not be included in final ID token",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(upstreamLDAPIdentityProviderBuilder.
					WithTransformsForFederationDomain(transformtestutil.NewPipeline(t,
						[]celtransformer.CELTransformation{
							&celtransformer.AllowAuthenticationPolicy{
								Expression:                    `!groups.exists(g, g in ["` + happyLDAPGroups[0] + `"])`, // reject auth for users who belongs to an upstream group
								RejectedAuthenticationMessage: `users who belong to certain upstream group are not allowed`,
							},
						}),
					).Build()),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude groups scope)
					[]supervisorconfigv1alpha1.Scope{"openid", "offline_access", "username"},    // groups not allowed
					downstreamRedirectURI, nil, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"scope": "openid username offline_access"},
				).Encode()
			}),
			formParams:      happyUsernamePasswordFormParams,
			wantStatus:      http.StatusSeeOther,
			wantContentType: htmlContentType,
			wantBodyString:  "",
			wantRedirectLocationString: urlWithQuery(downstreamRedirectURI, map[string]string{
				"error": "access_denied",
				// auth was rejected because of the upstream group to which the user belonged, as shown by the configured RejectedAuthenticationMessage appearing here
				"error_description": "The resource owner or authorization server denied the request. Reason: configured identity policy rejected this authentication: users who belong to certain upstream group are not allowed.",
				"state":             happyDownstreamState,
			}),
		},
		{
			name: "happy LDAP when downstream OIDC validations are skipped because the openid scope was not requested",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{
						"scope": "email",
						// The following prompt value is illegal when openid is requested, but note that openid is not requested.
						"prompt": "none login",
					},
				).Encode()
			}),
			formParams:      happyUsernamePasswordFormParams,
			wantStatus:      http.StatusSeeOther,
			wantContentType: htmlContentType,
			wantBodyString:  "",
			// username and groups scopes were not requested but are granted anyway for the pinniped-cli client for backwards compatibility
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     []string{"email"}, // only email was requested
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       []string{"username", "groups"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamPinnipedCLIClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name: "happy LDAP login when username and groups scopes are not requested",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(upstreamLDAPIdentityProvider). // should pick this one
				WithActiveDirectory(erroringUpstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"scope": "openid"},
				).Encode()
			}),
			formParams:      happyUsernamePasswordFormParams,
			wantStatus:      http.StatusSeeOther,
			wantContentType: htmlContentType,
			wantBodyString:  "",
			// username and groups scopes were not requested but are granted anyway for the pinniped-cli client for backwards compatibility
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+username\+groups&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      upstreamLDAPURL + "&idpName=" + ldapUpstreamName + "&sub=" + happyLDAPUID,
			wantDownstreamIDTokenUsername:     happyLDAPUsernameFromAuthenticator,
			wantDownstreamIDTokenGroups:       happyLDAPGroups,
			wantDownstreamRequestedScopes:     []string{"openid"},
			wantDownstreamRedirectURI:         downstreamRedirectURI,
			wantDownstreamGrantedScopes:       []string{"openid", "username", "groups"},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamClient:              downstreamPinnipedCLIClientID,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantDownstreamCustomSessionData:   expectedHappyLDAPUpstreamCustomSession,
		},
		{
			name:                         "bad username LDAP login",
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState:                 happyLDAPDecodedState,
			formParams:                   url.Values{userParam: []string{"wrong!"}, passParam: []string{happyLDAPPassword}},
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectToLoginPageError: badUserPassErrParamValue,
		},
		{
			name:                         "bad password LDAP login",
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState:                 happyLDAPDecodedState,
			formParams:                   url.Values{userParam: []string{happyLDAPUsername}, passParam: []string{"wrong!"}},
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectToLoginPageError: badUserPassErrParamValue,
		},
		{
			name:                         "blank username LDAP login",
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState:                 happyLDAPDecodedState,
			formParams:                   url.Values{userParam: []string{""}, passParam: []string{happyLDAPPassword}},
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectToLoginPageError: badUserPassErrParamValue,
		},
		{
			name:                         "blank password LDAP login",
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState:                 happyLDAPDecodedState,
			formParams:                   url.Values{userParam: []string{happyLDAPUsername}, passParam: []string{""}},
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectToLoginPageError: badUserPassErrParamValue,
		},
		{
			name:                         "username and password sent as URI query params should be ignored since they are expected in form post body",
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState:                 happyLDAPDecodedState,
			reqURIQuery:                  happyUsernamePasswordFormParams,
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectToLoginPageError: badUserPassErrParamValue,
		},
		{
			name:                         "error during upstream LDAP authentication",
			idps:                         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(erroringUpstreamLDAPIdentityProvider),
			decodedState:                 happyLDAPDecodedState,
			formParams:                   happyUsernamePasswordFormParams,
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectToLoginPageError: internalErrParamValue,
		},
		{
			name: "downstream redirect uri does not match what is configured for client",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"redirect_uri": "http://127.0.0.1/wrong_callback"},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name:          "downstream redirect uri does not match what is configured for client with dynamic client",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"redirect_uri": "http://127.0.0.1/wrong_callback"},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name: "downstream client does not exist",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"client_id": "wrong_client_id"},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name: "downstream client is missing",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"client_id": ""},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name: "response type is unsupported",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"response_type": "unsupported"},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name:          "response type form_post is unsupported for dynamic clients",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"response_type": "form_post"},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name: "response type is missing",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"response_type": ""},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name: "PKCE code_challenge is missing",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"code_challenge": ""},
				).Encode()
			}),
			formParams:                   happyUsernamePasswordFormParams,
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectLocationString:   urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeErrorQuery),
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name: "PKCE code_challenge_method is invalid",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"code_challenge_method": "this-is-not-a-valid-pkce-alg"},
				).Encode()
			}),
			formParams:                   happyUsernamePasswordFormParams,
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectLocationString:   urlWithQuery(downstreamRedirectURI, fositeInvalidCodeChallengeErrorQuery),
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name: "PKCE code_challenge_method is `plain`",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"code_challenge_method": "plain"}, // plain is not allowed
				).Encode()
			}),
			formParams:                   happyUsernamePasswordFormParams,
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectLocationString:   urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name: "PKCE code_challenge_method is missing",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"code_challenge_method": ""},
				).Encode()
			}),
			formParams:                   happyUsernamePasswordFormParams,
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectLocationString:   urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name:          "PKCE code_challenge_method is missing with dynamic client",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"code_challenge_method": ""},
				).Encode()
			}),
			formParams:                   happyUsernamePasswordFormParams,
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectLocationString:   urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantUnnecessaryStoredRecords: 2, // fosite already stored the authcode and oidc session before it noticed the error
		},
		{
			name: "prompt param is not allowed to have none and another legal value at the same time",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"prompt": "none login"},
				).Encode()
			}),
			formParams:                   happyUsernamePasswordFormParams,
			wantStatus:                   http.StatusSeeOther,
			wantContentType:              htmlContentType,
			wantBodyString:               "",
			wantRedirectLocationString:   urlWithQuery(downstreamRedirectURI, fositePromptHasNoneAndOtherValueErrorQuery),
			wantUnnecessaryStoredRecords: 1, // fosite already stored the authcode before it noticed the error
		},
		{
			name: "LDAP login using identity transformations which reject the authentication",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(upstreamLDAPIdentityProviderBuilder.WithTransformsForFederationDomain(rejectAuthPipeline).Build()),
			decodedState:               happyLDAPDecodedState,
			formParams:                 happyUsernamePasswordFormParams,
			wantStatus:                 http.StatusSeeOther,
			wantContentType:            htmlContentType,
			wantBodyString:             "",
			wantRedirectLocationString: urlWithQuery(downstreamRedirectURI, fositeConfiguredPolicyRejectedAuthErrorQuery),
		},
		{
			name: "AD login using identity transformations which reject the authentication",
			idps: testidplister.NewUpstreamIDPListerBuilder().
				WithActiveDirectory(upstreamActiveDirectoryIdentityProviderBuilder.WithTransformsForFederationDomain(rejectAuthPipeline).Build()),
			decodedState:               happyActiveDirectoryDecodedState,
			formParams:                 happyUsernamePasswordFormParams,
			wantStatus:                 http.StatusSeeOther,
			wantContentType:            htmlContentType,
			wantBodyString:             "",
			wantRedirectLocationString: urlWithQuery(downstreamRedirectURI, fositeConfiguredPolicyRejectedAuthErrorQuery),
		},
		{
			name: "downstream state does not have enough entropy",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"state": "short"},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name: "downstream scopes do not match what is configured for client",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery,
					map[string]string{"scope": "openid offline_access pinniped:request-audience scope_not_allowed"},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name: "using dynamic client which is not allowed to request username scope in authorize request but requests it anyway",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude username scope)
					[]supervisorconfigv1alpha1.Scope{"openid", "offline_access", "groups"},      // username not allowed
					downstreamRedirectURI, nil, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"scope": "openid username offline_access"},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name: "using dynamic client which is not allowed to request groups scope in authorize request but requests it anyway",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				oidcClient, secret := testutil.OIDCClientAndStorageSecret(t,
					"some-namespace", downstreamDynamicClientID, downstreamDynamicClientUID,
					[]supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"}, // token exchange not allowed (required to exclude groups scope)
					[]supervisorconfigv1alpha1.Scope{"openid", "offline_access", "username"},    // groups not allowed
					downstreamRedirectURI, nil, []string{testutil.HashedPassword1AtGoMinCost}, oidcclientvalidator.Validate)
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"scope": "openid groups offline_access"},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name:          "downstream scopes do not match what is configured for client with dynamic client",
			idps:          testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			decodedState: modifyHappyLDAPDecodedState(func(data *oidc.UpstreamStateParamData) {
				data.AuthParams = shallowCopyAndModifyQuery(happyDownstreamRequestParamsQueryForDynamicClient,
					map[string]string{"scope": "openid offline_access pinniped:request-audience scope_not_allowed"},
				).Encode()
			}),
			formParams: happyUsernamePasswordFormParams,
			wantErr:    "error using state downstream auth params",
		},
		{
			name:         "no upstream providers are configured or provider cannot be found by name",
			idps:         testidplister.NewUpstreamIDPListerBuilder(), // empty
			decodedState: happyLDAPDecodedState,
			formParams:   happyUsernamePasswordFormParams,
			wantErr:      "error finding upstream provider: did not find IDP with name \"some-ldap-idp\"",
		},
		{
			name:         "upstream provider cannot be found by name and type",
			idps:         testidplister.NewUpstreamIDPListerBuilder().WithLDAP(upstreamLDAPIdentityProvider),
			decodedState: happyActiveDirectoryDecodedState, // correct upstream IDP name, but wrong upstream IDP type
			formParams:   happyUsernamePasswordFormParams,
			wantErr:      "error finding upstream provider: did not find IDP with name \"some-active-directory-idp\"",
		},
	}

	for _, test := range tests {
		tt := test

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kubeClient := fake.NewSimpleClientset()
			supervisorClient := supervisorfake.NewSimpleClientset()
			secretsClient := kubeClient.CoreV1().Secrets("some-namespace")
			oidcClientsClient := supervisorClient.ConfigV1alpha1().OIDCClients("some-namespace")

			if tt.kubeResources != nil {
				tt.kubeResources(t, supervisorClient, kubeClient)
			}

			// Configure fosite the same way that the production code would.
			// Inject this into our test subject at the last second so we get a fresh storage for every test.
			timeoutsConfiguration := oidc.DefaultOIDCTimeoutsConfiguration()
			// Use lower minimum required bcrypt cost than we would use in production to keep unit the tests fast.
			kubeOauthStore := storage.NewKubeStorage(secretsClient, oidcClientsClient, timeoutsConfiguration, bcrypt.MinCost)
			hmacSecretFunc := func() []byte { return []byte("some secret - must have at least 32 bytes") }
			require.GreaterOrEqual(t, len(hmacSecretFunc()), 32, "fosite requires that hmac secrets have at least 32 bytes")
			jwksProviderIsUnused := jwks.NewDynamicJWKSProvider()
			oauthHelper := oidc.FositeOauth2Helper(kubeOauthStore, downstreamIssuer, hmacSecretFunc, jwksProviderIsUnused, timeoutsConfiguration)

			req := httptest.NewRequest(http.MethodPost, "/ignored", strings.NewReader(tt.formParams.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.reqURIQuery != nil {
				req.URL.RawQuery = tt.reqURIQuery.Encode()
			}

			rsp := httptest.NewRecorder()

			subject := NewPostHandler(downstreamIssuer, tt.idps.BuildFederationDomainIdentityProvidersListerFinder(), oauthHelper, plog.New())

			err := subject(rsp, req, happyEncodedUpstreamState, tt.decodedState)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Empty(t, oidctestutil.FilterClientSecretCreateActions(kubeClient.Actions()))
				return // the http response doesn't matter when the function returns an error, because the caller should handle the error
			}
			// Otherwise, expect no error.
			require.NoError(t, err)

			require.Equal(t, tt.wantStatus, rsp.Code)
			testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), tt.wantContentType)

			actualLocation := rsp.Header().Get("Location")

			switch {
			case tt.wantRedirectLocationRegexp != "":
				// Expecting a success redirect to the client.
				require.Equal(t, tt.wantBodyString, rsp.Body.String())
				require.Len(t, rsp.Header().Values("Location"), 1)
				oidctestutil.RequireAuthCodeRegexpMatch(
					t,
					actualLocation,
					tt.wantRedirectLocationRegexp,
					kubeClient,
					secretsClient,
					kubeOauthStore,
					tt.wantDownstreamGrantedScopes,
					tt.wantDownstreamIDTokenSubject,
					tt.wantDownstreamIDTokenUsername,
					tt.wantDownstreamIDTokenGroups,
					tt.wantDownstreamRequestedScopes,
					tt.wantDownstreamPKCEChallenge,
					tt.wantDownstreamPKCEChallengeMethod,
					tt.wantDownstreamNonce,
					tt.wantDownstreamClient,
					tt.wantDownstreamRedirectURI,
					tt.wantDownstreamCustomSessionData,
					map[string]any{},
				)
			case tt.wantRedirectToLoginPageError != "":
				// Expecting an error redirect to the login UI page.
				require.Equal(t, tt.wantBodyString, rsp.Body.String())
				expectedLocation := downstreamIssuer + oidc.PinnipedLoginPath +
					"?err=" + tt.wantRedirectToLoginPageError + "&state=" + happyEncodedUpstreamState
				require.Equal(t, expectedLocation, actualLocation)
				require.Len(t, oidctestutil.FilterClientSecretCreateActions(kubeClient.Actions()), tt.wantUnnecessaryStoredRecords)
			case tt.wantRedirectLocationString != "":
				// Expecting an error redirect to the client.
				require.Equal(t, tt.wantBodyString, rsp.Body.String())
				require.Equal(t, tt.wantRedirectLocationString, actualLocation)
				require.Len(t, oidctestutil.FilterClientSecretCreateActions(kubeClient.Actions()), tt.wantUnnecessaryStoredRecords)
			case tt.wantBodyFormResponseRegexp != "":
				// Expecting the body of the response to be a html page with a form (for "response_mode=form_post").
				_, hasLocationHeader := rsp.Header()["Location"]
				require.False(t, hasLocationHeader)
				oidctestutil.RequireAuthCodeRegexpMatch(
					t,
					rsp.Body.String(),
					tt.wantBodyFormResponseRegexp,
					kubeClient,
					secretsClient,
					kubeOauthStore,
					tt.wantDownstreamGrantedScopes,
					tt.wantDownstreamIDTokenSubject,
					tt.wantDownstreamIDTokenUsername,
					tt.wantDownstreamIDTokenGroups,
					tt.wantDownstreamRequestedScopes,
					tt.wantDownstreamPKCEChallenge,
					tt.wantDownstreamPKCEChallengeMethod,
					tt.wantDownstreamNonce,
					tt.wantDownstreamClient,
					tt.wantDownstreamRedirectURI,
					tt.wantDownstreamCustomSessionData,
					map[string]any{},
				)
			default:
				require.Failf(t, "test should have expected a redirect or form body",
					"actual location was %q", actualLocation)
			}
		})
	}
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
