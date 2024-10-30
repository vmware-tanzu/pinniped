// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"context"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	kubetesting "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/openidconnect"
	"go.pinniped.dev/internal/fositestorage/pkce"
	"go.pinniped.dev/internal/fositestoragei"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
)

func RequireAuthCodeRegexpMatch(
	t *testing.T,
	actualContent string,
	wantRegexp string,
	kubeClient *fake.Clientset,
	secretsClient v1.SecretInterface,
	oauthStore fositestoragei.AllFositeStorage,
	wantDownstreamGrantedScopes []string,
	wantDownstreamIDTokenSubject string,
	wantDownstreamIDTokenUsername string,
	wantDownstreamIDTokenGroups []string,
	wantDownstreamRequestedScopes []string,
	wantDownstreamPKCEChallenge string,
	wantDownstreamPKCEChallengeMethod string,
	wantDownstreamNonce string,
	wantDownstreamClientID string,
	wantDownstreamRedirectURI string,
	wantCustomSessionData *psession.CustomSessionData,
	wantDownstreamAdditionalClaims map[string]any,
) string {
	t.Helper()

	// Assert that Location header matches regular expression.
	regex := regexp.MustCompile(wantRegexp)
	submatches := regex.FindStringSubmatch(actualContent)
	require.Lenf(t, submatches, 2, "no regexp match in actualContent: %", actualContent)
	capturedAuthCode := submatches[1]

	// Authcodes should start with the custom prefix "pin_ac_" to make them identifiable as authcodes when seen by a user out of context.
	require.True(t, strings.HasPrefix(capturedAuthCode, "pin_ac_"), "token %q did not have expected prefix 'pin_ac_'", capturedAuthCode)

	// fosite authcodes are in the format `data.signature`, so grab the signature part, which is the lookup key in the storage interface
	authcodeDataAndSignature := strings.Split(capturedAuthCode, ".")
	require.Len(t, authcodeDataAndSignature, 2)

	// Several Secrets should have been created
	expectedNumberOfCreatedSecrets := 2
	if includesOpenIDScope(wantDownstreamGrantedScopes) {
		expectedNumberOfCreatedSecrets++
	}
	require.Len(t, FilterClientSecretCreateActions(kubeClient.Actions()), expectedNumberOfCreatedSecrets)

	// One authcode should have been stored.
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secretsClient, labels.Set{crud.SecretLabelKey: authorizationcode.TypeLabelValue}, 1)

	sessionID, storedRequestFromAuthcode, storedSessionFromAuthcode := validateAuthcodeStorage(
		t,
		oauthStore,
		authcodeDataAndSignature[1], // Authcode store key is authcode signature
		wantDownstreamGrantedScopes,
		wantDownstreamIDTokenSubject,
		wantDownstreamIDTokenUsername,
		wantDownstreamIDTokenGroups,
		wantDownstreamRequestedScopes,
		wantDownstreamClientID,
		wantDownstreamRedirectURI,
		wantCustomSessionData,
		wantDownstreamAdditionalClaims,
	)

	// One PKCE should have been stored.
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secretsClient, labels.Set{crud.SecretLabelKey: pkce.TypeLabelValue}, 1)

	validatePKCEStorage(
		t,
		oauthStore,
		authcodeDataAndSignature[1], // PKCE store key is authcode signature
		storedRequestFromAuthcode,
		storedSessionFromAuthcode,
		wantDownstreamPKCEChallenge,
		wantDownstreamPKCEChallengeMethod,
	)

	// One IDSession should have been stored, if the downstream actually requested the "openid" scope
	if includesOpenIDScope(wantDownstreamGrantedScopes) {
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secretsClient, labels.Set{crud.SecretLabelKey: openidconnect.TypeLabelValue}, 1)

		validateIDSessionStorage(
			t,
			oauthStore,
			capturedAuthCode, // IDSession store key is full authcode
			storedRequestFromAuthcode,
			storedSessionFromAuthcode,
			wantDownstreamNonce,
		)
	}

	return sessionID
}

func includesOpenIDScope(scopes []string) bool {
	for _, scope := range scopes {
		if scope == "openid" {
			return true
		}
	}
	return false
}

//nolint:funlen
func validateAuthcodeStorage(
	t *testing.T,
	oauthStore fositestoragei.AllFositeStorage,
	storeKey string,
	wantDownstreamGrantedScopes []string,
	wantDownstreamIDTokenSubject string,
	wantDownstreamIDTokenUsername string,
	wantDownstreamIDTokenGroups []string,
	wantDownstreamRequestedScopes []string,
	wantDownstreamClientID string,
	wantDownstreamRedirectURI string,
	wantCustomSessionData *psession.CustomSessionData,
	wantDownstreamAdditionalClaims map[string]any,
) (string, *fosite.Request, *psession.PinnipedSession) {
	t.Helper()

	const (
		authCodeExpirationSeconds = 10 * 60 // Currently, we set our auth code expiration to 10 minutes
		timeComparisonFudgeFactor = time.Second * 15
	)

	// Get the authcode session back from storage so we can require that it was stored correctly.
	storedAuthorizeRequestFromAuthcode, err := oauthStore.GetAuthorizeCodeSession(context.Background(), storeKey, nil)
	require.NoError(t, err)

	sessionID := storedAuthorizeRequestFromAuthcode.GetID()

	// Check that storage returned the expected concrete data types.
	storedRequestFromAuthcode, storedSessionFromAuthcode := castStoredAuthorizeRequest(t, storedAuthorizeRequestFromAuthcode)

	// Check which scopes were granted.
	require.ElementsMatch(t, wantDownstreamGrantedScopes, storedRequestFromAuthcode.GetGrantedScopes())

	// Don't care about the order of requested scopes, as long as they match the expected list.
	storedRequestedScopes := storedRequestFromAuthcode.Form["scope"]
	require.Len(t, storedRequestedScopes, 1)
	require.NotEmpty(t, storedRequestedScopes[0])
	storedRequestedScopesSlice := strings.Split(storedRequestedScopes[0], " ")
	require.ElementsMatch(t, storedRequestedScopesSlice, wantDownstreamRequestedScopes)

	// Check all the other fields of the stored request.
	require.NotEmpty(t, storedRequestFromAuthcode.ID)
	require.Equal(t, wantDownstreamClientID, storedRequestFromAuthcode.Client.GetID())
	require.ElementsMatch(t, wantDownstreamRequestedScopes, storedRequestFromAuthcode.RequestedScope)
	require.Nil(t, storedRequestFromAuthcode.RequestedAudience)
	require.Empty(t, storedRequestFromAuthcode.GrantedAudience)
	require.Equal(t,
		url.Values{
			"client_id":     []string{wantDownstreamClientID},
			"redirect_uri":  []string{wantDownstreamRedirectURI},
			"response_type": []string{"code"},
			"scope":         storedRequestedScopes, // already asserted about this actual value above
		},
		storedRequestFromAuthcode.Form,
	)
	testutil.RequireTimeInDelta(t, time.Now(), storedRequestFromAuthcode.RequestedAt, timeComparisonFudgeFactor)

	// We're not using these fields yet, so confirm that we did not set them (for now).
	require.Empty(t, storedSessionFromAuthcode.Fosite.Subject)
	require.Empty(t, storedSessionFromAuthcode.Fosite.Username)
	require.Empty(t, storedSessionFromAuthcode.Fosite.Headers)

	// The authcode that we are issuing should be good for the length of time that we declare in the fosite config.
	testutil.RequireTimeInDelta(t, time.Now().Add(authCodeExpirationSeconds*time.Second), storedSessionFromAuthcode.Fosite.ExpiresAt[fosite.AuthorizeCode], timeComparisonFudgeFactor)
	require.Len(t, storedSessionFromAuthcode.Fosite.ExpiresAt, 1)

	// Now confirm the ID token claims.
	actualClaims := storedSessionFromAuthcode.Fosite.Claims

	// Should always have an azp claim.
	require.Equal(t, wantDownstreamClientID, actualClaims.Extra["azp"])
	wantDownstreamIDTokenExtraClaimsCount := 1 // should always have azp claim

	if len(wantDownstreamAdditionalClaims) > 0 {
		wantDownstreamIDTokenExtraClaimsCount++
	}

	// Check the user's identity, which are put into the downstream ID token's subject, username and groups claims.
	require.Equal(t, wantDownstreamIDTokenSubject, actualClaims.Subject)
	if wantDownstreamIDTokenUsername == "" {
		require.NotContains(t, actualClaims.Extra, "username")
	} else {
		wantDownstreamIDTokenExtraClaimsCount++ // should also have username claim
		require.Equal(t, wantDownstreamIDTokenUsername, actualClaims.Extra["username"])
	}
	if slices.Contains(wantDownstreamGrantedScopes, "groups") {
		wantDownstreamIDTokenExtraClaimsCount++ // should also have groups claim
		actualDownstreamIDTokenGroups := actualClaims.Extra["groups"]
		require.NotNil(t, actualDownstreamIDTokenGroups)
		require.ElementsMatch(t, wantDownstreamIDTokenGroups, actualDownstreamIDTokenGroups)
	} else {
		require.Emptyf(t, wantDownstreamIDTokenGroups, "test case did not want the groups scope to be granted, "+
			"but wanted something in the groups claim, which doesn't make sense. please review the test case's expectations.")
		actualDownstreamIDTokenGroups := actualClaims.Extra["groups"]
		require.Nil(t, actualDownstreamIDTokenGroups)
	}
	if len(wantDownstreamAdditionalClaims) > 0 {
		actualAdditionalClaims, ok := actualClaims.Get("additionalClaims").(map[string]any)
		require.True(t, ok, "expected additionalClaims to be a map[string]any")
		require.Equal(t, wantDownstreamAdditionalClaims, actualAdditionalClaims)
	} else {
		require.NotContains(t, actualClaims.Extra, "additionalClaims", "additionalClaims must not be present when there are no wanted additional claims")
	}

	// Make sure that we asserted on every extra claim.
	require.Len(t, actualClaims.Extra, wantDownstreamIDTokenExtraClaimsCount)

	// Check the rest of the downstream ID token's claims. Fosite wants us to set these (in UTC time).
	testutil.RequireTimeInDelta(t, time.Now().UTC(), actualClaims.RequestedAt, timeComparisonFudgeFactor)
	testutil.RequireTimeInDelta(t, time.Now().UTC(), actualClaims.AuthTime, timeComparisonFudgeFactor)
	requestedAtZone, _ := actualClaims.RequestedAt.Zone()
	require.Equal(t, "UTC", requestedAtZone)
	authTimeZone, _ := actualClaims.AuthTime.Zone()
	require.Equal(t, "UTC", authTimeZone)

	// Fosite will set these fields for us in the token endpoint based on the store session
	// information. Therefore, we assert that they are empty because we want the library to do the
	// lifting for us.
	require.Empty(t, actualClaims.Issuer)
	require.Nil(t, actualClaims.Audience)
	require.Empty(t, actualClaims.Nonce)
	require.Zero(t, actualClaims.ExpiresAt)
	require.Zero(t, actualClaims.IssuedAt)

	// These are not needed yet.
	require.Empty(t, actualClaims.JTI)
	require.Empty(t, actualClaims.CodeHash)
	require.Empty(t, actualClaims.AccessTokenHash)
	require.Empty(t, actualClaims.AuthenticationContextClassReference)
	require.Empty(t, actualClaims.AuthenticationMethodsReferences)

	// Check that the custom Pinniped session data matches.
	require.Equal(t, wantCustomSessionData, storedSessionFromAuthcode.Custom)

	return sessionID, storedRequestFromAuthcode, storedSessionFromAuthcode
}

func validatePKCEStorage(
	t *testing.T,
	oauthStore fositestoragei.AllFositeStorage,
	storeKey string,
	storedRequestFromAuthcode *fosite.Request,
	storedSessionFromAuthcode *psession.PinnipedSession,
	wantDownstreamPKCEChallenge, wantDownstreamPKCEChallengeMethod string,
) {
	t.Helper()

	storedAuthorizeRequestFromPKCE, err := oauthStore.GetPKCERequestSession(context.Background(), storeKey, nil)
	require.NoError(t, err)

	// Check that storage returned the expected concrete data types.
	storedRequestFromPKCE, storedSessionFromPKCE := castStoredAuthorizeRequest(t, storedAuthorizeRequestFromPKCE)

	// The stored PKCE request should be the same as the stored authcode request.
	require.Equal(t, storedRequestFromAuthcode.ID, storedRequestFromPKCE.ID)
	require.Equal(t, storedSessionFromAuthcode, storedSessionFromPKCE)

	// The stored PKCE request should also contain the PKCE challenge that the downstream sent us.
	require.Equal(t, wantDownstreamPKCEChallenge, storedRequestFromPKCE.Form.Get("code_challenge"))
	require.Equal(t, wantDownstreamPKCEChallengeMethod, storedRequestFromPKCE.Form.Get("code_challenge_method"))
}

func validateIDSessionStorage(
	t *testing.T,
	oauthStore fositestoragei.AllFositeStorage,
	storeKey string,
	storedRequestFromAuthcode *fosite.Request,
	storedSessionFromAuthcode *psession.PinnipedSession,
	wantDownstreamNonce string,
) {
	t.Helper()

	storedAuthorizeRequestFromIDSession, err := oauthStore.GetOpenIDConnectSession(context.Background(), storeKey, nil)
	require.NoError(t, err)

	// Check that storage returned the expected concrete data types.
	storedRequestFromIDSession, storedSessionFromIDSession := castStoredAuthorizeRequest(t, storedAuthorizeRequestFromIDSession)

	// The stored IDSession request should be the same as the stored authcode request.
	require.Equal(t, storedRequestFromAuthcode.ID, storedRequestFromIDSession.ID)
	require.Equal(t, storedSessionFromAuthcode, storedSessionFromIDSession)

	// The stored IDSession request should also contain the nonce that the downstream sent us.
	require.Equal(t, wantDownstreamNonce, storedRequestFromIDSession.Form.Get("nonce"))
}

func castStoredAuthorizeRequest(t *testing.T, storedAuthorizeRequest fosite.Requester) (*fosite.Request, *psession.PinnipedSession) {
	t.Helper()

	storedRequest, ok := storedAuthorizeRequest.(*fosite.Request)
	require.Truef(t, ok, "could not cast %T to %T", storedAuthorizeRequest, &fosite.Request{})
	storedSession, ok := storedAuthorizeRequest.GetSession().(*psession.PinnipedSession)
	require.Truef(t, ok, "could not cast %T to %T", storedAuthorizeRequest.GetSession(), &psession.PinnipedSession{})

	return storedRequest, storedSession
}

// FilterClientSecretCreateActions ignores any reads made to get a storage secret corresponding to an OIDCClient, since these
// are normal actions when the request is using a dynamic client's client_id, and we don't need to make assertions
// about these Secrets since they are not related to session storage.
func FilterClientSecretCreateActions(actions []kubetesting.Action) []kubetesting.Action {
	filtered := make([]kubetesting.Action, 0, len(actions))
	for _, action := range actions {
		if action.Matches("get", "secrets") {
			getAction := action.(kubetesting.GetAction)
			if strings.HasPrefix(getAction.GetName(), "pinniped-storage-oidc-client-secret-") {
				continue // filter out OIDCClient's storage secret reads
			}
		}
		filtered = append(filtered, action) // otherwise include the action
	}
	return filtered
}
