// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/openidconnect"
	pkce2 "go.pinniped.dev/internal/fositestorage/pkce"
	"go.pinniped.dev/internal/fositestoragei"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

// Test helpers for the OIDC package.

// ExchangeAuthcodeAndValidateTokenArgs is used to spy on calls to
// TestUpstreamOIDCIdentityProvider.ExchangeAuthcodeAndValidateTokensFunc().
type ExchangeAuthcodeAndValidateTokenArgs struct {
	Ctx                  context.Context
	Authcode             string
	PKCECodeVerifier     pkce.Code
	ExpectedIDTokenNonce nonce.Nonce
	RedirectURI          string
}

type TestUpstreamLDAPIdentityProvider struct {
	Name             string
	URL              *url.URL
	AuthenticateFunc func(ctx context.Context, username, password string) (*authenticator.Response, bool, error)
}

var _ provider.UpstreamLDAPIdentityProviderI = &TestUpstreamLDAPIdentityProvider{}

func (u *TestUpstreamLDAPIdentityProvider) GetName() string {
	return u.Name
}

func (u *TestUpstreamLDAPIdentityProvider) AuthenticateUser(ctx context.Context, username, password string) (*authenticator.Response, bool, error) {
	return u.AuthenticateFunc(ctx, username, password)
}

func (u *TestUpstreamLDAPIdentityProvider) GetURL() *url.URL {
	return u.URL
}

type TestUpstreamOIDCIdentityProvider struct {
	Name                                  string
	ClientID                              string
	AuthorizationURL                      url.URL
	UsernameClaim                         string
	GroupsClaim                           string
	Scopes                                []string
	ExchangeAuthcodeAndValidateTokensFunc func(
		ctx context.Context,
		authcode string,
		pkceCodeVerifier pkce.Code,
		expectedIDTokenNonce nonce.Nonce,
	) (*oidctypes.Token, error)

	exchangeAuthcodeAndValidateTokensCallCount int
	exchangeAuthcodeAndValidateTokensArgs      []*ExchangeAuthcodeAndValidateTokenArgs
}

func (u *TestUpstreamOIDCIdentityProvider) GetName() string {
	return u.Name
}

func (u *TestUpstreamOIDCIdentityProvider) GetClientID() string {
	return u.ClientID
}

func (u *TestUpstreamOIDCIdentityProvider) GetAuthorizationURL() *url.URL {
	return &u.AuthorizationURL
}

func (u *TestUpstreamOIDCIdentityProvider) GetScopes() []string {
	return u.Scopes
}

func (u *TestUpstreamOIDCIdentityProvider) GetUsernameClaim() string {
	return u.UsernameClaim
}

func (u *TestUpstreamOIDCIdentityProvider) GetGroupsClaim() string {
	return u.GroupsClaim
}

func (u *TestUpstreamOIDCIdentityProvider) ExchangeAuthcodeAndValidateTokens(
	ctx context.Context,
	authcode string,
	pkceCodeVerifier pkce.Code,
	expectedIDTokenNonce nonce.Nonce,
	redirectURI string,
) (*oidctypes.Token, error) {
	if u.exchangeAuthcodeAndValidateTokensArgs == nil {
		u.exchangeAuthcodeAndValidateTokensArgs = make([]*ExchangeAuthcodeAndValidateTokenArgs, 0)
	}
	u.exchangeAuthcodeAndValidateTokensCallCount++
	u.exchangeAuthcodeAndValidateTokensArgs = append(u.exchangeAuthcodeAndValidateTokensArgs, &ExchangeAuthcodeAndValidateTokenArgs{
		Ctx:                  ctx,
		Authcode:             authcode,
		PKCECodeVerifier:     pkceCodeVerifier,
		ExpectedIDTokenNonce: expectedIDTokenNonce,
		RedirectURI:          redirectURI,
	})
	return u.ExchangeAuthcodeAndValidateTokensFunc(ctx, authcode, pkceCodeVerifier, expectedIDTokenNonce)
}

func (u *TestUpstreamOIDCIdentityProvider) ExchangeAuthcodeAndValidateTokensCallCount() int {
	return u.exchangeAuthcodeAndValidateTokensCallCount
}

func (u *TestUpstreamOIDCIdentityProvider) ExchangeAuthcodeAndValidateTokensArgs(call int) *ExchangeAuthcodeAndValidateTokenArgs {
	if u.exchangeAuthcodeAndValidateTokensArgs == nil {
		u.exchangeAuthcodeAndValidateTokensArgs = make([]*ExchangeAuthcodeAndValidateTokenArgs, 0)
	}
	return u.exchangeAuthcodeAndValidateTokensArgs[call]
}

func (u *TestUpstreamOIDCIdentityProvider) ValidateToken(_ context.Context, _ *oauth2.Token, _ nonce.Nonce) (*oidctypes.Token, error) {
	panic("implement me")
}

type UpstreamIDPListerBuilder struct {
	upstreamOIDCIdentityProviders            []*TestUpstreamOIDCIdentityProvider
	upstreamLDAPIdentityProviders            []*TestUpstreamLDAPIdentityProvider
	upstreamActiveDirectoryIdentityProviders []*TestUpstreamLDAPIdentityProvider
}

func (b *UpstreamIDPListerBuilder) WithOIDC(upstreamOIDCIdentityProviders ...*TestUpstreamOIDCIdentityProvider) *UpstreamIDPListerBuilder {
	b.upstreamOIDCIdentityProviders = append(b.upstreamOIDCIdentityProviders, upstreamOIDCIdentityProviders...)
	return b
}

func (b *UpstreamIDPListerBuilder) WithLDAP(upstreamLDAPIdentityProviders ...*TestUpstreamLDAPIdentityProvider) *UpstreamIDPListerBuilder {
	b.upstreamLDAPIdentityProviders = append(b.upstreamLDAPIdentityProviders, upstreamLDAPIdentityProviders...)
	return b
}

func (b *UpstreamIDPListerBuilder) WithActiveDirectory(upstreamActiveDirectoryIdentityProviders ...*TestUpstreamLDAPIdentityProvider) *UpstreamIDPListerBuilder {
	b.upstreamActiveDirectoryIdentityProviders = append(b.upstreamActiveDirectoryIdentityProviders, upstreamActiveDirectoryIdentityProviders...)
	return b
}

func (b *UpstreamIDPListerBuilder) Build() provider.DynamicUpstreamIDPProvider {
	idpProvider := provider.NewDynamicUpstreamIDPProvider()

	oidcUpstreams := make([]provider.UpstreamOIDCIdentityProviderI, len(b.upstreamOIDCIdentityProviders))
	for i := range b.upstreamOIDCIdentityProviders {
		oidcUpstreams[i] = provider.UpstreamOIDCIdentityProviderI(b.upstreamOIDCIdentityProviders[i])
	}
	idpProvider.SetOIDCIdentityProviders(oidcUpstreams)

	ldapUpstreams := make([]provider.UpstreamLDAPIdentityProviderI, len(b.upstreamLDAPIdentityProviders))
	for i := range b.upstreamLDAPIdentityProviders {
		ldapUpstreams[i] = provider.UpstreamLDAPIdentityProviderI(b.upstreamLDAPIdentityProviders[i])
	}
	idpProvider.SetLDAPIdentityProviders(ldapUpstreams)

	adUpstreams := make([]provider.UpstreamLDAPIdentityProviderI, len(b.upstreamActiveDirectoryIdentityProviders))
	for i := range b.upstreamActiveDirectoryIdentityProviders {
		adUpstreams[i] = provider.UpstreamLDAPIdentityProviderI(b.upstreamActiveDirectoryIdentityProviders[i])
	}
	idpProvider.SetActiveDirectoryIdentityProviders(adUpstreams)

	return idpProvider
}

func NewUpstreamIDPListerBuilder() *UpstreamIDPListerBuilder {
	return &UpstreamIDPListerBuilder{}
}

// Declare a separate type from the production code to ensure that the state param's contents was serialized
// in the format that we expect, with the json keys that we expect, etc. This also ensure that the order of
// the serialized fields is the same, which doesn't really matter expect that we can make simpler equality
// assertions about the redirect URL in this test.
type ExpectedUpstreamStateParamFormat struct {
	P string `json:"p"`
	U string `json:"u"`
	N string `json:"n"`
	C string `json:"c"`
	K string `json:"k"`
	V string `json:"v"`
}

type staticKeySet struct {
	publicKey crypto.PublicKey
}

func newStaticKeySet(publicKey crypto.PublicKey) coreosoidc.KeySet {
	return &staticKeySet{publicKey}
}

func (s *staticKeySet) VerifySignature(_ context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %w", err)
	}
	return jws.Verify(s.publicKey)
}

// VerifyECDSAIDToken verifies that the provided idToken was issued via the provided jwtSigningKey.
// It also performs some light validation on the claims, i.e., it makes sure the provided idToken
// has the provided  issuer and clientID.
//
// Further validation can be done via callers via the returned coreosoidc.IDToken.
func VerifyECDSAIDToken(
	t *testing.T,
	issuer, clientID string,
	jwtSigningKey *ecdsa.PrivateKey,
	idToken string,
) *coreosoidc.IDToken {
	t.Helper()

	keySet := newStaticKeySet(jwtSigningKey.Public())
	verifyConfig := coreosoidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{coreosoidc.ES256}}
	verifier := coreosoidc.NewVerifier(issuer, keySet, &verifyConfig)
	token, err := verifier.Verify(context.Background(), idToken)
	require.NoError(t, err)

	return token
}

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
) {
	t.Helper()

	// Assert that Location header matches regular expression.
	regex := regexp.MustCompile(wantRegexp)
	submatches := regex.FindStringSubmatch(actualContent)
	require.Lenf(t, submatches, 2, "no regexp match in actualContent: %", actualContent)
	capturedAuthCode := submatches[1]

	// fosite authcodes are in the format `data.signature`, so grab the signature part, which is the lookup key in the storage interface
	authcodeDataAndSignature := strings.Split(capturedAuthCode, ".")
	require.Len(t, authcodeDataAndSignature, 2)

	// Several Secrets should have been created
	expectedNumberOfCreatedSecrets := 2
	if includesOpenIDScope(wantDownstreamGrantedScopes) {
		expectedNumberOfCreatedSecrets++
	}
	require.Len(t, kubeClient.Actions(), expectedNumberOfCreatedSecrets)

	// One authcode should have been stored.
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secretsClient, labels.Set{crud.SecretLabelKey: authorizationcode.TypeLabelValue}, 1)

	storedRequestFromAuthcode, storedSessionFromAuthcode := validateAuthcodeStorage(
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
	)

	// One PKCE should have been stored.
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secretsClient, labels.Set{crud.SecretLabelKey: pkce2.TypeLabelValue}, 1)

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
}

func includesOpenIDScope(scopes []string) bool {
	for _, scope := range scopes {
		if scope == "openid" {
			return true
		}
	}
	return false
}

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
) (*fosite.Request, *openid.DefaultSession) {
	t.Helper()

	const (
		authCodeExpirationSeconds = 10 * 60 // Currently, we set our auth code expiration to 10 minutes
		timeComparisonFudgeFactor = time.Second * 15
	)

	// Get the authcode session back from storage so we can require that it was stored correctly.
	storedAuthorizeRequestFromAuthcode, err := oauthStore.GetAuthorizeCodeSession(context.Background(), storeKey, nil)
	require.NoError(t, err)

	// Check that storage returned the expected concrete data types.
	storedRequestFromAuthcode, storedSessionFromAuthcode := castStoredAuthorizeRequest(t, storedAuthorizeRequestFromAuthcode)

	// Check which scopes were granted.
	require.ElementsMatch(t, wantDownstreamGrantedScopes, storedRequestFromAuthcode.GetGrantedScopes())

	// Check all the other fields of the stored request.
	require.NotEmpty(t, storedRequestFromAuthcode.ID)
	require.Equal(t, wantDownstreamClientID, storedRequestFromAuthcode.Client.GetID())
	require.ElementsMatch(t, wantDownstreamRequestedScopes, storedRequestFromAuthcode.RequestedScope)
	require.Nil(t, storedRequestFromAuthcode.RequestedAudience)
	require.Empty(t, storedRequestFromAuthcode.GrantedAudience)
	require.Equal(t, url.Values{"redirect_uri": []string{wantDownstreamRedirectURI}}, storedRequestFromAuthcode.Form)
	testutil.RequireTimeInDelta(t, time.Now(), storedRequestFromAuthcode.RequestedAt, timeComparisonFudgeFactor)

	// We're not using these fields yet, so confirm that we did not set them (for now).
	require.Empty(t, storedSessionFromAuthcode.Subject)
	require.Empty(t, storedSessionFromAuthcode.Username)
	require.Empty(t, storedSessionFromAuthcode.Headers)

	// The authcode that we are issuing should be good for the length of time that we declare in the fosite config.
	testutil.RequireTimeInDelta(t, time.Now().Add(authCodeExpirationSeconds*time.Second), storedSessionFromAuthcode.ExpiresAt[fosite.AuthorizeCode], timeComparisonFudgeFactor)
	require.Len(t, storedSessionFromAuthcode.ExpiresAt, 1)

	// Now confirm the ID token claims.
	actualClaims := storedSessionFromAuthcode.Claims

	// Check the user's identity, which are put into the downstream ID token's subject, username and groups claims.
	require.Equal(t, wantDownstreamIDTokenSubject, actualClaims.Subject)
	require.Equal(t, wantDownstreamIDTokenUsername, actualClaims.Extra["username"])
	require.Len(t, actualClaims.Extra, 2)
	actualDownstreamIDTokenGroups := actualClaims.Extra["groups"]
	require.NotNil(t, actualDownstreamIDTokenGroups)
	require.ElementsMatch(t, wantDownstreamIDTokenGroups, actualDownstreamIDTokenGroups)

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
	require.Empty(t, actualClaims.AuthenticationMethodsReference)

	return storedRequestFromAuthcode, storedSessionFromAuthcode
}

func validatePKCEStorage(
	t *testing.T,
	oauthStore fositestoragei.AllFositeStorage,
	storeKey string,
	storedRequestFromAuthcode *fosite.Request,
	storedSessionFromAuthcode *openid.DefaultSession,
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
	storedSessionFromAuthcode *openid.DefaultSession,
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

func castStoredAuthorizeRequest(t *testing.T, storedAuthorizeRequest fosite.Requester) (*fosite.Request, *openid.DefaultSession) {
	t.Helper()

	storedRequest, ok := storedAuthorizeRequest.(*fosite.Request)
	require.Truef(t, ok, "could not cast %T to %T", storedAuthorizeRequest, &fosite.Request{})
	storedSession, ok := storedAuthorizeRequest.GetSession().(*openid.DefaultSession)
	require.Truef(t, ok, "could not cast %T to %T", storedAuthorizeRequest.GetSession(), &openid.DefaultSession{})

	return storedRequest, storedSession
}
