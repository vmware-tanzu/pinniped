// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamoidc implements an abstraction of upstream OIDC provider interactions.
package upstreamoidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

func New(config *oauth2.Config, provider *coreosoidc.Provider, client *http.Client) provider.UpstreamOIDCIdentityProviderI {
	return &ProviderConfig{Config: config, Provider: provider, Client: client}
}

// ProviderConfig holds the active configuration of an upstream OIDC provider.
type ProviderConfig struct {
	Name                     string
	ResourceUID              types.UID
	UsernameClaim            string
	GroupsClaim              string
	Config                   *oauth2.Config
	Client                   *http.Client
	AllowPasswordGrant       bool
	AdditionalAuthcodeParams map[string]string
	RevocationURL            *url.URL // will commonly be nil: many providers do not offer this
	Provider                 interface {
		Verifier(*coreosoidc.Config) *coreosoidc.IDTokenVerifier
		Claims(v interface{}) error
		UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*coreosoidc.UserInfo, error)
	}
}

var _ provider.UpstreamOIDCIdentityProviderI = (*ProviderConfig)(nil)

func (p *ProviderConfig) GetResourceUID() types.UID {
	return p.ResourceUID
}

func (p *ProviderConfig) GetRevocationURL() *url.URL {
	return p.RevocationURL
}

func (p *ProviderConfig) GetAdditionalAuthcodeParams() map[string]string {
	return p.AdditionalAuthcodeParams
}

func (p *ProviderConfig) GetName() string {
	return p.Name
}

func (p *ProviderConfig) GetClientID() string {
	return p.Config.ClientID
}

func (p *ProviderConfig) GetAuthorizationURL() *url.URL {
	result, _ := url.Parse(p.Config.Endpoint.AuthURL)
	return result
}

func (p *ProviderConfig) GetScopes() []string {
	return p.Config.Scopes
}

func (p *ProviderConfig) GetUsernameClaim() string {
	return p.UsernameClaim
}

func (p *ProviderConfig) GetGroupsClaim() string {
	return p.GroupsClaim
}

func (p *ProviderConfig) AllowsPasswordGrant() bool {
	return p.AllowPasswordGrant
}

func (p *ProviderConfig) PasswordCredentialsGrantAndValidateTokens(ctx context.Context, username, password string) (*oidctypes.Token, error) {
	// Disallow this grant when requested.
	if !p.AllowPasswordGrant {
		return nil, fmt.Errorf("resource owner password credentials grant is not allowed for this upstream provider according to its configuration")
	}

	// Note that this implicitly uses the scopes from p.Config.Scopes.
	tok, err := p.Config.PasswordCredentialsToken(
		coreosoidc.ClientContext(ctx, p.Client),
		username,
		password,
	)
	if err != nil {
		return nil, err
	}

	// There is no nonce to validate for a resource owner password credentials grant because it skips using
	// the authorize endpoint and goes straight to the token endpoint.
	const skipNonceValidation nonce.Nonce = ""
	return p.ValidateToken(ctx, tok, skipNonceValidation)
}

func (p *ProviderConfig) ExchangeAuthcodeAndValidateTokens(ctx context.Context, authcode string, pkceCodeVerifier pkce.Code, expectedIDTokenNonce nonce.Nonce, redirectURI string) (*oidctypes.Token, error) {
	tok, err := p.Config.Exchange(
		coreosoidc.ClientContext(ctx, p.Client),
		authcode,
		pkceCodeVerifier.Verifier(),
		oauth2.SetAuthURLParam("redirect_uri", redirectURI),
	)
	if err != nil {
		return nil, err
	}

	return p.ValidateToken(ctx, tok, expectedIDTokenNonce)
}

// TODO this is reused between the client and the supervisor... don't change it.
func (p *ProviderConfig) PerformRefresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	// Use the provided HTTP client to benefit from its CA, proxy, and other settings.
	httpClientContext := coreosoidc.ClientContext(ctx, p.Client)
	// Create a TokenSource without an access token, so it thinks that a refresh is immediately required.
	// Then ask it for the tokens to cause it to perform the refresh and return the results.
	return p.Config.TokenSource(httpClientContext, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

// RevokeRefreshToken will attempt to revoke the given token, if the provider has a revocation endpoint.
func (p *ProviderConfig) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if p.RevocationURL == nil {
		plog.Trace("RevokeRefreshToken() was called but upstream provider has no available revocation endpoint", "providerName", p.Name)
		return nil
	}
	// First try using client auth in the request params.
	tryAnotherClientAuthMethod, err := p.tryRevokeRefreshToken(ctx, refreshToken, false)
	if tryAnotherClientAuthMethod {
		// Try again using basic auth this time. Overwrite the first client auth error,
		// which isn't useful anymore when retrying.
		_, err = p.tryRevokeRefreshToken(ctx, refreshToken, true)
	}
	return err
}

// tryRevokeRefreshToken will call the revocation endpoint using either basic auth or by including
// client auth in the request params. It will return an error when the request failed. If the
// request failed for a reason that might be due to bad client auth, then it will return true
// for the tryAnotherClientAuthMethod return value, indicating that it might be worth trying
// again using the other client auth method.
// RFC 7009 defines how to make a revocation request and how to interpret the response.
// See https://datatracker.ietf.org/doc/html/rfc7009#section-2.1 for details.
func (p *ProviderConfig) tryRevokeRefreshToken(
	ctx context.Context,
	refreshToken string,
	useBasicAuth bool,
) (tryAnotherClientAuthMethod bool, err error) {
	clientID := p.Config.ClientID
	clientSecret := p.Config.ClientSecret
	// Use the provided HTTP client to benefit from its CA, proxy, and other settings.
	httpClient := p.Client

	params := url.Values{
		"token":           []string{refreshToken},
		"token_type_hint": []string{"refresh_token"},
	}
	if !useBasicAuth {
		params["client_id"] = []string{clientID}
		params["client_secret"] = []string{clientSecret}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.RevocationURL.String(), strings.NewReader(params.Encode()))
	if err != nil {
		// This shouldn't really happen since we already know that the method and URL are legal.
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if useBasicAuth {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// Couldn't connect to the server or some similar error.
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Success!
		plog.Trace("RevokeRefreshToken() got 200 OK response from provider's revocation endpoint", "providerName", p.Name, "usedBasicAuth", useBasicAuth)
		return false, nil
	case http.StatusBadRequest:
		// Bad request might be due to bad client auth method. Try to detect that.
		plog.Trace("RevokeRefreshToken() got 400 Bad Request response from provider's revocation endpoint", "providerName", p.Name, "usedBasicAuth", useBasicAuth)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false,
				fmt.Errorf("error reading response body on response with status code %d: %w", resp.StatusCode, err)
		}
		var parsedResp struct {
			ErrorType        string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		bodyStr := strings.TrimSpace(string(body)) // trimmed for logging purposes
		err = json.Unmarshal(body, &parsedResp)
		if err != nil {
			return false,
				fmt.Errorf("error parsing response body %q on response with status code %d: %w", bodyStr, resp.StatusCode, err)
		}
		err = fmt.Errorf("server responded with status %d with body: %s", resp.StatusCode, bodyStr)
		if parsedResp.ErrorType != "invalid_client" {
			// Got an error unrelated to client auth, so not worth trying again.
			return false, err
		}
		// Got an "invalid_client" response, which might mean client auth failed, so it may be worth trying again
		// using another client auth method. See https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
		plog.Trace("RevokeRefreshToken()'s 400 Bad Request response from provider's revocation endpoint was type 'invalid_client'", "providerName", p.Name, "usedBasicAuth", useBasicAuth)
		return true, err
	default:
		// Any other error is probably not due to failed client auth.
		plog.Trace("RevokeRefreshToken() got unexpected error response from provider's revocation endpoint", "providerName", p.Name, "usedBasicAuth", useBasicAuth, "statusCode", resp.StatusCode)
		return false, fmt.Errorf("server responded with status %d", resp.StatusCode)
	}
}

func (p *ProviderConfig) ValidateRefresh(ctx context.Context, tok *oauth2.Token, storedAttributes provider.StoredRefreshAttributes) error {
	idTok, hasIDTok := tok.Extra("id_token").(string)
	var validatedClaims = make(map[string]interface{})
	if hasIDTok {
		coreosConfig := &coreosoidc.Config{ClientID: p.GetClientID()}
		coreosClientContext := coreosoidc.ClientContext(ctx, p.Client)
		verifier := p.Provider.Verifier(coreosConfig)
		validated, err := verifier.Verify(coreosClientContext, idTok)
		if err != nil {
			return httperr.Wrap(http.StatusBadRequest, "received invalid ID token", err)
		}
		if err := validated.Claims(&validatedClaims); err != nil {
			return httperr.Wrap(http.StatusInternalServerError, "could not unmarshal id token claims", err)
		}
		maybeLogClaims("claims from ID token", p.Name, validatedClaims)
	}

	originalUpstreamSubject, err := extractUpstreamSubjectFromDownstream(storedAttributes.Subject)
	if err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "could not parse stored subject", err)
	}

	// it's okay to not have an id token. It's okay to have an id token with a subject.
	// but if we have an id token without a subject that's a problem.
	idTokenSubject, _ := validatedClaims[oidc.IDTokenSubjectClaim].(string)
	switch {
	case len(idTokenSubject) > 0:
		// TODO url escape
		if url.QueryEscape(idTokenSubject) != originalUpstreamSubject {
			return httperr.Newf(http.StatusInternalServerError, "subject from id token did not match previous stored value. New subject: %s. Old subject: %s", idTokenSubject, originalUpstreamSubject)
		}
	case len(validatedClaims) == 0:
		validatedClaims[oidc.IDTokenSubjectClaim] = originalUpstreamSubject
	default:
		return httperr.New(http.StatusInternalServerError, "id token did not have a subject")
	}

	if err := p.maybeFetchUserInfoAndMergeClaims(ctx, tok, validatedClaims); err != nil {
		return err
	}

	return nil
}

func extractUpstreamSubjectFromDownstream(downstreamSubject string) (string, error) {
	if !strings.Contains(downstreamSubject, "?sub=") {
		return "", errors.New("downstream subject did not contain original upstream subject")
	}
	return strings.Split(downstreamSubject, "?sub=")[1], nil
}

// ValidateToken will validate the ID token. It will also merge the claims from the userinfo endpoint response,
// if the provider offers the userinfo endpoint.
func (p *ProviderConfig) ValidateToken(ctx context.Context, tok *oauth2.Token, expectedIDTokenNonce nonce.Nonce) (*oidctypes.Token, error) {
	idTok, hasIDTok := tok.Extra("id_token").(string)
	if !hasIDTok {
		return nil, httperr.New(http.StatusBadRequest, "received response missing ID token")
	}
	validated, err := p.Provider.Verifier(&coreosoidc.Config{ClientID: p.GetClientID()}).Verify(coreosoidc.ClientContext(ctx, p.Client), idTok)
	if err != nil {
		return nil, httperr.Wrap(http.StatusBadRequest, "received invalid ID token", err)
	}
	if validated.AccessTokenHash != "" {
		if err := validated.VerifyAccessToken(tok.AccessToken); err != nil {
			return nil, httperr.Wrap(http.StatusBadRequest, "received invalid ID token", err)
		}
	}
	if expectedIDTokenNonce != "" {
		if err := expectedIDTokenNonce.Validate(validated); err != nil {
			return nil, httperr.Wrap(http.StatusBadRequest, "received ID token with invalid nonce", err)
		}
	}

	var validatedClaims map[string]interface{}
	if err := validated.Claims(&validatedClaims); err != nil {
		return nil, httperr.Wrap(http.StatusInternalServerError, "could not unmarshal id token claims", err)
	}
	maybeLogClaims("claims from ID token", p.Name, validatedClaims)

	idTokenSubject, _ := validatedClaims[oidc.IDTokenSubjectClaim].(string)
	if len(idTokenSubject) > 0 {
		if err := p.maybeFetchUserInfoAndMergeClaims(ctx, tok, validatedClaims); err != nil {
			return nil, httperr.Wrap(http.StatusInternalServerError, "could not fetch user info claims", err)
		}
	}

	return &oidctypes.Token{
		AccessToken: &oidctypes.AccessToken{
			Token:  tok.AccessToken,
			Type:   tok.TokenType,
			Expiry: metav1.NewTime(tok.Expiry),
		},
		RefreshToken: &oidctypes.RefreshToken{
			Token: tok.RefreshToken,
		},
		IDToken: &oidctypes.IDToken{
			Token:  idTok,
			Expiry: metav1.NewTime(validated.Expiry),
			Claims: validatedClaims,
		},
	}, nil
}

func (p *ProviderConfig) maybeFetchUserInfoAndMergeClaims(ctx context.Context, tok *oauth2.Token, claims map[string]interface{}) error {
	// TODO separate this.
	//  extract: fetching userinfo
	//  - validate some userinfo? subject stuff: for refresh subjects must match but also match stored subject
	//  - extract: merging claims
	//  - deciding when to do each of those things
	idTokenSubject, _ := claims[oidc.IDTokenSubjectClaim].(string)

	userInfo, err := p.fetchUserInfo(ctx, tok)
	if err != nil {
		return err
	}
	if userInfo == nil {
		return nil
	}

	// TODO if there is no idTokenSubject, defer to checking the stored claims.
	// The sub (subject) Claim MUST always be returned in the UserInfo Response.
	//
	// NOTE: Due to the possibility of token substitution attacks (see Section 16.11), the UserInfo Response is not
	// guaranteed to be about the End-User identified by the sub (subject) element of the ID Token. The sub Claim in
	// the UserInfo Response MUST be verified to exactly match the sub Claim in the ID Token; if they do not match,
	// the UserInfo Response values MUST NOT be used.
	//
	// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	if (len(idTokenSubject) > 0) && (len(userInfo.Subject) == 0 || userInfo.Subject != idTokenSubject) {
		return httperr.Newf(http.StatusUnprocessableEntity, "userinfo 'sub' claim (%s) did not match id_token 'sub' claim (%s)", userInfo.Subject, idTokenSubject)
	}

	// merge existing claims with user info claims
	if err := userInfo.Claims(&claims); err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "could not unmarshal user info claims", err)
	}

	maybeLogClaims("claims from ID token and userinfo", p.Name, claims)

	return nil
}

func (p *ProviderConfig) fetchUserInfo(ctx context.Context, tok *oauth2.Token) (*coreosoidc.UserInfo, error) {
	providerJSON := &struct {
		UserInfoURL string `json:"userinfo_endpoint"`
	}{}
	if err := p.Provider.Claims(providerJSON); err != nil {
		// this should never happen because we should have already parsed these claims at an earlier stage
		return nil, httperr.Wrap(http.StatusInternalServerError, "could not unmarshal discovery JSON", err)
	}

	// implementing the user info endpoint is not required, skip this logic when it is absent
	if len(providerJSON.UserInfoURL) == 0 {
		return nil, nil
	}

	userInfo, err := p.Provider.UserInfo(coreosoidc.ClientContext(ctx, p.Client), oauth2.StaticTokenSource(tok))
	if err != nil {
		return nil, httperr.Wrap(http.StatusInternalServerError, "could not get user info", err)
	}
	return userInfo, nil
}

func maybeLogClaims(msg, name string, claims map[string]interface{}) {
	if plog.Enabled(plog.LevelAll) { // log keys and values at all level
		data, _ := json.Marshal(claims) // nothing we can do if it fails, but it really never should
		plog.Info(msg, "providerName", name, "claims", string(data))
		return
	}

	if plog.Enabled(plog.LevelDebug) { // log keys at debug level
		keys := sets.StringKeySet(claims).List() // note: this is only safe because the compiler asserts that claims is a map[string]<anything>
		plog.Info(msg, "providerName", name, "keys", keys)
		return
	}
}
