// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamoidc implements an abstraction of upstream OIDC provider interactions.
package upstreamoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/httputil/httperr"
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
	AdditionalClaimMappings  map[string]string
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

func (p *ProviderConfig) HasUserInfoURL() bool {
	providerJSON := &struct {
		UserInfoURL string `json:"userinfo_endpoint"`
	}{}
	if err := p.Provider.Claims(providerJSON); err != nil {
		// This should never happen in practice because we should have already successfully
		// parsed these claims when p.Provider was created.
		return false
	}

	return len(providerJSON.UserInfoURL) > 0
}

func (p *ProviderConfig) GetAdditionalAuthcodeParams() map[string]string {
	return p.AdditionalAuthcodeParams
}

func (p *ProviderConfig) GetAdditionalClaimMappings() map[string]string {
	return p.AdditionalClaimMappings
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
	return p.ValidateTokenAndMergeWithUserInfo(ctx, tok, skipNonceValidation, true, false)
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

	return p.ValidateTokenAndMergeWithUserInfo(ctx, tok, expectedIDTokenNonce, true, false)
}

func (p *ProviderConfig) PerformRefresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	// Use the provided HTTP client to benefit from its CA, proxy, and other settings.
	httpClientContext := coreosoidc.ClientContext(ctx, p.Client)
	// Create a TokenSource without an access token, so it thinks that a refresh is immediately required.
	// Then ask it for the tokens to cause it to perform the refresh and return the results.
	return p.Config.TokenSource(httpClientContext, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

// RevokeToken will attempt to revoke the given token, if the provider has a revocation endpoint.
// It may return an error wrapped by a RetryableRevocationError, which is an error indicating that it may
// be worth trying to revoke the same token again later. Any other error returned should be assumed to
// represent an error such that it is not worth retrying revocation later, even though revocation failed.
func (p *ProviderConfig) RevokeToken(ctx context.Context, token string, tokenType provider.RevocableTokenType) error {
	if p.RevocationURL == nil {
		plog.Trace("RevokeToken() was called but upstream provider has no available revocation endpoint",
			"providerName", p.Name,
			"tokenType", tokenType,
		)
		return nil
	}
	// First try using client auth in the request params.
	tryAnotherClientAuthMethod, err := p.tryRevokeToken(ctx, token, tokenType, false)
	if tryAnotherClientAuthMethod {
		// Try again using basic auth this time. Overwrite the first client auth error,
		// which isn't useful anymore when retrying.
		_, err = p.tryRevokeToken(ctx, token, tokenType, true)
	}
	return err
}

// tryRevokeToken will call the revocation endpoint using either basic auth or by including
// client auth in the request params. It will return an error when the request failed. If the
// request failed for a reason that might be due to bad client auth, then it will return true
// for the tryAnotherClientAuthMethod return value, indicating that it might be worth trying
// again using the other client auth method.
// RFC 7009 defines how to make a revocation request and how to interpret the response.
// See https://datatracker.ietf.org/doc/html/rfc7009#section-2.1 for details.
func (p *ProviderConfig) tryRevokeToken(
	ctx context.Context,
	token string,
	tokenType provider.RevocableTokenType,
	useBasicAuth bool,
) (tryAnotherClientAuthMethod bool, err error) {
	clientID := p.Config.ClientID
	clientSecret := p.Config.ClientSecret
	// Use the provided HTTP client to benefit from its CA, proxy, and other settings.
	httpClient := p.Client

	params := url.Values{
		"token":           []string{token},
		"token_type_hint": []string{string(tokenType)},
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
		// Could be a temporary network problem, so it might be worth retrying.
		return false, provider.NewRetryableRevocationError(err)
	}
	defer resp.Body.Close()

	status := resp.StatusCode

	switch {
	case status == http.StatusOK:
		// Success!
		plog.Trace("RevokeToken() got 200 OK response from provider's revocation endpoint", "providerName", p.Name, "usedBasicAuth", useBasicAuth)
		return false, nil
	case status == http.StatusBadRequest:
		// Bad request might be due to bad client auth method. Try to detect that.
		plog.Trace("RevokeToken() got 400 Bad Request response from provider's revocation endpoint", "providerName", p.Name, "usedBasicAuth", useBasicAuth)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false,
				fmt.Errorf("error reading response body on response with status code %d: %w", status, err)
		}
		var parsedResp struct {
			ErrorType        string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		bodyStr := strings.TrimSpace(string(body)) // trimmed for logging purposes
		err = json.Unmarshal(body, &parsedResp)
		if err != nil {
			return false,
				fmt.Errorf("error parsing response body %q on response with status code %d: %w", bodyStr, status, err)
		}
		err = fmt.Errorf("server responded with status %d with body: %s", status, bodyStr)
		if parsedResp.ErrorType != "invalid_client" {
			// Got an error unrelated to client auth, so not worth trying client auth again. Also, these are errors
			// of the type where the server is pretty conclusively rejecting our request, so they are generally
			// not worth trying again later either.
			// These errors could be any of the other errors from https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
			// or "unsupported_token_type" from https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1
			// or could be some unspecified custom error added by the OIDC provider.
			return false, err
		}
		// Got an "invalid_client" response, which might mean client auth failed, so it may be worth trying again
		// using another client auth method. See https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
		plog.Trace("RevokeToken()'s 400 Bad Request response from provider's revocation endpoint was type 'invalid_client'", "providerName", p.Name, "usedBasicAuth", useBasicAuth)
		return true, err
	case status >= 500 && status <= 599:
		// The spec says 503 Service Unavailable should be retried by the client later.
		// See https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1.
		// Other forms of 5xx server errors are not particularly conclusive failures. For example, gateway errors could
		// be caused by an underlying problem which could potentially become resolved in the near future. We'll be
		// optimistic and call all 5xx errors retryable.
		plog.Trace("RevokeToken() got unexpected error response from provider's revocation endpoint", "providerName", p.Name, "usedBasicAuth", useBasicAuth, "statusCode", status)
		return false, provider.NewRetryableRevocationError(fmt.Errorf("server responded with status %d", status))
	default:
		// Any other error is probably not due to failed client auth, and is probably not worth retrying later.
		plog.Trace("RevokeToken() got unexpected error response from provider's revocation endpoint", "providerName", p.Name, "usedBasicAuth", useBasicAuth, "statusCode", status)
		return false, fmt.Errorf("server responded with status %d", status)
	}
}

// ValidateTokenAndMergeWithUserInfo will validate the ID token. It will also merge the claims from the userinfo endpoint response,
// if the provider offers the userinfo endpoint.
func (p *ProviderConfig) ValidateTokenAndMergeWithUserInfo(ctx context.Context, tok *oauth2.Token, expectedIDTokenNonce nonce.Nonce, requireIDToken bool, requireUserInfo bool) (*oidctypes.Token, error) {
	var validatedClaims = make(map[string]interface{})

	var idTokenExpiry time.Time
	// if we require the id token, make sure we have it.
	// also, if it exists but wasn't required, still make sure it passes these checks.
	idTokenExpiry, idTok, err := p.validateIDToken(ctx, tok, expectedIDTokenNonce, validatedClaims, requireIDToken)
	if err != nil {
		return nil, err
	}

	idTokenSubject, _ := validatedClaims[oidcapi.IDTokenClaimSubject].(string)

	if len(idTokenSubject) > 0 || !requireIDToken {
		// only fetch userinfo if the ID token has a subject or if we are ignoring the id token completely.
		// otherwise, defer to existing ID token validation
		if err := p.maybeFetchUserInfoAndMergeClaims(ctx, tok, validatedClaims, requireIDToken, requireUserInfo); err != nil {
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
			Expiry: metav1.NewTime(idTokenExpiry),
			Claims: validatedClaims,
		},
	}, nil
}

func (p *ProviderConfig) validateIDToken(ctx context.Context, tok *oauth2.Token, expectedIDTokenNonce nonce.Nonce, validatedClaims map[string]interface{}, requireIDToken bool) (time.Time, string, error) {
	idTok, hasIDTok := tok.Extra("id_token").(string)
	if !hasIDTok && !requireIDToken {
		return time.Time{}, "", nil // exit early
	}

	var idTokenExpiry time.Time
	if !hasIDTok {
		return time.Time{}, "", httperr.New(http.StatusBadRequest, "received response missing ID token")
	}
	validated, err := p.Provider.Verifier(&coreosoidc.Config{ClientID: p.GetClientID()}).Verify(coreosoidc.ClientContext(ctx, p.Client), idTok)
	if err != nil {
		return time.Time{}, "", httperr.Wrap(http.StatusBadRequest, "received invalid ID token", err)
	}
	if validated.AccessTokenHash != "" {
		if err := validated.VerifyAccessToken(tok.AccessToken); err != nil {
			return time.Time{}, "", httperr.Wrap(http.StatusBadRequest, "received invalid ID token", err)
		}
	}
	if expectedIDTokenNonce != "" {
		if err := expectedIDTokenNonce.Validate(validated); err != nil {
			return time.Time{}, "", httperr.Wrap(http.StatusBadRequest, "received ID token with invalid nonce", err)
		}
	}
	if err := validated.Claims(&validatedClaims); err != nil {
		return time.Time{}, "", httperr.Wrap(http.StatusInternalServerError, "could not unmarshal id token claims", err)
	}
	maybeLogClaims("claims from ID token", p.Name, validatedClaims)
	idTokenExpiry = validated.Expiry // keep track of the id token expiry if we have an id token. Otherwise, it'll just be the zero value.
	return idTokenExpiry, idTok, nil
}

func (p *ProviderConfig) maybeFetchUserInfoAndMergeClaims(ctx context.Context, tok *oauth2.Token, claims map[string]interface{}, requireIDToken bool, requireUserInfo bool) error {
	idTokenSubject, _ := claims[oidcapi.IDTokenClaimSubject].(string)

	userInfo, err := p.maybeFetchUserInfo(ctx, tok, requireUserInfo)
	if err != nil {
		return err
	}
	if userInfo == nil {
		return nil
	}

	// The sub (subject) Claim MUST always be returned in the UserInfo Response.
	// NOTE: Due to the possibility of token substitution attacks (see Section 16.11), the UserInfo Response is not
	// guaranteed to be about the End-User identified by the sub (subject) element of the ID Token. The sub Claim in
	// the UserInfo Response MUST be verified to exactly match the sub Claim in the ID Token; if they do not match,
	// the UserInfo Response values MUST NOT be used.
	//
	// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	// If there is no ID token and it is not required, we must assume that the caller is performing other checks
	// to ensure the subject is correct.
	checkIDToken := requireIDToken || len(idTokenSubject) > 0
	if checkIDToken && (len(userInfo.Subject) == 0 || userInfo.Subject != idTokenSubject) {
		return httperr.Newf(http.StatusUnprocessableEntity, "userinfo 'sub' claim (%s) did not match id_token 'sub' claim (%s)", userInfo.Subject, idTokenSubject)
	}

	// keep track of the issuer from the ID token
	idTokenIssuer := claims[oidcapi.IDTokenClaimIssuer]

	// merge existing claims with user info claims
	if err := userInfo.Claims(&claims); err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "could not unmarshal user info claims", err)
	}
	//  The OIDC spec for the UserInfo response does not make any guarantees about the iss claim's existence or validity:
	//  "If signed, the UserInfo Response SHOULD contain the Claims iss (issuer) and aud (audience) as members. The iss value SHOULD be the OP's Issuer Identifier URL."
	//  See https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	//  So we just ignore it and use it the version from the id token, which has stronger guarantees.
	delete(claims, oidcapi.IDTokenClaimIssuer)
	if idTokenIssuer != nil {
		claims[oidcapi.IDTokenClaimIssuer] = idTokenIssuer
	}

	maybeLogClaims("claims from ID token and userinfo", p.Name, claims)

	return nil
}

func (p *ProviderConfig) maybeFetchUserInfo(ctx context.Context, tok *oauth2.Token, requireUserInfo bool) (*coreosoidc.UserInfo, error) {
	// implementing the user info endpoint is not required by the OIDC spec, but we may require it in certain situations.
	if !p.HasUserInfoURL() {
		if requireUserInfo {
			// TODO should these all be http errors?
			return nil, httperr.New(http.StatusInternalServerError, "userinfo endpoint not found, but is required")
		}
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
		plog.All(msg, "providerName", name, "claims", string(data))
		return
	}

	if plog.Enabled(plog.LevelDebug) { // log keys at debug level
		keys := sets.StringKeySet(claims).List() // note: this is only safe because the compiler asserts that claims is a map[string]<anything>
		plog.Debug(msg, "providerName", name, "keys", keys)
		return
	}
}
