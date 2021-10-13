// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamoidc implements an abstraction of upstream OIDC provider interactions.
package upstreamoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

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

func (p *ProviderConfig) PerformRefresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	// Use the provided HTTP client to benefit from its CA, proxy, and other settings.
	httpClientContext := coreosoidc.ClientContext(ctx, p.Client)
	// Create a TokenSource without an access token, so it thinks that a refresh is immediately required.
	// Then ask it for the tokens to cause it to perform the refresh and return the results.
	return p.Config.TokenSource(httpClientContext, &oauth2.Token{RefreshToken: refreshToken}).Token()
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

	if err := p.maybeFetchUserInfoAndMergeClaims(ctx, tok, validatedClaims); err != nil {
		return nil, httperr.Wrap(http.StatusInternalServerError, "could not fetch user info claims", err)
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
	idTokenSubject, _ := claims[oidc.IDTokenSubjectClaim].(string)
	if len(idTokenSubject) == 0 {
		return nil // defer to existing ID token validation
	}

	providerJSON := &struct {
		UserInfoURL string `json:"userinfo_endpoint"`
	}{}
	if err := p.Provider.Claims(providerJSON); err != nil {
		// this should never happen because we should have already parsed these claims at an earlier stage
		return httperr.Wrap(http.StatusInternalServerError, "could not unmarshal discovery JSON", err)
	}

	// implementing the user info endpoint is not required, skip this logic when it is absent
	if len(providerJSON.UserInfoURL) == 0 {
		return nil
	}

	userInfo, err := p.Provider.UserInfo(coreosoidc.ClientContext(ctx, p.Client), oauth2.StaticTokenSource(tok))
	if err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "could not get user info", err)
	}

	// The sub (subject) Claim MUST always be returned in the UserInfo Response.
	//
	// NOTE: Due to the possibility of token substitution attacks (see Section 16.11), the UserInfo Response is not
	// guaranteed to be about the End-User identified by the sub (subject) element of the ID Token. The sub Claim in
	// the UserInfo Response MUST be verified to exactly match the sub Claim in the ID Token; if they do not match,
	// the UserInfo Response values MUST NOT be used.
	//
	// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	if len(userInfo.Subject) == 0 || userInfo.Subject != idTokenSubject {
		return httperr.Newf(http.StatusUnprocessableEntity, "userinfo 'sub' claim (%s) did not match id_token 'sub' claim (%s)", userInfo.Subject, idTokenSubject)
	}

	// merge existing claims with user info claims
	if err := userInfo.Claims(&claims); err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "could not unmarshal user info claims", err)
	}

	maybeLogClaims("claims from ID token and userinfo", p.Name, claims)

	return nil
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
