// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamoidc implements an abstraction of upstream OIDC provider interactions.
package upstreamoidc

import (
	"context"
	"net/http"
	"net/url"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	Name          string
	UsernameClaim string
	GroupsClaim   string
	Config        *oauth2.Config
	Provider      interface {
		Verifier(*coreosoidc.Config) *coreosoidc.IDTokenVerifier
		UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*coreosoidc.UserInfo, error)
	}
	Client *http.Client
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
	plog.All("claims from ID token", "providerName", p.Name, "claims", validatedClaims)

	if err := p.fetchUserInfo(ctx, tok, validatedClaims); err != nil {
		return nil, httperr.Wrap(http.StatusInternalServerError, "could not fetch user info claims", err)
	}
	plog.All("claims from ID token and userinfo", "providerName", p.Name, "claims", validatedClaims)

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

func (p *ProviderConfig) fetchUserInfo(ctx context.Context, tok *oauth2.Token, claims map[string]interface{}) error {
	idTokenSubject, _ := claims[oidc.IDTokenSubjectClaim].(string)
	if len(idTokenSubject) == 0 {
		return nil // defer to existing ID token validation
	}

	userInfo, err := p.Provider.UserInfo(coreosoidc.ClientContext(ctx, p.Client), oauth2.StaticTokenSource(tok))
	if err != nil {
		// the user info endpoint is not required but we do not have a good way to probe if it was provided
		const userInfoUnsupported = "oidc: user info endpoint is not supported by this provider"
		if err.Error() == userInfoUnsupported {
			return nil
		}

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

	return nil
}
