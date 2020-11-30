// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamoidc implements an abstraction of upstream OIDC provider interactions.
package upstreamoidc

import (
	"context"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

func New(config *oauth2.Config, provider *oidc.Provider) provider.UpstreamOIDCIdentityProviderI {
	return &ProviderConfig{Config: config, Provider: provider}
}

// ProviderConfig holds the active configuration of an upstream OIDC provider.
type ProviderConfig struct {
	Name          string
	UsernameClaim string
	GroupsClaim   string
	Config        *oauth2.Config
	Provider      interface {
		Verifier(*oidc.Config) *oidc.IDTokenVerifier
	}
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

func (p *ProviderConfig) ExchangeAuthcodeAndValidateTokens(ctx context.Context, authcode string, pkceCodeVerifier pkce.Code, expectedIDTokenNonce nonce.Nonce) (oidctypes.Token, map[string]interface{}, error) {
	tok, err := p.Config.Exchange(ctx, authcode, pkceCodeVerifier.Verifier())
	if err != nil {
		return oidctypes.Token{}, nil, err
	}

	return p.ValidateToken(ctx, tok, expectedIDTokenNonce)
}

func (p *ProviderConfig) ValidateToken(ctx context.Context, tok *oauth2.Token, expectedIDTokenNonce nonce.Nonce) (oidctypes.Token, map[string]interface{}, error) {
	idTok, hasIDTok := tok.Extra("id_token").(string)
	if !hasIDTok {
		return oidctypes.Token{}, nil, httperr.New(http.StatusBadRequest, "received response missing ID token")
	}
	validated, err := p.Provider.Verifier(&oidc.Config{ClientID: p.GetClientID()}).Verify(ctx, idTok)
	if err != nil {
		return oidctypes.Token{}, nil, httperr.Wrap(http.StatusBadRequest, "received invalid ID token", err)
	}
	if validated.AccessTokenHash != "" {
		if err := validated.VerifyAccessToken(tok.AccessToken); err != nil {
			return oidctypes.Token{}, nil, httperr.Wrap(http.StatusBadRequest, "received invalid ID token", err)
		}
	}
	if expectedIDTokenNonce != "" {
		if err := expectedIDTokenNonce.Validate(validated); err != nil {
			return oidctypes.Token{}, nil, httperr.Wrap(http.StatusBadRequest, "received ID token with invalid nonce", err)
		}
	}

	var validatedClaims map[string]interface{}
	if err := validated.Claims(&validatedClaims); err != nil {
		return oidctypes.Token{}, nil, httperr.Wrap(http.StatusInternalServerError, "could not unmarshal claims", err)
	}

	return oidctypes.Token{
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
		},
	}, validatedClaims, nil
}
