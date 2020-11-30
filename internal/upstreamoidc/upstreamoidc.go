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
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

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

// *ProviderConfig should implement provider.UpstreamOIDCIdentityProviderI.
var _ provider.UpstreamOIDCIdentityProviderI = (*ProviderConfig)(nil)

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

func (p *ProviderConfig) ExchangeAuthcodeAndValidateTokens(ctx context.Context, authcode string, pkceCodeVerifier pkce.Code, expectedIDTokenNonce nonce.Nonce) (oidcclient.Token, map[string]interface{}, error) {
	tok, err := p.Config.Exchange(ctx, authcode, pkceCodeVerifier.Verifier())
	if err != nil {
		return oidcclient.Token{}, nil, err
	}

	idTok, hasIDTok := tok.Extra("id_token").(string)
	if !hasIDTok {
		return oidcclient.Token{}, nil, httperr.New(http.StatusBadRequest, "received response missing ID token")
	}
	validated, err := p.Provider.Verifier(&oidc.Config{ClientID: p.GetClientID()}).Verify(ctx, idTok)
	if err != nil {
		return oidcclient.Token{}, nil, httperr.Wrap(http.StatusBadRequest, "received invalid ID token", err)
	}
	if validated.AccessTokenHash != "" {
		if err := validated.VerifyAccessToken(tok.AccessToken); err != nil {
			return oidcclient.Token{}, nil, httperr.Wrap(http.StatusBadRequest, "received invalid ID token", err)
		}
	}
	if expectedIDTokenNonce != "" {
		if err := expectedIDTokenNonce.Validate(validated); err != nil {
			return oidcclient.Token{}, nil, httperr.Wrap(http.StatusBadRequest, "received ID token with invalid nonce", err)
		}
	}

	var validatedClaims map[string]interface{}
	if err := validated.Claims(&validatedClaims); err != nil {
		return oidcclient.Token{}, nil, httperr.Wrap(http.StatusInternalServerError, "could not unmarshal claims", err)
	}

	return oidcclient.Token{
		AccessToken: &oidcclient.AccessToken{
			Token:  tok.AccessToken,
			Type:   tok.TokenType,
			Expiry: metav1.NewTime(tok.Expiry),
		},
		RefreshToken: &oidcclient.RefreshToken{
			Token: tok.RefreshToken,
		},
		IDToken: &oidcclient.IDToken{
			Token:  idTok,
			Expiry: metav1.NewTime(validated.Expiry),
		},
	}, validatedClaims, nil
}
