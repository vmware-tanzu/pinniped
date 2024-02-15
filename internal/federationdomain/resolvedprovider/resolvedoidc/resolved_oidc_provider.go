// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedoidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/federationdomain/downstreamsession"
	"go.pinniped.dev/internal/federationdomain/downstreamsubject"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

const (
	// The name of the email claim from https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	emailClaimName = oidc.ScopeEmail

	// The name of the email_verified claim from https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	emailVerifiedClaimName = "email_verified"

	requiredClaimMissingErr            = constable.Error("required claim in upstream ID token missing")
	requiredClaimInvalidFormatErr      = constable.Error("required claim in upstream ID token has invalid format")
	requiredClaimEmptyErr              = constable.Error("required claim in upstream ID token is empty")
	emailVerifiedClaimInvalidFormatErr = constable.Error("email_verified claim in upstream ID token has invalid format")
	emailVerifiedClaimFalseErr         = constable.Error("email_verified claim in upstream ID token has false value")
)

// FederationDomainResolvedOIDCIdentityProvider represents a FederationDomainIdentityProvider which has
// been resolved dynamically based on the currently loaded IDP CRs to include the provider.UpstreamOIDCIdentityProviderI
// and other metadata about the provider.
type FederationDomainResolvedOIDCIdentityProvider struct {
	DisplayName         string
	Provider            upstreamprovider.UpstreamOIDCIdentityProviderI
	SessionProviderType psession.ProviderType
	Transforms          *idtransform.TransformationPipeline
}

var _ resolvedprovider.FederationDomainResolvedIdentityProvider = (*FederationDomainResolvedOIDCIdentityProvider)(nil)

func (p *FederationDomainResolvedOIDCIdentityProvider) GetDisplayName() string {
	return p.DisplayName
}

func (p *FederationDomainResolvedOIDCIdentityProvider) GetProvider() upstreamprovider.UpstreamIdentityProviderI {
	return p.Provider
}

func (p *FederationDomainResolvedOIDCIdentityProvider) GetSessionProviderType() psession.ProviderType {
	return p.SessionProviderType
}

func (p *FederationDomainResolvedOIDCIdentityProvider) GetIDPDiscoveryType() v1alpha1.IDPType {
	return v1alpha1.IDPTypeOIDC
}

func (p *FederationDomainResolvedOIDCIdentityProvider) GetIDPDiscoveryFlows() []v1alpha1.IDPFlow {
	flows := []v1alpha1.IDPFlow{v1alpha1.IDPFlowBrowserAuthcode}
	if p.Provider.AllowsPasswordGrant() {
		flows = append(flows, v1alpha1.IDPFlowCLIPassword)
	}
	return flows
}

func (p *FederationDomainResolvedOIDCIdentityProvider) GetTransforms() *idtransform.TransformationPipeline {
	return p.Transforms
}

func (p *FederationDomainResolvedOIDCIdentityProvider) UpstreamAuthorizeRedirectURL(state *resolvedprovider.UpstreamAuthorizeRequestState, downstreamIssuerURL string) (string, error) {
	upstreamOAuthConfig := oauth2.Config{
		ClientID: p.Provider.GetClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL: p.Provider.GetAuthorizationURL().String(),
		},
		RedirectURL: fmt.Sprintf("%s/callback", downstreamIssuerURL),
		Scopes:      p.Provider.GetScopes(),
	}

	authCodeOptions := []oauth2.AuthCodeOption{
		state.Nonce.Param(),
		state.PKCE.Challenge(),
		state.PKCE.Method(),
	}

	for key, val := range p.Provider.GetAdditionalAuthcodeParams() {
		authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam(key, val))
	}

	redirectURL := upstreamOAuthConfig.AuthCodeURL(
		state.EncodedStateParam,
		authCodeOptions...,
	)

	return redirectURL, nil
}

func (p *FederationDomainResolvedOIDCIdentityProvider) Login(
	ctx context.Context,
	submittedUsername string,
	submittedPassword string,
	_groupsWillBeIgnored bool, // ignored because we always compute the user's group memberships for OIDC, if possible
) (*resolvedprovider.Identity, error) {
	if !p.Provider.AllowsPasswordGrant() {
		// Return a user-friendly error for this case which is entirely within our control.
		return nil, fosite.ErrAccessDenied.WithHint(
			"Resource owner password credentials grant is not allowed for this upstream provider according to its configuration.")
	}

	token, err := p.Provider.PasswordCredentialsGrantAndValidateTokens(ctx, submittedUsername, submittedPassword)
	if err != nil {
		// Upstream password grant errors can be generic errors (e.g. a network failure) or can be oauth2.RetrieveError errors
		// which represent the http response from the upstream server. These could be a 5XX or some other unexpected error,
		// or could be a 400 with a JSON body as described by https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
		// which notes that wrong resource owner credentials should result in an "invalid_grant" error.
		// However, the exact response is undefined in the sense that there is no such thing as a password grant in
		// the OIDC spec, so we don't try too hard to read the upstream errors in this case. (E.g. Dex departs from the
		// spec and returns something other than an "invalid_grant" error for bad resource owner credentials.)
		return nil, fosite.ErrAccessDenied.WithDebug(err.Error()) // WithDebug hides the error from the client
	}

	subject, upstreamUsername, upstreamGroups, err := getDownstreamIdentityFromUpstreamIDToken(
		p.Provider, token.IDToken.Claims, p.DisplayName,
	)
	if err != nil {
		// Return a user-friendly error for this case which is entirely within our control.
		return nil, fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error())
	}

	username, groups, err := downstreamsession.ApplyIdentityTransformations(ctx, p.Transforms, upstreamUsername, upstreamGroups)
	if err != nil {
		return nil, fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error())
	}

	additionalClaims := mapAdditionalClaimsFromUpstreamIDToken(p.Provider, token.IDToken.Claims)

	customSessionData, err := makeDownstreamOIDCCustomSessionData(p.Provider, token, username, upstreamUsername, upstreamGroups)
	if err != nil {
		return nil, fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error())
	}

	return &resolvedprovider.Identity{
		SessionData:      customSessionData,
		Groups:           groups,
		Subject:          subject,
		AdditionalClaims: additionalClaims,
	}, nil
}

func (p *FederationDomainResolvedOIDCIdentityProvider) HandleCallback(
	ctx context.Context,
	authCode string,
	pkce pkce.Code,
	nonce nonce.Nonce,
	redirectURI string,
) (*resolvedprovider.Identity, error) {
	token, err := p.Provider.ExchangeAuthcodeAndValidateTokens(
		ctx,
		authCode,
		pkce,
		nonce,
		redirectURI,
	)
	if err != nil {
		plog.WarningErr("error exchanging and validating upstream tokens", err, "upstreamName", p.Provider.GetName())
		return nil, httperr.New(http.StatusBadGateway, "error exchanging and validating upstream tokens")
	}

	subject, upstreamUsername, upstreamGroups, err := getDownstreamIdentityFromUpstreamIDToken(
		p.Provider, token.IDToken.Claims, p.DisplayName,
	)
	if err != nil {
		return nil, httperr.Wrap(http.StatusUnprocessableEntity, err.Error(), err)
	}

	username, groups, err := downstreamsession.ApplyIdentityTransformations(
		ctx, p.Transforms, upstreamUsername, upstreamGroups,
	)
	if err != nil {
		return nil, httperr.Wrap(http.StatusUnprocessableEntity, err.Error(), err)
	}

	additionalClaims := mapAdditionalClaimsFromUpstreamIDToken(p.Provider, token.IDToken.Claims)

	customSessionData, err := makeDownstreamOIDCCustomSessionData(
		p.Provider, token, username, upstreamUsername, upstreamGroups,
	)
	if err != nil {
		return nil, httperr.Wrap(http.StatusUnprocessableEntity, err.Error(), err)
	}

	return &resolvedprovider.Identity{
		SessionData:      customSessionData,
		Groups:           groups,
		Subject:          subject,
		AdditionalClaims: additionalClaims,
	}, nil
}

func makeDownstreamOIDCCustomSessionData(
	oidcUpstream upstreamprovider.UpstreamOIDCIdentityProviderI,
	token *oidctypes.Token,
	username string,
	untransformedUpstreamUsername string,
	untransformedUpstreamGroups []string,
) (*psession.CustomSessionData, error) {
	upstreamSubject, err := extractStringClaimValue(oidc.IDTokenClaimSubject, oidcUpstream.GetName(), token.IDToken.Claims)
	if err != nil {
		return nil, err
	}
	upstreamIssuer, err := extractStringClaimValue(oidc.IDTokenClaimIssuer, oidcUpstream.GetName(), token.IDToken.Claims)
	if err != nil {
		return nil, err
	}

	customSessionData := &psession.CustomSessionData{
		Username:         username,
		UpstreamUsername: untransformedUpstreamUsername,
		UpstreamGroups:   untransformedUpstreamGroups,
		ProviderUID:      oidcUpstream.GetResourceUID(),
		ProviderName:     oidcUpstream.GetName(),
		ProviderType:     psession.ProviderTypeOIDC,
		OIDC: &psession.OIDCSessionData{
			UpstreamIssuer:  upstreamIssuer,
			UpstreamSubject: upstreamSubject,
		},
	}

	const pleaseCheck = "please check configuration of OIDCIdentityProvider and the client in the " +
		"upstream provider's API/UI and try to get a refresh token if possible"
	logKV := []interface{}{
		"upstreamName", oidcUpstream.GetName(),
		"scopes", oidcUpstream.GetScopes(),
		"additionalParams", oidcUpstream.GetAdditionalAuthcodeParams(),
	}

	hasRefreshToken := token.RefreshToken != nil && token.RefreshToken.Token != ""
	hasAccessToken := token.AccessToken != nil && token.AccessToken.Token != ""
	switch {
	case hasRefreshToken: // we prefer refresh tokens, so check for this first
		customSessionData.OIDC.UpstreamRefreshToken = token.RefreshToken.Token
	case hasAccessToken: // as a fallback, we can use the access token as long as there is a userinfo endpoint
		if !oidcUpstream.HasUserInfoURL() {
			plog.Warning("access token was returned by upstream provider during login without a refresh token "+
				"and there was no userinfo endpoint available on the provider. "+pleaseCheck, logKV...)
			return nil, errors.New("access token was returned by upstream provider but there was no userinfo endpoint")
		}
		plog.Info("refresh token not returned by upstream provider during login, using access token instead. "+pleaseCheck, logKV...)
		customSessionData.OIDC.UpstreamAccessToken = token.AccessToken.Token
		// When we are in a flow where we will be performing access token based refresh, issue a warning to the client if the access
		// token lifetime is very short, since that would mean that the user's session is very short.
		// The warnings are stored here and will be processed by the token handler.
		threeHoursFromNow := metav1.NewTime(time.Now().Add(3 * time.Hour))
		if !token.AccessToken.Expiry.IsZero() && token.AccessToken.Expiry.Before(&threeHoursFromNow) {
			customSessionData.Warnings = append(customSessionData.Warnings, "Access token from identity provider has lifetime of less than 3 hours. Expect frequent prompts to log in.")
		}
	default:
		plog.Warning("refresh token and access token not returned by upstream provider during login. "+pleaseCheck, logKV...)
		return nil, errors.New("neither access token nor refresh token returned by upstream provider")
	}

	return customSessionData, nil
}

// getDownstreamIdentityFromUpstreamIDToken returns the mapped subject, username, and group names, in that order.
func getDownstreamIdentityFromUpstreamIDToken(
	upstreamIDPConfig upstreamprovider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
	idpDisplayName string,
) (string, string, []string, error) {
	subject, username, err := getSubjectAndUsernameFromUpstreamIDToken(upstreamIDPConfig, idTokenClaims, idpDisplayName)
	if err != nil {
		return "", "", nil, err
	}

	groups, err := GetGroupsFromUpstreamIDToken(upstreamIDPConfig, idTokenClaims)
	if err != nil {
		return "", "", nil, err
	}

	return subject, username, groups, err
}

// mapAdditionalClaimsFromUpstreamIDToken returns the additionalClaims mapped from the upstream token, if any.
func mapAdditionalClaimsFromUpstreamIDToken(
	upstreamIDPConfig upstreamprovider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
) map[string]interface{} {
	mapped := make(map[string]interface{}, len(upstreamIDPConfig.GetAdditionalClaimMappings()))
	for downstreamClaimName, upstreamClaimName := range upstreamIDPConfig.GetAdditionalClaimMappings() {
		upstreamClaimValue, ok := idTokenClaims[upstreamClaimName]
		if !ok {
			plog.Warning(
				"additionalClaims mapping claim in upstream ID token missing",
				"upstreamName", upstreamIDPConfig.GetName(),
				"claimName", upstreamClaimName,
			)
		} else {
			mapped[downstreamClaimName] = upstreamClaimValue
		}
	}
	return mapped
}

func getSubjectAndUsernameFromUpstreamIDToken(
	upstreamIDPConfig upstreamprovider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
	idpDisplayName string,
) (string, string, error) {
	// The spec says the "sub" claim is only unique per issuer,
	// so we will prepend the issuer string to make it globally unique.
	upstreamIssuer, err := extractStringClaimValue(oidc.IDTokenClaimIssuer, upstreamIDPConfig.GetName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}
	upstreamSubject, err := extractStringClaimValue(oidc.IDTokenClaimSubject, upstreamIDPConfig.GetName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}
	subject := downstreamsubject.OIDC(upstreamIssuer, upstreamSubject, idpDisplayName)

	usernameClaimName := upstreamIDPConfig.GetUsernameClaim()
	if usernameClaimName == "" {
		return subject, downstreamUsernameFromUpstreamOIDCSubject(upstreamIssuer, upstreamSubject), nil
	}

	// If the upstream username claim is configured to be the special "email" claim and the upstream "email_verified"
	// claim is present, then validate that the "email_verified" claim is true.
	emailVerifiedAsInterface, ok := idTokenClaims[emailVerifiedClaimName]
	if usernameClaimName == emailClaimName && ok {
		emailVerified, ok := emailVerifiedAsInterface.(bool)
		if !ok {
			plog.Warning(
				"username claim configured as \"email\" and upstream email_verified claim is not a boolean",
				"upstreamName", upstreamIDPConfig.GetName(),
				"configuredUsernameClaim", usernameClaimName,
				"emailVerifiedClaim", emailVerifiedAsInterface,
			)
			return "", "", emailVerifiedClaimInvalidFormatErr
		}
		if !emailVerified {
			plog.Warning(
				"username claim configured as \"email\" and upstream email_verified claim has false value",
				"upstreamName", upstreamIDPConfig.GetName(),
				"configuredUsernameClaim", usernameClaimName,
			)
			return "", "", emailVerifiedClaimFalseErr
		}
	}

	username, err := extractStringClaimValue(usernameClaimName, upstreamIDPConfig.GetName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}

	return subject, username, nil
}

func extractStringClaimValue(claimName string, upstreamIDPName string, idTokenClaims map[string]interface{}) (string, error) {
	value, ok := idTokenClaims[claimName]
	if !ok {
		plog.Warning(
			"required claim in upstream ID token missing",
			"upstreamName", upstreamIDPName,
			"claimName", claimName,
		)
		return "", requiredClaimMissingErr
	}

	valueAsString, ok := value.(string)
	if !ok {
		plog.Warning(
			"required claim in upstream ID token is not a string value",
			"upstreamName", upstreamIDPName,
			"claimName", claimName,
		)
		return "", requiredClaimInvalidFormatErr
	}

	if valueAsString == "" {
		plog.Warning(
			"required claim in upstream ID token has an empty string value",
			"upstreamName", upstreamIDPName,
			"claimName", claimName,
		)
		return "", requiredClaimEmptyErr
	}

	return valueAsString, nil
}

func downstreamUsernameFromUpstreamOIDCSubject(upstreamIssuerAsString string, upstreamSubject string) string {
	return fmt.Sprintf("%s?%s=%s", upstreamIssuerAsString,
		oidc.IDTokenClaimSubject, url.QueryEscape(upstreamSubject),
	)
}

// GetGroupsFromUpstreamIDToken returns mapped group names coerced into a slice of strings.
// It returns nil when there is no configured groups claim name, or then when the configured claim name is not found
// in the provided map of claims. It returns an error when the claim exists but its value cannot be parsed.
func GetGroupsFromUpstreamIDToken(
	upstreamIDPConfig upstreamprovider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
) ([]string, error) {
	groupsClaimName := upstreamIDPConfig.GetGroupsClaim()
	if groupsClaimName == "" {
		return nil, nil
	}

	groupsAsInterface, ok := idTokenClaims[groupsClaimName]
	if !ok {
		plog.Warning(
			"no groups claim in upstream ID token",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredGroupsClaim", groupsClaimName,
		)
		return nil, nil // the upstream IDP may have omitted the claim if the user has no groups
	}

	groupsAsArray, okAsArray := extractGroups(groupsAsInterface)
	if !okAsArray {
		plog.Warning(
			"groups claim in upstream ID token has invalid format",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredGroupsClaim", groupsClaimName,
		)
		return nil, requiredClaimInvalidFormatErr
	}

	return groupsAsArray, nil
}

func extractGroups(groupsAsInterface interface{}) ([]string, bool) {
	groupsAsString, okAsString := groupsAsInterface.(string)
	if okAsString {
		return []string{groupsAsString}, true
	}

	groupsAsStringArray, okAsStringArray := groupsAsInterface.([]string)
	if okAsStringArray {
		return groupsAsStringArray, true
	}

	groupsAsInterfaceArray, okAsArray := groupsAsInterface.([]interface{})
	if !okAsArray {
		return nil, false
	}

	var groupsAsStrings []string
	for _, groupAsInterface := range groupsAsInterfaceArray {
		groupAsString, okAsString := groupAsInterface.(string)
		if !okAsString {
			return nil, false
		}
		if groupAsString != "" {
			groupsAsStrings = append(groupsAsStrings, groupAsString)
		}
	}

	return groupsAsStrings, true
}
