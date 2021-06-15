// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	fositepkce "github.com/ory/fosite/handler/pkce"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/fositestorage/accesstoken"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/openidconnect"
	"go.pinniped.dev/internal/fositestorage/pkce"
	"go.pinniped.dev/internal/fositestorage/refreshtoken"
	"go.pinniped.dev/internal/fositestoragei"
	"go.pinniped.dev/internal/oidc/staticclient"
)

const errKubeStorageNotImplemented = constable.Error("KubeStorage does not implement this method. It should not have been called.")

type KubeStorage struct {
	authorizationCodeStorage oauth2.AuthorizeCodeStorage
	pkceStorage              fositepkce.PKCERequestStorage
	oidcStorage              openid.OpenIDConnectRequestStorage
	accessTokenStorage       accesstoken.RevocationStorage
	refreshTokenStorage      refreshtoken.RevocationStorage
}

var _ fositestoragei.AllFositeStorage = &KubeStorage{}

func NewKubeStorage(secrets corev1client.SecretInterface, timeoutsConfiguration TimeoutsConfiguration) *KubeStorage {
	nowFunc := time.Now
	return &KubeStorage{
		authorizationCodeStorage: authorizationcode.New(secrets, nowFunc, timeoutsConfiguration.AuthorizationCodeSessionStorageLifetime),
		pkceStorage:              pkce.New(secrets, nowFunc, timeoutsConfiguration.PKCESessionStorageLifetime),
		oidcStorage:              openidconnect.New(secrets, nowFunc, timeoutsConfiguration.OIDCSessionStorageLifetime),
		accessTokenStorage:       accesstoken.New(secrets, nowFunc, timeoutsConfiguration.AccessTokenSessionStorageLifetime),
		refreshTokenStorage:      refreshtoken.New(secrets, nowFunc, timeoutsConfiguration.RefreshTokenSessionStorageLifetime),
	}
}

//
// Authorization Code sessions:
//
// These are keyed by the signature of the authcode.
//
// Fosite will create these in the authorize endpoint.
//
// Fosite will never delete them. Instead, it wants to mark them as invalidated once the authcode is used to redeem tokens.
// That way, it can later detect the case where an authcode that was already redeemed gets used again.
//

func (k KubeStorage) CreateAuthorizeCodeSession(ctx context.Context, signatureOfAuthcode string, r fosite.Requester) (err error) {
	return k.authorizationCodeStorage.CreateAuthorizeCodeSession(ctx, signatureOfAuthcode, r)
}

func (k KubeStorage) GetAuthorizeCodeSession(ctx context.Context, signatureOfAuthcode string, s fosite.Session) (request fosite.Requester, err error) {
	return k.authorizationCodeStorage.GetAuthorizeCodeSession(ctx, signatureOfAuthcode, s)
}

func (k KubeStorage) InvalidateAuthorizeCodeSession(ctx context.Context, signatureOfAuthcode string) (err error) {
	return k.authorizationCodeStorage.InvalidateAuthorizeCodeSession(ctx, signatureOfAuthcode)
}

//
// PKCE sessions:
//
// These are keyed by the signature of the authcode.
//
// Fosite will create these in the authorize endpoint at the same time that it is creating an authcode.
//
// Fosite will delete these in the token endpoint during authcode redemption since they are no longer needed after that.
// If the user chooses to never redeem their authcode, then fosite will never delete these.
//

func (k KubeStorage) CreatePKCERequestSession(ctx context.Context, signatureOfAuthcode string, requester fosite.Requester) error {
	return k.pkceStorage.CreatePKCERequestSession(ctx, signatureOfAuthcode, requester)
}

func (k KubeStorage) GetPKCERequestSession(ctx context.Context, signatureOfAuthcode string, session fosite.Session) (fosite.Requester, error) {
	return k.pkceStorage.GetPKCERequestSession(ctx, signatureOfAuthcode, session)
}

func (k KubeStorage) DeletePKCERequestSession(ctx context.Context, signatureOfAuthcode string) error {
	return k.pkceStorage.DeletePKCERequestSession(ctx, signatureOfAuthcode)
}

//
// OpenID Connect sessions:
//
// These are keyed by the full value of the authcode (not just the signature).
//
// Fosite will create these in the authorize endpoint when it creates an authcode, but only if the user
// requested the openid scope.
//
// Fosite will never delete these, which is likely a bug in fosite. Although there is a delete method below, fosite
// never calls it. Used during authcode redemption, they will never be accessed again after a successful authcode
// redemption. Although that implies that they should probably follow a lifecycle similar the the PKCE storage, they
// are, in fact, not deleted.
//

func (k KubeStorage) CreateOpenIDConnectSession(ctx context.Context, fullAuthcode string, requester fosite.Requester) error {
	return k.oidcStorage.CreateOpenIDConnectSession(ctx, fullAuthcode, requester)
}

func (k KubeStorage) GetOpenIDConnectSession(ctx context.Context, fullAuthcode string, requester fosite.Requester) (fosite.Requester, error) {
	return k.oidcStorage.GetOpenIDConnectSession(ctx, fullAuthcode, requester)
}

func (k KubeStorage) DeleteOpenIDConnectSession(ctx context.Context, fullAuthcode string) error {
	return k.oidcStorage.DeleteOpenIDConnectSession(ctx, fullAuthcode)
}

//
// Access token sessions:
//
// These are keyed by the signature of the access token.
//
// Fosite will create these in the token endpoint whenever it wants to hand out an access token, including the original
// authcode redemption and also during refresh.
//
// Fosite will not use the delete method. Instead, it will use the revoke method to delete them.
// During a refresh in the token endpoint, the old access token is revoked just before the new access token is created.
// Also, if the token endpoint receives an authcode that was already used successfully, then it revokes the access token
// that was previously handed out for that authcode. If a user stops coming back to refresh their tokens, then that
// access token will never be deleted.
//

func (k KubeStorage) CreateAccessTokenSession(ctx context.Context, signatureOfAccessToken string, requester fosite.Requester) (err error) {
	return k.accessTokenStorage.CreateAccessTokenSession(ctx, signatureOfAccessToken, requester)
}

func (k KubeStorage) GetAccessTokenSession(ctx context.Context, signatureOfAccessToken string, session fosite.Session) (request fosite.Requester, err error) {
	return k.accessTokenStorage.GetAccessTokenSession(ctx, signatureOfAccessToken, session)
}

func (k KubeStorage) DeleteAccessTokenSession(ctx context.Context, signatureOfAccessToken string) (err error) {
	return k.accessTokenStorage.DeleteAccessTokenSession(ctx, signatureOfAccessToken)
}

func (k KubeStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return k.accessTokenStorage.RevokeAccessToken(ctx, requestID)
}

//
// Refresh token sessions:
//
// These are keyed by the signature of the refresh token.
//
// Fosite will create these in the token endpoint whenever it wants to hand out an refresh token, including the original
// authcode redemption and also during refresh. Refresh tokens are only handed out when the user requested the
// offline_access scope on the original authorization request.
//
// Fosite will not use the delete method. Instead, it will use the revoke method to delete them.
// During a refresh in the token endpoint, the old refresh token is revoked just before the new refresh token is created.
// Also, if the token endpoint receives an authcode that was already used successfully, then it revokes the refresh token
// that was previously handed out for that authcode. If a user stops coming back to refresh their tokens, then that
// refresh token will never be deleted.
//

func (k KubeStorage) CreateRefreshTokenSession(ctx context.Context, signatureOfRefreshToken string, request fosite.Requester) (err error) {
	return k.refreshTokenStorage.CreateRefreshTokenSession(ctx, signatureOfRefreshToken, request)
}

func (k KubeStorage) GetRefreshTokenSession(ctx context.Context, signatureOfRefreshToken string, session fosite.Session) (request fosite.Requester, err error) {
	return k.refreshTokenStorage.GetRefreshTokenSession(ctx, signatureOfRefreshToken, session)
}

func (k KubeStorage) DeleteRefreshTokenSession(ctx context.Context, signatureOfRefreshToken string) (err error) {
	return k.refreshTokenStorage.DeleteRefreshTokenSession(ctx, signatureOfRefreshToken)
}

func (k KubeStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return k.refreshTokenStorage.RevokeRefreshToken(ctx, requestID)
}

//
// OAuth client definitions:
//
// For the time being, we only allow a single pre-defined client, so we do not need to interact with any underlying
// storage mechanism to fetch them.
//

func (KubeStorage) GetClient(_ context.Context, id string) (fosite.Client, error) {
	return staticclient.Get(id)
}

//
// Unused interface methods.
//

func (KubeStorage) ClientAssertionJWTValid(_ context.Context, _ string) error {
	return errKubeStorageNotImplemented
}

func (KubeStorage) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error {
	return errKubeStorageNotImplemented
}
