// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorstorage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ory/fosite"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/federationdomain/dynamicupstreamprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/fositestorage/accesstoken"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/openidconnect"
	"go.pinniped.dev/internal/fositestorage/pkce"
	"go.pinniped.dev/internal/fositestorage/refreshtoken"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
)

const minimumRepeatInterval = 30 * time.Second

type garbageCollectorController struct {
	idpCache       UpstreamOIDCIdentityProviderICache
	secretInformer corev1informers.SecretInformer
	kubeClient     kubernetes.Interface
	clock          clock.Clock
	auditLogger    plog.AuditLogger

	timeOfMostRecentSweep time.Time
}

// UpstreamOIDCIdentityProviderICache is a thread safe cache that holds a list of validated upstream OIDC IDP configurations.
type UpstreamOIDCIdentityProviderICache interface {
	GetOIDCIdentityProviders() []upstreamprovider.UpstreamOIDCIdentityProviderI
}

func GarbageCollectorController(
	idpCache UpstreamOIDCIdentityProviderICache,
	clock clock.Clock,
	kubeClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	auditLogger plog.AuditLogger,
) controllerlib.Controller {
	isSecretWithGCAnnotation := func(obj metav1.Object) bool {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return false
		}
		_, ok = secret.Annotations[crud.SecretLifetimeAnnotationKey]
		return ok
	}
	return controllerlib.New(
		controllerlib.Config{
			Name: "garbage-collector-controller",
			Syncer: &garbageCollectorController{
				idpCache:       idpCache,
				secretInformer: secretInformer,
				kubeClient:     kubeClient,
				clock:          clock,
				auditLogger:    auditLogger,
			},
		},
		withInformer(
			secretInformer,
			controllerlib.FilterFuncs{
				AddFunc: isSecretWithGCAnnotation,
				UpdateFunc: func(oldObj, newObj metav1.Object) bool {
					return isSecretWithGCAnnotation(oldObj) || isSecretWithGCAnnotation(newObj)
				},
				DeleteFunc: func(_ metav1.Object) bool { return false }, // ignore all deletes
				ParentFunc: pinnipedcontroller.SingletonQueue(),
			},
			controllerlib.InformerOption{},
		),
	)
}

func (c *garbageCollectorController) Sync(ctx controllerlib.Context) error {
	// make sure we have a consistent, static meaning for the current time during the sync loop
	frozenClock := clocktesting.NewFakeClock(c.clock.Now())

	// The Sync method is triggered upon any change to any Secret, which would make this
	// controller too chatty, so it rate limits itself to a more reasonable interval.
	// Note that even during a period when no secrets are changing, it will still run
	// at the informer's full-resync interval (as long as there are some secrets).
	if since := frozenClock.Since(c.timeOfMostRecentSweep); since < minimumRepeatInterval {
		ctx.Queue.AddAfter(ctx.Key, minimumRepeatInterval-since)
		return nil
	}

	plog.Info("starting storage garbage collection sweep")
	c.timeOfMostRecentSweep = frozenClock.Now()

	listOfSecrets, err := c.secretInformer.Lister().List(labels.Everything())
	if err != nil {
		return err
	}

	for i := range listOfSecrets {
		secret := listOfSecrets[i]

		timeString, ok := secret.Annotations[crud.SecretLifetimeAnnotationKey]
		if !ok {
			// Secret did not request garbage collection via annotations, so skip deletion.
			continue
		}

		garbageCollectAfterTime, err := time.Parse(crud.SecretLifetimeAnnotationDateFormat, timeString)
		if err != nil {
			plog.WarningErr("could not parse resource timestamp for garbage collection", err, logKV(secret)...)
			// Can't tell if the Secret has expired or not, so skip deletion.
			continue
		}

		if !garbageCollectAfterTime.Before(frozenClock.Now()) {
			// Secret is not old enough yet, so skip deletion.
			continue
		}

		// The Secret has expired. Check if it is a downstream session storage Secret, which may require extra processing.
		storageType, isSessionStorage := secret.Labels[crud.SecretLabelKey]
		if isSessionStorage {
			revokeErr := c.maybeRevokeUpstreamOIDCToken(ctx.Context, storageType, secret)
			if revokeErr != nil {
				plog.WarningErr("garbage collector could not revoke upstream OIDC token", revokeErr, logKV(secret)...)
				// Note that RevokeToken (called by the private helper) might have returned an error of type
				// provider.RetryableRevocationError, in which case we would like to retry the revocation later.
				// If the error is of a type that is worth retrying, then do not delete the Secret right away.
				// A future call to Sync will try revocation again for that secret. However, if the Secret is
				// getting too old, then just delete it anyway. We don't want to extend the lifetime of these
				// session Secrets by too much time, since the garbage collector is the only thing that is
				// cleaning them out of etcd storage.
				fourHoursAgo := frozenClock.Now().Add(-4 * time.Hour)
				nowIsLessThanFourHoursBeyondSecretGCTime := garbageCollectAfterTime.After(fourHoursAgo)
				if errors.As(revokeErr, &dynamicupstreamprovider.RetryableRevocationError{}) && nowIsLessThanFourHoursBeyondSecretGCTime {
					// Hasn't been very long since secret expired, so skip deletion to try revocation again later.
					plog.Trace("garbage collector keeping Secret to retry upstream OIDC token revocation later", logKV(secret)...)
					continue
				}
			}
		}

		// Garbage collect the Secret.
		err = c.kubeClient.CoreV1().Secrets(secret.Namespace).Delete(ctx.Context, secret.Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{
				UID:             &secret.UID,
				ResourceVersion: &secret.ResourceVersion,
			},
		})
		if err != nil {
			plog.WarningErr("failed to garbage collect resource", err, logKV(secret)...)
			continue
		}
		c.maybeAuditLogGC(storageType, secret)
		plog.Info("storage garbage collector deleted resource", logKV(secret)...)
	}

	return nil
}

func (c *garbageCollectorController) maybeRevokeUpstreamOIDCToken(ctx context.Context, storageType string, secret *corev1.Secret) error {
	// All downstream session storage types hold upstream tokens when the upstream IDP is an OIDC provider.
	// However, some of them will be outdated because they are not updated by fosite after creation.
	// Our goal below is to always revoke the latest upstream refresh token that we are holding for the
	// session, and only the latest, or to revoke the original upstream access token. Note that we don't
	// bother to store new upstream access tokens seen during upstream refresh because we only need to store
	// the upstream access token when we intend to use it *instead* of an upstream refresh token.
	// This implies that all the storage types will contain a copy of the original upstream access token,
	// since it is never updated in the session. Thus, we can use the same logic to decide which upstream
	// access token to revoke as we use for upstream refresh tokens, which allows us to avoid revoking an
	// upstream access token more than once.
	switch storageType {
	case authorizationcode.TypeLabelValue:
		authorizeCodeSession, err := authorizationcode.ReadFromSecret(secret)
		if err != nil {
			return err
		}
		// Check if this downstream authcode was already used. If it was already used (i.e. not active anymore),
		// then the latest upstream token can be found in one of the other storage types handled below instead.
		if !authorizeCodeSession.Active {
			return nil
		}
		// When the downstream authcode was never used, then its storage must contain the latest upstream token.
		return c.tryRevokeUpstreamOIDCToken(ctx,
			authorizeCodeSession.Request.Session.(*psession.PinnipedSession).Custom,
			authorizeCodeSession.Request,
			secret)

	case accesstoken.TypeLabelValue:
		// For access token storage, check if the "offline_access" scope was granted on the downstream session.
		// If it was granted, then the latest upstream token should be found in the refresh token storage instead.
		// If it was not granted, then the user could not possibly have performed a downstream refresh, so the
		// access token storage has the latest version of the upstream token.
		accessTokenSession, err := accesstoken.ReadFromSecret(secret)
		if err != nil {
			return err
		}
		if accessTokenSession.Request.GetGrantedScopes().Has(oidcapi.ScopeOfflineAccess) {
			return nil
		}
		return c.tryRevokeUpstreamOIDCToken(ctx,
			accessTokenSession.Request.Session.(*psession.PinnipedSession).Custom,
			accessTokenSession.Request,
			secret)

	case refreshtoken.TypeLabelValue:
		// For refresh token storage, always revoke its upstream token. This refresh token storage could be
		// the result of the initial downstream authcode exchange, or it could be the result of a downstream
		// refresh. Either way, it always contains the latest upstream token when it exists.
		refreshTokenSession, err := refreshtoken.ReadFromSecret(secret)
		if err != nil {
			return err
		}
		return c.tryRevokeUpstreamOIDCToken(ctx,
			refreshTokenSession.Request.Session.(*psession.PinnipedSession).Custom,
			refreshTokenSession.Request,
			secret)

	case pkce.TypeLabelValue:
		// For PKCE storage, its very existence means that the downstream authcode was never exchanged, because
		// these are deleted during downstream authcode exchange. No need to do anything, since the upstream
		// token revocation is handled by authcode storage case above.
		return nil

	case openidconnect.TypeLabelValue:
		// For OIDC storage, there is no need to do anything for reasons similar to the PKCE storage.
		// These are deleted during downstream authcode exchange. The upstream token contained inside will
		// be revoked by one of the other cases above.
		return nil

	default:
		// There are no other storage types, so this should never happen in practice.
		return errors.New("garbage collector saw invalid label on Secret when trying to determine if upstream revocation was needed")
	}
}

func (c *garbageCollectorController) tryRevokeUpstreamOIDCToken(
	ctx context.Context,
	customSessionData *psession.CustomSessionData,
	request *fosite.Request,
	secret *corev1.Secret,
) error {
	// When session was for another upstream IDP type, e.g. LDAP, there is no upstream OIDC token involved.
	if customSessionData.ProviderType != psession.ProviderTypeOIDC {
		return nil
	}

	// Try to find the provider that was originally used to create the stored session.
	var foundOIDCIdentityProviderI upstreamprovider.UpstreamOIDCIdentityProviderI
	for _, p := range c.idpCache.GetOIDCIdentityProviders() {
		if p.GetResourceName() == customSessionData.ProviderName && p.GetResourceUID() == customSessionData.ProviderUID {
			foundOIDCIdentityProviderI = p
			break
		}
	}
	if foundOIDCIdentityProviderI == nil {
		return fmt.Errorf("could not find upstream OIDC provider named %q with resource UID %q", customSessionData.ProviderName, customSessionData.ProviderUID)
	}

	// In practice, there should only be one of these tokens saved in the session.
	upstreamRefreshToken := customSessionData.OIDC.UpstreamRefreshToken
	upstreamAccessToken := customSessionData.OIDC.UpstreamAccessToken

	if upstreamRefreshToken != "" {
		err := foundOIDCIdentityProviderI.RevokeToken(ctx, upstreamRefreshToken, upstreamprovider.RefreshTokenType)
		if err != nil {
			return err
		}
		c.auditLogger.Audit(plog.AuditEventUpstreamOIDCTokenRevoked, nil, request,
			"type", upstreamprovider.RefreshTokenType)
		plog.Trace("garbage collector successfully revoked upstream OIDC refresh token (or provider has no revocation endpoint)", logKV(secret)...)
	}

	if upstreamAccessToken != "" {
		err := foundOIDCIdentityProviderI.RevokeToken(ctx, upstreamAccessToken, upstreamprovider.AccessTokenType)
		if err != nil {
			return err
		}
		c.auditLogger.Audit(plog.AuditEventUpstreamOIDCTokenRevoked, nil, request,
			"type", upstreamprovider.AccessTokenType)
		plog.Trace("garbage collector successfully revoked upstream OIDC access token (or provider has no revocation endpoint)", logKV(secret)...)
	}

	return nil
}

func (c *garbageCollectorController) maybeAuditLogGC(storageType string, secret *corev1.Secret) {
	r, err := c.requestFromSecret(storageType, secret)
	if err == nil && r != nil {
		c.auditLogger.Audit(plog.AuditEventSessionGarbageCollected, nil, r, "storageType", storageType)
	}
}

func (c *garbageCollectorController) requestFromSecret(storageType string, secret *corev1.Secret) (*fosite.Request, error) {
	switch storageType {
	case authorizationcode.TypeLabelValue:
		authorizeCodeSession, err := authorizationcode.ReadFromSecret(secret)
		if err != nil {
			return nil, err
		}
		return authorizeCodeSession.Request, nil

	case accesstoken.TypeLabelValue:
		accessTokenSession, err := accesstoken.ReadFromSecret(secret)
		if err != nil {
			return nil, err
		}
		return accessTokenSession.Request, nil

	case refreshtoken.TypeLabelValue:
		refreshTokenSession, err := refreshtoken.ReadFromSecret(secret)
		if err != nil {
			return nil, err
		}
		return refreshTokenSession.Request, nil

	case pkce.TypeLabelValue:
		return nil, nil // if this still exists, then it means that the user never exchanged their authcode

	case openidconnect.TypeLabelValue:
		return nil, nil // if this still exists, then it means that the user never exchanged their authcode

	default:
		// There are no other storage types, so this should never happen in practice.
		return nil, errors.New("garbage collector saw invalid label on Secret when trying to determine session ID")
	}
}

func logKV(secret *corev1.Secret) []any {
	return []any{
		"secretName", secret.Name,
		"secretNamespace", secret.Namespace,
		"secretType", string(secret.Type),
		"garbageCollectAfter", secret.Annotations[crud.SecretLifetimeAnnotationKey],
		"storageTypeLabelValue", secret.Labels[crud.SecretLabelKey],
	}
}
