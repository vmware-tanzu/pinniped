// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorstorage

import (
	"context"
	"errors"
	"fmt"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/strings/slices"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage/accesstoken"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/openidconnect"
	"go.pinniped.dev/internal/fositestorage/pkce"
	"go.pinniped.dev/internal/fositestorage/refreshtoken"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
)

const minimumRepeatInterval = 30 * time.Second

type garbageCollectorController struct {
	idpCache              UpstreamOIDCIdentityProviderICache
	secretInformer        corev1informers.SecretInformer
	kubeClient            kubernetes.Interface
	clock                 clock.Clock
	timeOfMostRecentSweep time.Time
}

// UpstreamOIDCIdentityProviderICache is a thread safe cache that holds a list of validated upstream OIDC IDP configurations.
type UpstreamOIDCIdentityProviderICache interface {
	GetOIDCIdentityProviders() []provider.UpstreamOIDCIdentityProviderI
}

func GarbageCollectorController(
	idpCache UpstreamOIDCIdentityProviderICache,
	clock clock.Clock,
	kubeClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	isSecretWithGCAnnotation := func(obj metav1.Object) bool {
		secret, ok := obj.(*v1.Secret)
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
			},
		},
		withInformer(
			secretInformer,
			controllerlib.FilterFuncs{
				AddFunc: isSecretWithGCAnnotation,
				UpdateFunc: func(oldObj, newObj metav1.Object) bool {
					return isSecretWithGCAnnotation(oldObj) || isSecretWithGCAnnotation(newObj)
				},
				DeleteFunc: func(obj metav1.Object) bool { return false }, // ignore all deletes
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
			continue
		}

		garbageCollectAfterTime, err := time.Parse(crud.SecretLifetimeAnnotationDateFormat, timeString)
		if err != nil {
			plog.WarningErr("could not parse resource timestamp for garbage collection", err, logKV(secret)...)
			continue
		}

		if !garbageCollectAfterTime.Before(frozenClock.Now()) {
			// not old enough yet
			continue
		}

		storageType, isSessionStorage := secret.Labels[crud.SecretLabelKey]
		if isSessionStorage {
			err := c.maybeRevokeUpstreamOIDCRefreshToken(ctx.Context, storageType, secret)
			if err != nil {
				plog.WarningErr("garbage collector could not revoke upstream refresh token", err, logKV(secret)...)
				// If the error is of a type that is worth retrying, then do not delete the Secret right away.
				// A future call to Sync will try revocation again for that secret. However, if the Secret is
				// getting too old, then just delete it anyway. We don't want to extend the lifetime of these
				// session Secrets by too much time, since the garbage collector is the only thing that is
				// cleaning them out of etcd storage.
				fourHoursAgo := frozenClock.Now().Add(-4 * time.Hour)
				nowIsLessThanFourHoursBeyondSecretGCTime := garbageCollectAfterTime.After(fourHoursAgo)
				if errors.As(err, &retryableRevocationError{}) && nowIsLessThanFourHoursBeyondSecretGCTime {
					// Hasn't been very long since secret expired, so skip deletion to try revocation again later.
					continue
				}
			}
		}

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
		plog.Info("storage garbage collector deleted resource", logKV(secret)...)
	}

	return nil
}

func (c *garbageCollectorController) maybeRevokeUpstreamOIDCRefreshToken(ctx context.Context, storageType string, secret *v1.Secret) error {
	// All session storage types hold upstream refresh tokens when the upstream IDP is an OIDC provider.
	// However, some of them will be outdated because they are not updated by fosite after creation.
	// Our goal below is to always revoke the latest upstream refresh token that we are holding for the
	// session, and only the latest.
	switch storageType {
	case authorizationcode.TypeLabelValue:
		authorizeCodeSession, err := authorizationcode.ReadFromSecret(secret)
		if err != nil {
			return err
		}
		// Check if this downstream authcode was already used. If it was already used (i.e. not active anymore), then
		// the latest upstream refresh token can be found in one of the other storage types handled below instead.
		if !authorizeCodeSession.Active {
			return nil
		}
		// When the downstream authcode was never used, then its storage must contain the latest upstream refresh token.
		return c.revokeUpstreamOIDCRefreshToken(ctx, authorizeCodeSession.Request.Session.(*psession.PinnipedSession).Custom, secret)

	case accesstoken.TypeLabelValue:
		// For access token storage, check if the "offline_access" scope was granted on the downstream session.
		// If it was granted, then the latest upstream refresh token should be found in the refresh token storage instead.
		// If it was not granted, then the user could not possibly have performed a downstream refresh, so the
		// access token storage has the latest version of the upstream refresh token.
		accessTokenSession, err := accesstoken.ReadFromSecret(secret)
		if err != nil {
			return err
		}
		pinnipedSession := accessTokenSession.Request.Session.(*psession.PinnipedSession)
		if slices.Contains(accessTokenSession.Request.GetGrantedScopes(), coreosoidc.ScopeOfflineAccess) {
			return nil
		}
		return c.revokeUpstreamOIDCRefreshToken(ctx, pinnipedSession.Custom, secret)

	case refreshtoken.TypeLabelValue:
		// For refresh token storage, always revoke its upstream refresh token. This refresh token storage could
		// be the result of the initial downstream authcode exchange, or it could be the result of a downstream
		// refresh. Either way, it always contains the latest upstream refresh token when it exists.
		refreshTokenSession, err := refreshtoken.ReadFromSecret(secret)
		if err != nil {
			return err
		}
		return c.revokeUpstreamOIDCRefreshToken(ctx, refreshTokenSession.Request.Session.(*psession.PinnipedSession).Custom, secret)

	case pkce.TypeLabelValue:
		// For PKCE storage, its very existence means that the authcode was never exchanged, because these
		// are deleted during authcode exchange. No need to do anything, since the upstream refresh token
		// revocation is handled by authcode storage case above.
		return nil

	case openidconnect.TypeLabelValue:
		// For OIDC storage, there is no need to do anything for reasons similar to the PKCE storage.
		// These are not deleted during authcode exchange, probably due to a bug in fosite, even though it
		// will never be read or updated again. However, the refresh token contained inside will be revoked
		// by one of the other cases above.
		return nil

	default:
		// There are no other storage types, so this should never happen in practice.
		return errors.New("garbage collector saw invalid label on Secret when trying to determine if upstream revocation was needed")
	}
}

func (c *garbageCollectorController) revokeUpstreamOIDCRefreshToken(ctx context.Context, customSessionData *psession.CustomSessionData, secret *v1.Secret) error {
	// When session was for another upstream IDP type, e.g. LDAP, there is no upstream OIDC refresh token involved.
	if customSessionData.ProviderType != psession.ProviderTypeOIDC {
		return nil
	}

	// Try to find the provider that was originally used to create the stored session.
	var foundOIDCIdentityProviderI provider.UpstreamOIDCIdentityProviderI
	for _, p := range c.idpCache.GetOIDCIdentityProviders() {
		if p.GetName() == customSessionData.ProviderName && p.GetResourceUID() == customSessionData.ProviderUID {
			foundOIDCIdentityProviderI = p
			break
		}
	}
	if foundOIDCIdentityProviderI == nil {
		return fmt.Errorf("could not find upstream OIDC provider named %q with resource UID %q", customSessionData.ProviderName, customSessionData.ProviderUID)
	}

	// Revoke the upstream refresh token. This is a noop if the upstream provider does not offer a revocation endpoint.
	err := foundOIDCIdentityProviderI.RevokeRefreshToken(ctx, customSessionData.OIDC.UpstreamRefreshToken)
	if err != nil {
		// This could be a network failure, a 503 result which we should retry
		// (see https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1),
		// or any other non-200 response from the revocation endpoint.
		// Regardless of which, it is probably worth retrying.
		return retryableRevocationError{wrapped: err}
	}

	plog.Trace("garbage collector successfully revoked upstream OIDC refresh token (or provider has no revocation endpoint)", logKV(secret)...)
	return nil
}

type retryableRevocationError struct {
	wrapped error
}

func (e retryableRevocationError) Error() string {
	return fmt.Sprintf("retryable revocation error: %v", e.wrapped)
}

func (e retryableRevocationError) Unwrap() error {
	return e.wrapped
}

func logKV(secret *v1.Secret) []interface{} {
	return []interface{}{
		"secretName", secret.Name,
		"secretNamespace", secret.Namespace,
		"secretType", string(secret.Type),
		"garbageCollectAfter", secret.Annotations[crud.SecretLifetimeAnnotationKey],
		"storageTypeLabelValue", secret.Labels[crud.SecretLabelKey],
	}
}
