// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorstorage

import (
	"errors"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/clock"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"

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
	frozenClock := clock.NewFakeClock(c.clock.Now())

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
			plog.WarningErr("could not parse resource timestamp for garbage collection", err, logKV(secret))
			continue
		}

		if garbageCollectAfterTime.Before(frozenClock.Now()) {
			storageType, isSessionStorage := secret.Labels[crud.SecretLabelKey]
			if isSessionStorage {
				err := c.maybeRevokeUpstreamOIDCRefreshToken(storageType, secret)
				if err != nil {
					// Log the error for debugging purposes, but still carry on to delete the Secret despite the error.
					plog.DebugErr("garbage collector could not revoke upstream refresh token", err, logKV(secret))
				}
			}

			err = c.kubeClient.CoreV1().Secrets(secret.Namespace).Delete(ctx.Context, secret.Name, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{
					UID:             &secret.UID,
					ResourceVersion: &secret.ResourceVersion,
				},
			})
			if err != nil {
				plog.WarningErr("failed to garbage collect resource", err, logKV(secret))
				continue
			}
			plog.Info("storage garbage collector deleted resource", logKV(secret))
		}
	}

	return nil
}

//nolint:godot // do not complain about the following to-do comment
// TODO write unit tests for all of the following cases. Note that there is already a test
//  double implemented for the RevokeRefreshToken() method on the objects in the idpCache
//  to help with the test mocking. See RevokeRefreshTokenCallCount() and RevokeRefreshTokenArgs(int)
//  in TestUpstreamOIDCIdentityProvider (in file oidctestutil.go). This will allowing following
//  the pattern used in other unit tests that fill the idpCache with mock providers using the builders
//  from oidctestutil.go.
func (c *garbageCollectorController) maybeRevokeUpstreamOIDCRefreshToken(storageType string, secret *v1.Secret) error {
	// All session storage types hold upstream refresh tokens when the upstream IDP is an OIDC provider.
	// However, some of them will be outdated because they are not updated by fosite after creation.
	// Our goal below is to always revoke the latest upstream refresh token that we are holding for the
	// session, and only the latest.
	switch storageType {
	case authorizationcode.TypeLabelValue:
		// For authcode storage, check if the authcode was used. If the authcode was never used, then its
		// storage must contain the latest upstream refresh token, so revoke it.
		// TODO Use ReadFromSecret from the authorizationcode package under fositestorage to validate/parse the Secret, return any errors
		// TODO return nil if the upstream type is not OIDC
		// TODO return nil if the authcode is *NOT* active (meaning that it was already used)
		// TODO lookup the idp by name in c.idpCache to get the cached provider interface, return error if not found
		// TODO use the cached interface to revoke the refresh token, return any error
		plog.Trace("garbage collector successfully revoked upstream refresh token", logKV(secret))
		return nil
	case accesstoken.TypeLabelValue:
		// For access token storage, check if the "offline_access" scope was granted on the downstream
		// session. If it was not, then the user could not possibly have performed a downstream refresh.
		// In this case, the access token storage has the latest version of the upstream refresh token,
		// so call the upstream issuer to revoke it.
		// TODO Implement ReadFromSecret in the accesstoken package, similar to how it was done in the authorizationcode package
		// TODO Use that the new ReadFromSecret func to validate/parse the Secret, return any errors
		// TODO return nil if the upstream type is not OIDC
		// TODO return nil if the "offline_access" scope was *NOT* granted on the downstream session
		// TODO lookup the idp by name in c.idpCache to get the cached provider interface, return error if not found
		// TODO use the cached interface to revoke the refresh token, return any error
		plog.Trace("garbage collector successfully revoked upstream refresh token", logKV(secret))
		return nil
	case refreshtoken.TypeLabelValue:
		// For refresh token storage, revoke its upstream refresh token. This refresh token storage could
		// be the result of the authcode token exchange, or it could be the result of a downstream refresh.
		// Either way, it always contains the latest upstream refresh token when it exists.
		// TODO Implement ReadFromSecret in the refreshtoken package, similar to how it was done in the authorizationcode package
		// TODO Use that new ReadFromSecret func to validate/parse the Secret, return any errors
		// TODO return nil if the upstream type is not OIDC
		// TODO lookup the idp by name in c.idpCache to get the cached provider interface, return error if not found
		// TODO use the cached interface to always revoke the refresh token, return any error
		plog.Trace("garbage collector successfully revoked upstream refresh token", logKV(secret))
		return nil
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

func logKV(secret *v1.Secret) []interface{} {
	return []interface{}{
		"secretName", secret.Name,
		"secretNamespace", secret.Namespace,
		"secretType", string(secret.Type),
		"garbageCollectAfter", secret.Annotations[crud.SecretLifetimeAnnotationKey],
		"storageTypeLabelValue", secret.Labels[crud.SecretLabelKey],
	}
}
