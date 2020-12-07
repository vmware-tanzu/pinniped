// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/events"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/controllerlib/test/integration/examplecontroller/api"
)

func NewExampleUpdatingController(
	services corev1informers.ServiceInformer,
	secrets corev1informers.SecretInformer,
	secretClient corev1client.SecretsGetter,
	recorder events.EventRecorder,
	secretData string,
) controllerlib.Controller {
	serviceLister := services.Lister()
	secretLister := secrets.Lister()

	// note that these functions do not need to be inlined
	// this just demonstrates that for simple Syncer implementations, everything can be in one place

	toServiceName := func(secret *corev1.Secret) (string, bool) {
		serviceName := secret.Annotations[api.ServiceNameAnnotation]
		return serviceName, len(serviceName) != 0
	}

	ensureSecretData := func(service *corev1.Service, secretCopy *corev1.Secret) bool {
		var needsUpdate bool

		expectedData := map[string][]byte{
			api.SecretDataKey: []byte(secretData),
		}
		if !reflect.DeepEqual(secretCopy.Data, expectedData) {
			secretCopy.Data = expectedData
			needsUpdate = true
		}

		expectedOwnerReferences := []metav1.OwnerReference{
			{
				APIVersion: "v1",
				Kind:       "Service",
				Name:       service.Name,
				UID:        service.UID,
			},
		}
		if !reflect.DeepEqual(secretCopy.OwnerReferences, expectedOwnerReferences) {
			secretCopy.OwnerReferences = expectedOwnerReferences
			needsUpdate = true
		}

		return needsUpdate
	}

	isSecretValidForService := func(service *corev1.Service, secret *corev1.Secret) bool {
		if service.Annotations[api.SecretNameAnnotation] != secret.Name {
			return false
		}
		if secret.Annotations[api.ServiceUIDAnnotation] != string(service.UID) {
			return false
		}
		return true
	}

	getServiceForSecret := func(secret *corev1.Secret) (*corev1.Service, error) {
		serviceName, ok := toServiceName(secret)
		if !ok {
			return nil, nil
		}
		service, err := serviceLister.Services(secret.Namespace).Get(serviceName)
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("unable to get service %s/%s: %w", secret.Namespace, serviceName, err)
		}
		return service, nil
	}

	syncer := controllerlib.SyncFunc(func(ctx controllerlib.Context) error {
		secret, err := secretLister.Secrets(ctx.Key.Namespace).Get(ctx.Key.Name)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("unable to get the secret %s/%s: %w", secret.Namespace, secret.Name, err)
		}

		service, err := getServiceForSecret(secret)
		if err != nil || service == nil {
			return err
		}

		if !isSecretValidForService(service, secret) {
			utilruntime.HandleError(fmt.Errorf("secret %s/%s does not have corresponding service UID %v", secret.Namespace, secret.Name, service.UID))
			return nil
		}

		// make a copy to avoid mutating cache state
		secretCopy := secret.DeepCopy()

		if needsUpdate := ensureSecretData(service, secretCopy); needsUpdate {
			_, updateErr := secretClient.Secrets(secretCopy.Namespace).Update(context.TODO(), secretCopy, metav1.UpdateOptions{})
			return updateErr
		}

		return nil
	})

	config := controllerlib.Config{
		Name:   "example-controller-updating",
		Syncer: syncer,
	}

	addSecret := func(obj metav1.Object) bool {
		secret := obj.(*corev1.Secret)
		_, ok := toServiceName(secret)
		return ok
	}

	return controllerlib.New(config,
		controllerlib.WithInformer(services, controllerlib.FilterFuncs{}, controllerlib.InformerOption{SkipEvents: true}),

		controllerlib.WithInformer(secrets, controllerlib.FilterFuncs{
			AddFunc: addSecret,
			UpdateFunc: func(oldObj, newObj metav1.Object) bool {
				return addSecret(newObj) || addSecret(oldObj)
			},
		}, controllerlib.InformerOption{}),

		controllerlib.WithRecorder(recorder), // TODO actually use the recorder
	)
}
