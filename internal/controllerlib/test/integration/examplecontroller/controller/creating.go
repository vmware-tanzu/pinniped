// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/events"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/controllerlib/test/integration/examplecontroller/api"
	"go.pinniped.dev/internal/plog"
)

func NewExampleCreatingController(
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

	requiresSecretGeneration := func(service *corev1.Service) (bool, error) {
		// check the secret since it could not have been created yet
		secretName := service.Annotations[api.SecretNameAnnotation]
		if len(secretName) == 0 {
			return false, nil
		}

		secret, err := secretLister.Secrets(service.Namespace).Get(secretName)
		if apierrors.IsNotFound(err) {
			// we have not created the secret yet
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("unable to get the secret %s/%s: %w", service.Namespace, secretName, err)
		}

		if string(secret.Data[api.SecretDataKey]) == secretData {
			return false, nil
		}

		// the secret exists but the data does not match what we expect (i.e. we have new secretData now)
		return true, nil
	}

	generateSecret := func(service *corev1.Service) error {
		plog.Debug("generating new secret for service", "namespace", service.Namespace, "name", service.Name)

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      service.Annotations[api.SecretNameAnnotation],
				Namespace: service.Namespace,
				Annotations: map[string]string{
					api.ServiceUIDAnnotation:  string(service.UID),
					api.ServiceNameAnnotation: service.Name,
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "v1",
						Kind:       "Service",
						Name:       service.Name,
						UID:        service.UID,
					},
				},
				Finalizers: nil, // TODO maybe add finalizer to guarantee we never miss a delete event?
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				api.SecretDataKey: []byte(secretData),
			},
		}

		_, err := secretClient.Secrets(service.Namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			actualSecret, getErr := secretClient.Secrets(service.Namespace).Get(context.TODO(), secret.Name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}

			if actualSecret.Annotations[api.ServiceUIDAnnotation] != string(service.UID) {
				utilruntime.HandleError(fmt.Errorf("secret %s/%s does not have corresponding service UID %v", actualSecret.Namespace, actualSecret.Name, service.UID))
				return nil // drop from queue because we cannot safely update this secret
			}

			plog.Debug("updating data in existing secret", "namespace", secret.Namespace, "name", secret.Name)
			// Actually update the secret in the regeneration case (the secret already exists but we want to update to new secretData).
			_, updateErr := secretClient.Secrets(secret.Namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
			return updateErr
		}
		if err != nil {
			return fmt.Errorf("unable to create secret %s/%s: %w", secret.Namespace, secret.Name, err)
		}

		return nil
	}

	syncer := controllerlib.SyncFunc(func(ctx controllerlib.Context) error {
		service, err := serviceLister.Services(ctx.Key.Namespace).Get(ctx.Key.Name)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("unable to get the service %s/%s: %w", service.Namespace, service.Name, err)
		}

		ok, err := requiresSecretGeneration(service)
		if err != nil || !ok {
			return err
		}

		return generateSecret(service)
	})

	config := controllerlib.Config{
		Name:   "example-controller-creating",
		Syncer: syncer,
	}

	toServiceName := func(secret *corev1.Secret) (string, bool) {
		serviceName := secret.Annotations[api.ServiceNameAnnotation]
		return serviceName, len(serviceName) != 0
	}

	hasSecretNameAnnotation := func(obj metav1.Object) bool {
		return len(obj.GetAnnotations()[api.SecretNameAnnotation]) != 0
	}
	hasSecretNameAnnotationUpdate := func(oldObj, newObj metav1.Object) bool {
		return hasSecretNameAnnotation(newObj) || hasSecretNameAnnotation(oldObj)
	}

	return controllerlib.New(config,
		controllerlib.WithInformer(services, controllerlib.FilterFuncs{
			AddFunc:    hasSecretNameAnnotation,
			UpdateFunc: hasSecretNameAnnotationUpdate,
		}, controllerlib.InformerOption{}),

		controllerlib.WithInformer(secrets, controllerlib.FilterFuncs{
			ParentFunc: func(obj metav1.Object) controllerlib.Key {
				secret := obj.(*corev1.Secret)
				serviceName, _ := toServiceName(secret)
				return controllerlib.Key{Namespace: secret.Namespace, Name: serviceName}
			},
			DeleteFunc: func(obj metav1.Object) bool {
				secret := obj.(*corev1.Secret)
				serviceName, ok := toServiceName(secret)
				if !ok {
					return false
				}
				service, err := serviceLister.Services(secret.Namespace).Get(serviceName)
				if apierrors.IsNotFound(err) {
					return false
				}
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("unable to get service %s/%s: %w", secret.Namespace, serviceName, err))
					return false
				}
				plog.Debug("recreating secret", "namespace", service.Namespace, "name", service.Name)
				return true
			},
		}, controllerlib.InformerOption{}),

		controllerlib.WithRecorder(recorder), // TODO actually use the recorder
	)
}
