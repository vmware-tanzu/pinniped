// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorstorage

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/plog"
)

type garbageCollectorController struct {
	secretInformer corev1informers.SecretInformer
	kubeClient     kubernetes.Interface
}

func GarbageCollectorController(
	kubeClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "garbage-collector-controller",
			Syncer: &garbageCollectorController{
				secretInformer: secretInformer,
				kubeClient:     kubeClient,
			},
		},
		withInformer(
			secretInformer,
			pinnipedcontroller.MatchNothingFilter(nil),
			controllerlib.InformerOption{},
		),
	)
}

func (c *garbageCollectorController) Sync(ctx controllerlib.Context) error {
	listOfSecrets, err := c.secretInformer.Lister().List(labels.Everything())
	if err != nil {
		return err
	}
	for i := range listOfSecrets {
		secret := listOfSecrets[i]
		s, ok := secret.Annotations[crud.SecretLifetimeAnnotationKey]
		if !ok {
			continue
		}
		currentTime := time.Now()
		garbageCollectAfterTime, err := time.Parse(time.RFC3339, s)
		if err != nil {
			plog.WarningErr("could not parse for garbage collection", err, "secretName", secret.Name, "garbageCollectAfter", s)
			continue
		}
		if garbageCollectAfterTime.Before(currentTime) {
			err = c.kubeClient.CoreV1().Secrets(secret.Namespace).Delete(ctx.Context, secret.Name, metav1.DeleteOptions{})
			if err != nil {
				plog.WarningErr("failed to garbage collect value", err, "secretName", secret.Name, "garbageCollectAfter", s)
			}
		}
	}
	return nil
}
