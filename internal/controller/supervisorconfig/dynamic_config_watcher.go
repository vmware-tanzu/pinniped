// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
)

type dynamicConfigWatcherController struct {
	k8sClient         kubernetes.Interface
	configMapInformer corev1informers.ConfigMapInformer
}

func NewDynamicConfigWatcherController(
	serverInstallationNamespace string,
	configMapName string,
	k8sClient kubernetes.Interface,
	configMapInformer corev1informers.ConfigMapInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "DynamicConfigWatcherController",
			Syncer: &dynamicConfigWatcherController{
				k8sClient:         k8sClient,
				configMapInformer: configMapInformer,
			},
		},
		withInformer(
			configMapInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(configMapName, serverInstallationNamespace),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *dynamicConfigWatcherController) Sync(ctx controllerlib.Context) error {
	// TODO Watch the configmap to find the issuer name, ingress url, etc.
	// TODO Update some kind of in-memory representation of the configuration so the discovery endpoint can use it.
	// TODO The discovery endpoint would return an error until all missing configuration options are filled in.

	klog.InfoS("DynamicConfigWatcherController sync finished")

	return nil
}
