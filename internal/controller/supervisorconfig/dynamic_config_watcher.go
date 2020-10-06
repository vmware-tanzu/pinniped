// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
)

const (
	issuerConfigMapKey = "issuer"
)

// IssuerSetter can be notified of a valid issuer with its SetIssuer function. If there is no
// longer any valid issuer, then nil can be passed to this interface.
//
// Implementations of this type should be thread-safe to support calls from multiple goroutines.
type IssuerSetter interface {
	SetIssuer(issuer *string)
}

type dynamicConfigWatcherController struct {
	configMapName      string
	configMapNamespace string
	issuerSetter       IssuerSetter
	k8sClient          kubernetes.Interface
	configMapInformer  corev1informers.ConfigMapInformer
}

func NewDynamicConfigWatcherController(
	serverInstallationNamespace string,
	configMapName string,
	issuerObserver IssuerSetter,
	k8sClient kubernetes.Interface,
	configMapInformer corev1informers.ConfigMapInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "DynamicConfigWatcherController",
			Syncer: &dynamicConfigWatcherController{
				configMapNamespace: serverInstallationNamespace,
				configMapName:      configMapName,
				issuerSetter:       issuerObserver,
				k8sClient:          k8sClient,
				configMapInformer:  configMapInformer,
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
	// TODO The discovery endpoint would return an error until all missing configuration options are
	// filled in.

	configMap, err := c.configMapInformer.
		Lister().
		ConfigMaps(c.configMapNamespace).
		Get(c.configMapName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s secret: %w", c.configMapNamespace, c.configMapName, err)
	}

	if notFound {
		klog.InfoS(
			"dynamicConfigWatcherController Sync found no configmap",
			"configmap",
			klog.KRef(c.configMapNamespace, c.configMapName),
		)
		c.issuerSetter.SetIssuer(nil)
		return nil
	}

	issuer, ok := configMap.Data[issuerConfigMapKey]
	if !ok {
		klog.InfoS(
			"dynamicConfigWatcherController Sync found no issuer",
			"configmap",
			klog.KObj(configMap),
		)
		c.issuerSetter.SetIssuer(nil)
		return nil
	}

	klog.InfoS(
		"dynamicConfigWatcherController Sync issuer",
		"configmap",
		klog.KObj(configMap),
		"issuer",
		issuer,
	)
	c.issuerSetter.SetIssuer(&issuer)

	return nil
}
