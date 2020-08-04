/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package logindiscovery

import (
	"context"
	"encoding/base64"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/controller-go"
	crdsplaceholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/crdsplaceholder/v1alpha1"
	placeholderclientset "github.com/suzerain-io/placeholder-name-client-go/pkg/generated/clientset/versioned"
	crdsplaceholderv1alpha1informers "github.com/suzerain-io/placeholder-name-client-go/pkg/generated/informers/externalversions/crdsplaceholder/v1alpha1"
)

const (
	ClusterInfoNamespace = "kube-public"

	clusterInfoName         = "cluster-info"
	clusterInfoConfigMapKey = "kubeconfig"

	configName = "placeholder-name-config"
)

func nameAndNamespaceExactMatchFilterFactory(name, namespace string) controller.FilterFuncs {
	objMatchesFunc := func(obj metav1.Object) bool {
		return obj.GetName() == name && obj.GetNamespace() == namespace
	}
	return controller.FilterFuncs{
		AddFunc: objMatchesFunc,
		UpdateFunc: func(oldObj, newObj metav1.Object) bool {
			return objMatchesFunc(oldObj) || objMatchesFunc(newObj)
		},
		DeleteFunc: objMatchesFunc,
	}
}

// Same signature as controller.WithInformer().
type withInformerOptionFunc func(
	getter controller.InformerGetter,
	filter controller.Filter,
	opt controller.InformerOption) controller.Option

type publisherController struct {
	namespace                    string
	serverOverride               *string
	placeholderClient            placeholderclientset.Interface
	configMapInformer            corev1informers.ConfigMapInformer
	loginDiscoveryConfigInformer crdsplaceholderv1alpha1informers.LoginDiscoveryConfigInformer
}

func NewPublisherController(
	namespace string,
	serverOverride *string,
	placeholderClient placeholderclientset.Interface,
	configMapInformer corev1informers.ConfigMapInformer,
	loginDiscoveryConfigInformer crdsplaceholderv1alpha1informers.LoginDiscoveryConfigInformer,
	withInformer withInformerOptionFunc,
) controller.Controller {
	return controller.New(
		controller.Config{
			Name: "publisher-controller",
			Syncer: &publisherController{
				namespace:                    namespace,
				serverOverride:               serverOverride,
				placeholderClient:            placeholderClient,
				configMapInformer:            configMapInformer,
				loginDiscoveryConfigInformer: loginDiscoveryConfigInformer,
			},
		},
		withInformer(
			configMapInformer,
			nameAndNamespaceExactMatchFilterFactory(clusterInfoName, ClusterInfoNamespace),
			controller.InformerOption{},
		),
		withInformer(
			loginDiscoveryConfigInformer,
			nameAndNamespaceExactMatchFilterFactory(configName, namespace),
			controller.InformerOption{},
		),
	)
}

func (c *publisherController) Sync(ctx controller.Context) error {
	configMap, err := c.configMapInformer.
		Lister().
		ConfigMaps(ClusterInfoNamespace).
		Get(clusterInfoName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s configmap: %w", clusterInfoName, err)
	}
	if notFound {
		klog.InfoS(
			"could not find config map",
			"configmap",
			klog.KRef(ClusterInfoNamespace, clusterInfoName),
		)
		return nil
	}

	kubeConfig, kubeConfigPresent := configMap.Data[clusterInfoConfigMapKey]
	if !kubeConfigPresent {
		klog.InfoS("could not find kubeconfig configmap key")
		return nil
	}

	config, _ := clientcmd.Load([]byte(kubeConfig))

	var certificateAuthorityData, server string
	for _, v := range config.Clusters {
		certificateAuthorityData = base64.StdEncoding.EncodeToString(v.CertificateAuthorityData)
		server = v.Server
		break
	}

	if c.serverOverride != nil {
		server = *c.serverOverride
	}

	discoveryConfig := crdsplaceholderv1alpha1.LoginDiscoveryConfig{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      configName,
			Namespace: c.namespace,
		},
		Spec: crdsplaceholderv1alpha1.LoginDiscoveryConfigSpec{
			Server:                   server,
			CertificateAuthorityData: certificateAuthorityData,
		},
	}
	if err := c.createOrUpdateLoginDiscoveryConfig(ctx.Context, &discoveryConfig); err != nil {
		return err
	}

	return nil
}

func (c *publisherController) createOrUpdateLoginDiscoveryConfig(
	ctx context.Context,
	discoveryConfig *crdsplaceholderv1alpha1.LoginDiscoveryConfig,
) error {
	existingDiscoveryConfig, err := c.loginDiscoveryConfigInformer.
		Lister().
		LoginDiscoveryConfigs(c.namespace).
		Get(discoveryConfig.Name)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("could not get logindiscoveryconfig: %w", err)
	}

	loginDiscoveryConfigs := c.placeholderClient.
		CrdsV1alpha1().
		LoginDiscoveryConfigs(c.namespace)
	if notFound {
		if _, err := loginDiscoveryConfigs.Create(
			ctx,
			discoveryConfig,
			metav1.CreateOptions{},
		); err != nil {
			return fmt.Errorf("could not create logindiscoveryconfig: %w", err)
		}
	} else if !equal(existingDiscoveryConfig, discoveryConfig) {
		// Update just the fields we care about.
		existingDiscoveryConfig.Spec.Server = discoveryConfig.Spec.Server
		existingDiscoveryConfig.Spec.CertificateAuthorityData = discoveryConfig.Spec.CertificateAuthorityData

		if _, err := loginDiscoveryConfigs.Update(
			ctx,
			existingDiscoveryConfig,
			metav1.UpdateOptions{},
		); err != nil {
			return fmt.Errorf("could not update logindiscoveryconfig: %w", err)
		}
	}

	return nil
}

func equal(a, b *crdsplaceholderv1alpha1.LoginDiscoveryConfig) bool {
	return a.Spec.Server == b.Spec.Server &&
		a.Spec.CertificateAuthorityData == b.Spec.CertificateAuthorityData
}
