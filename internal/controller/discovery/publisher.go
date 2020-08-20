/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package discovery

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
	pinnipedcontroller "github.com/suzerain-io/pinniped/internal/controller"
	crdpinnipedv1alpha1 "github.com/suzerain-io/pinniped/kubernetes/1.19/api/apis/crdpinniped/v1alpha1"
	pinnipedclientset "github.com/suzerain-io/pinniped/kubernetes/1.19/client-go/clientset/versioned"
	crdpinnipedv1alpha1informers "github.com/suzerain-io/pinniped/kubernetes/1.19/client-go/informers/externalversions/crdpinniped/v1alpha1"
)

const (
	ClusterInfoNamespace = "kube-public"

	clusterInfoName         = "cluster-info"
	clusterInfoConfigMapKey = "kubeconfig"

	configName = "pinniped-config"
)

type publisherController struct {
	namespace                     string
	serverOverride                *string
	pinnipedClient                pinnipedclientset.Interface
	configMapInformer             corev1informers.ConfigMapInformer
	pinnipedDiscoveryInfoInformer crdpinnipedv1alpha1informers.PinnipedDiscoveryInfoInformer
}

func NewPublisherController(
	namespace string,
	serverOverride *string,
	pinnipedClient pinnipedclientset.Interface,
	configMapInformer corev1informers.ConfigMapInformer,
	pinnipedDiscoveryInfoInformer crdpinnipedv1alpha1informers.PinnipedDiscoveryInfoInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controller.Controller {
	return controller.New(
		controller.Config{
			Name: "publisher-controller",
			Syncer: &publisherController{
				namespace:                     namespace,
				serverOverride:                serverOverride,
				pinnipedClient:                pinnipedClient,
				configMapInformer:             configMapInformer,
				pinnipedDiscoveryInfoInformer: pinnipedDiscoveryInfoInformer,
			},
		},
		withInformer(
			configMapInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(clusterInfoName, ClusterInfoNamespace),
			controller.InformerOption{},
		),
		withInformer(
			pinnipedDiscoveryInfoInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(configName, namespace),
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

	discoveryInfo := crdpinnipedv1alpha1.PinnipedDiscoveryInfo{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      configName,
			Namespace: c.namespace,
		},
		Spec: crdpinnipedv1alpha1.PinnipedDiscoveryInfoSpec{
			Server:                   server,
			CertificateAuthorityData: certificateAuthorityData,
		},
	}
	if err := c.createOrUpdatePinnipedDiscoveryInfo(ctx.Context, &discoveryInfo); err != nil {
		return err
	}

	return nil
}

func (c *publisherController) createOrUpdatePinnipedDiscoveryInfo(
	ctx context.Context,
	discoveryInfo *crdpinnipedv1alpha1.PinnipedDiscoveryInfo,
) error {
	existingDiscoveryInfo, err := c.pinnipedDiscoveryInfoInformer.
		Lister().
		PinnipedDiscoveryInfos(c.namespace).
		Get(discoveryInfo.Name)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("could not get pinnipeddiscoveryinfo: %w", err)
	}

	pinnipedDiscoveryInfos := c.pinnipedClient.
		CrdV1alpha1().
		PinnipedDiscoveryInfos(c.namespace)
	if notFound {
		if _, err := pinnipedDiscoveryInfos.Create(
			ctx,
			discoveryInfo,
			metav1.CreateOptions{},
		); err != nil {
			return fmt.Errorf("could not create pinnipeddiscoveryinfo: %w", err)
		}
	} else if !equal(existingDiscoveryInfo, discoveryInfo) {
		// Update just the fields we care about.
		existingDiscoveryInfo.Spec.Server = discoveryInfo.Spec.Server
		existingDiscoveryInfo.Spec.CertificateAuthorityData = discoveryInfo.Spec.CertificateAuthorityData

		if _, err := pinnipedDiscoveryInfos.Update(
			ctx,
			existingDiscoveryInfo,
			metav1.UpdateOptions{},
		); err != nil {
			return fmt.Errorf("could not update pinnipeddiscoveryinfo: %w", err)
		}
	}

	return nil
}

func equal(a, b *crdpinnipedv1alpha1.PinnipedDiscoveryInfo) bool {
	return a.Spec.Server == b.Spec.Server &&
		a.Spec.CertificateAuthorityData == b.Spec.CertificateAuthorityData
}
