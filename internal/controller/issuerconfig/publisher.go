/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package issuerconfig

import (
	"encoding/base64"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/controller-go"
	crdpinnipedv1alpha1 "github.com/suzerain-io/pinniped/generated/1.19/apis/crdpinniped/v1alpha1"
	pinnipedclientset "github.com/suzerain-io/pinniped/generated/1.19/client/clientset/versioned"
	crdpinnipedv1alpha1informers "github.com/suzerain-io/pinniped/generated/1.19/client/informers/externalversions/crdpinniped/v1alpha1"
	pinnipedcontroller "github.com/suzerain-io/pinniped/internal/controller"
)

const (
	ClusterInfoNamespace = "kube-public"

	clusterInfoName         = "cluster-info"
	clusterInfoConfigMapKey = "kubeconfig"

	configName = "pinniped-config"
)

type publisherController struct {
	namespace                      string
	serverOverride                 *string
	pinnipedClient                 pinnipedclientset.Interface
	configMapInformer              corev1informers.ConfigMapInformer
	credentialIssuerConfigInformer crdpinnipedv1alpha1informers.CredentialIssuerConfigInformer
}

func NewPublisherController(
	namespace string,
	serverOverride *string,
	pinnipedClient pinnipedclientset.Interface,
	configMapInformer corev1informers.ConfigMapInformer,
	credentialIssuerConfigInformer crdpinnipedv1alpha1informers.CredentialIssuerConfigInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controller.Controller {
	return controller.New(
		controller.Config{
			Name: "publisher-controller",
			Syncer: &publisherController{
				namespace:                      namespace,
				serverOverride:                 serverOverride,
				pinnipedClient:                 pinnipedClient,
				configMapInformer:              configMapInformer,
				credentialIssuerConfigInformer: credentialIssuerConfigInformer,
			},
		},
		withInformer(
			configMapInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(clusterInfoName, ClusterInfoNamespace),
			controller.InformerOption{},
		),
		withInformer(
			credentialIssuerConfigInformer,
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

	config, err := clientcmd.Load([]byte(kubeConfig))
	if err != nil {
		klog.InfoS("could not load kubeconfig configmap key")
		return nil
	}

	var certificateAuthorityData, server string
	for _, v := range config.Clusters {
		certificateAuthorityData = base64.StdEncoding.EncodeToString(v.CertificateAuthorityData)
		server = v.Server
		break
	}

	if c.serverOverride != nil {
		server = *c.serverOverride
	}

	existingCredentialIssuerConfigFromInformerCache, err := c.credentialIssuerConfigInformer.
		Lister().
		CredentialIssuerConfigs(c.namespace).
		Get(configName)
	notFound = k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("could not get credentialissuerconfig: %w", err)
	}

	updateServerAndCAFunc := func(c *crdpinnipedv1alpha1.CredentialIssuerConfig) {
		c.Status.KubeConfigInfo = &crdpinnipedv1alpha1.CredentialIssuerConfigKubeConfigInfo{
			Server:                   server,
			CertificateAuthorityData: certificateAuthorityData,
		}
	}

	err = createOrUpdateCredentialIssuerConfig(
		ctx.Context,
		existingCredentialIssuerConfigFromInformerCache,
		notFound,
		configName,
		c.namespace,
		c.pinnipedClient,
		updateServerAndCAFunc)

	if err != nil {
		return fmt.Errorf("could not create or update credentialissuerconfig: %w", err)
	}
	return nil
}
