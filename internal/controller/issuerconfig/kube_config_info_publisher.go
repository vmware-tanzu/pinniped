// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuerconfig

import (
	"encoding/base64"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

const (
	ClusterInfoNamespace    = "kube-public"
	clusterInfoName         = "cluster-info"
	clusterInfoConfigMapKey = "kubeconfig"
)

type kubeConigInfoPublisherController struct {
	credentialIssuerResourceName string
	credentialIssuerLabels       map[string]string
	serverOverride               *string
	pinnipedClient               pinnipedclientset.Interface
	configMapInformer            corev1informers.ConfigMapInformer
}

// NewKubeConfigInfoPublisherController returns a controller that syncs the
// configv1alpha1.CredentialIssuer.Status.KubeConfigInfo field with the cluster-info ConfigMap
// in the kube-public namespace.
func NewKubeConfigInfoPublisherController(
	credentialIssuerResourceName string,
	credentialIssuerLabels map[string]string,
	serverOverride *string,
	pinnipedClient pinnipedclientset.Interface,
	configMapInformer corev1informers.ConfigMapInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "publisher-controller",
			Syncer: &kubeConigInfoPublisherController{
				credentialIssuerResourceName: credentialIssuerResourceName,
				credentialIssuerLabels:       credentialIssuerLabels,
				serverOverride:               serverOverride,
				pinnipedClient:               pinnipedClient,
				configMapInformer:            configMapInformer,
			},
		},
		withInformer(
			configMapInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(clusterInfoName, ClusterInfoNamespace),
			controllerlib.InformerOption{},
		),
	)
}

func (c *kubeConigInfoPublisherController) Sync(ctx controllerlib.Context) error {
	configMap, err := c.configMapInformer.
		Lister().
		ConfigMaps(ClusterInfoNamespace).
		Get(clusterInfoName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s configmap: %w", clusterInfoName, err)
	}
	if notFound {
		plog.Debug(
			"could not find config map",
			"configmap",
			klog.KRef(ClusterInfoNamespace, clusterInfoName),
		)
		return nil
	}

	kubeConfig, kubeConfigPresent := configMap.Data[clusterInfoConfigMapKey]
	if !kubeConfigPresent {
		plog.Debug("could not find kubeconfig configmap key")
		return nil
	}

	config, err := clientcmd.Load([]byte(kubeConfig))
	if err != nil {
		plog.Debug("could not load kubeconfig configmap key")
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

	updateServerAndCAFunc := func(c *configv1alpha1.CredentialIssuerStatus) {
		c.KubeConfigInfo = &configv1alpha1.CredentialIssuerKubeConfigInfo{
			Server:                   server,
			CertificateAuthorityData: certificateAuthorityData,
		}
	}

	return CreateOrUpdateCredentialIssuerStatus(
		ctx.Context,
		c.credentialIssuerResourceName,
		c.credentialIssuerLabels,
		c.pinnipedClient,
		updateServerAndCAFunc,
	)
}
